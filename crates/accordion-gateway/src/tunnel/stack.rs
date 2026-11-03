//! The tunnel's own small TCP/IP stack (decision 21).
//!
//! WireGuard hands over the IP packets it opens. This stack, built on
//! smoltcp, turns the ones for the gateway into TCP connections and hands
//! each to the gateway's servers, as if it had come in on a real port. It
//! answers nothing else: a packet for any other address, port, or protocol
//! is dropped before smoltcp sees it, so a device on the tunnel can reach
//! Accordion and nothing else on the machine or the home network.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::{Buf, BytesMut};
use gotatun::packet::{Ip, Packet, PacketBufPool};
use gotatun::tun::{IpRecv, IpSend, MtuWatcher};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, mpsc, watch};

use crate::peer::Peer;

/// The largest packet inside the tunnel. WireGuard's own headers fit in the
/// rest of a 1,500-byte packet on IPv6, which every WireGuard app assumes.
pub const MTU: u16 = 1420;

/// Packets waiting between WireGuard and the stack, each way. When a queue
/// is full, packets are dropped, as a busy network card would, and TCP
/// sends them again.
const QUEUE: usize = 1024;

/// Listening sockets kept ready on each port. A browser opens several
/// connections at once, and each socket takes one.
const SPARE_LISTENERS: usize = 4;

/// Connections open at once, across every device. Each one can hold up to
/// 256 KB in buffers, so this caps the stack at about 64 MB.
const MAX_CONNECTIONS: usize = 256;

/// smoltcp's buffers for each connection, each way.
const SOCKET_BUFFER: usize = 64 * 1024;

/// Data waiting between smoltcp and the gateway's server, each way.
const STREAM_BUFFER: usize = 64 * 1024;

/// An idle connection is checked this often. A device that doesn't answer
/// for `GONE_AFTER` has gone, such as a phone that left the mobile
/// network, so its connection is ended.
const KEEP_ALIVE: Duration = Duration::from_secs(60);
const GONE_AFTER: Duration = Duration::from_secs(180);

/// The addresses that devices reach the server at: its address on the home
/// network, which its name points at, and its own address on the tunnel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Addresses {
    pub home: Ipv4Addr,
    pub tunnel: Ipv4Addr,
}

impl Addresses {
    fn contains(self, address: Ipv4Addr) -> bool {
        address == self.home || address == self.tunnel
    }
}

/// A connection from a device, for the gateway's server on `port`.
pub struct Accepted {
    pub stream: TunnelStream,
    pub peer: Peer,
}

/// Where the stack sends each port's connections: usually HTTPS on 443,
/// and the redirect to it on 80.
#[derive(Clone)]
pub struct Listeners(pub Vec<(u16, mpsc::Sender<Accepted>)>);

impl Listeners {
    fn ports(&self) -> Vec<u16> {
        self.0.iter().map(|(port, _)| *port).collect()
    }

    fn for_port(&self, port: u16) -> Option<&mpsc::Sender<Accepted>> {
        self.0
            .iter()
            .find(|(each, _)| *each == port)
            .map(|(_, sender)| sender)
    }
}

/// Packets that WireGuard opened, on their way to the stack.
pub struct Inbound {
    packets: mpsc::Sender<Vec<u8>>,
    addresses: watch::Receiver<Addresses>,
    ports: Vec<u16>,
}

/// Packets from the stack, on their way to WireGuard to be sealed.
pub struct Outbound {
    packets: mpsc::Receiver<Vec<u8>>,
}

/// The stack itself, until [`Stack::run`] takes it over.
pub struct Stack {
    inbound: mpsc::Receiver<Vec<u8>>,
    outbound: mpsc::Sender<Vec<u8>>,
    addresses: watch::Receiver<Addresses>,
    listeners: Listeners,
}

/// Makes a stack and the two ends WireGuard uses to reach it.
pub fn new(
    addresses: watch::Receiver<Addresses>,
    listeners: Listeners,
) -> (Stack, Inbound, Outbound) {
    let (to_stack, inbound) = mpsc::channel(QUEUE);
    let (outbound, from_stack) = mpsc::channel(QUEUE);
    let ports = listeners.ports();
    (
        Stack {
            inbound,
            outbound,
            addresses: addresses.clone(),
            listeners,
        },
        Inbound {
            packets: to_stack,
            addresses,
            ports,
        },
        Outbound {
            packets: from_stack,
        },
    )
}

impl IpSend for Inbound {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        let packet = packet.into_bytes();
        if for_gateway(&packet, *self.addresses.borrow(), &self.ports) {
            // A full queue drops the packet, and a stopped stack means the
            // tunnel is stopping too.
            let _ = self.packets.try_send(packet.to_vec());
        }
        Ok(())
    }
}

impl IpRecv for Outbound {
    async fn recv<'a>(
        &'a mut self,
        _pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let Some(first) = self.packets.recv().await else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the tunnel's network stack stopped",
            ));
        };
        let mut packets = vec![first];
        while packets.len() < 64
            && let Ok(packet) = self.packets.try_recv()
        {
            packets.push(packet);
        }
        Ok(packets.into_iter().filter_map(|packet| {
            Packet::from_bytes(BytesMut::from(&packet[..]))
                .try_into_ip()
                .ok()
        }))
    }

    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(MTU)
    }
}

/// Whether an IP packet from a device is for the gateway: TCP, to one of
/// `ports`, at one of the stack's addresses. Fragments are dropped too:
/// devices send packets that fit the tunnel, and only the first fragment
/// would say which port it's for.
fn for_gateway(packet: &[u8], addresses: Addresses, ports: &[u16]) -> bool {
    const TCP: u8 = 6;
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return false;
    }
    let header = usize::from(packet[0] & 0x0f) * 4;
    let fragment = u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff;
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    if packet[9] != TCP || fragment != 0 || !addresses.contains(destination) {
        return false;
    }
    let Some(port) = packet.get(header + 2..header + 4) else {
        return false;
    };
    ports.contains(&u16::from_be_bytes([port[0], port[1]]))
}

/// smoltcp's view of the tunnel: packets in from WireGuard, and packets
/// out to it.
#[derive(Default)]
struct Wire {
    received: VecDeque<Vec<u8>>,
    sent: VecDeque<Vec<u8>>,
}

impl phy::Device for Wire {
    type RxToken<'a> = Received;
    type TxToken<'a> = Sending<'a>;

    fn receive(
        &mut self,
        _: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.received.pop_front()?;
        Some((Received(packet), Sending(&mut self.sent)))
    }

    fn transmit(&mut self, _: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(Sending(&mut self.sent))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = MTU.into();
        capabilities
    }
}

struct Received(Vec<u8>);

impl phy::RxToken for Received {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

struct Sending<'a>(&'a mut VecDeque<Vec<u8>>);

impl phy::TxToken for Sending<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        self.0.push_back(packet);
        result
    }
}

/// One TCP connection, from the stack's side.
struct Connection {
    socket: SocketHandle,
    port: u16,
    shared: Arc<Shared>,
    /// Handed to the gateway's server yet.
    handed_over: bool,
    /// smoltcp was told to close it.
    closing: bool,
}

impl Stack {
    /// Moves packets and connections until `stop` completes, then ends
    /// every connection.
    pub async fn run(mut self, stop: impl Future<Output = ()>) {
        let mut stop = std::pin::pin!(stop);
        let mut wire = Wire::default();
        let mut iface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut wire,
            smoltcp::time::Instant::now(),
        );
        let mut addresses = *self.addresses.borrow_and_update();
        set_addresses(&mut iface, addresses);
        let mut sockets = SocketSet::new(Vec::new());
        let mut listening: Vec<(SocketHandle, u16)> = Vec::new();
        let mut connections: Vec<Connection> = Vec::new();
        let wake = Arc::new(Notify::new());

        loop {
            let now = smoltcp::time::Instant::now();
            iface.poll(now, &mut wire, &mut sockets);

            // A listening socket that took a connection becomes the
            // connection's, and another takes its place.
            listening.retain(|&(socket, port)| {
                if sockets.get::<tcp::Socket>(socket).is_listening() {
                    return true;
                }
                connections.push(Connection {
                    socket,
                    port,
                    shared: Arc::new(Shared::new(Arc::clone(&wake))),
                    handed_over: false,
                    closing: false,
                });
                false
            });
            for port in self.listeners.ports() {
                while listening.iter().filter(|&&(_, each)| each == port).count() < SPARE_LISTENERS
                    && listening.len() + connections.len() < MAX_CONNECTIONS
                {
                    listening.push((listen(&mut sockets, port), port));
                }
            }

            connections.retain_mut(|connection| {
                let open = connection.move_data(&mut sockets, Some(&self.listeners));
                if !open {
                    sockets.remove(connection.socket);
                }
                open
            });
            // Moving data can leave packets to send, such as a window update.
            iface.poll(now, &mut wire, &mut sockets);
            for packet in wire.sent.drain(..) {
                // A full queue drops the packet, which TCP sends again.
                let _ = self.outbound.try_send(packet);
            }

            let delay = iface
                .poll_delay(now, &sockets)
                .map_or(Duration::from_secs(60), Duration::from);
            tokio::select! {
                biased;
                () = &mut stop => break,
                packet = self.inbound.recv() => {
                    let Some(packet) = packet else { break };
                    wire.received.push_back(packet);
                    while wire.received.len() < 64
                        && let Ok(packet) = self.inbound.try_recv()
                    {
                        wire.received.push_back(packet);
                    }
                }
                () = wake.notified() => {}
                Ok(()) = self.addresses.changed() => {
                    addresses = *self.addresses.borrow_and_update();
                    set_addresses(&mut iface, addresses);
                }
                () = tokio::time::sleep(delay) => {}
            }
        }

        for connection in connections {
            connection.shared.lock().end(true);
        }
    }
}

fn set_addresses(iface: &mut Interface, addresses: Addresses) {
    iface.update_ip_addrs(|list| {
        list.clear();
        // The tunnel's own /24 is on the link, so replies to devices need
        // no route.
        let _ = list.push(IpCidr::new(IpAddress::Ipv4(addresses.tunnel), 24));
        if addresses.home != addresses.tunnel {
            let _ = list.push(IpCidr::new(IpAddress::Ipv4(addresses.home), 32));
        }
    });
}

fn listen(sockets: &mut SocketSet<'_>, port: u16) -> SocketHandle {
    let buffer = || tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER]);
    let mut socket = tcp::Socket::new(buffer(), buffer());
    socket.set_keep_alive(Some(KEEP_ALIVE.into()));
    socket.set_timeout(Some(GONE_AFTER.into()));
    socket
        .listen(port)
        .expect("a new socket can listen on a port other than 0");
    sockets.add(socket)
}

fn socket_address(endpoint: IpEndpoint) -> SocketAddr {
    let address = match endpoint.addr {
        IpAddress::Ipv4(address) => IpAddr::V4(address),
    };
    SocketAddr::new(address, endpoint.port)
}

impl Connection {
    /// Moves data between smoltcp and the gateway's server. Returns
    /// `false` once the connection is over.
    fn move_data(&mut self, sockets: &mut SocketSet<'_>, listeners: Option<&Listeners>) -> bool {
        let socket = sockets.get_mut::<tcp::Socket>(self.socket);
        if let Some(listeners) = listeners
            && !self.handed_over
            && socket.may_send()
        {
            self.handed_over = true;
            let (Some(local), Some(remote)) = (socket.local_endpoint(), socket.remote_endpoint())
            else {
                socket.abort();
                return true;
            };
            let accepted = Accepted {
                stream: TunnelStream {
                    shared: Arc::clone(&self.shared),
                },
                peer: Peer {
                    local: socket_address(local),
                    remote: socket_address(remote),
                },
            };
            // The server is too busy or stopping, so turn the device away.
            let taken = listeners
                .for_port(self.port)
                .is_some_and(|listener| listener.try_send(accepted).is_ok());
            if !taken {
                socket.abort();
            }
        }

        let mut state = self.shared.lock();
        if state.dropped {
            // Nobody will read it, so take it and let the device finish.
            while socket.can_recv() && socket.recv(|data| (data.len(), ())).is_ok() {}
        }
        if self.handed_over && !state.dropped {
            let mut received = false;
            while socket.can_recv() && state.received.len() < STREAM_BUFFER {
                let room = STREAM_BUFFER - state.received.len();
                let taken = socket.recv(|data| {
                    let taken = data.len().min(room);
                    state.received.extend_from_slice(&data[..taken]);
                    (taken, taken)
                });
                match taken {
                    Ok(0) | Err(_) => break,
                    Ok(_) => received = true,
                }
            }
            // The device sent everything it's going to.
            let opening = matches!(
                socket.state(),
                tcp::State::Listen | tcp::State::SynSent | tcp::State::SynReceived
            );
            if !opening && !socket.may_recv() && !socket.can_recv() && !state.finished {
                state.finished = true;
                received = true;
            }
            if received {
                state.wake_reader();
            }
        }
        if self.handed_over {
            if !state.to_send.is_empty() && socket.can_send() {
                let sent = socket.send_slice(&state.to_send).unwrap_or(0);
                if sent > 0 {
                    state.to_send.advance(sent);
                    state.wake_writer();
                }
            }
            if state.done_writing && state.to_send.is_empty() && !self.closing {
                socket.close();
                self.closing = true;
            }
        }
        if socket.state() == tcp::State::Closed {
            let reset = !state.finished;
            state.end(reset);
            return false;
        }
        true
    }
}

/// What the stack and the gateway's server share about one connection.
struct Shared {
    state: Mutex<StreamState>,
    /// Wakes the stack when the server reads, writes, or closes.
    wake: Arc<Notify>,
}

#[derive(Default)]
struct StreamState {
    /// From the device, waiting for the server to read it.
    received: BytesMut,
    /// From the server, waiting for room in smoltcp's buffer.
    to_send: BytesMut,
    /// The device finished sending, so reads end once `received` is empty.
    finished: bool,
    /// The connection is gone, such as after the device reset it.
    ended: bool,
    /// The connection ended before the device finished sending, so reads
    /// fail rather than end.
    reset: bool,
    /// The server shut down its side, or dropped the stream.
    done_writing: bool,
    /// The server dropped the stream.
    dropped: bool,
    reader: Option<Waker>,
    writer: Option<Waker>,
}

impl Shared {
    fn new(wake: Arc<Notify>) -> Self {
        Self {
            state: Mutex::default(),
            wake,
        }
    }

    fn lock(&self) -> MutexGuard<'_, StreamState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl StreamState {
    fn wake_reader(&mut self) {
        if let Some(waker) = self.reader.take() {
            waker.wake();
        }
    }

    fn wake_writer(&mut self) {
        if let Some(waker) = self.writer.take() {
            waker.wake();
        }
    }

    fn end(&mut self, reset: bool) {
        self.ended = true;
        self.reset = reset;
        self.wake_reader();
        self.wake_writer();
    }
}

/// A TCP connection from a device on the tunnel, as the gateway's server
/// reads and writes it.
pub struct TunnelStream {
    shared: Arc<Shared>,
}

impl AsyncRead for TunnelStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut state = self.shared.lock();
        if !state.received.is_empty() {
            let taken = state.received.len().min(buf.remaining());
            buf.put_slice(&state.received.split_to(taken));
            drop(state);
            self.shared.wake.notify_one();
            return Poll::Ready(Ok(()));
        }
        if state.finished {
            return Poll::Ready(Ok(()));
        }
        if state.ended {
            return Poll::Ready(if state.reset {
                Err(io::ErrorKind::ConnectionReset.into())
            } else {
                Ok(())
            });
        }
        state.reader = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for TunnelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut state = self.shared.lock();
        if state.ended || state.done_writing {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let room = STREAM_BUFFER.saturating_sub(state.to_send.len());
        if room == 0 {
            state.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let taken = room.min(buf.len());
        state.to_send.extend_from_slice(&buf[..taken]);
        drop(state);
        self.shared.wake.notify_one();
        Poll::Ready(Ok(taken))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.shared.lock();
        if state.to_send.is_empty() {
            return Poll::Ready(Ok(()));
        }
        if state.ended {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        state.writer = Some(cx.waker().clone());
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shared.lock().done_writing = true;
        self.shared.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for TunnelStream {
    fn drop(&mut self) {
        let mut state = self.shared.lock();
        state.done_writing = true;
        state.dropped = true;
        drop(state);
        self.shared.wake.notify_one();
    }
}

/// A device's side of a connection, for tests: a stack with one address
/// that opens one connection to `to`.
#[cfg(test)]
pub(super) mod client {
    use super::*;

    /// Every packet WireGuard opens for the device.
    pub struct ToDevice(mpsc::Sender<Vec<u8>>);

    impl IpSend for ToDevice {
        async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
            let _ = self.0.try_send(packet.into_bytes().to_vec());
            Ok(())
        }
    }

    /// Connects from `own` to `to`. Returns the ends for WireGuard, the
    /// connection, and the stack to run.
    pub fn connect(
        own: Ipv4Addr,
        to: SocketAddr,
    ) -> (ToDevice, Outbound, TunnelStream, impl Future<Output = ()>) {
        let (to_device, mut inbound) = mpsc::channel(QUEUE);
        let (outbound, from_device) = mpsc::channel(QUEUE);
        let wake = Arc::new(Notify::new());
        let shared = Arc::new(Shared::new(Arc::clone(&wake)));
        let stream = TunnelStream {
            shared: Arc::clone(&shared),
        };
        let IpAddr::V4(to_address) = to.ip() else {
            panic!("the tunnel carries IPv4");
        };
        let run = async move {
            let mut wire = Wire::default();
            let mut iface = Interface::new(
                Config::new(HardwareAddress::Ip),
                &mut wire,
                smoltcp::time::Instant::now(),
            );
            // A /0 puts every address on the link, so the device needs no
            // route.
            iface.update_ip_addrs(|list| {
                let _ = list.push(IpCidr::new(IpAddress::Ipv4(own), 0));
            });
            let mut sockets = SocketSet::new(Vec::new());
            let buffer = || tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER]);
            let socket = sockets.add(tcp::Socket::new(buffer(), buffer()));
            sockets
                .get_mut::<tcp::Socket>(socket)
                .connect(
                    iface.context(),
                    (IpAddress::Ipv4(to_address), to.port()),
                    49152,
                )
                .unwrap();
            let mut connection = Connection {
                socket,
                port: to.port(),
                shared,
                handed_over: true,
                closing: false,
            };
            loop {
                let now = smoltcp::time::Instant::now();
                iface.poll(now, &mut wire, &mut sockets);
                if !connection.move_data(&mut sockets, None) {
                    return;
                }
                iface.poll(now, &mut wire, &mut sockets);
                for packet in wire.sent.drain(..) {
                    let _ = outbound.try_send(packet);
                }
                let delay = iface
                    .poll_delay(now, &sockets)
                    .map_or(Duration::from_secs(60), Duration::from);
                tokio::select! {
                    packet = inbound.recv() => match packet {
                        Some(packet) => wire.received.push_back(packet),
                        None => return,
                    },
                    () = wake.notified() => {}
                    () = tokio::time::sleep(delay) => {}
                }
            }
        };
        (
            ToDevice(to_device),
            Outbound {
                packets: from_device,
            },
            stream,
            run,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A TCP packet from 10.8.0.2 to `destination`:`port`, with only the
    /// fields the filter reads filled in.
    fn tcp_packet(destination: [u8; 4], port: u16) -> Vec<u8> {
        let mut packet = vec![0; 40];
        packet[0] = 0x45;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 8, 0, 2]);
        packet[16..20].copy_from_slice(&destination);
        packet[22..24].copy_from_slice(&port.to_be_bytes());
        packet
    }

    #[test]
    fn lets_through_only_tcp_to_the_gateway() {
        let addresses = Addresses {
            home: Ipv4Addr::new(192, 168, 1, 20),
            tunnel: Ipv4Addr::new(10, 8, 0, 1),
        };
        let ports = [443, 80];
        let allowed = |packet: &[u8]| for_gateway(packet, addresses, &ports);

        assert!(allowed(&tcp_packet([192, 168, 1, 20], 443)));
        assert!(allowed(&tcp_packet([192, 168, 1, 20], 80)));
        assert!(allowed(&tcp_packet([10, 8, 0, 1], 443)));

        // Other ports and other machines.
        assert!(!allowed(&tcp_packet([192, 168, 1, 20], 22)));
        assert!(!allowed(&tcp_packet([192, 168, 1, 1], 443)));
        assert!(!allowed(&tcp_packet([10, 8, 0, 3], 443)));

        // UDP, fragments, IPv6, and packets too short to read.
        let mut udp = tcp_packet([192, 168, 1, 20], 443);
        udp[9] = 17;
        assert!(!allowed(&udp));
        let mut fragment = tcp_packet([192, 168, 1, 20], 443);
        fragment[6] = 0x20;
        assert!(!allowed(&fragment));
        let mut ipv6 = tcp_packet([192, 168, 1, 20], 443);
        ipv6[0] = 0x60;
        assert!(!allowed(&ipv6));
        assert!(!allowed(&tcp_packet([192, 168, 1, 20], 443)[..21]));
    }
}
