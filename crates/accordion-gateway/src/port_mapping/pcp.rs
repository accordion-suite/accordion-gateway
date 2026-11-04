//! The Port Control Protocol (PCP, RFC 6887) and its older form, NAT-PMP
//! (RFC 6886). Both ask the router, on UDP port 5351, to forward a port,
//! and the answer says what the home's public address is.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;

use super::{Forward, Mapping, Method, Protocol, Refused};

/// How long to wait for each answer. RFC 6886 starts at 250 ms and doubles;
/// three tries cover routers that are slow to wake up.
const WAITS: [Duration; 3] = [
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_millis(1000),
];

const PCP_VERSION: u8 = 2;
const NAT_PMP_VERSION: u8 = 0;
const MAP: u8 = 1;
/// PCP's and NAT-PMP's "unsupported version" result codes.
const UNSUPPORTED_VERSION: u8 = 1;

/// What the router said.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Answer {
    Mapped(Mapping),
    Refused(Refused),
    /// The router doesn't speak this version.
    WrongVersion,
}

/// Asks the router at `router` to forward a port through PCP. With a
/// lifetime of zero, it removes the mapping instead. `nonce` has to be the
/// same for a renewal or removal as for the request that made the mapping.
pub(super) async fn map_pcp(
    router: SocketAddr,
    protocol: Protocol,
    forward: Forward,
    lifetime: u32,
    nonce: [u8; 12],
) -> Option<Answer> {
    let socket = connected(router).await?;
    let IpAddr::V4(own) = socket.local_addr().ok()?.ip() else {
        return None;
    };
    let mut request = Vec::with_capacity(60);
    request.extend_from_slice(&[PCP_VERSION, MAP, 0, 0]);
    request.extend_from_slice(&lifetime.to_be_bytes());
    request.extend_from_slice(&own.to_ipv6_mapped().octets());
    request.extend_from_slice(&nonce);
    request.extend_from_slice(&[protocol.number(), 0, 0, 0]);
    request.extend_from_slice(&forward.internal.to_be_bytes());
    request.extend_from_slice(&forward.external.to_be_bytes());
    // Any external address.
    request.extend_from_slice(&Ipv4Addr::UNSPECIFIED.to_ipv6_mapped().octets());

    let reply = ask(&socket, &request, |reply| {
        // A NAT-PMP router answers PCP with its own unsupported version.
        if reply.len() >= 4 && reply[0] == NAT_PMP_VERSION {
            return true;
        }
        // Refusals may leave out the request's details.
        reply.len() >= 24
            && reply[0] == PCP_VERSION
            && reply[1] == 0x80 | MAP
            && (reply[3] != 0 || (reply.len() >= 60 && reply[24..36] == nonce))
    })
    .await?;
    if reply[0] == NAT_PMP_VERSION || reply[3] == UNSUPPORTED_VERSION {
        return Some(Answer::WrongVersion);
    }
    let result = reply[3];
    if result != 0 {
        return Some(Answer::Refused(pcp_refusal(result)));
    }
    let lifetime = u32::from_be_bytes(reply[4..8].try_into().ok()?);
    let external_port = u16::from_be_bytes([reply[42], reply[43]]);
    let external = Ipv6Addr::from(<[u8; 16]>::try_from(&reply[44..60]).ok()?);
    Some(Answer::Mapped(Mapping {
        method: Method::Pcp,
        external_address: external.to_ipv4_mapped().map(IpAddr::V4),
        external_port,
        lifetime: Duration::from_secs(lifetime.into()),
    }))
}

/// Asks the router at `router` to forward a port through NAT-PMP, then for
/// the public address. With a lifetime of zero, it removes the mapping.
pub(super) async fn map_nat_pmp(
    router: SocketAddr,
    protocol: Protocol,
    forward: Forward,
    lifetime: u32,
) -> Option<Answer> {
    let socket = connected(router).await?;
    // NAT-PMP's opcodes: 1 maps UDP, and 2 maps TCP.
    let opcode = match protocol {
        Protocol::Udp => 1,
        Protocol::Tcp => 2,
    };
    let mut request = vec![NAT_PMP_VERSION, opcode, 0, 0];
    request.extend_from_slice(&forward.internal.to_be_bytes());
    request.extend_from_slice(&if lifetime == 0 { 0 } else { forward.external }.to_be_bytes());
    request.extend_from_slice(&lifetime.to_be_bytes());
    let reply = ask(&socket, &request, |reply| {
        reply.len() >= 16 && reply[0] == NAT_PMP_VERSION && reply[1] == 0x80 | opcode
    })
    .await?;
    let result = u16::from_be_bytes([reply[2], reply[3]]);
    if result == u16::from(UNSUPPORTED_VERSION) {
        return Some(Answer::WrongVersion);
    }
    if result != 0 {
        return Some(Answer::Refused(nat_pmp_refusal(result)));
    }
    let external_port = u16::from_be_bytes([reply[10], reply[11]]);
    let granted = u32::from_be_bytes(reply[12..16].try_into().ok()?);
    let external_address = if lifetime == 0 {
        None
    } else {
        public_address(&socket).await
    };
    Some(Answer::Mapped(Mapping {
        method: Method::NatPmp,
        external_address,
        external_port,
        lifetime: Duration::from_secs(granted.into()),
    }))
}

/// NAT-PMP's public address request, which a mapping doesn't answer.
async fn public_address(socket: &UdpSocket) -> Option<IpAddr> {
    let reply = ask(socket, &[NAT_PMP_VERSION, 0], |reply| {
        reply.len() >= 12 && reply[0] == NAT_PMP_VERSION && reply[1] == 0x80
    })
    .await?;
    (reply[2..4] == [0, 0])
        .then(|| IpAddr::V4(Ipv4Addr::new(reply[8], reply[9], reply[10], reply[11])))
}

async fn connected(router: SocketAddr) -> Option<UdpSocket> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.ok()?;
    socket.connect(router).await.ok()?;
    Some(socket)
}

/// Sends `request` until an answer that `fits` comes back, or the waits
/// run out.
async fn ask(socket: &UdpSocket, request: &[u8], fits: impl Fn(&[u8]) -> bool) -> Option<Vec<u8>> {
    let mut buffer = [0; 1100];
    for wait in WAITS {
        socket.send(request).await.ok()?;
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            match tokio::time::timeout_at(deadline, socket.recv(&mut buffer)).await {
                Ok(Ok(len)) if fits(&buffer[..len]) => return Some(buffer[..len].to_vec()),
                // Not an answer to this request, or the router isn't
                // listening, which shows as a refused connection.
                Ok(Ok(_)) => {}
                Ok(Err(_)) => return None,
                Err(_) => break,
            }
        }
    }
    None
}

fn pcp_refusal(result: u8) -> Refused {
    match result {
        2 => Refused::NotAllowed,
        8 | 10 => Refused::NoRoom,
        11 => Refused::PortTaken,
        other => Refused::Other(format!("PCP result {other}")),
    }
}

fn nat_pmp_refusal(result: u16) -> Refused {
    match result {
        2 => Refused::NotAllowed,
        4 => Refused::NoRoom,
        other => Refused::Other(format!("NAT-PMP result {other}")),
    }
}
