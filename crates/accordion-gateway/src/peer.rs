//! Who's on the other end of a connection, and whether they're on the home
//! network.
//!
//! The setup wizard and admin pages answer only the home network, and sign-in
//! limits treat it more gently. Both need the client's address and the
//! address it reached the server on.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use axum::extract::connect_info::Connected;
use axum::serve::IncomingStream;
use tokio::net::TcpListener;

/// The two ends of a connection. [`crate::tls::serve`] adds it to every
/// request as `ConnectInfo<Peer>`. For plain HTTP, serve the router with
/// `into_make_service_with_connect_info::<Peer>()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peer {
    /// The server's address, as the client reached it.
    pub local: SocketAddr,
    /// The client's address.
    pub remote: SocketAddr,
}

impl Connected<IncomingStream<'_, TcpListener>> for Peer {
    fn connect_info(stream: IncomingStream<'_, TcpListener>) -> Self {
        let remote = *stream.remote_addr();
        Self {
            local: stream.io().local_addr().unwrap_or(remote),
            remote,
        }
    }
}

impl Peer {
    /// Whether the client is on the same network as the server. Private and
    /// link-local addresses always are, which also covers VPN clients. Home
    /// networks give devices public IPv6 addresses too, so those count when
    /// they share the server's /64.
    pub fn on_home_network(&self) -> bool {
        match self.remote.ip().to_canonical() {
            IpAddr::V4(address) => {
                address.is_loopback() || address.is_private() || address.is_link_local()
            }
            IpAddr::V6(address) => {
                address.is_loopback()
                    || address.is_unique_local()
                    || address.is_unicast_link_local()
                    || matches!(
                        self.local.ip().to_canonical(),
                        IpAddr::V6(local) if same_64(local, address)
                    )
            }
        }
    }
}

fn same_64(a: Ipv6Addr, b: Ipv6Addr) -> bool {
    a.segments()[..4] == b.segments()[..4]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(local: &str, remote: &str) -> Peer {
        Peer {
            local: SocketAddr::new(local.parse().unwrap(), 443),
            remote: SocketAddr::new(remote.parse().unwrap(), 50000),
        }
    }

    #[test]
    fn knows_the_home_network() {
        for remote in [
            "192.168.1.30",
            "10.0.0.5",
            "127.0.0.1",
            "169.254.1.1",
            "::ffff:192.168.1.30",
        ] {
            assert!(peer("192.168.1.20", remote).on_home_network(), "{remote}");
        }
        for remote in ["203.0.113.5", "8.8.8.8", "2001:db8::5"] {
            assert!(!peer("192.168.1.20", remote).on_home_network(), "{remote}");
        }

        let local = "2001:db8:1:2::20";
        assert!(peer(local, "2001:db8:1:2::99").on_home_network());
        assert!(peer(local, "fe80::1").on_home_network());
        assert!(peer(local, "fd12::1").on_home_network());
        assert!(!peer(local, "2001:db8:1:3::99").on_home_network());
    }
}
