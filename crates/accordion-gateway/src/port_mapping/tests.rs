//! Port mapping against stand-in routers that speak PCP, NAT-PMP, or UPnP,
//! including routers that refuse and ones behind carrier-grade NAT.

use std::sync::{Arc, Mutex};

use axum::Router as HttpRouter;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::{get, post};
use tokio::net::{TcpListener, UdpSocket};

use super::*;

/// What a stand-in router does with requests.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Speaks {
    Pcp,
    NatPmp,
    /// PCP, but it refuses every request.
    PcpRefusing,
}

/// The requests a stand-in got: the port and lifetime of each mapping
/// request, or the action of each UPnP call.
type Log = Arc<Mutex<Vec<String>>>;

/// A PCP or NAT-PMP router on a local port, reporting `external` as the
/// home's public address.
async fn pcp_router(speaks: Speaks, external: Ipv4Addr, log: Log) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = [0; 1100];
        loop {
            let (len, from) = socket.recv_from(&mut buffer).await.unwrap();
            let request = &buffer[..len];
            let reply = match (speaks, request[0]) {
                // NAT-PMP's answer to any other version.
                (Speaks::NatPmp, 2) => vec![0, 0x80 | request[1], 0, 1],
                (Speaks::NatPmp, 0) if request[1] == 0 => {
                    let mut reply = vec![0, 0x80, 0, 0, 0, 0, 0, 1];
                    reply.extend_from_slice(&external.octets());
                    reply
                }
                (Speaks::NatPmp, 0) => {
                    let port = u16::from_be_bytes([request[4], request[5]]);
                    let lifetime = u32::from_be_bytes(request[8..12].try_into().unwrap());
                    log.lock()
                        .unwrap()
                        .push(format!("map {port} for {lifetime}"));
                    let mut reply = vec![0, 0x81, 0, 0, 0, 0, 0, 1];
                    reply.extend_from_slice(&request[4..6]);
                    reply.extend_from_slice(&request[6..8]);
                    reply.extend_from_slice(&request[8..12]);
                    reply
                }
                (Speaks::Pcp | Speaks::PcpRefusing, 2) => {
                    let port = u16::from_be_bytes([request[40], request[41]]);
                    let lifetime = u32::from_be_bytes(request[4..8].try_into().unwrap());
                    if request[36] == 6 {
                        let external = u16::from_be_bytes([request[42], request[43]]);
                        log.lock()
                            .unwrap()
                            .push(format!("map TCP {external} to {port} for {lifetime}"));
                    } else {
                        log.lock()
                            .unwrap()
                            .push(format!("map {port} for {lifetime}"));
                    }
                    let result = if speaks == Speaks::PcpRefusing { 2 } else { 0 };
                    let mut reply = vec![2, 0x81, 0, result];
                    reply.extend_from_slice(&request[4..8]);
                    reply.extend_from_slice(&[0; 16]);
                    reply.extend_from_slice(&request[24..36]);
                    reply.extend_from_slice(&request[36..42]);
                    reply.extend_from_slice(&request[40..42]);
                    reply.extend_from_slice(&external.to_ipv6_mapped().octets());
                    reply
                }
                _ => continue,
            };
            socket.send_to(&reply, from).await.unwrap();
        }
    });
    address
}

/// A UDP port where nothing listens, standing in for a router that doesn't
/// speak a protocol.
async fn silent() -> SocketAddr {
    UdpSocket::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

/// A UPnP router: its search answer, and the HTTP server with its
/// description and control service. Returns where to search.
async fn upnp_router(external: Ipv4Addr, log: Log) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http = listener.local_addr().unwrap();
    let description = r#"<?xml version="1.0"?><root><device><deviceList><device><serviceList>
<service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
<controlURL>/ctl/IPConn</controlURL></service></serviceList></device></deviceList></device></root>"#;
    let control = post(
        |State((log, external)): State<(Log, Ipv4Addr)>, headers: HeaderMap, body: String| async move {
            let action = headers["soapaction"].to_str().unwrap().to_owned();
            let action = action
                .trim_matches('"')
                .rsplit('#')
                .next()
                .unwrap()
                .to_owned();
            if action == "AddPortMapping" {
                let port = upnp::element(&body, "NewExternalPort").unwrap();
                let lease = upnp::element(&body, "NewLeaseDuration").unwrap();
                log.lock().unwrap().push(format!("map {port} for {lease}"));
            } else {
                log.lock().unwrap().push(action.clone());
            }
            format!(
                "<s:Envelope><s:Body><u:{action}Response>\
                 <NewExternalIPAddress>{external}</NewExternalIPAddress>\
                 </u:{action}Response></s:Body></s:Envelope>"
            )
        },
    );
    let app = HttpRouter::new()
        .route("/desc.xml", get(move || async move { description }))
        .route("/ctl/IPConn", control)
        .with_state((log, external));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let ssdp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = ssdp.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = [0; 2048];
        loop {
            let (_, from) = ssdp.recv_from(&mut buffer).await.unwrap();
            let reply = format!(
                "HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
                 LOCATION: http://{http}/desc.xml\r\n\r\n"
            );
            ssdp.send_to(reply.as_bytes(), from).await.unwrap();
        }
    });
    address
}

/// Runs a mapper for `router` until the test ends.
fn start(
    router: Router,
    port: Option<u16>,
) -> (watch::Sender<Option<Forward>>, watch::Receiver<PortStatus>) {
    start_for(router, Protocol::Udp, port.map(Forward::same))
}

fn start_for(
    router: Router,
    protocol: Protocol,
    forward: Option<Forward>,
) -> (watch::Sender<Option<Forward>>, watch::Receiver<PortStatus>) {
    let (switch, port) = watch::channel(forward);
    let mapper = PortMapper::new(Some(router), protocol, port);
    let status = mapper.status();
    tokio::spawn(mapper.run(std::future::pending()));
    (switch, status)
}

async fn wait_for(
    status: &mut watch::Receiver<PortStatus>,
    done: impl Fn(&PortStatus) -> bool,
) -> PortStatus {
    tokio::time::timeout(
        Duration::from_secs(20),
        status.wait_for(|status| done(status)),
    )
    .await
    .expect("the status changed in time")
    .unwrap()
    .clone()
}

const PUBLIC: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);

#[tokio::test]
async fn maps_through_pcp_and_removes_the_mapping() {
    let log = Log::default();
    let router = Router {
        pcp: pcp_router(Speaks::Pcp, PUBLIC, log.clone()).await,
        ssdp: silent().await,
    };
    let (switch, mut status) = start(router, Some(51820));
    let mapped = wait_for(&mut status, |status| status.mapping.is_some()).await;
    let mapping = mapped.mapping.unwrap();
    assert_eq!(mapping.method, Method::Pcp);
    assert_eq!(mapping.external_address, Some(IpAddr::V4(PUBLIC)));
    assert_eq!(mapping.external_port, 51820);
    assert!(!mapped.shared_address);

    // A new port replaces the old one, and turning off removes it.
    switch.send_replace(Some(Forward::same(51821)));
    wait_for(&mut status, |status| {
        status.port == Some(51821) && status.mapping.is_some()
    })
    .await;
    switch.send_replace(None);
    wait_for(&mut status, |status| status.port.is_none()).await;
    assert_eq!(
        *log.lock().unwrap(),
        [
            "map 51820 for 3600",
            "map 51820 for 0",
            "map 51821 for 3600",
            "map 51821 for 0"
        ]
    );
}

#[tokio::test]
async fn forwards_a_tcp_port_to_another_port_on_the_server() {
    let log = Log::default();
    let router = Router {
        pcp: pcp_router(Speaks::Pcp, PUBLIC, log.clone()).await,
        ssdp: silent().await,
    };
    let forward = Forward {
        internal: 8443,
        external: 443,
    };
    let (_switch, mut status) = start_for(router, Protocol::Tcp, Some(forward));
    let mapped = wait_for(&mut status, |status| status.mapping.is_some()).await;
    assert_eq!(mapped.port, Some(443));
    assert_eq!(*log.lock().unwrap(), ["map TCP 443 to 8443 for 3600"]);
}

#[tokio::test]
async fn falls_back_to_nat_pmp() {
    let log = Log::default();
    let router = Router {
        pcp: pcp_router(Speaks::NatPmp, PUBLIC, log.clone()).await,
        ssdp: silent().await,
    };
    let (_switch, mut status) = start(router, Some(51820));
    let mapping = wait_for(&mut status, |status| status.mapping.is_some())
        .await
        .mapping
        .unwrap();
    assert_eq!(mapping.method, Method::NatPmp);
    assert_eq!(mapping.external_address, Some(IpAddr::V4(PUBLIC)));
    assert_eq!(*log.lock().unwrap(), ["map 51820 for 3600"]);
}

#[tokio::test]
async fn falls_back_to_upnp() {
    let log = Log::default();
    let router = Router {
        pcp: silent().await,
        ssdp: upnp_router(PUBLIC, log.clone()).await,
    };
    let (switch, mut status) = start(router, Some(51820));
    let mapping = wait_for(&mut status, |status| status.mapping.is_some())
        .await
        .mapping
        .unwrap();
    assert_eq!(mapping.method, Method::Upnp);
    assert_eq!(mapping.external_address, Some(IpAddr::V4(PUBLIC)));
    switch.send_replace(None);
    wait_for(&mut status, |status| status.port.is_none()).await;
    assert_eq!(
        *log.lock().unwrap(),
        [
            "map 51820 for 3600",
            "GetExternalIPAddress",
            "DeletePortMapping"
        ]
    );
}

#[tokio::test]
async fn explains_a_refusal_and_a_shared_address() {
    let refusing = Router {
        pcp: pcp_router(Speaks::PcpRefusing, PUBLIC, Log::default()).await,
        ssdp: silent().await,
    };
    let (_switch, mut status) = start(refusing, Some(51820));
    let refused = wait_for(&mut status, |status| status.problem.is_some()).await;
    assert!(
        refused
            .problem
            .unwrap()
            .contains("port forwarding requests turned off"),
    );
    assert!(!refused.no_answer);

    // The provider shares one address among many homes.
    let shared = Router {
        pcp: pcp_router(Speaks::Pcp, Ipv4Addr::new(100, 72, 9, 14), Log::default()).await,
        ssdp: silent().await,
    };
    let (_switch, mut status) = start(shared, Some(51820));
    assert!(
        wait_for(&mut status, |status| status.mapping.is_some())
            .await
            .shared_address
    );
}

#[tokio::test]
async fn says_when_no_router_answers() {
    let router = Router {
        pcp: silent().await,
        ssdp: silent().await,
    };
    let (_switch, mut status) = start(router, Some(51820));
    let status = wait_for(&mut status, |status| status.problem.is_some()).await;
    assert!(status.no_answer);
    assert!(status.mapping.is_none());
}

#[test]
fn reads_the_default_route() {
    let routes = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n\
                  eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n\
                  eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\n";
    assert_eq!(default_gateway(routes), Some(Ipv4Addr::new(192, 168, 1, 1)));
    assert_eq!(default_gateway("Iface\tDestination\n"), None);
    assert!(is_shared(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
    assert!(is_shared(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2))));
    assert!(!is_shared(IpAddr::V4(PUBLIC)));
}
