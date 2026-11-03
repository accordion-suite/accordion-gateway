//! UPnP's Internet Gateway Device protocol, which most home routers speak:
//! find the router with a multicast search, read its description, then ask
//! its WAN connection service to forward a port.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::{Method as HttpMethod, Request};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use tokio::net::UdpSocket;

use super::{Mapping, Method, Refused};

/// How long routers get to answer the search, and each request.
const SEARCH_WAIT: Duration = Duration::from_secs(3);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Routers' descriptions are a few kilobytes. Anything much bigger isn't one.
const MAX_REPLY: usize = 256 * 1024;

const SEARCH_TARGET: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";

/// The description says what port mappings are called in it.
const DESCRIPTION: &str = "Accordion remote access";

/// UPnP error codes worth a plain explanation.
const CONFLICT: u32 = 718;
const ONLY_PERMANENT: u32 = 725;
const NOT_AUTHORIZED: u32 = 606;

/// A router's WAN connection service, once found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Gateway {
    control: String,
    service: String,
    /// The server's address on the network the router is on.
    own: Ipv4Addr,
}

/// Searches for a router at `ssdp`, which is UPnP's multicast address on a
/// real network.
pub(super) async fn find(ssdp: SocketAddr) -> Option<Gateway> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.ok()?;
    let search = format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: {SEARCH_TARGET}\r\n\
         MAN: \"ssdp:discover\"\r\nMX: 2\r\n\r\n"
    );
    socket.send_to(search.as_bytes(), ssdp).await.ok()?;
    let mut buffer = [0; 2048];
    let deadline = tokio::time::Instant::now() + SEARCH_WAIT;
    loop {
        let (len, from) = tokio::time::timeout_at(deadline, socket.recv_from(&mut buffer))
            .await
            .ok()?
            .ok()?;
        let Some(location) = header(&String::from_utf8_lossy(&buffer[..len]), "location") else {
            continue;
        };
        if let Some(gateway) = describe(&location, from).await {
            return Some(gateway);
        }
    }
}

/// Reads the router's description at `location` and finds its WAN
/// connection service.
async fn describe(location: &str, from: SocketAddr) -> Option<Gateway> {
    let description = get(location).await?;
    let (service, control) = wan_service(&description)?;
    let base = element(&description, "URLBase").unwrap_or_else(|| origin(location).to_owned());
    let control = if control.starts_with("http://") {
        control
    } else {
        format!(
            "{}/{}",
            base.trim_end_matches('/'),
            control.trim_start_matches('/')
        )
    };
    // The address the server reaches the router from, which is the one to
    // forward to.
    let probe = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    probe.connect(from).ok()?;
    let IpAddr::V4(own) = probe.local_addr().ok()?.ip() else {
        return None;
    };
    Some(Gateway {
        control,
        service,
        own,
    })
}

/// Asks the router to forward UDP `port` to the server for `lifetime`.
pub(super) async fn map(
    gateway: &Gateway,
    port: u16,
    lifetime: Duration,
) -> Result<Mapping, Refused> {
    let mut lease = lifetime.as_secs();
    let mut reply = add(gateway, port, lease).await;
    if matches!(reply, Err(Some(ONLY_PERMANENT))) {
        // Older routers only keep mappings until they restart.
        lease = 0;
        reply = add(gateway, port, lease).await;
    }
    match reply {
        Ok(()) => {}
        Err(Some(CONFLICT)) => return Err(Refused::PortTaken),
        Err(Some(NOT_AUTHORIZED)) => return Err(Refused::NotAllowed),
        Err(Some(code)) => return Err(Refused::Other(format!("UPnP error {code}"))),
        Err(None) => return Err(Refused::Other("no answer to UPnP".into())),
    }
    let external_address = soap(gateway, "GetExternalIPAddress", "")
        .await
        .ok()
        .and_then(|reply| element(&reply, "NewExternalIPAddress"))
        .and_then(|address| address.trim().parse().ok());
    Ok(Mapping {
        method: Method::Upnp,
        external_address,
        external_port: port,
        // A permanent lease is still renewed, in case the router restarts.
        lifetime: if lease == 0 {
            lifetime
        } else {
            Duration::from_secs(lease)
        },
    })
}

async fn add(gateway: &Gateway, port: u16, lease: u64) -> Result<(), Option<u32>> {
    let arguments = format!(
        "<NewRemoteHost></NewRemoteHost><NewExternalPort>{port}</NewExternalPort>\
         <NewProtocol>UDP</NewProtocol><NewInternalPort>{port}</NewInternalPort>\
         <NewInternalClient>{own}</NewInternalClient><NewEnabled>1</NewEnabled>\
         <NewPortMappingDescription>{DESCRIPTION}</NewPortMappingDescription>\
         <NewLeaseDuration>{lease}</NewLeaseDuration>",
        own = gateway.own
    );
    soap(gateway, "AddPortMapping", &arguments).await.map(drop)
}

/// Removes the mapping for UDP `port`.
pub(super) async fn unmap(gateway: &Gateway, port: u16) {
    let arguments = format!(
        "<NewRemoteHost></NewRemoteHost><NewExternalPort>{port}</NewExternalPort>\
         <NewProtocol>UDP</NewProtocol>"
    );
    let _ = soap(gateway, "DeletePortMapping", &arguments).await;
}

/// Calls `action` on the router's service. A refusal carries the UPnP error
/// code, if the router sent one.
async fn soap(gateway: &Gateway, action: &str, arguments: &str) -> Result<String, Option<u32>> {
    let body = format!(
        "<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>\
         <u:{action} xmlns:u=\"{service}\">{arguments}</u:{action}></s:Body></s:Envelope>\r\n",
        service = gateway.service
    );
    let request = Request::builder()
        .method(HttpMethod::POST)
        .uri(&gateway.control)
        .header("content-type", "text/xml; charset=\"utf-8\"")
        .header("soapaction", format!("\"{}#{action}\"", gateway.service))
        .body(Full::new(Bytes::from(body)))
        .map_err(|_| None)?;
    let (ok, reply) = send(request).await.ok_or(None)?;
    if ok {
        return Ok(reply);
    }
    Err(element(&reply, "errorCode").and_then(|code| code.trim().parse().ok()))
}

async fn get(url: &str) -> Option<String> {
    let request = Request::builder()
        .uri(url)
        .body(Full::new(Bytes::new()))
        .ok()?;
    let (ok, reply) = send(request).await?;
    ok.then_some(reply)
}

/// Sends a plain HTTP request on the home network. Returns whether it
/// succeeded, and the reply.
async fn send(request: Request<Full<Bytes>>) -> Option<(bool, String)> {
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(HttpConnector::new());
    let response = tokio::time::timeout(REQUEST_TIMEOUT, client.request(request))
        .await
        .ok()?
        .ok()?;
    let ok = response.status().is_success();
    let body = tokio::time::timeout(
        REQUEST_TIMEOUT,
        Limited::new(response.into_body(), MAX_REPLY).collect(),
    )
    .await
    .ok()?
    .ok()?
    .to_bytes();
    Some((ok, String::from_utf8_lossy(&body).into_owned()))
}

/// The value of an HTTP-style header in an SSDP reply.
fn header(reply: &str, name: &str) -> Option<String> {
    reply.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_owned())
    })
}

/// The text of the first `<name>` element, with or without a namespace
/// prefix.
pub(super) fn element(xml: &str, name: &str) -> Option<String> {
    let mut rest = xml;
    loop {
        let start = rest.find('<')?;
        rest = &rest[start + 1..];
        let end = rest.find('>')?;
        let tag = &rest[..end];
        let local = tag.rsplit(':').next().unwrap_or(tag);
        if local == name {
            let text = &rest[end + 1..];
            let close = text.find("</")?;
            return Some(text[..close].trim().to_owned());
        }
        rest = &rest[end..];
    }
}

/// The router's WAN connection service and its control address: IP for
/// most routers, PPP for those that dial in.
fn wan_service(description: &str) -> Option<(String, String)> {
    description.split("<service>").skip(1).find_map(|service| {
        let service_type = element(service, "serviceType")?;
        let wanted = service_type.contains(":WANIPConnection:")
            || service_type.contains(":WANPPPConnection:");
        wanted.then_some((service_type, element(service, "controlURL")?))
    })
}

/// `http://host:port` from a URL.
fn origin(url: &str) -> &str {
    let after_scheme = url.find("://").map_or(0, |at| at + 3);
    let end = url[after_scheme..]
        .find('/')
        .map_or(url.len(), |at| after_scheme + at);
    &url[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_router_description() {
        let description = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
<device><serviceList>
<service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>
<controlURL>/ctl/L3F</controlURL></service>
</serviceList>
<deviceList><device><deviceList><device><serviceList>
<service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:2</serviceType>
<serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
<controlURL>/ctl/IPConn</controlURL></service>
</serviceList></device></deviceList></device></deviceList>
</device></root>"#;
        assert_eq!(
            wan_service(description),
            Some((
                "urn:schemas-upnp-org:service:WANIPConnection:2".into(),
                "/ctl/IPConn".into()
            ))
        );
        assert_eq!(
            origin("http://192.168.1.1:5000/rootDesc.xml"),
            "http://192.168.1.1:5000"
        );
        assert_eq!(
            element(
                "<s:Body><u:R><NewExternalIPAddress>203.0.113.7</NewExternalIPAddress>",
                "NewExternalIPAddress"
            ),
            Some("203.0.113.7".into())
        );
        assert_eq!(
            header(
                "HTTP/1.1 200 OK\r\nLocation: http://192.168.1.1/desc.xml\r\n",
                "location"
            ),
            Some("http://192.168.1.1/desc.xml".into())
        );
    }
}
