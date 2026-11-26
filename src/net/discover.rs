use crate::crypto::trust::PeerKey;
use crate::proto::{Name, PROTO};
use crossbeam_channel::{Receiver, bounded};
use mdns_sd::{
    IfKind, IfPredicate, ServiceDaemon, ServiceEvent, ServiceInfo, instance_name_unescaped,
};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    thread,
    time::Duration,
};

pub const SERVICE: &str = "_csync._tcp.local.";
const TXT_PROJECT: &str = "p";
const TXT_PROTO: &str = "v";
const TXT_FPR: &str = "k";
const TXT_VAL_MAX: usize = 200;
const LABEL_MAX: usize = 40;
const ADDRS_MAX: usize = 8;
const EVENTS_MAX: usize = 256;
const VPN_PREFIXES: &[&str] = &[
    "utun",
    "tun",
    "tap",
    "wg",
    "ppp",
    "ipsec",
    "tailscale",
    "zt",
    "gif",
    "stf",
    "awdl",
    "llw",
];

#[derive(Clone, Debug)]
pub struct HostAd {
    pub fullname: String,
    pub label: Name,
    pub project: Name,
    pub proto: u16,
    pub fpr: [u8; 8],
    pub addrs: Vec<SocketAddr>,
}

#[derive(Clone, Debug)]
pub enum Found {
    Added(HostAd),
    Removed { fullname: String },
}

fn mdns_err(e: mdns_sd::Error) -> io::Error {
    io::Error::other(format!("mdns: {e}"))
}

fn is_vpn(name: &str) -> bool {
    VPN_PREFIXES.iter().any(|p| name.starts_with(p))
}

fn daemon(all_ifaces: bool) -> io::Result<ServiceDaemon> {
    let d = ServiceDaemon::new().map_err(mdns_err)?;
    if !all_ifaces {
        let skip = IfPredicate::new(|i| i.is_p2p() || is_vpn(&i.name));
        if let Err(e) = d.disable_interface(IfKind::Predicate(skip)) {
            let _ = d.shutdown();
            return Err(mdns_err(e));
        }
    }
    Ok(d)
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn parse_fpr(s: &str) -> Option<[u8; 8]> {
    let b = s.as_bytes();
    if b.len() != 16 {
        return None;
    }
    let nib = |c: u8| (c as char).to_digit(16).map(|v| v as u8);
    let mut out = [0u8; 8];
    for (i, o) in out.iter_mut().enumerate() {
        *o = (nib(b[2 * i])? << 4) | nib(b[2 * i + 1])?;
    }
    Some(out)
}

pub struct Advert {
    daemon: ServiceDaemon,
    fullname: String,
}

pub fn advertise(project: &Name, port: u16, key: &PeerKey, all_ifaces: bool) -> io::Result<Advert> {
    let fpr = key.fpr_hex();
    let instance = format!("{}-{}", truncate(project.as_str(), LABEL_MAX), &fpr[..8]);
    let host = format!("csync-{fpr}.local.");
    let mut props = HashMap::new();
    props.insert(
        TXT_PROJECT.to_string(),
        truncate(project.as_str(), TXT_VAL_MAX).to_string(),
    );
    props.insert(TXT_PROTO.to_string(), PROTO.to_string());
    props.insert(TXT_FPR.to_string(), fpr);
    let info = ServiceInfo::new(SERVICE, &instance, &host, (), port, props)
        .map_err(mdns_err)?
        .enable_addr_auto();
    let fullname = info.get_fullname().to_string();
    let daemon = daemon(all_ifaces)?;
    if let Err(e) = daemon.register(info) {
        let _ = daemon.shutdown();
        return Err(mdns_err(e));
    }
    Ok(Advert { daemon, fullname })
}

impl Drop for Advert {
    fn drop(&mut self) {
        // wait briefly so the goodbye packets leave before the daemon stops
        if let Ok(rx) = self.daemon.unregister(&self.fullname) {
            let _ = rx.recv_timeout(Duration::from_millis(500));
        }
        let _ = self.daemon.shutdown();
    }
}

pub struct Browser {
    daemon: ServiceDaemon,
    rx: Receiver<Found>,
}

impl Browser {
    pub fn events(&self) -> &Receiver<Found> {
        &self.rx
    }
}

impl Drop for Browser {
    fn drop(&mut self) {
        let _ = self.daemon.stop_browse(SERVICE);
        let _ = self.daemon.shutdown();
    }
}

fn usable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_unspecified() && !v4.is_multicast() && !v4.is_broadcast(),
        // link-local v6 needs a scope id that a plain SocketAddr cannot carry
        IpAddr::V6(v6) => {
            !v6.is_unspecified() && !v6.is_multicast() && (v6.segments()[0] & 0xffc0) != 0xfe80
        }
    }
}

fn to_ad(r: &mdns_sd::ResolvedService) -> Option<HostAd> {
    let project = Name::new(r.get_property_val_str(TXT_PROJECT)?).ok()?;
    let proto = r.get_property_val_str(TXT_PROTO)?.parse::<u16>().ok()?;
    let fpr = parse_fpr(r.get_property_val_str(TXT_FPR)?)?;
    let port = r.get_port();
    if port == 0 {
        return None;
    }
    let mut addrs: Vec<SocketAddr> = r
        .get_addresses()
        .iter()
        .map(|a| a.to_ip_addr())
        .filter(usable)
        .map(|ip| SocketAddr::new(ip, port))
        .collect();
    addrs.sort_by_key(|a| (a.is_ipv6(), *a));
    addrs.dedup();
    addrs.truncate(ADDRS_MAX);
    if addrs.is_empty() {
        return None;
    }
    let fullname = r.get_fullname().to_string();
    let label = Name::new(truncate(
        &instance_name_unescaped(&fullname),
        LABEL_MAX + 17,
    ))
    .unwrap_or_else(|_| project.clone());
    Some(HostAd {
        fullname,
        label,
        project,
        proto,
        fpr,
        addrs,
    })
}

pub fn browse(all_ifaces: bool) -> io::Result<Browser> {
    let daemon = daemon(all_ifaces)?;
    let events = match daemon.browse(SERVICE) {
        Ok(rx) => rx,
        Err(e) => {
            let _ = daemon.shutdown();
            return Err(mdns_err(e));
        }
    };
    let (tx, rx) = bounded(EVENTS_MAX);
    let spawned = thread::Builder::new()
        .name("csync-mdns".into())
        .spawn(move || {
            while let Ok(ev) = events.recv() {
                let out = match ev {
                    ServiceEvent::ServiceResolved(r) => match to_ad(&r) {
                        Some(ad) => Found::Added(ad),
                        None => continue,
                    },
                    ServiceEvent::ServiceRemoved(_, fullname) => Found::Removed { fullname },
                    _ => continue,
                };
                if tx.send(out).is_err() {
                    return;
                }
            }
        });
    if let Err(e) = spawned {
        let _ = daemon.shutdown();
        return Err(e);
    }
    Ok(Browser { daemon, rx })
}
