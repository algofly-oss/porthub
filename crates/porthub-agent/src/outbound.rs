//! Socket-local path selection. Discovery never modifies host networking.
use anyhow::{Context, Result};
use serde::Serialize;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Default)]
pub struct Settings {
    /// Empty means automatic selection within the kernel-selected interface.
    pub interface: Option<String>,
    pub source: Option<IpAddr>,
    /// Let the operating system select every connection's source.
    pub system: bool,
}
impl Settings {
    pub fn from_env() -> Result<Self> {
        let mode = std::env::var("PORTHUB_OUTBOUND_MODE").unwrap_or_else(|_| "auto".into());
        anyhow::ensure!(
            ["auto", "system", "interface"].contains(&mode.as_str()),
            "PORTHUB_OUTBOUND_MODE must be auto, system, or interface"
        );
        let interface = std::env::var("PORTHUB_OUTBOUND_INTERFACE")
            .ok()
            .filter(|v| !v.is_empty());
        let source = std::env::var("PORTHUB_OUTBOUND_SOURCE")
            .ok()
            .map(|v| v.parse())
            .transpose()
            .context("invalid PORTHUB_OUTBOUND_SOURCE")?;
        anyhow::ensure!(
            mode != "interface" || interface.is_some(),
            "interface mode requires PORTHUB_OUTBOUND_INTERFACE"
        );
        anyhow::ensure!(
            mode != "system" || (interface.is_none() && source.is_none()),
            "system mode cannot specify an interface or source"
        );
        Ok(Self {
            interface,
            source,
            system: mode == "system",
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Candidate {
    pub source: IpAddr,
    pub interface: String,
    pub destination: SocketAddr,
    pub gateway: Option<IpAddr>,
    pub metric: Option<u32>,
}
/// Linux uses source-aware FIB queries, not a physical-interface preference.
/// Alternatives must use the same kernel-selected egress as the unbound socket;
/// this deliberately refuses to escape a VPN or source-policy routing rule.
pub async fn discover(settings: &Settings, destinations: &[SocketAddr]) -> Result<Vec<Candidate>> {
    let interfaces: Vec<_> = getifaddrs::getifaddrs()
        .context("interface inventory unavailable")?
        .collect();
    #[cfg(target_os = "linux")]
    let netlink = nlink::netlink::Connection::<nlink::netlink::Route>::new()?;
    #[cfg(target_os = "linux")]
    let addresses = netlink.get_addresses().await?;
    let mut result = Vec::new();
    let (v4, v6): (Vec<&SocketAddr>, Vec<&SocketAddr>) = destinations
        .iter()
        .take(16)
        .partition(|address| address.is_ipv4());
    let mut v4 = v4.into_iter();
    let mut v6 = v6.into_iter();
    let mut targets: Vec<&SocketAddr> = Vec::new();
    loop {
        let a = v4.next();
        let b = v6.next();
        if a.is_none() && b.is_none() {
            break;
        }
        targets.extend(a);
        targets.extend(b);
    }
    for destination in targets {
        #[cfg(target_os = "linux")]
        let route = match netlink.lookup_route(destination.ip()).await {
            Ok(route) if route.route_type() == 1.into() => route,
            _ => continue,
        };
        let mut local_interfaces: Vec<_> = interfaces.iter().collect();
        #[cfg(target_os = "linux")]
        local_interfaces
            .sort_by_key(|interface| interface.address.ip_addr().as_ref() != route.prefsrc());
        for interface in local_interfaces {
            let Some(source) = interface.address.ip_addr() else {
                continue;
            };
            if !interface.flags.contains(getifaddrs::InterfaceFlags::UP)
                || source.is_ipv4() != destination.is_ipv4()
                || !porthub_mesh::underlay::candidate_ip(source)
                || interface.name.starts_with("ph")
                || settings
                    .interface
                    .as_ref()
                    .is_some_and(|name| name != &interface.name)
                || settings.source.is_some_and(|ip| ip != source)
            {
                continue;
            }
            #[cfg(target_os = "linux")]
            let (gateway, metric) = {
                if !addresses.iter().any(|address| {
                    Some(address.ifindex()) == interface.index
                        && address.local().or(address.address()) == Some(&source)
                        && !address.is_tentative()
                        && !address.is_dad_failed()
                        && !address.is_deprecated()
                }) {
                    continue;
                }
                let permitted = netlink.lookup_route_from(destination.ip(), source).await;
                let Ok(permitted) = permitted else {
                    continue;
                };
                if permitted.route_type() != 1.into() || permitted.oif() != interface.index {
                    continue;
                }
                if settings.interface.is_none()
                    && settings.source.is_none()
                    && permitted.oif() != route.oif()
                    && !route.oif().is_some_and(|index| {
                        crate::private_network::owned_exit_underlay(index, source)
                    })
                {
                    continue;
                }
                (permitted.gateway().copied(), permitted.priority())
            };
            // Other platforms conservatively retain the kernel's source. They
            // can still pin an explicitly selected local address administratively.
            #[cfg(not(target_os = "linux"))]
            if settings.source.is_none() && settings.interface.is_none() {
                let bind = if destination.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                };
                let socket = std::net::UdpSocket::bind(bind)?;
                socket.connect(destination)?;
                if socket.local_addr()?.ip() != source {
                    continue;
                }
            }
            result.push(Candidate {
                source,
                interface: interface.name.clone(),
                destination: *destination,
                #[cfg(target_os = "linux")]
                gateway,
                #[cfg(not(target_os = "linux"))]
                gateway: None,
                #[cfg(target_os = "linux")]
                metric,
                #[cfg(not(target_os = "linux"))]
                metric: None,
            });
            if result.len() == 32 {
                return Ok(result);
            }
        }
    }
    Ok(result)
}
#[derive(Default)]
pub struct Selection {
    selected: Option<Candidate>,
    failed: HashMap<(IpAddr, SocketAddr), (u32, Instant)>,
}
impl Selection {
    pub fn selected(&self) -> Option<&Candidate> {
        self.selected.as_ref()
    }
    pub fn order(&mut self, candidates: &[Candidate], now: Instant) -> Vec<Candidate> {
        self.failed
            .retain(|key, _| candidates.iter().any(|c| (c.source, c.destination) == *key));
        if let Some(previous) = self.selected.as_ref() {
            self.selected = candidates
                .iter()
                .find(|candidate| {
                    candidate.source == previous.source
                        && candidate.destination == previous.destination
                        && candidate.interface == previous.interface
                })
                .cloned();
        }
        let mut available: Vec<_> = candidates
            .iter()
            .filter(|c| {
                self.failed
                    .get(&(c.source, c.destination))
                    .is_none_or(|(_, until)| *until <= now)
            })
            .cloned()
            .collect();
        available.sort_by_key(|c| self.selected.as_ref() != Some(c));
        // A host with many IPv4 answers must still attempt IPv6 within the
        // per-operation budget (and vice versa).
        let preferred = self
            .selected
            .as_ref()
            .and_then(|selected| available.iter().position(|c| c == selected))
            .map(|index| available.remove(index));
        let (v4, v6): (Vec<_>, Vec<_>) = available.into_iter().partition(|c| c.source.is_ipv4());
        let mut v4 = v4.into_iter();
        let mut v6 = v6.into_iter();
        let mut ordered: Vec<_> = preferred.into_iter().collect();
        while ordered.len() < 8 {
            let next4 = v4.next();
            let next6 = v6.next();
            if next4.is_none() && next6.is_none() {
                break;
            }
            if let Some(candidate) = next4 {
                ordered.push(candidate);
            }
            if ordered.len() < 8 {
                if let Some(candidate) = next6 {
                    ordered.push(candidate);
                }
            }
        }
        ordered
    }
    pub fn failure(&mut self, candidate: &Candidate, now: Instant) {
        let failure = self
            .failed
            .entry((candidate.source, candidate.destination))
            .or_insert((0, now));
        failure.0 = (failure.0 + 1).min(6);
        failure.1 = now + Duration::from_secs((1u64 << failure.0).min(60));
        if self.selected.as_ref() == Some(candidate) {
            self.selected = None;
        }
    }
    pub fn success(&mut self, candidate: Candidate) {
        self.failed
            .remove(&(candidate.source, candidate.destination));
        self.selected = Some(candidate);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn path(source: &str, destination: &str) -> Candidate {
        Candidate {
            source: source.parse().unwrap(),
            interface: "eth0".into(),
            destination: destination.parse().unwrap(),
            gateway: None,
            metric: Some(100),
        }
    }
    #[test]
    fn failover_is_sticky_bounded_and_recovers_without_flapping() {
        let a = path("192.0.2.1", "192.0.2.10:443");
        let b = path("192.0.2.2", "192.0.2.10:443");
        let now = Instant::now();
        let mut state = Selection::default();
        state.failure(&a, now);
        assert_eq!(state.order(&[a.clone(), b.clone()], now), vec![b.clone()]);
        state.success(b.clone());
        assert_eq!(
            state.order(&[a.clone(), b.clone()], now + Duration::from_secs(120))[0],
            b
        );
        assert_eq!(
            state.order(&[a.clone()], now + Duration::from_secs(120)),
            vec![a]
        );
        assert!(state.selected().is_none());
    }
    #[test]
    fn ipv6_and_remote_addresses_have_independent_backoff() {
        let a = path("2001:db8::1", "[2001:db8::10]:443");
        let b = path("2001:db8::1", "[2001:db8::11]:443");
        let now = Instant::now();
        let mut state = Selection::default();
        state.failure(&a, now);
        assert_eq!(state.order(&[a, b.clone()], now), vec![b]);
    }
}

#[cfg(all(test, target_os = "linux", feature = "netns-tests"))]
mod namespace_tests {
    use super::*;
    use nlink::netlink::{link::DummyLink, route::Ipv4Route, rule::RuleBuilder, Connection, Route};
    #[tokio::test]
    #[ignore = "requires an owned disposable container network namespace"]
    async fn source_policy_interface_changes_and_gateway_metrics_are_respected() -> Result<()> {
        anyhow::ensure!(
            std::env::var("PORTHUB_TEST_OWNED_NETNS").as_deref() == Ok("1")
                && std::path::Path::new("/.dockerenv").is_file(),
            "owned namespace required"
        );
        let kernel = Connection::<Route>::new()?;
        kernel.add_link(DummyLink::new("enphoutbound0")).await?;
        kernel.set_link_up("enphoutbound0").await?;
        let index = kernel
            .get_link_by_name("enphoutbound0")
            .await?
            .unwrap()
            .ifindex();
        kernel
            .add_address_by_index(index, "192.0.2.1".parse()?, 24)
            .await?;
        kernel
            .add_address_by_index(index, "192.0.2.2".parse()?, 24)
            .await?;
        kernel
            .add_route(
                Ipv4Route::new("0.0.0.0".parse()?, 0)
                    .gateway("192.0.2.254".parse()?)
                    .dev("enphoutbound0")
                    .priority(100),
            )
            .await?;
        kernel
            .add_route(
                Ipv4Route::new("0.0.0.0".parse()?, 0)
                    .gateway("192.0.2.253".parse()?)
                    .dev("enphoutbound0")
                    .priority(200),
            )
            .await?;
        let destination: SocketAddr = "198.51.100.10:443".parse()?;
        let settings = Settings::default();
        let paths = discover(&settings, &[destination]).await?;
        anyhow::ensure!(
            paths.len() == 2,
            "both source addresses must be discovered: {paths:?}"
        );
        anyhow::ensure!(
            paths
                .iter()
                .all(|p| p.gateway == Some("192.0.2.254".parse().unwrap())),
            "lowest metric gateway must win"
        );
        kernel
            .add_rule(
                RuleBuilder::v4()
                    .priority(100)
                    .from_prefix("192.0.2.1", 32)
                    .prohibit(),
            )
            .await?;
        let permitted = discover(&settings, &[destination]).await?;
        anyhow::ensure!(
            permitted.len() == 1 && permitted[0].source == "192.0.2.2".parse::<IpAddr>()?,
            "source-specific prohibition must not be bypassed: {permitted:?}"
        );
        let pinned = Settings {
            interface: Some("not-permitted".into()),
            ..Default::default()
        };
        anyhow::ensure!(discover(&pinned, &[destination]).await?.is_empty());
        kernel
            .del_address_by_index(index, "192.0.2.2".parse()?, 24)
            .await?;
        anyhow::ensure!(
            discover(&settings, &[destination]).await?.is_empty(),
            "removed source must disappear"
        );
        kernel
            .add_address_by_index(index, "192.0.2.2".parse()?, 24)
            .await?;
        anyhow::ensure!(
            discover(&settings, &[destination]).await?.len() == 1,
            "restored source must recover"
        );
        kernel.set_link_down("enphoutbound0").await?;
        anyhow::ensure!(
            discover(&settings, &[destination]).await?.is_empty(),
            "down interface must be excluded"
        );
        kernel.set_link_up("enphoutbound0").await?;
        // Linux removes the default route when a link goes down. Simulate the
        // administrator/DHCP restoring it; the agent must never restore it.
        if !kernel
            .get_routes()
            .await?
            .iter()
            .any(|route| route.is_ipv4() && route.dst_len() == 0 && route.table_id() == 254)
        {
            kernel
                .add_route(
                    Ipv4Route::new("0.0.0.0".parse()?, 0)
                        .gateway("192.0.2.254".parse()?)
                        .dev("enphoutbound0")
                        .priority(100),
                )
                .await?;
        }
        anyhow::ensure!(
            discover(&settings, &[destination]).await?.len() == 1,
            "interface recovery must be detected after host routing is restored"
        );
        kernel.del_link("enphoutbound0").await?;
        Ok(())
    }
}

#[cfg(test)]
mod bounded_family_tests {
    use super::*;
    #[test]
    fn a_large_ipv4_inventory_cannot_starve_ipv6_or_override_a_healthy_selection() {
        let mut paths: Vec<_> = (1..=16)
            .map(|last| Candidate {
                source: format!("192.0.2.{last}").parse().unwrap(),
                interface: "fixture".into(),
                destination: "198.51.100.1:443".parse().unwrap(),
                gateway: None,
                metric: None,
            })
            .collect();
        let ipv6 = Candidate {
            source: "2001:db8::1".parse().unwrap(),
            interface: "fixture".into(),
            destination: "[2001:db8::2]:443".parse().unwrap(),
            gateway: None,
            metric: None,
        };
        paths.push(ipv6.clone());
        let mut selector = Selection::default();
        let ordered = selector.order(&paths, Instant::now());
        assert_eq!(ordered.len(), 8);
        assert!(ordered.contains(&ipv6));
        selector.success(ipv6.clone());
        assert_eq!(selector.order(&paths, Instant::now())[0], ipv6);
    }
}
