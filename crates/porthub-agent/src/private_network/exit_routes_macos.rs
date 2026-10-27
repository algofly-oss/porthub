//! Owned macOS exit-consumer routes. The real default route and LAN routes are
//! retained. A private PF anchor preserves physical-source connections while
//! split routes select the utun address for new internet connections.
use anyhow::{ensure, Context, Result};
use route_manager::{Route, RouteManager};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    ffi::CStr,
    fs::{File, OpenOptions},
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

const DIRECTORY: &str = "/private/var/run/porthub-exits";
const JOURNAL: &str = "/private/var/run/porthub-exits/consumer.json";
const PREFIXES: [Ipv4Addr; 2] = [Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(128, 0, 0, 0)];

#[derive(Clone, Debug, PartialEq, Eq)]
struct Underlay {
    source: Ipv4Addr,
    interface: String,
    gateway: Ipv4Addr,
}
#[derive(Serialize, Deserialize)]
struct Ownership {
    index: u32,
    own: Ipv4Addr,
    name: String,
    anchor: String,
    token: Option<String>,
    #[serde(default)]
    physical_routes: Vec<PhysicalRoute>,
}
struct Consumer {
    ownership: Ownership,
    _lock: File,
    rules: String,
    bypass: bool,
}

fn pf(args: &[&str], input: Option<&str>) -> Result<String> {
    native("/sbin/pfctl", args, input)
}
fn native(program: &str, args: &[&str], input: Option<&str>) -> Result<String> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().context("cannot run macOS route control")?;
    if let Some(input) = input {
        child
            .stdin
            .take()
            .context("route control input unavailable")?
            .write_all(input.as_bytes())?;
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("macOS route control timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output()?;
    ensure!(
        output.status.success(),
        "macOS route control rejected exit configuration"
    );
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(text)
}
/// An interface-scoped default is required for IP_BOUND_IF sockets when a
/// global split default exists. The ordinary system default stays untouched.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PhysicalRoute {
    interface: String,
    gateway: Ipv4Addr,
}
impl PhysicalRoute {
    fn inspect(&self) -> Result<Option<Self>> {
        let text = native(
            "/sbin/route",
            &["-n", "get", "-net", "default", "-ifscope", &self.interface],
            None,
        )?;
        Ok(parse_physical_route(&text))
    }
    fn change(&self, action: &str) -> Result<()> {
        native(
            "/sbin/route",
            &[
                "-n",
                action,
                "-net",
                "default",
                &self.gateway.to_string(),
                "-ifscope",
                &self.interface,
            ],
            None,
        )?;
        Ok(())
    }
    fn remove_owned(&self) -> Result<()> {
        // A vanished interface also removes its scoped routes. Never remove a
        // replacement gateway installed by DHCP or another network manager.
        let name = std::ffi::CString::new(self.interface.as_str())?;
        if unsafe { libc::if_nametoindex(name.as_ptr()) } == 0 {
            return Ok(());
        }
        if self.inspect()?.as_ref() == Some(self) {
            self.change("delete")?;
        }
        Ok(())
    }
}
fn parse_physical_route(text: &str) -> Option<PhysicalRoute> {
    let field = |key: &str| {
        text.lines()
            .find_map(|line| line.trim().strip_prefix(key))
            .map(str::trim)
    };
    let flags = field("flags:")?.trim_matches(['<', '>']);
    if !flags.split(',').any(|flag| flag == "IFSCOPE") || field("destination:")? != "default" {
        return None;
    }
    let interface = field("interface:")?.to_owned();
    if !valid_name(&interface) {
        return None;
    }
    Some(PhysicalRoute {
        interface,
        gateway: field("gateway:")?.parse().ok()?,
    })
}
fn interface_name(index: u32) -> Result<String> {
    let mut name = [0i8; libc::IF_NAMESIZE];
    // SAFETY: the buffer has IF_NAMESIZE bytes, as required by if_indextoname.
    ensure!(
        !unsafe { libc::if_indextoname(index, name.as_mut_ptr()) }.is_null(),
        "exit interface unavailable"
    );
    // SAFETY: a successful if_indextoname call writes a NUL-terminated name.
    Ok(unsafe { CStr::from_ptr(name.as_ptr()) }
        .to_str()?
        .to_owned())
}
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() < libc::IF_NAMESIZE
        && name.bytes().all(|c| c.is_ascii_alphanumeric())
}
fn underlays(sources: &BTreeSet<Ipv4Addr>, routes: &[Route]) -> Result<Vec<Underlay>> {
    let mut result = Vec::new();
    for route in routes {
        if route.destination() != IpAddr::V4(Ipv4Addr::UNSPECIFIED) || route.prefix() != 0 {
            continue;
        }
        let (Some(index), Some(IpAddr::V4(gateway))) = (route.if_index(), route.gateway()) else {
            continue;
        };
        let name = interface_name(index)?;
        if !valid_name(&name) || name.starts_with("utun") || name.starts_with("lo") {
            continue;
        }
        for source in sources {
            if source_interface(*source)? == Some(index) {
                result.push(Underlay {
                    source: *source,
                    interface: name.clone(),
                    gateway,
                });
            }
        }
    }
    result.sort_by_key(|route| route.source);
    result.dedup_by_key(|route| route.source);
    ensure!(
        !result.is_empty() && result.len() <= 16,
        "physical default route unavailable"
    );
    Ok(result)
}
fn source_interface(source: Ipv4Addr) -> Result<Option<u32>> {
    let mut head = std::ptr::null_mut();
    // SAFETY: getifaddrs writes a linked list, freed once by Guard.
    ensure!(
        unsafe { libc::getifaddrs(&mut head) } == 0,
        "cannot inspect physical interfaces"
    );
    struct Guard(*mut libc::ifaddrs);
    impl Drop for Guard {
        fn drop(&mut self) {
            unsafe {
                libc::freeifaddrs(self.0);
            }
        }
    }
    let _guard = Guard(head);
    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: cursor is within the live list and AF_INET selects sockaddr_in.
        let item = unsafe { &*cursor };
        cursor = item.ifa_next;
        if item.ifa_addr.is_null() || item.ifa_name.is_null() {
            continue;
        }
        if unsafe { (*item.ifa_addr).sa_family as i32 } != libc::AF_INET {
            continue;
        }
        let ip = Ipv4Addr::from(u32::from_be(unsafe {
            (*item.ifa_addr.cast::<libc::sockaddr_in>()).sin_addr.s_addr
        }));
        if ip == source {
            return Ok(Some(unsafe { libc::if_nametoindex(item.ifa_name) }));
        }
    }
    Ok(None)
}
fn rules(owner: &Ownership, underlay: &[Underlay], bypass: bool) -> String {
    let mut rules = String::new();
    for route in underlay {
        // Only reroute physical sources that the split route sent to our TUN.
        // Connected LAN and other private host routes retain their own device.
        rules.push_str(&format!(
            "pass out quick on {} route-to ({} {}) inet from {} to any no state\n",
            owner.name, route.interface, route.gateway, route.source
        ));
    }
    // When fallback removes the split routes, established overlay-source flows
    // still belong to their selected exit and must not leak onto the underlay.
    rules.push_str(&format!(
        "pass out quick on ! {} route-to ({} {}) inet from {} to any no state\n",
        owner.name, owner.name, owner.own, owner.own
    ));
    if !bypass {
        // Preserve local IPv6 and established TCP; reject new public IPv6 so
        // dual-stack applications can use the supported IPv4 exit transport.
        rules.push_str("pass out quick inet6 to { ::1, fe80::/10, fc00::/7, ff00::/8 } no state\n");
        rules.push_str("block return out quick inet6 proto tcp from any to any flags S/SA\n");
        rules.push_str("pass out quick inet6 proto tcp from any to any no state\n");
        rules.push_str("block return out quick inet6 from any to any\n");
    }
    rules
}
fn lock() -> Result<File> {
    match std::fs::DirBuilder::new().mode(0o700).create(DIRECTORY) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error.into()),
    }
    let meta = std::fs::symlink_metadata(DIRECTORY)?;
    ensure!(
        meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o077 == 0,
        "invalid exit state directory"
    );
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(Path::new(DIRECTORY).join("consumer.lock"))?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.uid() == 0 && meta.nlink() == 1 && meta.mode() & 0o077 == 0,
        "invalid exit owner lock"
    );
    fs2::FileExt::try_lock_exclusive(&file)
        .context("another registration already owns exit routing")?;
    Ok(file)
}
impl Ownership {
    fn save(&self) -> Result<()> {
        let mut file = tempfile::NamedTempFile::new_in(DIRECTORY)?;
        serde_json::to_writer(file.as_file_mut(), self)?;
        file.flush()?;
        file.as_file().sync_all()?;
        file.persist(JOURNAL)?;
        Ok(())
    }
    fn load() -> Result<Option<Self>> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(JOURNAL)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let meta = file.metadata()?;
        ensure!(
            meta.is_file()
                && meta.uid() == 0
                && meta.nlink() == 1
                && meta.mode() & 0o077 == 0
                && meta.len() <= 4096,
            "invalid macOS exit journal"
        );
        let owner: Self = serde_json::from_reader(file.take(4096))?;
        ensure!(
            owner.index > 0
                && owner.own.is_private()
                && valid_name(&owner.name)
                && owner.name.starts_with("utun")
                && owner
                    .anchor
                    .strip_prefix("com.apple/porthub-")
                    .is_some_and(|id| id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()))
                && owner.token.as_ref().is_none_or(|token| !token.is_empty()
                    && token.len() <= 32
                    && token.bytes().all(|c| c.is_ascii_digit())),
            "invalid macOS exit ownership"
        );
        ensure!(
            owner.physical_routes.len() <= 16
                && owner
                    .physical_routes
                    .iter()
                    .all(|route| valid_name(&route.interface)
                        && !route.interface.starts_with("utun")
                        && !route.gateway.is_unspecified()
                        && !route.gateway.is_multicast()),
            "invalid physical route ownership"
        );
        Ok(Some(owner))
    }
    fn route(&self, prefix: Ipv4Addr) -> Route {
        Route::new(prefix.into(), 1).with_if_index(self.index)
    }
    fn remove_routes(&self) -> Result<()> {
        let mut manager = RouteManager::new()?;
        let existing = manager.list()?;
        // The kernel removes these routes when the owned utun closes. Never
        // delete an overlapping route belonging to a different interface.
        for prefix in PREFIXES {
            if existing.iter().any(|route| {
                route.destination() == IpAddr::V4(prefix)
                    && route.prefix() == 1
                    && route.if_index() == Some(self.index)
            }) {
                ensure!(
                    interface_name(self.index)? == self.name
                        && source_interface(self.own)? == Some(self.index),
                    "exit route ownership changed"
                );
                manager.delete(&self.route(prefix))?;
            }
        }
        Ok(())
    }
    fn clear(&mut self) -> Result<()> {
        self.remove_routes()?;
        for route in &self.physical_routes {
            route.remove_owned()?;
        }
        self.physical_routes.clear();
        self.save()?;
        pf(&["-a", &self.anchor, "-F", "rules"], None)?;
        if let Some(token) = self.token.as_ref() {
            if pf(&["-X", token], None).is_err() {
                // The reference may have been released just before a crash,
                // while its journal still recorded the token. Never disable PF
                // or release someone else's reference to recover this state.
                let references = pf(&["-s", "References"], None)?;
                ensure!(
                    references
                        .lines()
                        .any(|line| line.trim() == "No pf starter references held"),
                    "packet filter reference cleanup is pending"
                );
            }
            self.token = None;
            self.save()?;
        }
        match std::fs::remove_file(JOURNAL) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }
}
impl Consumer {
    fn activate(
        index: u32,
        own: Ipv4Addr,
        sources: &BTreeSet<Ipv4Addr>,
        bypass: bool,
    ) -> Result<Self> {
        ensure!(
            own.is_private() && !sources.contains(&own),
            "invalid exit source"
        );
        let lock = lock()?;
        if let Some(mut previous) = Ownership::load()? {
            previous.clear()?;
        }
        let name = interface_name(index)?;
        ensure!(
            name.starts_with("utun") && valid_name(&name) && source_interface(own)? == Some(index),
            "exit interface is not the owned private tunnel"
        );
        let existing = RouteManager::new()?.list()?;
        ensure!(
            !existing
                .iter()
                .any(|route| matches!(route.destination(), IpAddr::V4(_)) && route.prefix() == 1),
            "another VPN owns split default routes"
        );
        let underlay = underlays(sources, &existing)?;
        let root = pf(&["-sr"], None)?;
        ensure!(
            root.lines()
                .any(|line| line.trim() == "anchor \"com.apple/*\" all"),
            "system packet filter has no compatible anchor hook"
        );
        let mut owner = Self {
            ownership: Ownership {
                index,
                own,
                name,
                anchor: format!("com.apple/porthub-{}", uuid::Uuid::new_v4().simple()),
                token: None,
                physical_routes: Vec::new(),
            },
            _lock: lock,
            rules: String::new(),
            bypass: true,
        };
        owner.ownership.save()?;
        let result = (|| -> Result<()> {
            let next = rules(&owner.ownership, &underlay, bypass);
            pf(
                &["-n", "-a", &owner.ownership.anchor, "-f", "-"],
                Some(&next),
            )?;
            let enabled = pf(&["-E"], None)?;
            let token = enabled
                .lines()
                .find_map(|line| {
                    line.trim()
                        .strip_prefix("Token :")
                        .or_else(|| line.trim().strip_prefix("Token:"))
                })
                .map(str::trim)
                .filter(|token| !token.is_empty() && token.bytes().all(|c| c.is_ascii_digit()))
                .context("packet filter ownership token unavailable")?;
            owner.ownership.token = Some(token.to_owned());
            owner.ownership.save()?;
            owner.refresh(sources, bypass)?;
            Ok(())
        })();
        if let Err(error) = result {
            let _ = owner.clear();
            return Err(error);
        }
        Ok(owner)
    }
    fn preserve_physical_routes(&mut self, underlay: &[Underlay]) -> Result<()> {
        for route in underlay {
            let wanted = PhysicalRoute {
                interface: route.interface.clone(),
                gateway: route.gateway,
            };
            if let Some(existing) = wanted.inspect()? {
                ensure!(
                    existing == wanted,
                    "physical scoped gateway differs from default"
                );
                continue; // Existing system or previously owned route.
            }
            if !self.ownership.physical_routes.contains(&wanted) {
                self.ownership.physical_routes.push(wanted.clone());
                self.ownership.save()?; // Recover safely if interrupted during add.
            }
            wanted.change("add")?;
        }
        let obsolete: Vec<_> = self
            .ownership
            .physical_routes
            .iter()
            .filter(|owned| {
                !underlay.iter().any(|route| {
                    route.interface == owned.interface && route.gateway == owned.gateway
                })
            })
            .cloned()
            .collect();
        for route in obsolete {
            route.remove_owned()?;
            self.ownership
                .physical_routes
                .retain(|owned| *owned != route);
            self.ownership.save()?;
        }
        Ok(())
    }
    fn refresh(&mut self, sources: &BTreeSet<Ipv4Addr>, bypass: bool) -> Result<()> {
        let mut manager = RouteManager::new()?;
        let existing = manager.list()?;
        let underlay = underlays(sources, &existing)?;
        self.preserve_physical_routes(&underlay)?;
        let next = rules(&self.ownership, &underlay, bypass);
        if next != self.rules {
            pf(
                &["-n", "-a", &self.ownership.anchor, "-f", "-"],
                Some(&next),
            )?;
            pf(&["-a", &self.ownership.anchor, "-f", "-"], Some(&next))?;
            self.rules = next;
        }
        if bypass {
            self.ownership.remove_routes()?;
        } else {
            for prefix in PREFIXES {
                if let Some(route) = existing
                    .iter()
                    .find(|route| route.destination() == IpAddr::V4(prefix) && route.prefix() == 1)
                {
                    ensure!(
                        route.if_index() == Some(self.ownership.index),
                        "another VPN owns split default routes"
                    );
                } else {
                    manager.add(&self.ownership.route(prefix))?;
                }
            }
        }
        self.bypass = bypass;
        Ok(())
    }
    fn clear(&mut self) -> Result<()> {
        self.ownership.clear()
    }
}
impl Drop for Consumer {
    fn drop(&mut self) {
        if Path::new(JOURNAL).exists() && self.clear().is_err() {
            tracing::warn!("owned macOS exit cleanup pending recovery");
        }
    }
}

pub async fn watch_reported(
    mut desired: watch::Receiver<Option<(u32, Ipv4Addr, bool)>>,
    mut interfaces: watch::Receiver<Vec<SocketAddr>>,
    cancel: CancellationToken,
    report: Option<watch::Sender<&'static str>>,
) -> Result<()> {
    let mut active: Option<Consumer> = None;
    // The initial tick also recovers owned state after a crash when no policy
    // remains. Recovery failure must never terminate the gateway controller.
    let mut retry = true;
    let mut timer = tokio::time::interval(Duration::from_secs(30));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            changed = desired.changed() => if changed.is_err() { break; },
            changed = interfaces.changed() => if changed.is_err() { break; },
            _ = timer.tick(), if retry || active.is_some() => {},
        }
        let wanted = *desired.borrow_and_update();
        let sources = interfaces
            .borrow_and_update()
            .iter()
            .filter_map(|address| {
                if let IpAddr::V4(ip) = address.ip() {
                    Some(ip)
                } else {
                    None
                }
            })
            .collect::<BTreeSet<_>>();
        let (next, failed) = tokio::task::spawn_blocking(move || {
            let result = (|| -> Result<()> {
                if active.as_ref().is_some_and(|route| {
                    wanted.map(|(index, own, _)| (index, own))
                        != Some((route.ownership.index, route.ownership.own))
                }) {
                    active.as_mut().unwrap().clear()?;
                    active = None;
                }
                if wanted.is_none() && active.is_none() {
                    if let Ok(_lock) = lock() {
                        if let Some(mut previous) = Ownership::load()? {
                            previous.clear()?;
                        }
                    }
                }
                if let Some((index, own, bypass)) = wanted {
                    if let Some(route) = &mut active {
                        route.refresh(&sources, bypass)?;
                    } else {
                        active = Some(Consumer::activate(index, own, &sources, bypass)?);
                    }
                }
                Ok(())
            })();
            (active, result.is_err())
        })
        .await?;
        active = next;
        if failed && !retry {
            tracing::warn!("macOS exit configuration failed; gateway control stays available");
        }
        retry = failed;
        if let Some(report) = &report {
            let state = if failed {
                "configuration error"
            } else if let Some(route) = &active {
                if route.bypass {
                    "normal internet fallback"
                } else {
                    "exit routing active"
                }
            } else {
                "inactive"
            };
            report.send_if_modified(|previous| {
                if *previous == state {
                    false
                } else {
                    *previous = state;
                    true
                }
            });
        }
    }
    tokio::task::spawn_blocking(move || -> Result<()> {
        if let Some(route) = &mut active {
            route.clear()?;
        }
        Ok(())
    })
    .await??;
    if let Some(report) = report {
        report.send_replace("inactive");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scoped_route_inspection_does_not_claim_global_or_host_routes() {
        let scoped = "destination: default\ngateway: 192.168.0.1\ninterface: en0\nflags: <UP,GATEWAY,DONE,STATIC,IFSCOPE>\n";
        assert_eq!(
            parse_physical_route(scoped),
            Some(PhysicalRoute {
                interface: "en0".into(),
                gateway: "192.168.0.1".parse().unwrap()
            })
        );
        assert!(parse_physical_route(&scoped.replace(",IFSCOPE", "")).is_none());
        assert!(parse_physical_route(
            &scoped.replace("destination: default", "destination: 34.160.111.145")
        )
        .is_none());
    }
    #[test]
    fn rules_keep_underlay_and_overlay_sources_pinned_across_fallback() {
        let owner = Ownership {
            index: 10,
            own: "10.203.0.87".parse().unwrap(),
            name: "utun6".into(),
            anchor: "unused".into(),
            token: None,
            physical_routes: Vec::new(),
        };
        let underlay = vec![Underlay {
            source: "192.168.0.40".parse().unwrap(),
            interface: "en0".into(),
            gateway: "192.168.0.1".parse().unwrap(),
        }];
        let active = rules(&owner, &underlay, false);
        assert!(active.contains("on utun6 route-to (en0 192.168.0.1) inet from 192.168.0.40"));
        assert!(active.contains("on ! utun6 route-to (utun6 10.203.0.87) inet from 10.203.0.87"));
        assert!(active.contains("flags S/SA"));
        let fallback = rules(&owner, &underlay, true);
        assert!(fallback.contains("on ! utun6 route-to"));
        assert!(!fallback.contains("block return"));
    }

    #[test]
    fn generated_rules_pass_native_packet_filter_validation() -> Result<()> {
        let owner = Ownership {
            index: 1,
            own: "10.203.0.87".parse()?,
            name: "utun6".into(),
            anchor: "com.apple/porthub-test".into(),
            token: None,
            physical_routes: Vec::new(),
        };
        let underlay = vec![Underlay {
            source: "192.168.0.40".parse()?,
            interface: "en0".into(),
            gateway: "192.168.0.1".parse()?,
        }];
        for bypass in [false, true] {
            pf(
                &["-n", "-a", &owner.anchor, "-f", "-"],
                Some(&rules(&owner, &underlay, bypass)),
            )?;
        }
        Ok(())
    }

    #[test]
    #[ignore = "requires explicit permission and an owned live PortHub utun with an exit policy"]
    fn owned_native_exit_routes_and_fallback() -> Result<()> {
        ensure!(
            std::env::var("PORTHUB_MACOS_EXIT_TEST").as_deref() == Ok("1"),
            "native exit test not authorized"
        );
        let own: Ipv4Addr = std::env::var("PORTHUB_MACOS_EXIT_TEST_ADDRESS")?.parse()?;
        let index = source_interface(own)?.context("owned test interface unavailable")?;
        let rt = tokio::runtime::Runtime::new()?;
        let sources = rt
            .block_on(super::super::interfaces::current())?
            .iter()
            .filter_map(|source| {
                if let IpAddr::V4(ip) = source.ip() {
                    Some(ip)
                } else {
                    None
                }
            })
            .collect();
        fn public_ip() -> Result<String> {
            let output = Command::new("/usr/bin/curl")
                .args(["-4", "-fsS", "--max-time", "10", "https://ifconfig.me/ip"])
                .output()?;
            ensure!(output.status.success(), "exit request failed");
            let value = String::from_utf8(output.stdout)?.trim().to_owned();
            let _: Ipv4Addr = value.parse()?;
            Ok(value)
        }
        let original = public_ip().context("baseline public request")?;
        eprintln!("baseline ready");
        let mut owner = Consumer::activate(index, own, &sources, false)?;
        for _ in 0..3 {
            ensure!(
                public_ip()? != original,
                "internet request bypassed the exit"
            );
        }
        let check = Command::new("/usr/bin/curl")
            .args([
                "-4",
                "-fsS",
                "--max-time",
                "10",
                "https://porthub.algofly.in/",
            ])
            .output()?;
        ensure!(
            check.status.success(),
            "gateway unavailable while exit active"
        );
        eprintln!("gateway request passed");
        owner.refresh(&sources, true)?;
        ensure!(
            public_ip().context("fallback public request")? == original,
            "normal internet fallback did not restore underlay"
        );
        owner.refresh(&sources, false)?;
        ensure!(
            public_ip()? != original,
            "exit did not resume after fallback"
        );
        owner.clear()?;
        ensure!(
            public_ip()? == original,
            "exit cleanup did not restore underlay"
        );
        Ok(())
    }
    #[test]
    fn interface_names_cannot_inject_packet_filter_rules() {
        for invalid in ["en0\npass all", "en0)", "", "utun0;", "en0:1"] {
            assert!(!valid_name(invalid));
        }
        assert!(valid_name("utun123"));
    }
}
