//! An in-process request-start timeout retires every answer and carrier permit.
//! Hold only the native endpoint briefly so a resolver can finish an outstanding
//! private question against the replacement worker's newly authorized zone.
use super::{
    authority_clock::{NativeClock, SuspendClock},
    dns,
};
use porthub_network::policy::Snapshot;
use std::{
    fs::File,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::Duration,
};

const WINDOW: Duration = Duration::from_secs(20);

#[derive(PartialEq, Eq)]
pub(super) struct Scope {
    workspace: String,
    peer: String,
    own: Ipv4Addr,
    suffixes: Vec<String>,
}
impl Scope {
    #[cfg(target_os = "macos")]
    pub(super) fn suffixes(&self) -> &[String] {
        &self.suffixes
    }

    #[cfg(target_os = "macos")]
    pub(super) fn binding(&self, p: &crate::private_profile::Profile) -> anyhow::Result<String> {
        use sha2::{Digest, Sha256};
        anyhow::ensure!(p.workspace == self.workspace && p.peer_id == self.peer, "DNS admission identity changed");
        let encoded = serde_json::to_vec(&(&p.server, &p.token, &self.workspace, &self.peer, self.own, &self.suffixes))?;
        Ok(format!("{:x}", Sha256::digest(encoded)))
    }

    pub fn new(snapshot: &Snapshot) -> Option<Self> {
        // Never hold a default route, an upstream DNS policy, or a legacy zone.
        if snapshot.sparse.is_none()
            || !snapshot.exit_routes.is_empty()
            || !snapshot.dns_rules.is_empty()
        {
            return None;
        }
        let own = snapshot.peers.iter().find(|p| p.id == snapshot.self_)?;
        let (_, suffix) = own.hostname.split_once('.')?;
        let mut suffixes = snapshot
            .dns_suffixes
            .iter()
            .map(|s| s.trim_matches('.').to_ascii_lowercase())
            .collect::<Vec<_>>();
        suffixes.push(suffix.to_ascii_lowercase());
        if suffixes.iter().any(String::is_empty) {
            return None;
        }
        suffixes.sort();
        suffixes.dedup();
        Some(Self {
            workspace: snapshot.workspace.clone(),
            peer: snapshot.self_.clone(),
            own: own.ip,
            suffixes,
        })
    }
}

pub(super) struct Endpoints {
    pub registration: dns::Registration,
    #[cfg(target_os = "linux")]
    pub handles: super::linux_handoff::Stored,
    #[cfg(target_os = "macos")]
    pub handles: (File, File),
}

// Only descriptors acquired by this locked enrollment ever enter this slot.
// Its timer takes no strong reference to the enrollment or the endpoint.
pub(super) struct Pending {
    slot: Arc<Mutex<Option<Endpoints>>>,
    timer: tokio::task::JoinHandle<()>,
    deadline: Duration,
    scope: Scope,
}
impl Pending {
    pub fn hold(
        scope: Scope,
        #[cfg(target_os = "linux")] tun: &super::device::Tun,
        sockets: (File, File),
        registration: &mut Option<dns::Registration>,
    ) -> Option<Self> {
        let deadline = NativeClock.elapsed_since_boot().ok()?.checked_add(WINDOW)?;
        #[cfg(target_os = "linux")]
        let handles = tun.recovery_handles(sockets.0, sockets.1).ok()??;
        #[cfg(target_os = "macos")]
        let handles = sockets;
        let endpoint = Endpoints {
            registration: registration.take()?,
            handles,
        };
        Some(Self::arm(scope, endpoint, deadline))
    }

    fn arm(scope: Scope, endpoint: Endpoints, deadline: Duration) -> Self {
        let slot = Arc::new(Mutex::new(Some(endpoint)));
        let weak = Arc::downgrade(&slot);
        let timer = tokio::spawn(async move {
            if let Ok(now) = NativeClock.elapsed_since_boot() {
                crate::unified::suspend_aware_delay(deadline.saturating_sub(now)).await;
            }
            if let Some(slot) = weak.upgrade() {
                let retired = slot.lock().unwrap_or_else(|p| p.into_inner()).take();
                drop(retired);
            }
        });
        Self {
            slot,
            timer,
            deadline,
            scope,
        }
    }

    pub fn awaiting_authorization(&self) -> bool {
        NativeClock.elapsed_since_boot().is_ok_and(|now| now < self.deadline)
    }

    pub fn resume(self, scope: Option<&Scope>) -> Option<Endpoints> {
        if scope != Some(&self.scope) || !self.awaiting_authorization() {
            return None;
        }
        self.slot.lock().unwrap_or_else(|p| p.into_inner()).take()
    }
}
impl Drop for Pending {
    fn drop(&mut self) {
        self.timer.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn continuity_requires_matching_enrollment_address_and_private_suffixes() {
        let doc = json!({
            "workspace":"workspace-a","self":"peer-a","revision":1,"expires_at":"2032-01-01T00:00:00Z",
            "sparse":{"protocol":1,"epoch":"fixture"},
            "dns_suffixes":["MORE.PHUB.","phub"],"grants":[],
            "peers":[{"id":"peer-a","ip":"10.1.2.3","hostname":"luna.phub","fingerprint":"one","instance":"alpha"}]
        });
        let scope =
            |doc: &serde_json::Value| Scope::new(&serde_json::from_value(doc.clone()).unwrap());
        let original = scope(&doc);
        assert!(original.is_some());
        let mut changed = doc.clone();
        changed["dns_suffixes"] = json!(["more.phub"]);
        assert!(scope(&changed) == original);
        for (pointer, value) in [
            ("/workspace", json!("another")),
            ("/peers/0/ip", json!("10.1.2.4")),
            ("/dns_suffixes", json!(["other.phub"])),
            ("/sparse", json!(null)),
        ] {
            let mut changed = doc.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(scope(&changed) != original);
        }
        let mut protected = doc.clone();
        protected["dns_rules"] =
            json!([{"domain":"example.org","include_subdomains":true,"action":{"type":"block"}}]);
        assert!(scope(&protected).is_none());
    }
    #[tokio::test]
    async fn switch_cancel_and_timeout_release_queued_endpoints() -> anyhow::Result<()> {
        use std::{
            net::{TcpListener, UdpSocket},
            os::fd::OwnedFd,
        };

        let scope = |peer: &str| Scope {
            workspace: "fixture".into(),
            peer: peer.into(),
            own: [10, 1, 2, 3].into(),
            suffixes: vec!["phub".into()],
        };
        for mode in ["switch", "cancel", "expire", "late"] {
            let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
            let addr = tcp.local_addr()?;
            let udp = UdpSocket::bind(addr)?;
            let udp = File::from(OwnedFd::from(udp));
            let tcp = File::from(OwnedFd::from(tcp));
            #[cfg(target_os = "linux")]
            let handles = super::super::linux_handoff::Stored {
                anchor: File::open("/dev/null")?,
                state: File::open("/dev/null")?,
                udp,
                tcp,
            };
            #[cfg(target_os = "macos")]
            let handles = (udp, tcp);

            let delay = Duration::from_millis(40);
            let now = NativeClock.elapsed_since_boot()?;
            let deadline = if mode == "late" { now } else { now + delay };
            let endpoint = Endpoints {
                registration: Default::default(),
                handles,
            };
            let pending = Pending::arm(scope("one"), endpoint, deadline);
            assert!(TcpListener::bind(addr).is_err());
            match mode {
                "switch" => assert!(pending.resume(Some(&scope("two"))).is_none()),
                "cancel" => drop(pending),
                "late" => assert!(pending.resume(Some(&scope("one"))).is_none()),
                _ => {
                    // Even if the controller never returns and the slot still exists, its timer closes the endpoint.
                    tokio::time::timeout(Duration::from_secs(2), async {
                        while UdpSocket::bind(addr).is_err() {
                            tokio::time::sleep(Duration::from_millis(5)).await;
                        }
                    })
                    .await?;
                    assert!(pending.resume(Some(&scope("one"))).is_none());
                }
            }
            assert!(TcpListener::bind(addr).is_ok());
            assert!(UdpSocket::bind(addr).is_ok());
        }
        Ok(())
    }
}
