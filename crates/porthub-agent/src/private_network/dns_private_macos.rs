//! Session-owned supplemental DNS. configd removes this exact session's key
//! after exit/crash; physical-interface and default DNS are never rewritten.
use anyhow::{ensure, Context, Result};
use core_foundation::{array::CFArray, base::TCFType, dictionary::CFDictionary,
    number::CFNumber, propertylist::{CFPropertyList, CFPropertyListSubClass}, string::CFString};
use system_configuration::dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder};
use std::time::{Duration, Instant};
use super::dns_convergence_macos::Endpoint;

// configd publishes the DNS-specific change after coordinating with its DNS
// consumers. This notification is process-external and system-wide. Callers
// must also verify the exact effective endpoints after observing it.
struct DnsChange(i32);

unsafe extern "C" {
    fn notify_register_check(name: *const std::ffi::c_char, token: *mut i32) -> u32;
    fn notify_check(token: i32, changed: *mut i32) -> u32;
    fn notify_cancel(token: i32) -> u32;
}

impl DnsChange {
    fn arm() -> Result<Self> {
        let mut token = 0;
        let key = c"com.apple.system.config.network_change.dns";
        ensure!(unsafe { notify_register_check(key.as_ptr(), &mut token) } == 0,
            "cannot observe macOS DNS change notifications");
        let watch = Self(token);
        watch.changed()?; // The first check reports the registration itself.
        Ok(watch)
    }

    fn changed(&self) -> Result<bool> {
        let mut changed = 0;
        ensure!(unsafe { notify_check(self.0, &mut changed) } == 0,
            "cannot check macOS DNS change notifications");
        Ok(changed != 0)
    }

    async fn wait(&self) -> Result<()> {
        tokio::time::timeout(std::time::Duration::from_secs(8), async {
            while !self.changed()? {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            Ok(())
        }).await.context("macOS DNS change notification timed out")?
    }
}

impl Drop for DnsChange {
    fn drop(&mut self) {
        unsafe { notify_cancel(self.0); }
    }
}

pub(super) struct Session {
    pub endpoints: Vec<Endpoint>,
    changes: DnsChange,
    awaiting_publication: bool,
    next_inspection: Instant,
    closing: tokio_util::sync::CancellationToken,
    refresh_sender: Option<tokio::sync::watch::Sender<u64>>,
    finished: Option<tokio::sync::oneshot::Receiver<()>>,
}
impl Drop for Session {
    fn drop(&mut self) {
        self.closing.cancel();
    }
}

impl Session {
    pub fn maintain(&mut self, recovered_name: bool) {
        let now = Instant::now();
        if !recovered_name && !self.changes.changed().unwrap_or(false) && now < self.next_inspection {
            return;
        }
        // Also notice a lost service if macOS missed the change notification.
        self.next_inspection = now + Duration::from_secs(60);
        if let Some(owner) = &self.refresh_sender {
            // Even when requests coalesce, the owner can distinguish an OS
            // ownership check from a request to evict a cached lookup failure.
            owner.send_modify(|generation| {
                if recovered_name {
                    *generation = generation.wrapping_add(1);
                }
            });
        }
    }

    pub async fn wait_for_change(&mut self) -> Result<()> {
        if self.awaiting_publication {
            self.changes.wait().await?;
            self.awaiting_publication = false;
        }
        Ok(())
    }

    pub async fn close(&mut self) -> Result<()> {
        self.closing.cancel();
        self.refresh_sender.take();
        if let Some(finished) = self.finished.as_mut() {
            tokio::time::timeout(std::time::Duration::from_secs(2), finished)
                .await.context("private DNS session closure timed out")?
                .context("private DNS session owner stopped without closure acknowledgement")?;
            self.finished.take();
        }
        Ok(())
    }
}

fn resolver_value(domains: &[String], port: u16, order: i32) -> CFPropertyList {
    let domain_values: Vec<_> = domains.iter().map(|s| CFString::new(s)).collect();
    let orders: Vec<_> = domains.iter().map(|_| CFNumber::from(order)).collect();
    CFDictionary::from_CFType_pairs(&[
        (CFString::new("ServerAddresses"), CFArray::from_CFTypes(&[CFString::new("127.0.0.1")]).as_CFType()),
        (CFString::new("ServerPort"), CFNumber::from(i32::from(port)).as_CFType()),
        (CFString::new("SupplementalMatchDomains"), CFArray::from_CFTypes(&domain_values).as_CFType()),
        (CFString::new("SupplementalMatchOrders"), CFArray::from_CFTypes(&orders).as_CFType()),
        (CFString::new("SupplementalMatchDomainsNoSearch"), CFNumber::from(1).as_CFType()),
        (CFString::new("SearchOrder"), CFNumber::from(order).as_CFType()),
    ]).into_untyped().into_CFPropertyList()
}

struct OwnedResolver {
    store: SCDynamicStore,
    key: String,
    settings: [CFPropertyList; 2],
}

impl OwnedResolver {
    fn publish(domains: &[String], port: u16) -> Result<Self> {
        let store = SCDynamicStoreBuilder::new("PortHub private DNS")
            .session_keys(true).build().context("cannot open private DNS session")?;
        let key = format!("State:/Network/Service/PortHub-Private-{}/DNS", uuid::Uuid::new_v4().simple());
        let settings = [100, 101].map(|order| resolver_value(domains, port, order));
        let resolver = Self { store, key, settings };
        resolver.add_missing()?;
        ensure!(resolver.read().as_ref() == Some(&resolver.settings[0]), "private DNS session readback differs");
        Ok(resolver)
    }

    fn read(&self) -> Option<CFPropertyList> {
        self.store.get(self.key.as_str())
    }

    fn add_missing(&self) -> Result<()> {
        let key = CFString::new(&self.key);
        // All references live across the call. AddTemporaryValue is atomic if
        // absent and ties the new key to this SCDynamicStore session.
        let added = unsafe {
            system_configuration::sys::dynamic_store::SCDynamicStoreAddTemporaryValue(
                self.store.as_concrete_TypeRef(), key.as_concrete_TypeRef(), self.settings[0].as_CFTypeRef(),
            )
        };
        ensure!(added != 0, "cannot add the owned private DNS resolver");
        Ok(())
    }

    async fn refresh(&self, domains: &[String], owned: &[Endpoint], recovered_name: bool) -> Result<()> {
        if !recovered_name && self.read().is_some() {
            return Ok(());
        }
        for domain in domains {
            if std::path::Path::new("/etc/resolver").join(domain).try_exists()? {
                return Ok(());
            }
        }
        if !super::dns_convergence_macos::scope_available(domains, owned).await? {
            return Ok(());
        }
        // Read again after asynchronous preflight. Never replace unexpected
        // settings or another service's registration.
        let Some(value) = self.read() else { return self.add_missing() };
        if recovered_name {
            if let Some(index) = self.settings.iter().position(|settings| settings == &value) {
                // configd needs a changed order to evict cached failures.
                ensure!(self.store.set_raw(self.key.as_str(), &self.settings[1 - index]),
                    "cannot republish the owned private DNS resolver");
            }
        }
        Ok(())
    }
}

pub(super) async fn register(port: u16, suffixes: &[String], allowed: &[Endpoint]) -> Result<Session> {
    ensure!(port != 0 && !suffixes.is_empty() && suffixes.len() <= 2048,
        "invalid private DNS endpoint scope");
    for suffix in suffixes {
        ensure!(!suffix.is_empty() && suffix.len() < 254 && suffix.split('.').all(|label|
            !label.is_empty() && label.len() <= 63 && !label.starts_with('-') && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')),
            "invalid private DNS suffix");
        ensure!(!std::path::Path::new("/etc/resolver").join(suffix).try_exists()?,
            "a resolver file already owns the requested private DNS suffix");
    }
    super::dns_convergence_macos::ensure_available(suffixes, allowed).await?;
    let endpoints: Vec<_> = suffixes.iter().map(|suffix| Endpoint { suffix: suffix.clone(), port }).collect();
    // Equivalent endpoints may produce no system notification.
    let awaiting_publication = endpoints.iter().any(|endpoint| !allowed.contains(endpoint));
    let changes = DnsChange::arm()?;
    let domains = suffixes.to_vec();
    let (refresh_sender, mut requests) = tokio::sync::watch::channel(0u64);
    let owned = endpoints.clone();
    let closing = tokio_util::sync::CancellationToken::new();
    let owner_closing = closing.clone();
    let runtime = tokio::runtime::Handle::current();
    let (ready, result) = tokio::sync::oneshot::channel();
    let (finished, completion) = tokio::sync::oneshot::channel();
    tokio::task::spawn_blocking(move || {
        match OwnedResolver::publish(&domains, port) {
            Ok(resolver) => {
                if ready.send(Ok(())).is_ok() {
                    let mut handled_generation = 0;
                    while runtime.block_on(requests.changed()).is_ok() {
                        let generation = *requests.borrow_and_update();
                        let recovered_name = generation != handled_generation;
                        handled_generation = generation;
                        runtime.block_on(async {
                            tokio::select! {
                                biased;
                                _ = owner_closing.cancelled() => {}
                                _ = super::dns_convergence_macos::retry_refresh(|| {
                                    resolver.refresh(&domains, &owned, recovered_name)
                                }) => {}
                            }
                        });
                        if owner_closing.is_cancelled() {
                            break;
                        }
                    }
                }
                // Dropping this store withdraws only its session-owned key.
            }
            Err(error) => { let _ = ready.send(Err(error)); }
        }
        let _ = finished.send(());
    });
    let mut session=Session { endpoints, changes, awaiting_publication, next_inspection: Instant::now() + Duration::from_secs(60), closing, refresh_sender: Some(refresh_sender), finished: Some(completion) };
    let readiness=async {
        tokio::time::timeout(std::time::Duration::from_secs(2),result).await
            .context("private DNS session publication timed out")?
            .context("private DNS session owner stopped before readiness")??;
        Ok::<_,anyhow::Error>(())
    }.await;
    if let Err(error)=readiness {
        let absent: Vec<_>=session.endpoints.iter().filter(|endpoint|!allowed.contains(endpoint)).cloned().collect();
        let cleanup=async {
            session.close().await?;
            // A retained old registration may legitimately expose the SAME
            // endpoint. Never mistake it for this failed attempt's residue.
            super::dns_convergence_macos::wait(allowed,&absent).await
        }.await;
        return Err(match cleanup {Ok(())=>error,Err(cleanup)=>error.context(format!("private DNS publication cleanup incomplete: {cleanup}"))});
    }
    Ok(session)
}

#[cfg(test)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires privileged macOS supplemental DNS registration"]
async fn restores_a_missing_owned_service_after_macos_withdraws_the_resolver() -> Result<()> {
    let domains = vec![format!("phcheck-{}.test", uuid::Uuid::new_v4().simple())];
    let listener = std::net::UdpSocket::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    let mut session = register(port, &domains, &[]).await?;
    session.wait_for_change().await?;
    super::dns_convergence_macos::wait(&session.endpoints, &[]).await?;
    let store = SCDynamicStoreBuilder::new("PortHub private DNS fixture").build()
        .context("cannot observe isolated test key")?;
    let expected = resolver_value(&domains, port, 100);
    let keys = store.get_keys("State:/Network/Service/PortHub-Private-.*/DNS")
        .context("cannot locate isolated test key")?;
    let matches: Vec<_> = keys.iter().map(|key| key.to_string())
        .filter(|key| store.get(key.as_str()).as_ref() == Some(&expected)).collect();
    let [key] = matches.as_slice() else { anyhow::bail!("isolated resolver key must be unique") };
    let result: Result<()> = async {
        ensure!(store.remove(key.as_str()), "cannot withdraw isolated resolver key");
        wait_for_restoration(&mut session, &store, key).await?;
        ensure!(store.get(key.as_str()).as_ref() == Some(&expected));

        let other_listener = std::net::UdpSocket::bind(("127.0.0.1", 0))?;
        let other_port = other_listener.local_addr()?.port();
        let competing = OwnedResolver::publish(&domains, other_port)?;
        tokio::time::timeout(Duration::from_secs(8), async {
            while super::dns_convergence_macos::scope_available(&domains, &session.endpoints).await? {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Ok::<_, anyhow::Error>(())
        }).await.context("macOS did not publish the competing test resolver")??;
        ensure!(store.remove(key.as_str()));
        for _ in 0..3 {
            session.maintain(true);
            tokio::time::sleep(Duration::from_secs(1)).await;
            ensure!(store.get(key.as_str()).is_none(), "agent reclaimed a contested suffix");
            ensure!(competing.read().as_ref() == Some(&competing.settings[0]));
        }
        drop(competing);
        wait_for_restoration(&mut session, &store, key).await?;

        // Exercise the fallback when the OS change notification was missed.
        let notification = DnsChange::arm()?;
        ensure!(store.remove(key.as_str()));
        notification.wait().await?;
        session.changes.changed()?;
        session.next_inspection = Instant::now();
        wait_for_restoration(&mut session, &store, key).await?;
        Ok(())
    }.await;
    session.close().await?;
    super::dns_convergence_macos::wait(&[], &session.endpoints).await?;
    result
}

#[cfg(test)]
async fn wait_for_restoration(session: &mut Session, store: &SCDynamicStore, key: &str) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(8), async {
        while store.get(key).is_none() {
            session.maintain(false);
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        super::dns_convergence_macos::wait(&session.endpoints, &[]).await
    }).await.context("Mac did not restore the missing private resolver")??;
    Ok(())
}
