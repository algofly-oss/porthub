//! Session-owned supplemental DNS. configd removes this exact session's key
//! after exit/crash; physical-interface and default DNS are never rewritten.
use anyhow::{ensure, Context, Result};
use core_foundation::{array::CFArray, base::TCFType, dictionary::CFDictionary,
    number::CFNumber, propertylist::CFPropertyListSubClass, string::CFString};
use system_configuration::dynamic_store::SCDynamicStoreBuilder;
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
    publication: Option<DnsChange>,
    stop: Option<std::sync::mpsc::Sender<()>>,
    finished: Option<tokio::sync::oneshot::Receiver<()>>,
}
impl Session {
    pub async fn wait_for_change(&mut self) -> Result<()> {
        if let Some(change) = &self.publication {
            change.wait().await?;
            self.publication = None;
        }
        Ok(())
    }

    pub async fn close(&mut self) -> Result<()> {
        self.stop.take();
        if let Some(finished) = self.finished.as_mut() {
            tokio::time::timeout(std::time::Duration::from_secs(2), finished)
                .await.context("private DNS session closure timed out")?
                .context("private DNS session owner stopped without closure acknowledgement")?;
            self.finished.take();
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
    let publication = if endpoints.iter().any(|endpoint| !allowed.contains(endpoint)) {
        Some(DnsChange::arm()?)
    } else {
        None
    };
    let domains = suffixes.to_vec();
    let (stop, stopped) = std::sync::mpsc::channel();
    let (ready, result) = tokio::sync::oneshot::channel();
    let (finished, completion) = tokio::sync::oneshot::channel();
    tokio::task::spawn_blocking(move || {
        let installed = (|| {
            let store = SCDynamicStoreBuilder::new("PortHub private DNS")
                .session_keys(true).build().context("cannot open private DNS session")?;
            let key = format!("State:/Network/Service/PortHub-Private-{}/DNS", uuid::Uuid::new_v4().simple());
            ensure!(store.get(key.as_str()).is_none(), "private DNS session key already exists");
            let domain_values: Vec<_> = domains.iter().map(|s| CFString::new(s)).collect();
            let orders: Vec<_> = domains.iter().map(|_| CFNumber::from(100)).collect();
            let value = CFDictionary::from_CFType_pairs(&[
                (CFString::new("ServerAddresses"), CFArray::from_CFTypes(&[CFString::new("127.0.0.1")]).as_CFType()),
                (CFString::new("ServerPort"), CFNumber::from(i32::from(port)).as_CFType()),
                (CFString::new("SupplementalMatchDomains"), CFArray::from_CFTypes(&domain_values).as_CFType()),
                (CFString::new("SupplementalMatchOrders"), CFArray::from_CFTypes(&orders).as_CFType()),
                (CFString::new("SupplementalMatchDomainsNoSearch"), CFNumber::from(1).as_CFType()),
                (CFString::new("SearchOrder"), CFNumber::from(100).as_CFType()),
            ]).into_untyped().into_CFPropertyList();
            ensure!(store.set_raw(key.as_str(), &value), "cannot publish private DNS session");
            ensure!(store.get(key.as_str()).as_ref() == Some(&value), "private DNS session readback differs");
            Ok::<_, anyhow::Error>(store)
        })();
        match installed {
            Ok(store) => {
                if ready.send(Ok(())).is_ok() { let _ = stopped.recv(); }
                // Closing only our private session removes only its session keys.
                drop(store);
            }
            Err(error) => { let _ = ready.send(Err(error)); }
        }
        let _ = finished.send(());
    });
    let mut session=Session { endpoints, publication, stop: Some(stop), finished: Some(completion) };
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
