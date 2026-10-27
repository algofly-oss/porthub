//! Explicit Tor-mode default DNS. A private Dynamic Store session owns only
//! its own supplemental resolver; macOS removes the key even after a crash.
//! Physical-interface DNS preferences are never rewritten.
use anyhow::{ensure, Context, Result};
use core_foundation::{
    array::CFArray, base::TCFType, dictionary::CFDictionary, number::CFNumber, string::CFString,
};
use system_configuration::dynamic_store::SCDynamicStoreBuilder;

pub(super) struct Registration {
    _lifetime: std::sync::mpsc::Sender<()>,
}

pub(super) async fn register(port: u16) -> Result<Registration> {
    ensure!(port != 0, "invalid Tor DNS port");
    let (lifetime, stop) = std::sync::mpsc::channel();
    let (ready, result) = tokio::sync::oneshot::channel();
    tokio::task::spawn_blocking(move || {
        let installed = (|| {
            let store = SCDynamicStoreBuilder::new("PortHub local Tor DNS")
                .session_keys(true)
                .build()
                .context("cannot open Tor DNS configuration session")?;
            let key = format!(
                "State:/Network/Service/PortHub-Tor-{}/DNS",
                uuid::Uuid::new_v4().simple()
            );
            ensure!(
                store.get(key.as_str()).is_none(),
                "Tor DNS configuration key already exists"
            );
            let values = CFDictionary::from_CFType_pairs(&[
                (
                    CFString::new("ServerAddresses"),
                    CFArray::from_CFTypes(&[CFString::new("127.0.0.1")]).as_CFType(),
                ),
                (
                    CFString::new("ServerPort"),
                    CFNumber::from(i32::from(port)).as_CFType(),
                ),
                (
                    CFString::new("SupplementalMatchDomains"),
                    CFArray::from_CFTypes(&[CFString::new("")]).as_CFType(),
                ),
                (
                    CFString::new("SupplementalMatchOrders"),
                    CFArray::from_CFTypes(&[CFNumber::from(1)]).as_CFType(),
                ),
                (
                    CFString::new("SupplementalMatchDomainsNoSearch"),
                    CFNumber::from(1).as_CFType(),
                ),
                (CFString::new("SearchOrder"), CFNumber::from(1).as_CFType()),
            ]);
            ensure!(
                store.set(key.as_str(), values.into_untyped()),
                "cannot publish Tor DNS configuration"
            );
            Ok::<_, anyhow::Error>(store)
        })();
        match installed {
            Ok(store) => {
                if ready.send(Ok(())).is_ok() {
                    // CF objects stay on this thread. No polling, subprocess
                    // loop or unsafe Send implementation is necessary.
                    let _ = stop.recv();
                }
                drop(store);
            }
            Err(error) => {
                let _ = ready.send(Err(error));
            }
        }
    });
    result
        .await
        .context("Tor DNS configuration owner stopped")??;
    Ok(Registration {
        _lifetime: lifetime,
    })
}
