//! Preparation is restricted to privileged setup, never background packet loops.
use anyhow::{Context, Result};
#[async_trait::async_trait]
trait Host: Send + Sync {
    fn present(&self) -> bool;
    fn privileged(&self) -> bool;
    fn installer(&self) -> Option<&'static str>;
    fn nss_missing(&self) -> bool {
        false
    }
    async fn run(&self, program: &str, arguments: &[&str]) -> Result<bool>;
}
struct Native;
#[async_trait::async_trait]
impl Host for Native {
    fn present(&self) -> bool {
        [
            "/usr/lib/systemd/system/systemd-resolved.service",
            "/lib/systemd/system/systemd-resolved.service",
        ]
        .iter()
        .any(|path| std::path::Path::new(path).is_file())
    }
    fn privileged(&self) -> bool {
        unsafe { libc::geteuid() == 0 }
    }
    fn installer(&self) -> Option<&'static str> {
        ["/usr/bin/dnf", "/usr/bin/apt-get"]
            .into_iter()
            .find(|path| std::path::Path::new(path).is_file())
    }
    fn nss_missing(&self) -> bool {
        let resolv = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
        !resolver_stub(&resolv) && !nss_library_present()
    }
    async fn run(&self, program: &str, arguments: &[&str]) -> Result<bool> {
        let operation = async {
            Ok(tokio::process::Command::new(program)
                .args(arguments)
                .env("DEBIAN_FRONTEND", "noninteractive")
                .status()
                .await
                .context("run private-network dependency preparation")?
                .success())
        };
        if arguments.first() == Some(&"install") {
            crate::private_resolver_file::preserve(
                std::path::Path::new("/etc/resolv.conf"),
                operation,
            )
            .await
        } else {
            operation.await
        }
    }
}
pub async fn prepare() -> Result<()> {
    let mode = std::env::var("PORTHUB_PRIVATE_DEPENDENCIES").unwrap_or_else(|_| "auto".into());
    anyhow::ensure!(
        ["auto", "check"].contains(&mode.as_str()),
        "PORTHUB_PRIVATE_DEPENDENCIES must be auto or check"
    );
    prepare_with(&Native, mode == "check").await?;
    if mode == "check" {
        anyhow::ensure!(dns_status()=="system hostname lookups use systemd-resolved","private DNS is not integrated with system hostname lookups; administrator must configure NSS resolve before dns or the resolved stub");
    } else {
        crate::private_dns_setup::configure().await?;
    }
    Ok(())
}
async fn prepare_with(host: &impl Host, check_only: bool) -> Result<()> {
    if !host.present() {
        anyhow::ensure!(!check_only,"systemd-resolved is missing; administrator must install it before enabling private networking");
        anyhow::ensure!(host.privileged(),"private DNS requires systemd-resolved; run privileged setup or ask an administrator to install it");
        let installer=host.installer().ok_or_else(||anyhow::anyhow!("systemd-resolved is missing; install it with the administrator-approved package manager"))?;
        anyhow::ensure!(
            host.run(installer, &["install", "-y", "systemd-resolved"])
                .await?,
            "systemd-resolved installation failed; review package manager output and retry setup"
        );
        anyhow::ensure!(host.present(),"systemd-resolved package installation did not provide its service; ask the administrator to check the package source");
    }
    if host.nss_missing() {
        anyhow::ensure!(!check_only,"systemd-resolved NSS module is missing; install libnss-resolve before enabling private DNS");
        anyhow::ensure!(
            host.privileged(),
            "installing the private DNS NSS module requires privileged enrollment"
        );
        let installer=host.installer().ok_or_else(||anyhow::anyhow!("private DNS NSS module is missing; administrator must install its distribution package"))?;
        anyhow::ensure!(installer=="/usr/bin/apt-get","private DNS NSS library is missing from the installed systemd-resolved package; check package integrity");
        anyhow::ensure!(
            host.run(installer, &["install", "-y", "libnss-resolve"])
                .await?,
            "libnss-resolve installation failed; review package manager output and retry setup"
        );
        anyhow::ensure!(
            !host.nss_missing(),
            "libnss-resolve installation did not provide the private DNS NSS library"
        );
    }
    if host
        .run(
            "/usr/bin/systemctl",
            &["is-active", "--quiet", "systemd-resolved.service"],
        )
        .await?
    {
        return Ok(());
    }
    anyhow::ensure!(!check_only,"systemd-resolved is inactive; administrator must start it before enabling private networking");
    anyhow::ensure!(
        host.privileged(),
        "systemd-resolved is inactive; ask an administrator to start it"
    );
    anyhow::ensure!(
        host.run(
            "/usr/bin/systemctl",
            &["enable", "--now", "systemd-resolved.service"]
        )
        .await?,
        "cannot activate systemd-resolved; check administrator service restrictions"
    );
    Ok(())
}
/// A running resolve1 service does not prove that libc applications use it.
/// This helper only reads host policy; enrollment handles configuration separately.
pub(crate) fn dns_integrated(nsswitch: &str, resolv: &str) -> bool {
    let resolve_first = nsswitch
        .lines()
        .filter_map(|line| line.split('#').next())
        .find_map(|line| {
            let (database, services) = line.split_once(':')?;
            if database.trim() != "hosts" {
                return None;
            }
            let services: Vec<_> = services.split_whitespace().collect();
            let resolve = services.iter().position(|service| *service == "resolve");
            let dns = services.iter().position(|service| *service == "dns");
            Some(resolve.is_some_and(|position| dns.is_none_or(|dns| position < dns)))
        })
        .unwrap_or(false);
    resolve_first || resolver_stub(resolv)
}
pub(crate) fn resolver_stub(resolv: &str) -> bool {
    resolv
        .lines()
        .filter_map(|line| line.split('#').next())
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            if fields.next() != Some("nameserver") {
                return None;
            }
            fields.next()
        })
        .is_some_and(|address| matches!(address, "127.0.0.53" | "127.0.0.54"))
}
fn nss_library_present() -> bool {
    for base in ["/usr/lib64", "/lib64", "/usr/lib", "/lib"] {
        let path = std::path::Path::new(base);
        if path.join("libnss_resolve.so.2").is_file() {
            return true;
        }
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.filter_map(Result::ok).take(256) {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if (name.ends_with("-linux-gnu")
                    || name.ends_with("-linux-gnueabihf")
                    || name.ends_with("-linux-gnueabi"))
                    && entry.path().join("libnss_resolve.so.2").is_file()
                {
                    return true;
                }
            }
        }
    }
    false
}

pub(crate) fn dns_status() -> &'static str {
    let nss = std::fs::read_to_string("/etc/nsswitch.conf").unwrap_or_default();
    let resolv = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    if dns_integrated(&nss, &resolv) {
        "system hostname lookups use systemd-resolved"
    } else {
        "private IP connectivity only: system hostname lookups bypass systemd-resolved; administrator must configure NSS resolve before dns or the resolved stub"
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rhel_default_dns_does_not_silently_pass_as_private_dns_ready() {
        assert!(!dns_integrated(
            "hosts: files dns myhostname\n",
            "nameserver 172.31.0.2\n"
        ));
        assert!(!dns_integrated(
            "hosts: files dns [NOTFOUND=return] resolve\n",
            "nameserver 172.31.0.2\n"
        ));
        assert!(dns_integrated(
            "hosts: files resolve [!UNAVAIL=return] dns myhostname\n",
            "nameserver 172.31.0.2\n"
        ));
        assert!(dns_integrated(
            "hosts: files dns\n",
            "# local stub\nnameserver 127.0.0.53\n"
        ));
        assert!(!dns_integrated(
            "# hosts: files resolve dns\nhosts: files dns\n",
            "# nameserver 127.0.0.53\nnameserver 172.31.0.2\n"
        ));
    }
}

#[cfg(test)]
mod preparation_tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    };
    struct Fake {
        present: AtomicBool,
        active: AtomicBool,
        nss_missing: AtomicBool,
        root: bool,
        installer: Option<&'static str>,
        install_ok: bool,
        service_ok: bool,
        calls: Mutex<Vec<(String, Vec<String>)>>,
    }
    impl Default for Fake {
        fn default() -> Self {
            Self {
                present: AtomicBool::new(false),
                active: AtomicBool::new(false),
                nss_missing: AtomicBool::new(false),
                root: true,
                installer: Some("/usr/bin/dnf"),
                install_ok: true,
                service_ok: true,
                calls: Mutex::new(vec![]),
            }
        }
    }
    #[async_trait::async_trait]
    impl Host for Fake {
        fn present(&self) -> bool {
            self.present.load(Ordering::SeqCst)
        }
        fn privileged(&self) -> bool {
            self.root
        }
        fn installer(&self) -> Option<&'static str> {
            self.installer
        }
        fn nss_missing(&self) -> bool {
            self.nss_missing.load(Ordering::SeqCst)
        }
        async fn run(&self, program: &str, args: &[&str]) -> Result<bool> {
            self.calls
                .lock()
                .unwrap()
                .push((program.into(), args.iter().map(|s| s.to_string()).collect()));
            if args.first() == Some(&"install") {
                self.present.store(self.install_ok, Ordering::SeqCst);
                if args.contains(&"libnss-resolve") && self.install_ok {
                    self.nss_missing.store(false, Ordering::SeqCst);
                }
                return Ok(self.install_ok);
            }
            if args.first() == Some(&"is-active") {
                return Ok(self.active.load(Ordering::SeqCst));
            }
            assert_eq!(args, ["enable", "--now", "systemd-resolved.service"]);
            self.active.store(self.service_ok, Ordering::SeqCst);
            Ok(self.service_ok)
        }
    }
    #[tokio::test]
    async fn missing_dependency_is_installed_and_started_once_for_dnf_and_apt() -> Result<()> {
        for installer in ["/usr/bin/dnf", "/usr/bin/apt-get"] {
            let host = Fake {
                installer: Some(installer),
                ..Default::default()
            };
            prepare_with(&host, false).await?;
            prepare_with(&host, false).await?;
            let calls = host.calls.lock().unwrap();
            assert_eq!(
                calls
                    .iter()
                    .filter(|(_, args)| args[0] == "install")
                    .count(),
                1
            );
            assert_eq!(
                calls.iter().filter(|(_, args)| args[0] == "enable").count(),
                1
            );
            assert!(host.active.load(Ordering::SeqCst));
        }
        Ok(())
    }
    #[tokio::test]
    async fn check_only_non_root_and_unrecognized_package_managers_never_install() {
        for (host, check) in [
            (Fake::default(), true),
            (
                Fake {
                    root: false,
                    ..Default::default()
                },
                false,
            ),
            (
                Fake {
                    installer: None,
                    ..Default::default()
                },
                false,
            ),
        ] {
            assert!(prepare_with(&host, check).await.is_err());
            assert!(host.calls.lock().unwrap().is_empty());
        }
    }
    #[tokio::test]
    async fn debian_nss_module_is_prepared_even_when_the_resolver_service_already_exists(
    ) -> Result<()> {
        let host = Fake {
            present: AtomicBool::new(true),
            active: AtomicBool::new(true),
            nss_missing: AtomicBool::new(true),
            installer: Some("/usr/bin/apt-get"),
            ..Default::default()
        };
        prepare_with(&host, false).await?;
        prepare_with(&host, false).await?;
        let calls = host.calls.lock().unwrap();
        assert_eq!(
            calls
                .iter()
                .filter(|(_, args)| args.iter().any(|arg| arg == "libnss-resolve"))
                .count(),
            1
        );
        assert!(!host.nss_missing());
        let restricted = Fake {
            nss_missing: AtomicBool::new(true),
            present: AtomicBool::new(true),
            ..Default::default()
        };
        assert!(prepare_with(&restricted, true).await.is_err());
        assert!(restricted.calls.lock().unwrap().is_empty());
        Ok(())
    }
    #[tokio::test]
    async fn package_failure_and_masked_service_are_actionable_and_do_not_loop() {
        let host = Fake {
            install_ok: false,
            ..Default::default()
        };
        assert!(prepare_with(&host, false)
            .await
            .unwrap_err()
            .to_string()
            .contains("installation failed"));
        assert_eq!(host.calls.lock().unwrap().len(), 1);
        let host = Fake {
            present: AtomicBool::new(true),
            service_ok: false,
            ..Default::default()
        };
        assert!(prepare_with(&host, false)
            .await
            .unwrap_err()
            .to_string()
            .contains("administrator service restrictions"));
        assert_eq!(host.calls.lock().unwrap().len(), 2);
    }
}

#[cfg(test)]
mod native_ci_tests {
    use super::*;
    #[tokio::test]
    #[ignore = "modifies resolver dependencies/NSS; only an explicitly owned GitHub-hosted Linux runner"]
    async fn privileged_enrollment_preparation_is_idempotent_and_preserves_system_dns() -> Result<()>
    {
        anyhow::ensure!(
            std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
                && std::env::var("RUNNER_ENVIRONMENT").as_deref() == Ok("github-hosted")
                && unsafe { libc::geteuid() } == 0,
            "disposable GitHub-hosted Linux runner required"
        );
        let dns = std::fs::read("/etc/resolv.conf")?;
        let mut pam = Vec::new();
        for name in [
            "common-auth",
            "common-account",
            "common-password",
            "common-session",
            "system-auth",
            "password-auth",
        ] {
            let path = std::path::Path::new("/etc/pam.d").join(name);
            if path.is_file() {
                pam.push((path.clone(), std::fs::read(path)?));
            }
        }
        prepare().await?;
        prepare().await?;
        anyhow::ensure!(
            std::fs::read("/etc/resolv.conf")? == dns,
            "enrollment changed upstream DNS"
        );
        for (path, bytes) in pam {
            anyhow::ensure!(std::fs::read(path)? == bytes, "enrollment changed PAM");
        }
        anyhow::ensure!(
            dns_status() == "system hostname lookups use systemd-resolved",
            "private DNS integration missing after enrollment"
        );
        Ok(())
    }
}
