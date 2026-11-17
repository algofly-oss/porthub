//! One-shot bounded owned NRPT transactions. No persistent shell or global DNS override.
use super::{device, windows_state};
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::{
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    suffix: String,
    id: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u8,
    binding: String,
    guid: String,
    server: Ipv4Addr,
    nonce: String,
    committed: Vec<String>,
    rules: Vec<Rule>,
}
#[derive(Serialize)]
struct Request<'a> {
    path: &'a Path,
    binding: &'a str,
    guid: &'a str,
    server: Ipv4Addr,
    desired: &'a [String],
    mode: &'a str,
}
pub(super) struct Registration {
    path: PathBuf,
    binding: String,
    guid: String,
    server: Ipv4Addr,
    index: u32,
    armed: bool,
}
fn powershell() -> Result<PathBuf> {
    use std::os::windows::{
        ffi::{OsStrExt, OsStringExt},
        fs::MetadataExt,
    };
    #[link(name = "kernel32")]
    extern "system" {
        fn GetWindowsDirectoryW(buffer: *mut u16, size: u32) -> u32;
    }
    let mut path = [0u16; 32768];
    let size = unsafe { GetWindowsDirectoryW(path.as_mut_ptr(), path.len() as u32) } as usize;
    ensure!(
        size > 0 && size < path.len(),
        "cannot locate the Windows system directory"
    );
    let root = PathBuf::from(std::ffi::OsString::from_wide(&path[..size]));
    ensure!(root.is_absolute(), "invalid Windows system directory");
    let exe = root.join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let metadata = std::fs::symlink_metadata(&exe)?;
    ensure!(
        metadata.is_file() && metadata.file_attributes() & 0x400 == 0,
        "Windows PowerShell is not a regular system executable"
    );
    ensure!(
        exe.as_os_str().encode_wide().count() <= 512,
        "Windows system executable path exceeds bound"
    );
    Ok(exe)
}
fn shell_path(path: &Path) -> Result<PathBuf> {
    let value = path
        .to_str()
        .context("PowerShell ownership path must be Unicode")?;
    let value = value.strip_prefix("\\\\?\\").unwrap_or(value);
    ensure!(
        value.len() >= 3 && value.as_bytes()[1] == b':' && value.as_bytes()[2] == b'\\',
        "NRPT ownership journal must be on a local drive"
    );
    ensure!(
        value.encode_utf16().count() <= 240,
        "NRPT protected journal path exceeds PowerShell 5 path bound"
    );
    Ok(PathBuf::from(value))
}

fn command() -> Result<String> {
    let source=concat!(include_str!("windows_nrpt.ps1"),"\ntry{$request=[Console]::In.ReadToEnd()|ConvertFrom-Json;Invoke-PortHubNrpt -Config $request|ConvertTo-Json -Compress}catch{$message=$_.Exception.Message;if($message.Length -gt 512){$message=$message.Substring(0,512)};[Console]::Error.WriteLine($message);exit 1}\n");
    encode_command(source)
}
fn encode_command(source: &str) -> Result<String> {
    // Embedded scripts may arrive via CRLF checkouts or source archives.
    let source = source.replace("\r\n", "\n");
    let bytes: Vec<_> = source.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let encoded = STANDARD.encode(bytes);
    ensure!(
        encoded.len() <= 31500,
        "NRPT constant script exceeds Windows command-line bound"
    );
    Ok(encoded)
}
fn cleanup_command() -> Result<String> {
    let source=concat!(include_str!("windows_nrpt.ps1"),"\ntry{$request=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:PORTHUB_NRPT_CLEANUP))|ConvertFrom-Json;Invoke-PortHubNrpt -Config $request|Out-Null}catch{exit 1}\n");
    encode_command(source)
}
async fn bounded(stream: impl AsyncRead + Unpin) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    stream.take(65537).read_to_end(&mut bytes).await?;
    ensure!(bytes.len() <= 65536, "NRPT child output exceeds bound");
    Ok(bytes)
}
impl Registration {
    pub async fn open(
        profile: &Path,
        index: u32,
        server: Ipv4Addr,
        desired: &[String],
    ) -> Result<Self> {
        ensure!(server.is_private(), "invalid owned DNS server address");
        let server = super::native_ownership::dns_endpoint(server);
        let path = windows_state::state_path(profile, ".nrpt-ownership.json")?;
        let binding = windows_state::profile_binding(&profile.canonicalize()?)?;
        let guid = device::adapter_guid(index)?;
        let mut fresh = false;
        if let Some(old) = windows_state::read_bounded::<Journal>(&path, 262144)? {
            ensure!(
                old.version == 1
                    && old.binding == binding
                    && (old.server.is_private() || old.server.is_loopback()),
                "NRPT ownership profile binding changed; foreign policy was not modified"
            );
            if old.guid != guid || old.server != server {
                // The previous TUN may already be gone after a clean address
                // rebind. Retire only the exact old journal's rule IDs/markers,
                // before publishing a different DNS endpoint under this profile.
                let mut prior = Self {
                    path: path.clone(),
                    binding: binding.clone(),
                    guid: old.guid,
                    server: old.server,
                    index,
                    armed: true,
                };
                prior.close().await?;
                fresh = true;
            }
        } else {
            fresh = true;
        }
        if fresh {
            let mut nonce = [0; 16];
            getrandom::fill(&mut nonce)?;
            windows_state::write_bounded(
                &path,
                &Journal {
                    version: 1,
                    binding: binding.clone(),
                    guid: guid.clone(),
                    server,
                    nonce: format!("{:032x}", u128::from_be_bytes(nonce)),
                    committed: Vec::new(),
                    rules: Vec::new(),
                },
                262144,
            )?;
        }
        let mut result = Self {
            path,
            binding,
            guid,
            server,
            index,
            armed: true,
        };
        if let Err(error) = result.replace(desired).await {
            if result.close().await.is_err() {
                tracing::warn!("initial NRPT transaction cleanup pending in protected journal");
            }
            return Err(error);
        }
        Ok(result)
    }
    pub async fn replace(&mut self, desired: &[String]) -> Result<()> {
        ensure!(
            device::adapter_guid(self.index)? == self.guid,
            "DNS adapter identity changed; policy was not modified"
        );
        self.run(desired, "reconcile").await
    }
    pub async fn close(&mut self) -> Result<()> {
        self.run(&[], "clear").await?;
        self.armed = false;
        Ok(())
    }
    async fn run(&self, desired: &[String], mode: &str) -> Result<()> {
        ensure!(desired.len() <= 256, "NRPT suffix count exceeds bound");
        // Validate the exact protected journal again before starting a privileged child.
        let _: Journal = windows_state::read_bounded(&self.path, 262144)?
            .context("NRPT ownership journal disappeared")?;
        let path = shell_path(&self.path)?;
        let input = serde_json::to_vec(&Request {
            path: &path,
            binding: &self.binding,
            guid: &self.guid,
            server: self.server,
            desired,
            mode,
        })?;
        ensure!(input.len() <= 65536, "NRPT request exceeds bound");
        let encoded = command()?;
        let mut child = tokio::process::Command::new(powershell()?)
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                &encoded,
            ])
            .creation_flags(0x08000000)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("cannot start owned NRPT transaction")?;
        let mut stdin = child.stdin.take().context("NRPT child stdin missing")?;
        let stdout = child.stdout.take().context("NRPT child stdout missing")?;
        let stderr = child.stderr.take().context("NRPT child stderr missing")?;
        let result = tokio::time::timeout(Duration::from_secs(30), async {
            stdin.write_all(&input).await?;
            stdin.shutdown().await?;
            drop(stdin);
            let (status, out, err) = tokio::try_join!(
                async { Ok::<_, anyhow::Error>(child.wait().await?) },
                bounded(stdout),
                bounded(stderr)
            )?;
            ensure!(
                status.success(),
                "owned NRPT transaction failed: {}",
                String::from_utf8_lossy(&err)
                    .chars()
                    .take(512)
                    .collect::<String>()
            );
            let receipt: serde_json::Value = serde_json::from_slice(&out)?;
            ensure!(
                receipt["ok"] == true && receipt["rules"].as_u64().is_some_and(|n| n <= 256),
                "invalid NRPT transaction receipt"
            );
            Ok::<_, anyhow::Error>(())
        })
        .await;
        match result {
            Ok(Ok(())) => Ok(()),
            other => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                match other {
                    Ok(Err(e)) => Err(e),
                    Err(_) => anyhow::bail!(
                        "owned NRPT transaction timed out; protected recovery journal retained"
                    ),
                    Ok(Ok(())) => unreachable!(),
                }
            }
        }
    }
}
impl Drop for Registration {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Cancellation can bypass async shutdown. Use one bounded hidden child,
        // no pipes/resident wrapper; keep the protected journal on any failure.
        use std::os::windows::process::CommandExt;
        let cleanup = (|| -> Result<()> {
            let _: Journal = windows_state::read_bounded(&self.path, 262144)?
                .context("NRPT cleanup journal missing")?;
            let path = shell_path(&self.path)?;
            let input = serde_json::to_vec(&Request {
                path: &path,
                binding: &self.binding,
                guid: &self.guid,
                server: self.server,
                desired: &[],
                mode: "clear",
            })?;
            ensure!(input.len() <= 65536, "NRPT cleanup request exceeds bound");
            let encoded = cleanup_command()?;
            let mut child = std::process::Command::new(powershell()?)
                .args([
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-EncodedCommand",
                    &encoded,
                ])
                .env("PORTHUB_NRPT_CLEANUP", STANDARD.encode(input))
                .creation_flags(0x08000000)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            let end = std::time::Instant::now() + Duration::from_secs(5);
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        return if status.success() {
                            Ok(())
                        } else {
                            anyhow::bail!("owned NRPT fallback failed")
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(error.into());
                    }
                }
                if std::time::Instant::now() >= end {
                    let _ = child.kill();
                    let _ = child.wait();
                    anyhow::bail!("owned NRPT fallback deadline exceeded");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        })();
        if cleanup.is_err() {
            tracing::warn!(
                "owned NRPT cleanup was not acknowledged; protected recovery journal retained"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn crlf_source_has_identical_native_command_bytes_and_budget() {
        let lf = include_str!("windows_nrpt.ps1").replace("\r\n", "\n");
        let crlf = lf.replace('\n', "\r\n");
        assert_eq!(
            super::encode_command(&lf).unwrap(),
            super::encode_command(&crlf).unwrap()
        );
        // Both production entrypoints pass their complete exact wrappers through
        // this normalizer; the existing size test covers both complete commands.
        for encoded in [super::command().unwrap(), super::cleanup_command().unwrap()] {
            use base64::Engine;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .unwrap();
            let words: Vec<_> = bytes
                .chunks_exact(2)
                .map(|v| u16::from_le_bytes([v[0], v[1]]))
                .collect();
            assert!(!String::from_utf16(&words).unwrap().contains('\r'));
        }
    }
    #[test]
    fn constant_script_fits_native_windows_command_line() {
        assert!(super::command().unwrap().len() <= 31500);
        assert!(super::cleanup_command().unwrap().len() <= 31500);
    }
}
