//! Explicit clipboard uploads through the existing credential-free local broker.
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{io::Cursor, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

const MAX_BYTES: usize = 8 * 1024 * 1024;

#[derive(clap::Args)]
pub struct Args {
    /// Use a per-user agent installation.
    #[arg(long, global = true)]
    pub user: bool,
    /// Override the saved image tenant for this upload; accepts a unique ID prefix.
    #[arg(long)]
    pub registration: Option<String>,
    #[command(subcommand)]
    pub command: Option<ImageCommand>,
}

#[derive(clap::Subcommand)]
pub enum ImageCommand {
    /// Enable, disable or inspect the opt-in Ctrl+Shift+U desktop shortcut.
    Shortcut {
        #[command(subcommand)]
        action: crate::image_shortcut::Action,
    },
    /// Show or save your image-upload tenant. Algofly is preferred by default.
    Tenant {
        #[command(subcommand)]
        command: Option<TenantCommand>,
    },
}
#[derive(clap::Subcommand)]
pub enum TenantCommand {
    /// Show available tenants and the current selection.
    List,
    /// Prefer this tenant; accepts a unique registration or machine ID prefix.
    Set { registration: String },
    /// Clear the preference and return to automatic Algofly selection.
    Reset,
}
#[derive(Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Preference {
    registration: String,
    user: bool,
}
#[derive(Clone)]
struct Tenant {
    id: String,
    machine_id: String,
    gateway: String,
    user: bool,
    enabled: bool,
}
fn tenant_config() -> Result<std::path::PathBuf> {
    Ok(directories::ProjectDirs::from("dev", "porthub", "porthub")
        .context("Cannot locate user configuration")?
        .config_dir()
        .join("images")
        .join("tenant.json"))
}
fn preference() -> Result<Option<Preference>> {
    let path = tenant_config()?;
    if !path.try_exists()? {
        return Ok(None);
    }
    let saved: Preference = serde_json::from_slice(&crate::profile::read_private(&path)?)
        .context("Invalid image tenant preference; run porthub image tenant reset")?;
    ensure!(
        saved.registration.len() == 64 && saved.registration.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid saved image tenant"
    );
    Ok(Some(saved))
}
fn registration_scopes(user_only: bool) -> Result<&'static [bool]> {
    #[cfg(windows)]
    {
        ensure!(!user_only,"Per-user Windows services are not supported; use the system registration without --user");
        Ok(&[false])
    }
    #[cfg(not(windows))]
    {
        Ok(if user_only { &[true] } else { &[false, true] })
    }
}
fn tenants(user_only: bool) -> Result<Vec<Tenant>> {
    let mut rows = Vec::new();
    for &user in registration_scopes(user_only)? {
        let layout = if user {
            crate::service::Layout::user()?
        } else {
            crate::service::Layout::system()?
        };
        for record in crate::service::readable::list(&layout)? {
            if !record.private {
                rows.push(Tenant {
                    id: record.id,
                    machine_id: record.machine_id,
                    gateway: record.gateway,
                    user,
                    enabled: record.enabled,
                });
            }
        }
    }
    Ok(rows)
}
fn choose<'a>(
    rows: &'a [Tenant],
    selector: Option<&str>,
    preferred: Option<&Preference>,
) -> Result<&'a Tenant> {
    let selected: Vec<_> = if let Some(selector) = selector {
        let selector = selector.to_ascii_lowercase();
        ensure!(
            (6..=64).contains(&selector.len()) && selector.bytes().all(|b| b.is_ascii_hexdigit())
                || selector.len() == 32
                    && selector.starts_with("porthub-")
                    && selector[8..].bytes().all(|b| b.is_ascii_hexdigit()),
            "Use a registration ID or unique prefix of at least 6 characters from porthub ls"
        );
        rows.iter()
            .filter(|r| {
                r.id.starts_with(&selector)
                    || r.machine_id.starts_with(&selector)
                    || format!("porthub-{}", &r.id[..24]) == selector
            })
            .collect()
    } else if let Some(preferred) = preferred {
        let matching: Vec<_> = rows
            .iter()
            .filter(|r| r.id == preferred.registration && r.user == preferred.user)
            .collect();
        ensure!(matching.len()==1,"Preferred image tenant is unavailable. Use porthub image tenant set <ID> or porthub image tenant reset; no other tenant was selected.");
        matching
    } else {
        let algofly: Vec<_> = rows
            .iter()
            .filter(|r| {
                url::Url::parse(&r.gateway)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_owned))
                    .as_deref()
                    == Some("porthub.algofly.in")
            })
            .collect();
        if algofly.is_empty() {
            rows.iter().collect()
        } else {
            algofly
        }
    };
    ensure!(selected.len()==1,"Select an image tenant with porthub image tenant set <unique-ID-prefix>; use porthub image tenant list to see available tenants");
    Ok(selected[0])
}
fn tenant_command(user_only: bool, command: Option<TenantCommand>) -> Result<()> {
    match command {
        Some(TenantCommand::Reset) => {
            let path = tenant_config()?;
            if path.try_exists()? {
                crate::profile::read_private(&path)?;
                std::fs::remove_file(path)?;
            }
            println!("Image tenant preference cleared. Algofly is preferred automatically.");
        }
        Some(TenantCommand::Set { registration }) => {
            let rows = tenants(user_only)?;
            let selected = choose(&rows, Some(&registration), None)?;
            let path = tenant_config()?;
            let mut directory = std::fs::DirBuilder::new();
            directory.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                directory.mode(0o700);
            }
            directory.create(path.parent().context("Missing configuration directory")?)?;
            crate::profile::write_private(
                &path,
                &serde_json::to_vec_pretty(&Preference {
                    registration: selected.id.clone(),
                    user: selected.user,
                })?,
                true,
            )?;
            println!(
                "Preferred image tenant: {} ({})",
                selected.gateway,
                &selected.id[..12]
            );
        }
        None | Some(TenantCommand::List) => {
            let rows = tenants(user_only)?;
            let saved = if user_only { None } else { preference()? };
            let selected = choose(&rows, None, saved.as_ref()).ok();
            for row in &rows {
                println!(
                    "{} {}  {}{}{}",
                    if selected.is_some_and(|s| s.id == row.id && s.user == row.user) {
                        "*"
                    } else {
                        " "
                    },
                    &row.id[..12],
                    row.gateway,
                    if row.user { " (user)" } else { "" },
                    if row.enabled { "" } else { " (disabled)" }
                );
            }
            println!(
                "{}",
                if saved.is_some() {
                    "Saved preference; * marks the selected tenant."
                } else {
                    "Automatic preference: Algofly, or the sole installed tenant. * marks the selection."
                }
            );
            if selected.is_none() {
                println!("Select one with: porthub image tenant set <unique-ID-prefix>");
            }
        }
    }
    Ok(())
}

fn clipboard_png() -> Result<Vec<u8>> {
    let mut clipboard = arboard::Clipboard::new().context(
        "Cannot access the desktop clipboard. Run this command in your graphical session.",
    )?;
    let data = clipboard
        .get_image()
        .context("No image on the clipboard. Take a screenshot or copy an image first.")?;
    ensure!(
        data.width.saturating_mul(data.height) <= 32 * 1024 * 1024,
        "Clipboard image exceeds 32 megapixels"
    );
    let image = image::RgbaImage::from_raw(
        data.width.try_into()?,
        data.height.try_into()?,
        data.bytes.into_owned(),
    )
    .context("Invalid clipboard image")?;
    let mut png = Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image).write_to(&mut png, image::ImageFormat::Png)?;
    let png = png.into_inner();
    ensure!(png.len() <= MAX_BYTES, "Clipboard image exceeds 8 MiB");
    Ok(png)
}

pub async fn run(mut args: Args) -> Result<()> {
    if let Some(command) = args.command.take() {
        ensure!(
            args.registration.is_none(),
            "Use tenant set <ID> to save a preference"
        );
        return match command {
            ImageCommand::Tenant { command } => tenant_command(args.user, command),
            ImageCommand::Shortcut { action } => crate::image_shortcut::run(action, args.user),
        };
    }
    let result = upload_clipboard(args).await;
    if let Err(error) = &result {
        notify(&format!("{error:#}"));
    }
    result
}
async fn upload_clipboard(args: Args) -> Result<()> {
    // Desktop integrations invoke this command once per shortcut. Lock before
    // reading so repeated key presses cannot upload the same image concurrently.
    use fs2::FileExt;
    let dirs = directories::ProjectDirs::from("dev", "porthub", "porthub")
        .context("Cannot locate user state directory")?;
    std::fs::create_dir_all(dirs.cache_dir())?;
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(dirs.cache_dir().join("clipboard-upload.lock"))?;
    lock.try_lock_exclusive()
        .context("An image upload is already running")?;
    let rows = tenants(args.user)?;
    let preferred = if args.registration.is_some() || args.user {
        None
    } else {
        preference()?
    };
    let registration = choose(&rows, args.registration.as_deref(), preferred.as_ref())?;
    let layout = if registration.user {
        crate::service::Layout::user()?
    } else {
        crate::service::Layout::system()?
    };
    let png = tokio::task::spawn_blocking(clipboard_png).await??;
    let original = png.clone();
    let mut stream = crate::exposure_broker::connect_stream(&layout, &registration.id).await?;
    let request = json!({"operation":"image_upload","size":png.len(),"request_id":uuid::Uuid::new_v4().simple().to_string()});
    let mut header = serde_json::to_vec(&request)?;
    header.push(b'\n');
    let reply = tokio::time::timeout(Duration::from_secs(90), async {
        stream.write_all(&header).await?;
        stream.write_all(&png).await?;
        let mut reader = BufReader::new(stream);
        let bytes = crate::exposure_protocol::line(&mut reader).await?;
        Ok::<Value, anyhow::Error>(serde_json::from_slice(&bytes)?)
    })
    .await
    .context("Image upload timed out; clipboard preserved")??;
    if let Some(error) = reply["error"].as_str() {
        anyhow::bail!("{error}");
    }
    let url = reply["url"]
        .as_str()
        .context("Agent returned no image URL; update the agent")?;
    let parsed =
        url::Url::parse(&format!("{}/", registration.gateway.trim_end_matches('/')))?.join(url)?;
    ensure!(
        matches!(parsed.scheme(), "https" | "http")
            && parsed.host_str().is_some()
            && parsed.username().is_empty()
            && parsed.password().is_none(),
        "Invalid image URL"
    );
    // Always print the link, including when clipboard access subsequently fails.
    println!("{parsed}");
    let url = parsed.to_string();
    tokio::task::spawn_blocking(move || {
        ensure!(clipboard_png().is_ok_and(|current| current == original),"Image uploaded. Clipboard changed during upload, so it was preserved. Copy the URL from Hosted images.");
        copy_url(&url)
    }).await??;
    notify("Image link copied. Paste it anywhere.");
    Ok(())
}

fn copy_url(url: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // These utilities fork to retain clipboard ownership after this command
        // exits. Dropping a short-lived arboard clipboard would lose the URL.
        use std::{
            io::Write,
            process::{Command, Stdio},
        };
        let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some();
        let (program, args): (&str, &[&str]) = if wayland {
            ("wl-copy", &["--type", "text/plain;charset=utf-8"])
        } else {
            (
                "xclip",
                &["-selection", "clipboard", "-in", "-target", "UTF8_STRING"],
            )
        };
        let mut child = Command::new(program).args(args).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().with_context(||format!("Image uploaded. Install {} to copy links, then use Copy link in Hosted images.",if wayland {"wl-clipboard"}else{"xclip"}))?;
        child
            .stdin
            .take()
            .context("Cannot write clipboard")?
            .write_all(url.as_bytes())?;
        ensure!(
            child.wait()?.success(),
            "Image uploaded, but clipboard write failed. Use Copy link in Hosted images."
        );
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        arboard::Clipboard::new()?.set_text(url)?;
        Ok(())
    }
}
fn notify(message: &str) {
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("notify-send")
            .args(["--app-name=PortHub", "PortHub images", message])
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("osascript").args(["-e","on run argv\ndisplay notification (item 1 of argv) with title \"PortHub images\"\nend run",message]).spawn();
    }
    #[cfg(windows)]
    {
        let _ = message;
    }
}

pub(crate) async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut reader: BufReader<S>,
    control: &crate::control::Control,
    message: Value,
) -> Result<()> {
    let size = message["size"].as_u64().context("Missing image size")?;
    ensure!(size > 0 && size <= MAX_BYTES as u64, "Invalid image size");
    let request_id = message["request_id"]
        .as_str()
        .context("Missing upload identity")?;
    ensure!(
        request_id.len() == 32 && request_id.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid upload identity"
    );
    let mut bytes = vec![0; size as usize];
    tokio::time::timeout(Duration::from_secs(15), reader.read_exact(&mut bytes)).await??;
    let result = control.request(reqwest::Method::POST,"machines/client/images",Some(json!({"machine_id":control.profile().machine_id,"token":control.profile().token,"image":STANDARD.encode(bytes),"request_id":request_id,"name":"Clipboard image"})),&[]).await;
    let reply = match result {
        Ok(reply) => reply
            .json()
            .unwrap_or_else(|_| json!({"error":"Invalid upload response"})),
        Err(error) => {
            json!({"error":format!("{error}. Check the portal's image storage and try again.")})
        }
    };
    let mut bytes = serde_json::to_vec(&reply)?;
    bytes.push(b'\n');
    reader.get_mut().write_all(&bytes).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tenant(id: char, gateway: &str, user: bool) -> Tenant {
        Tenant {
            id: id.to_string().repeat(64),
            machine_id: id.to_string().repeat(24),
            gateway: gateway.into(),
            user,
            enabled: true,
        }
    }
    #[test]
    fn image_tenants_only_inspect_supported_service_scopes() {
        #[cfg(windows)]
        {
            assert_eq!(registration_scopes(false).unwrap(), &[false]);
            assert!(registration_scopes(true).is_err());
        }
        #[cfg(not(windows))]
        {
            assert_eq!(registration_scopes(false).unwrap(), &[false, true]);
            assert_eq!(registration_scopes(true).unwrap(), &[true]);
        }
    }
    #[test]
    fn preference_is_explicit_and_algofly_is_the_automatic_default() -> Result<()> {
        let mut rows = vec![
            tenant('a', "http://luna.local", false),
            tenant('b', "https://porthub.algofly.in", false),
        ];
        ensure!(choose(&rows, None, None)?.id == rows[1].id);
        let saved = Preference {
            registration: rows[0].id.clone(),
            user: false,
        };
        ensure!(choose(&rows, None, Some(&saved))?.id == rows[0].id);
        ensure!(choose(&rows, Some("bbbbbb"), Some(&saved))?.id == rows[1].id);
        ensure!(choose(&rows, Some("bb"), None).is_err());
        rows[1].enabled = false;
        ensure!(
            choose(&rows, None, None)?.id == rows[1].id,
            "Never fall back from a disabled Algofly tenant"
        );
        let stale = Preference {
            registration: "c".repeat(64),
            user: false,
        };
        ensure!(choose(&rows, None, Some(&stale)).is_err());
        rows.push(tenant('b', "https://porthub.algofly.in", true));
        ensure!(choose(&rows, Some("bbbbbb"), None).is_err());
        ensure!(choose(&rows, None, None).is_err());
        Ok(())
    }
    #[tokio::test]
    async fn broker_forwards_bounded_image_and_returns_public_url_without_credentials() -> Result<()>
    {
        use axum::{routing::post, Json, Router};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let router = Router::new().route(
            "/api/machines/client/images",
            post(|Json(body): Json<Value>| async move {
                assert_eq!(body["machine_id"], "0123456789abcdef01234567");
                assert_eq!(body["token"], "private-test-token");
                assert_eq!(body["request_id"], "a".repeat(32));
                assert_eq!(
                    STANDARD.decode(body["image"].as_str().unwrap()).unwrap(),
                    b"test-image-bytes"
                );
                Json(json!({"url":"https://images.example.invalid/api/images/public/abc"}))
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, router).await });
        let profile: crate::profile::Profile = serde_json::from_value(
            json!({"server":format!("http://{address}"),"machine_id":"0123456789abcdef01234567","token":"private-test-token","allow_insecure_http_for_tests":true}),
        )?;
        let control = crate::control::Control::new(profile)?;
        let (mut client, stream) = tokio::io::duplex(65536);
        let message = json!({"size":16,"request_id":"a".repeat(32)});
        let upload = serve(BufReader::new(stream), &control, message);
        let client = async {
            client.write_all(b"test-image-bytes").await?;
            let bytes = crate::exposure_protocol::line(&mut BufReader::new(client)).await?;
            let reply: Value = serde_json::from_slice(&bytes)?;
            ensure!(reply["url"] == "https://images.example.invalid/api/images/public/abc");
            ensure!(!String::from_utf8_lossy(&bytes).contains("private-test-token"));
            Ok::<_, anyhow::Error>(())
        };
        let result = tokio::try_join!(upload, client);
        server.abort();
        result?;
        let (_, stream) = tokio::io::duplex(64);
        assert!(serve(
            BufReader::new(stream),
            &control,
            json!({"size":MAX_BYTES+1,"request_id":"a".repeat(32)})
        )
        .await
        .is_err());
        Ok(())
    }
}
