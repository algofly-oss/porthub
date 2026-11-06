//! Invitation-only SSH frontend; no enrollment or core dependency.
use anyhow::{ensure, Context, Result};
use porthub_terminal::protocol::token;
use std::{process::Command as Process, time::Duration};
pub async fn join(invitation: &str) -> Result<()> {
    let mut url =
        url::Url::parse(invitation).context("provide the complete terminal invitation URL")?;
    ensure!(
        url.scheme() == "https" && url.username().is_empty() && url.password().is_none(),
        "terminal invitations must use HTTPS"
    );
    let capability = url
        .fragment()
        .context("terminal invitation is missing its capability")?
        .to_owned();
    ensure!(token(&capability, 64), "invalid terminal invitation");
    url.set_fragment(None);
    url.set_query(None);
    url.set_path("/api/terminal/info");
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()?;
    let response = client
        .post(url)
        .json(&serde_json::json!({"token":capability}))
        .send()
        .await?;
    ensure!(
        response.status().is_success(),
        "terminal invitation expired, revoked, or host unavailable"
    );
    let info: serde_json::Value = response.json().await?;
    let info = info.get("data").unwrap_or(&info);
    ensure!(
        info["access"] != "web",
        "this invitation allows browser access only; open it in your browser"
    );
    let host = info["ssh_host"]
        .as_str()
        .context("SSH endpoint is unavailable")?;
    ensure!(valid_ssh_host(host), "invalid terminal SSH endpoint");
    let port = info["ssh_port"]
        .as_u64()
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port > 0)
        .context("invalid terminal SSH port")?;
    let status = Process::new("ssh")
        .args(["-p", &port.to_string(), "-l", &capability, "--", host])
        .status()
        .context("SSH client unavailable; install OpenSSH or open the browser invitation")?;
    ensure!(
        status.success(),
        "terminal SSH connection ended with an error"
    );
    Ok(())
}

fn valid_ssh_host(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
        || !host.is_empty()
            && host.len() <= 253
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label.as_bytes()[0].is_ascii_alphanumeric()
                    && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
}
