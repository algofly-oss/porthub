#![cfg(target_os = "linux")]
use anyhow::{ensure, Result};
#[test]
#[ignore = "requires a dedicated Xvfb display and focused browser test input"]
fn paste_inserts_the_copied_url_and_changed_focus_prevents_injection() -> Result<()> {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    ensure!(
        std::env::var("PORTHUB_TEST_ISOLATED_DISPLAY").as_deref() == Ok("1"),
        "Run only in an isolated Xvfb display"
    );
    let url = "https://images.example.invalid/i/AbC23.png";
    let original = Command::new("xdotool").arg("getactivewindow").output()?;
    ensure!(original.status.success(), "xdotool: {}", String::from_utf8_lossy(&original.stderr));
    let id = String::from_utf8(original.stdout)?.trim().to_owned();
    let mut copy = Command::new("xclip")
        .args(["-selection", "clipboard", "-in", "-target", "UTF8_STRING"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    copy.stdin.take().unwrap().write_all(url.as_bytes())?;
    ensure!(copy.wait()?.success());
    let focus = porthub_agent::image_delivery::Focus::capture()?;
    focus.paste(url)?;
    ensure!(Command::new("xprop")
        .args([
            "-root",
            "-f",
            "_NET_ACTIVE_WINDOW",
            "32x",
            "-set",
            "_NET_ACTIVE_WINDOW",
            "0"
        ])
        .status()?
        .success());
    ensure!(focus.paste(url).is_err());
    ensure!(Command::new("xprop")
        .args([
            "-root",
            "-f",
            "_NET_ACTIVE_WINDOW",
            "32x",
            "-set",
            "_NET_ACTIVE_WINDOW",
            &id
        ])
        .status()?
        .success());
    Ok(())
}
