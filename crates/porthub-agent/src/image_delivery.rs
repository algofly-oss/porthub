//! Per-desktop delivery preference. Pasting is explicitly opt-in.
use anyhow::{ensure, Context, Result};

#[derive(
    Clone,
    Copy,
    Default,
    Debug,
    PartialEq,
    Eq,
    clap::ValueEnum,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Copy,
    Paste,
}
fn path() -> Result<std::path::PathBuf> {
    Ok(directories::ProjectDirs::from("dev", "porthub", "porthub")
        .context("Cannot locate user configuration")?
        .config_dir()
        .join("images")
        .join("delivery.json"))
}
pub fn preference() -> Result<Mode> {
    let path = path()?;
    if !path.try_exists()? {
        return Ok(Mode::default());
    }
    serde_json::from_slice(&crate::profile::read_private(&path)?)
        .context("Invalid image delivery preference; run porthub image mode copy")
}
pub fn configure(mode: Option<Mode>) -> Result<()> {
    if let Some(mode) = mode {
        let path = path()?;
        let mut directory = std::fs::DirBuilder::new();
        directory.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            directory.mode(0o700);
        }
        directory.create(path.parent().context("Missing configuration directory")?)?;
        crate::profile::write_private(&path, &serde_json::to_vec(&mode)?, true)?;
    }
    println!(
        "Image URL mode: {}",
        match preference()? {
            Mode::Copy => "copy (copy the URL to the clipboard)",
            Mode::Paste => "paste (copy the URL and paste into the focused input)",
        }
    );
    Ok(())
}

pub struct Focus(String);
impl Focus {
    pub fn capture() -> Result<Self> {
        Ok(Self(foreground()?))
    }
    pub fn paste(&self) -> Result<()> {
        #[cfg(any(windows, target_os = "linux"))]
        release_modifiers()?;
        ensure!(
            foreground()? == self.0,
            "Image link copied. Focus changed during upload; paste the URL manually."
        );
        paste(&self.0)
    }
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn output(program: &str, args: &[&str]) -> Result<String> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("Cannot run {program} for direct paste"))?;
    ensure!(
        output.status.success(),
        "Direct paste failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}
#[cfg(target_os = "linux")]
fn foreground() -> Result<String> {
    ensure!(
        std::env::var_os("WAYLAND_DISPLAY").is_none(),
        "Direct paste currently supports Linux X11, macOS and Windows. Use copy mode on Wayland."
    );
    let id = output("xdotool", &["getactivewindow"])
        .context("Direct paste on X11 requires xdotool and a graphical session")?;
    ensure!(
        id.parse::<u64>().is_ok_and(|id| id != 0),
        "No focused desktop window"
    );
    Ok(id)
}
#[cfg(target_os = "linux")]
fn terminal_class(properties: &str) -> bool {
    properties.split('\0').any(|class| {
        matches!(
            class.to_ascii_lowercase().as_str(),
            "gnome-terminal"
                | "gnome-terminal-server"
                | "org.gnome.terminal"
                | "kgx"
                | "org.gnome.console"
                | "ptyxis"
                | "org.gnome.ptyxis"
                | "konsole"
                | "org.kde.konsole"
                | "xfce4-terminal"
                | "xfce4-terminal-server"
                | "mate-terminal"
                | "tilix"
                | "com.gexperts.tilix"
                | "terminator"
                | "alacritty"
                | "kitty"
                | "wezterm"
                | "org.wezfurlong.wezterm"
                | "ghostty"
                | "com.mitchellh.ghostty"
                | "st"
                | "st-256color"
                | "sakura"
                | "guake"
                | "tilda"
                | "hyper"
                | "warp"
                | "dev.warp.warp"
        )
    })
}
#[cfg(target_os = "linux")]
fn paste(window: &str) -> Result<()> {
    use x11rb::protocol::xproto::{AtomEnum, ConnectionExt};
    // Use application identity, never the window title (which may be a web page
    // or shell command). Editors and browsers keep their usual Ctrl+V behavior.
    let (connection, _) = x11rb::connect(None).context("Cannot access the desktop for paste")?;
    let properties = connection
        .get_property(
            false,
            window.parse::<u32>()?,
            AtomEnum::WM_CLASS,
            AtomEnum::STRING,
            0,
            1024,
        )?
        .reply()?
        .value;
    let terminal = terminal_class(&String::from_utf8_lossy(&properties));
    ensure!(
        foreground()? == window,
        "Image link copied. Focus changed before paste; paste the URL manually."
    );
    let key = if terminal { "ctrl+shift+v" } else { "ctrl+v" };
    output("xdotool", &["key", "--clearmodifiers", key])?;
    Ok(())
}
#[cfg(target_os = "linux")]
fn release_modifiers() -> Result<()> {
    use x11rb::{connection::Connection, protocol::xproto::ConnectionExt};
    let (connection, _) = x11rb::connect(None).context("Cannot check the shortcut keys")?;
    let setup = connection.setup();
    let count = u8::try_from(u16::from(setup.max_keycode) - u16::from(setup.min_keycode) + 1)?;
    let mapping = connection
        .get_keyboard_mapping(setup.min_keycode, count)?
        .reply()?;
    ensure!(
        mapping.keysyms_per_keycode > 0,
        "Cannot read the desktop keyboard mapping"
    );
    let watched: Vec<usize> = mapping
        .keysyms
        .chunks(mapping.keysyms_per_keycode as usize)
        .enumerate()
        .filter(|(_, symbols)| {
            symbols
                .iter()
                .any(|symbol| matches!(*symbol, 0xffe1..=0xffee | 0xfe03 | 0xff7e | 0x55 | 0x75))
        })
        .map(|(index, _)| usize::from(setup.min_keycode) + index)
        .collect();
    // Fast repeat-paste can reach delivery while Ctrl+Shift+U is still held.
    // Wait for real release instead of synthesizing conflicting modifier-ups.
    for _ in 0..150 {
        let keys = connection.query_keymap()?.reply()?.keys;
        if watched
            .iter()
            .all(|code| keys[code / 8] & (1 << (code % 8)) == 0)
        {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    anyhow::bail!("Release the shortcut keys, then paste the copied image link manually")
}
#[cfg(target_os = "macos")]
fn foreground() -> Result<String> {
    let id = output("osascript", &["-e", "tell application \"System Events\" to get unix id of first application process whose frontmost is true"])
        .context("Allow PortHub desktop automation in macOS Privacy & Security settings")?;
    ensure!(!id.is_empty(), "No focused desktop application");
    Ok(id)
}
#[cfg(target_os = "macos")]
fn paste(_window: &str) -> Result<()> {
    output(
        "osascript",
        &[
            "-e",
            "tell application \"System Events\" to keystroke \"v\" using command down",
        ],
    )?;
    Ok(())
}
#[cfg(windows)]
fn foreground() -> Result<String> {
    let window = unsafe { windows_sys::Win32::UI::WindowsAndMessaging::GetForegroundWindow() };
    ensure!(!window.is_null(), "No focused desktop window");
    Ok((window as usize).to_string())
}
#[cfg(windows)]
fn release_modifiers() -> Result<()> {
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::*;
    // Wait for the shortcut's physical modifiers to be released before Ctrl+V.
    for _ in 0..100 {
        let held = [VK_CONTROL, VK_SHIFT, VK_MENU]
            .iter()
            .any(|key| unsafe { GetAsyncKeyState(i32::from(*key)) } < 0);
        if !held {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    ensure!(
        [VK_CONTROL, VK_SHIFT, VK_MENU]
            .iter()
            .all(|key| unsafe { GetAsyncKeyState(i32::from(*key)) } >= 0),
        "Release the shortcut keys, then paste the copied image link manually"
    );
    Ok(())
}
#[cfg(windows)]
fn paste(_window: &str) -> Result<()> {
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::*;
    let input = |key, flags| INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: key,
                wScan: 0,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    };
    let inputs = [
        input(VK_CONTROL, 0),
        input(VK_V, 0),
        input(VK_V, KEYEVENTF_KEYUP),
        input(VK_CONTROL, KEYEVENTF_KEYUP),
    ];
    let sent = unsafe {
        SendInput(
            inputs.len() as u32,
            inputs.as_ptr(),
            std::mem::size_of::<INPUT>() as i32,
        )
    };
    if sent != inputs.len() as u32 {
        // Do not leave a synthetic modifier held when Windows blocks injection.
        let release = [
            input(VK_V, KEYEVENTF_KEYUP),
            input(VK_CONTROL, KEYEVENTF_KEYUP),
        ];
        unsafe {
            SendInput(
                release.len() as u32,
                release.as_ptr(),
                std::mem::size_of::<INPUT>() as i32,
            );
        }
        anyhow::bail!("Windows blocked direct paste. The link is copied; paste it manually.");
    }
    Ok(())
}
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn foreground() -> Result<String> {
    anyhow::bail!("Direct paste is unsupported on this desktop")
}
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn paste(_window: &str) -> Result<()> {
    anyhow::bail!("Direct paste is unsupported on this desktop")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    #[test]
    fn terminal_identity_selects_the_terminal_paste_shortcut() {
        for properties in [
            "gnome-terminal-server\0Gnome-terminal\0",
            "terminal\0org.gnome.Ptyxis\0",
            "kitty\0kitty\0",
            "konsole\0konsole\0",
            "xfce4-terminal\0Xfce4-terminal\0",
            "Alacritty\0Alacritty\0",
        ] {
            assert!(terminal_class(properties), "{properties}");
        }
        for properties in ["google-chrome\0Google-chrome\0", "code\0Code\0", ""] {
            assert!(!terminal_class(properties), "{properties}");
        }
    }
    #[test]
    fn copy_is_the_default_and_preferences_are_explicit() {
        assert_eq!(Mode::default(), Mode::Copy);
        assert_eq!(
            serde_json::from_str::<Mode>("\"copy\"").unwrap(),
            Mode::Copy
        );
        assert_eq!(
            serde_json::from_str::<Mode>("\"paste\"").unwrap(),
            Mode::Paste
        );
        assert!(serde_json::from_str::<Mode>("\"unknown\"").is_err());
    }
}
