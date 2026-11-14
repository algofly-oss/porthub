//! Desktop-owned input. Never initialized by the privileged network service.
//! Held keys/buttons are released on disconnect and after an idle deadman timeout.
use anyhow::{Context, Result};
use enigo::{Axis, Coordinate, Direction, Enigo, Key, Keyboard, Mouse, Settings};
use porthub_components::keyboard::{Button, Command, KeyState, PointerAction};
use std::time::{Duration, Instant};

pub struct Desktop {
    native: Option<Native>,
    clipboard: Option<arboard::Clipboard>,
    keys: Vec<String>,
    buttons: Vec<Button>,
    last: Instant,
}
enum Native {
    Enigo(Enigo),
    #[cfg(target_os = "linux")]
    Uinput(super::uinput::Device),
}
impl Desktop {
    pub fn new() -> Result<Self> {
        Ok(Self {
            native: None,
            clipboard: None,
            keys: Vec::new(),
            buttons: Vec::new(),
            last: Instant::now(),
        })
    }
    fn initialize(&mut self) -> Result<()> {
        if self.native.is_some() {
            return Ok(());
        }
        #[cfg(target_os = "linux")]
        let native = if std::env::var_os("WAYLAND_DISPLAY").is_some() {
            Native::Uinput(super::uinput::Device::new().context("Wayland input requires desktop-user access to /dev/uinput; see porthub keyboard help")?)
        } else {
            Native::Enigo(
                Enigo::new(&Settings::default()).context("Cannot initialize desktop input")?,
            )
        };
        #[cfg(not(target_os = "linux"))]
        let native = Native::Enigo(
            Enigo::new(&Settings::default())
                .context("Cannot initialize desktop input; allow Accessibility permissions")?,
        );
        self.native = Some(native);
        Ok(())
    }
    pub fn has_held(&self) -> bool {
        !self.keys.is_empty() || !self.buttons.is_empty()
    }
    fn key(&mut self, name: &str, state: KeyState) -> Result<()> {
        self.initialize()?;
        #[cfg(target_os = "linux")]
        if let Some(Native::Uinput(device)) = &mut self.native {
            return device.key(name, state);
        }
        let Some(Native::Enigo(native)) = &mut self.native else {
            unreachable!()
        };
        let parts: Vec<_> = name.split('+').collect();
        let direction = match state {
            KeyState::Press => Direction::Click,
            KeyState::Down => Direction::Press,
            KeyState::Up => Direction::Release,
        };
        let keys = parts.iter().map(|p| key(p)).collect::<Result<Vec<_>>>()?;
        if keys.len() == 1 {
            native.key(keys[0], direction)?;
        } else {
            if state == KeyState::Up {
                for key in keys.iter().rev() {
                    native.key(*key, Direction::Release)?;
                }
            } else {
                for (index, key) in keys[..keys.len() - 1].iter().enumerate() {
                    if let Err(error) = native.key(*key, Direction::Press) {
                        for pressed in keys[..=index].iter().rev() {
                            let _ = native.key(*pressed, Direction::Release);
                        }
                        return Err(error.into());
                    }
                }
                let result = native.key(*keys.last().unwrap(), direction);
                if state == KeyState::Press || result.is_err() {
                    for key in keys[..keys.len() - 1].iter().rev() {
                        let _ = native.key(*key, Direction::Release);
                    }
                }
                result?;
            }
        }
        Ok(())
    }
    fn copy(&mut self, text: &str) -> Result<()> {
        let clipboard = match self.clipboard.as_mut() {
            Some(c) => c,
            None => self.clipboard.insert(
                arboard::Clipboard::new()
                    .context("Cannot access the logged-in desktop clipboard")?,
            ),
        };
        clipboard
            .set_text(text.to_owned())
            .context("Cannot update the remote clipboard")?;
        Ok(())
    }
    fn paste(&mut self) -> Result<()> {
        #[cfg(target_os = "linux")]
        if std::env::var_os("WAYLAND_DISPLAY").is_none() {
            use x11rb::protocol::xproto::{AtomEnum, ConnectionExt};
            let (connection, _) =
                x11rb::connect(None).context("Cannot access focused desktop window")?;
            let window = connection.get_input_focus()?.reply()?.focus;
            let properties = connection
                .get_property(false, window, AtomEnum::WM_CLASS, AtomEnum::STRING, 0, 1024)?
                .reply()?
                .value;
            let terminal =
                crate::image_delivery::terminal_class(&String::from_utf8_lossy(&properties));
            return self.key(
                if terminal { "ctrl+shift+v" } else { "ctrl+v" },
                KeyState::Press,
            );
        }
        #[cfg(target_os = "macos")]
        return self.key("meta+v", KeyState::Press);
        #[cfg(not(target_os = "macos"))]
        self.key("ctrl+v", KeyState::Press)
    }
    pub fn execute(&mut self, command: &Command) -> Result<()> {
        command.validate()?;
        self.last = Instant::now();
        match command {
            Command::Text { text } => {
                self.initialize()?;
                match self.native.as_mut().unwrap() {
                    Native::Enigo(native) => native.text(text)?,
                    #[cfg(target_os = "linux")]
                    Native::Uinput(device) => device.text(text)?,
                }
            }
            Command::Clipboard { text, paste } => {
                self.copy(text)?;
                if *paste {
                    self.paste()?;
                }
            }
            Command::Paste {} => self.paste()?,
            Command::Key { key, state } => {
                self.key(key, *state)?;
                match state {
                    KeyState::Down => {
                        if !self.keys.contains(key) {
                            self.keys.push(key.clone());
                        }
                    }
                    KeyState::Up => self.keys.retain(|k| k != key),
                    _ => {}
                }
            }
            Command::Pointer {
                action,
                dx,
                dy,
                button,
            } => {
                self.initialize()?;
                #[cfg(target_os = "linux")]
                if let Some(Native::Uinput(device)) = &mut self.native {
                    device.pointer(*action, *dx, *dy, *button)?;
                } else if let Some(Native::Enigo(native)) = &mut self.native {
                    pointer(native, *action, *dx, *dy, *button)?;
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let Some(Native::Enigo(native)) = &mut self.native else {
                        unreachable!()
                    };
                    pointer(native, *action, *dx, *dy, *button)?;
                }
                match action {
                    PointerAction::Press => {
                        if !self.buttons.contains(button) {
                            self.buttons.push(*button);
                        }
                    }
                    PointerAction::Release => self.buttons.retain(|b| b != button),
                    _ => {}
                }
            }
            Command::ReleaseAll {} => self.release(),
        }
        Ok(())
    }
    pub fn release(&mut self) {
        for key in std::mem::take(&mut self.keys).iter().rev() {
            let _ = self.key(key, KeyState::Up);
        }
        for button in std::mem::take(&mut self.buttons) {
            #[cfg(target_os = "linux")]
            match &mut self.native {
                Some(Native::Uinput(d)) => {
                    let _ = d.pointer(PointerAction::Release, 0, 0, button);
                }
                Some(Native::Enigo(n)) => {
                    let _ = pointer(n, PointerAction::Release, 0, 0, button);
                }
                None => {}
            }
            #[cfg(not(target_os = "linux"))]
            {
                let Some(Native::Enigo(n)) = &mut self.native else {
                    continue;
                };
                let _ = pointer(n, PointerAction::Release, 0, 0, button);
            }
        }
    }
    pub fn deadman(&mut self) {
        if self.last.elapsed() > Duration::from_secs(5) {
            self.release();
        }
    }
}
impl Drop for Desktop {
    fn drop(&mut self) {
        self.release();
    }
}
fn pointer(
    native: &mut Enigo,
    action: PointerAction,
    dx: i32,
    dy: i32,
    button: Button,
) -> Result<()> {
    match action {
        PointerAction::Move => native.move_mouse(dx, dy, Coordinate::Rel)?,
        PointerAction::Scroll => {
            if dx != 0 {
                native.scroll(dx, Axis::Horizontal)?;
            }
            if dy != 0 {
                native.scroll(dy, Axis::Vertical)?;
            }
        }
        _ => native.button(
            match button {
                Button::Left => enigo::Button::Left,
                Button::Right => enigo::Button::Right,
                Button::Middle => enigo::Button::Middle,
            },
            match action {
                PointerAction::Press => Direction::Press,
                PointerAction::Release => Direction::Release,
                _ => Direction::Click,
            },
        )?,
    };
    Ok(())
}
fn key(name: &str) -> Result<Key> {
    Ok(match name {
        "plus" => Key::Unicode('+'),
        "ctrl" => Key::Control,
        "shift" => Key::Shift,
        "alt" => Key::Alt,
        "meta" => Key::Meta,
        "enter" => Key::Return,
        "escape" => Key::Escape,
        "space" => Key::Space,
        "tab" => Key::Tab,
        "backspace" => Key::Backspace,
        "delete" => Key::Delete,
        "up" => Key::UpArrow,
        "down" => Key::DownArrow,
        "left" => Key::LeftArrow,
        "right" => Key::RightArrow,
        "home" => Key::Home,
        "end" => Key::End,
        "pageup" => Key::PageUp,
        "pagedown" => Key::PageDown,
        "capslock" => Key::CapsLock,
        "f1" => Key::F1,
        "f2" => Key::F2,
        "f3" => Key::F3,
        "f4" => Key::F4,
        "f5" => Key::F5,
        "f6" => Key::F6,
        "f7" => Key::F7,
        "f8" => Key::F8,
        "f9" => Key::F9,
        "f10" => Key::F10,
        "f11" => Key::F11,
        "f12" => Key::F12,
        key if key.len() == 1 => Key::Unicode(key.chars().next().unwrap()),
        _ => anyhow::bail!("Unsupported key"),
    })
}
