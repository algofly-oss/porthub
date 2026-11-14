//! Native kernel input for Wayland, requiring an explicit local uaccess grant.
//! No daemon, external input injector, shell command, or global permissions.
use anyhow::{ensure, Result};
use porthub_components::keyboard::{Button, KeyState, PointerAction};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::fd::AsRawFd,
};
#[repr(C)]
struct Setup {
    id: [u16; 4],
    name: [u8; 80],
    effects: u32,
}
pub struct Device {
    file: File,
}
impl Device {
    pub fn new() -> Result<Self> {
        let d = Self {
            file: OpenOptions::new().write(true).open("/dev/uinput")?,
        };
        for event in [1, 2] {
            d.ioctl(0x40045564, event)?;
        }
        for key in (1..=255).chain(272..=274) {
            d.ioctl(0x40045565, key)?;
        }
        for axis in [0, 1, 6, 8] {
            d.ioctl(0x40045566, axis)?;
        }
        let mut setup = Setup {
            id: [6, 0x1209, 0x5048, 1],
            name: [0; 80],
            effects: 0,
        };
        setup.name[..16].copy_from_slice(b"PortHub keyboard");
        d.ioctl(0x405c5503, (&setup as *const Setup) as usize)?;
        d.ioctl(0x5501, 0)?;
        std::thread::sleep(std::time::Duration::from_millis(300));
        Ok(d)
    }
    fn ioctl(&self, request: libc::c_ulong, arg: usize) -> Result<()> {
        // SAFETY: fd is a live uinput descriptor, setup pointer is valid for the
        // synchronous ioctl; other requests take bounded integer constants.
        ensure!(
            unsafe { libc::ioctl(self.file.as_raw_fd(), request, arg) } >= 0,
            "Cannot configure virtual input: {}",
            std::io::Error::last_os_error()
        );
        Ok(())
    }
    fn event(&mut self, kind: u16, code: u16, value: i32) -> Result<()> {
        let mut data = vec![0u8; std::mem::size_of::<libc::timeval>()];
        data.extend_from_slice(&kind.to_ne_bytes());
        data.extend_from_slice(&code.to_ne_bytes());
        data.extend_from_slice(&value.to_ne_bytes());
        self.file.write_all(&data)?;
        Ok(())
    }
    fn sync(&mut self) -> Result<()> {
        self.event(0, 0, 0)
    }
    fn stroke(&mut self, code: u16, state: KeyState) -> Result<()> {
        match state {
            KeyState::Down => self.event(1, code, 1)?,
            KeyState::Up => self.event(1, code, 0)?,
            KeyState::Press => {
                self.event(1, code, 1)?;
                self.event(1, code, 0)?;
            }
        }
        self.sync()
    }
    pub fn key(&mut self, name: &str, state: KeyState) -> Result<()> {
        let keys = name.split('+').map(code).collect::<Result<Vec<_>>>()?;
        if keys.len() == 1 {
            return self.stroke(keys[0], state);
        }
        if state == KeyState::Up {
            for c in keys.iter().rev() {
                self.stroke(*c, KeyState::Up)?;
            }
        } else {
            for (index, c) in keys[..keys.len() - 1].iter().enumerate() {
                if let Err(error) = self.stroke(*c, KeyState::Down) {
                    for pressed in keys[..=index].iter().rev() {
                        let _ = self.stroke(*pressed, KeyState::Up);
                    }
                    return Err(error);
                }
            }
            let result = self.stroke(*keys.last().unwrap(), state);
            if state == KeyState::Press || result.is_err() {
                for c in keys[..keys.len() - 1].iter().rev() {
                    let _ = self.stroke(*c, KeyState::Up);
                }
            }
            result?;
        }
        Ok(())
    }
    pub fn text(&mut self, text: &str) -> Result<()> {
        let positions=text.chars().map(layout).collect::<Option<Vec<_>>>().ok_or_else(||anyhow::anyhow!("Wayland typing uses a US layout; use Update clipboard and paste for Unicode text"))?;
        for (code, shift) in positions {
            if shift {
                self.stroke(42, KeyState::Down)?;
            }
            let result = self.stroke(code, KeyState::Press);
            if shift {
                let _ = self.stroke(42, KeyState::Up);
            }
            result?;
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        Ok(())
    }
    pub fn pointer(
        &mut self,
        action: PointerAction,
        dx: i32,
        dy: i32,
        button: Button,
    ) -> Result<()> {
        match action {
            PointerAction::Move => {
                self.event(2, 0, dx)?;
                self.event(2, 1, dy)?;
            }
            PointerAction::Scroll => {
                self.event(2, 6, dx)?;
                self.event(2, 8, -dy)?;
            }
            _ => {
                let code = match button {
                    Button::Left => 272,
                    Button::Right => 273,
                    Button::Middle => 274,
                };
                self.stroke(
                    code,
                    match action {
                        PointerAction::Press => KeyState::Down,
                        PointerAction::Release => KeyState::Up,
                        _ => KeyState::Press,
                    },
                )?;
            }
        }
        self.sync()
    }
}
impl Drop for Device {
    fn drop(&mut self) {
        let _ = self.ioctl(0x5502, 0);
    }
}
fn layout(c: char) -> Option<(u16, bool)> {
    if let Some(code) = match c {
        ' ' => Some(57),
        '\n' => Some(28),
        '\t' => Some(15),
        _ => None,
    } {
        return Some((code, false));
    }
    for (plain, shifted, first) in [
        ("1234567890-=", "!@#$%^&*()_+", 2),
        ("qwertyuiop[]", "QWERTYUIOP{}", 16),
        ("asdfghjkl;'`", "ASDFGHJKL:\"~", 30),
        ("\\zxcvbnm,./", "|ZXCVBNM<>?", 43),
    ] {
        if let Some(i) = plain.chars().position(|x| x == c) {
            return Some((first + i as u16, false));
        }
        if let Some(i) = shifted.chars().position(|x| x == c) {
            return Some((first + i as u16, true));
        }
    }
    None
}
fn code(name: &str) -> Result<u16> {
    Ok(match name {
        "plus" => 13,
        "ctrl" => 29,
        "shift" => 42,
        "alt" => 56,
        "meta" => 125,
        "enter" => 28,
        "tab" => 15,
        "space" => 57,
        "escape" => 1,
        "backspace" => 14,
        "delete" => 111,
        "up" => 103,
        "down" => 108,
        "left" => 105,
        "right" => 106,
        "home" => 102,
        "end" => 107,
        "pageup" => 104,
        "pagedown" => 109,
        "capslock" => 58,
        "f1" => 59,
        "f2" => 60,
        "f3" => 61,
        "f4" => 62,
        "f5" => 63,
        "f6" => 64,
        "f7" => 65,
        "f8" => 66,
        "f9" => 67,
        "f10" => 68,
        "f11" => 87,
        "f12" => 88,
        key if key.len() == 1 => {
            layout(key.chars().next().unwrap())
                .ok_or_else(|| anyhow::anyhow!("Unsupported key"))?
                .0
        }
        _ => anyhow::bail!("Unsupported key"),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mapping_rejects_unrepresentable_text_before_typing() {
        assert_eq!(layout('A'), Some((30, true)));
        assert_eq!(layout('a'), Some((30, false)));
        assert_eq!(layout('अ'), None);
        assert_eq!(code("ctrl").unwrap(), 29);
    }
}
