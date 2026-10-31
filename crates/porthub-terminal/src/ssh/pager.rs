//! A read-only viewer's navigation state. Guest bytes never become shell input.
use crate::protocol::*;
use std::time::{Duration, Instant};
use unicode_width::UnicodeWidthChar;

pub(super) struct Pager {
    pub active: bool,
    cols: u16,
    rows: u16,
    before: u32,
    total: u32,
    shown: Option<u32>,
    serial: u32,
    pending: Option<(u32, Vec<u8>, Instant)>,
    last_request: Option<Instant>,
    keys: Vec<u8>,
}
impl Pager {
    pub fn new(cols: u16, rows: u16) -> Self {
        Self {
            active: false,
            cols,
            rows,
            before: 0,
            total: 0,
            shown: None,
            serial: 0,
            pending: None,
            last_request: None,
            keys: Vec::new(),
        }
    }
    pub fn resize(&mut self, cols: u16, rows: u16) {
        self.cols = cols;
        self.rows = rows;
        if self.active {
            self.shown = None;
        }
    }
    /// True requests a redraw after leaving this viewer's independent history.
    pub fn feed(&mut self, bytes: &[u8]) -> bool {
        let mut redraw = false;
        for &byte in bytes {
            if self.keys.is_empty() {
                if byte == 0x1b {
                    self.keys.push(byte);
                } else if self.active && byte == b'q' {
                    self.active = false;
                    self.pending = None;
                    redraw = true;
                }
                continue;
            }
            self.keys.push(byte);
            let key = self.keys.as_slice();
            if key == b"\x1b[18~" {
                self.active = !self.active;
                self.before = 0;
                self.shown = None;
                self.pending = None;
                redraw |= !self.active;
                self.keys.clear();
                continue;
            }
            if matches!(key, b"\x1b[H" | b"\x1b[1~" | b"\x1b[F" | b"\x1b[4~") {
                if self.active {
                    self.before = if matches!(key, b"\x1b[H" | b"\x1b[1~") {
                        if self.total == 0 {
                            200000
                        } else {
                            self.total.saturating_sub(u32::from(self.page_lines()))
                        }
                    } else {
                        0
                    };
                }
                self.keys.clear();
                continue;
            }
            if matches!(key, b"\x1b[5~" | b"\x1b[A") {
                if self.active {
                    let step = if key == b"\x1b[A" {
                        1
                    } else {
                        u32::from(self.page_lines())
                    };
                    self.before = self.before.saturating_add(step).min(200000);
                }
                self.keys.clear();
                continue;
            }
            if matches!(key, b"\x1b[6~" | b"\x1b[B") {
                if self.active {
                    let step = if key == b"\x1b[B" {
                        1
                    } else {
                        u32::from(self.page_lines())
                    };
                    self.before = self.before.saturating_sub(step);
                }
                self.keys.clear();
                continue;
            }
            if self.keys.starts_with(b"\x1b[<") && matches!(byte, b'M' | b'm') {
                if self.active {
                    let button = std::str::from_utf8(&self.keys[3..self.keys.len() - 1])
                        .ok()
                        .and_then(|text| text.split(';').next())
                        .and_then(|value| value.parse::<u16>().ok());
                    match button {
                        Some(64) => self.before = self.before.saturating_add(3).min(200000),
                        Some(65) => self.before = self.before.saturating_sub(3),
                        _ => {}
                    }
                }
                self.keys.clear();
                continue;
            }
            let known = [
                b"\x1b[18~".as_slice(),
                b"\x1b[5~",
                b"\x1b[6~",
                b"\x1b[A",
                b"\x1b[B",
                b"\x1b[H",
                b"\x1b[1~",
                b"\x1b[F",
                b"\x1b[4~",
            ]
            .iter()
            .any(|known| known.starts_with(&self.keys));
            if self.keys.len() >= 64 || !known && !self.keys.starts_with(b"\x1b[<") {
                self.keys.clear();
            }
        }
        redraw
    }
    fn page_lines(&self) -> u16 {
        self.rows.saturating_sub(3).clamp(1, 197)
    }
    pub fn request(&mut self) -> Option<ViewerInput> {
        if !self.active {
            return None;
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|(_, _, at)| at.elapsed() > Duration::from_secs(3))
        {
            self.pending = None;
        }
        if self.pending.is_some()
            || self.shown == Some(self.before)
            || self
                .last_request
                .is_some_and(|at| at.elapsed() < Duration::from_millis(500))
        {
            return None;
        }
        self.serial = self.serial.wrapping_add(1);
        self.pending = Some((self.serial, Vec::new(), Instant::now()));
        self.last_request = Some(Instant::now());
        Some(ViewerInput::History {
            request: self.serial,
            pane: String::new(),
            before: self.before,
            lines: self.page_lines(),
        })
    }
    pub fn page(&mut self, page: HistoryChunk) -> anyhow::Result<Option<Vec<u8>>> {
        page.validate()?;
        if !self.active {
            return Ok(None);
        }
        let Some((request, bytes, _)) = &mut self.pending else {
            return Ok(None);
        };
        if *request != page.request {
            return Ok(None);
        }
        let chunk = decode_data(&page.data)?;
        anyhow::ensure!(
            bytes.len() + chunk.len() <= 131072,
            "history response exceeds limit"
        );
        bytes.extend(chunk);
        if !page.done {
            return Ok(None);
        }
        let (_, bytes, _) = self.pending.take().expect("pending history");
        self.total = page.total;
        self.shown = Some(page.before);
        if page.before >= page.total && page.total > 0 {
            self.before = page.total.saturating_sub(u32::from(self.page_lines()));
            self.shown = None;
        }
        let text = String::from_utf8_lossy(&bytes);
        let mut screen = String::from("\x1b[?25l\x1b[2J\x1b[H");
        screen.push_str(&clip(
            &format!(
                "Scrollback · {} lines back / {} retained",
                page.before, page.total
            ),
            self.cols,
        ));
        screen.push_str("\r\n");
        if let Some(error) = page.error.as_deref() {
            screen.push_str(&clip(error, self.cols));
            self.shown = None;
        } else if bytes.is_empty() {
            screen.push_str("No retained scrollback yet.");
        } else {
            for line in text.lines().take(usize::from(self.page_lines())) {
                screen.push_str(&clip(line, self.cols));
                screen.push_str("\x1b[K\r\n");
            }
        }
        screen.push_str(&format!(
            "\x1b[{};1H\x1b[7m{}\x1b[0m",
            self.rows,
            clip(
                "F7 or q live · Wheel/PgUp/PgDn · Home/End · terminal selection",
                self.cols
            )
        ));
        Ok(Some(screen.into_bytes()))
    }
}
fn clip(text: &str, cols: u16) -> String {
    let mut width = 0;
    let mut output = String::new();
    for ch in text.chars().filter(|ch| !ch.is_control()) {
        let size = ch.width().unwrap_or(0);
        if width + size > usize::from(cols.saturating_sub(1)) {
            break;
        }
        width += size;
        output.push(ch);
    }
    output
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fragmented_keys_mouse_and_plain_input_never_become_shell_commands() {
        let mut pager = Pager::new(80, 24);
        assert!(!pager.feed(b"exit\r"));
        assert!(pager.request().is_none());
        assert!(!pager.feed(b"\x1b[1"));
        assert!(!pager.active);
        assert!(!pager.feed(b"8~"));
        assert!(pager.active);
        assert!(matches!(
            pager.request(),
            Some(ViewerInput::History {
                before: 0,
                lines: 21,
                ..
            })
        ));
        pager.feed(b"\x1b[5~");
        assert_eq!(pager.before, 21);
        pager.feed(b"\x1b[<64;10;10M");
        assert_eq!(pager.before, 24);
        pager.feed(b"\x1b[A");
        assert_eq!(pager.before, 25);
        pager.feed(b"\x1b[B");
        assert_eq!(pager.before, 24);
        pager.total = 100;
        pager.feed(b"\x1b[H");
        assert_eq!(pager.before, 79);
        pager.feed(b"\x1b[F");
        assert_eq!(pager.before, 0);
        assert!(pager.feed(b"q"));
        assert!(!pager.active);
        assert!(pager.request().is_none());
        assert_eq!(clip("a界b\x1b", 4), "a界");
    }
}
