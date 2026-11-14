//! Bounded desktop input commands, shared by the Rust API and desktop module.
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

pub const MAX_TEXT: usize = 8192;
pub const MAX_FRAME: usize = 32768;
pub const CHANNEL: &str = "porthub-keyboard/1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Text {
        text: String,
    },
    Clipboard {
        text: String,
        #[serde(default)]
        paste: bool,
    },
    Paste {},
    Key {
        key: String,
        #[serde(default)]
        state: KeyState,
    },
    Pointer {
        action: PointerAction,
        #[serde(default)]
        dx: i32,
        #[serde(default)]
        dy: i32,
        #[serde(default)]
        button: Button,
    },
    ReleaseAll {},
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyState {
    #[default]
    Press,
    Down,
    Up,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PointerAction {
    Move,
    Scroll,
    Click,
    Press,
    Release,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Button {
    #[default]
    Left,
    Right,
    Middle,
}

pub fn valid_key(key: &str) -> bool {
    if key.is_empty() || key.len() > 64 {
        return false;
    }
    let parts: Vec<_> = key.split('+').collect();
    if parts.len() > 5
        || !parts[..parts.len() - 1]
            .iter()
            .all(|k| matches!(*k, "ctrl" | "alt" | "shift" | "meta"))
    {
        return false;
    }
    let key = parts[parts.len() - 1];
    key.len() == 1 && key.bytes().all(|c| c.is_ascii_graphic() && c != b'+')
        || matches!(
            key,
            "ctrl"
                | "alt"
                | "shift"
                | "meta"
                | "backspace"
                | "delete"
                | "enter"
                | "tab"
                | "space"
                | "escape"
                | "up"
                | "down"
                | "left"
                | "right"
                | "home"
                | "end"
                | "pageup"
                | "pagedown"
                | "plus"
                | "capslock"
                | "f1"
                | "f2"
                | "f3"
                | "f4"
                | "f5"
                | "f6"
                | "f7"
                | "f8"
                | "f9"
                | "f10"
                | "f11"
                | "f12"
        )
}
impl Command {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Text { text } | Self::Clipboard { text, .. } => ensure!(
                text.len() <= MAX_TEXT && !text.contains('\0'),
                "Text exceeds 8 KiB or contains a NUL"
            ),
            Self::Key { key, .. } => ensure!(valid_key(key), "Unsupported key or shortcut"),
            Self::Pointer { action, dx, dy, .. } => {
                let limit = if *action == PointerAction::Scroll {
                    100
                } else {
                    4000
                };
                ensure!(
                    dx.unsigned_abs() <= limit && dy.unsigned_abs() <= limit,
                    "Pointer movement exceeds limit"
                );
            }
            _ => {}
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub id: String,
    pub command: Command,
}
impl Input {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.id.len() == 36 && self.id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'),
            "Invalid input identity"
        );
        self.command.validate()
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ack {
    pub id: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unbounded_and_untyped_input() {
        assert!(Command::Text {
            text: "a".repeat(MAX_TEXT + 1)
        }
        .validate()
        .is_err());
        for key in ["ctrl+v", "meta+shift+left", "f12", "a"] {
            assert!(valid_key(key));
        }
        for key in ["", "ctrl+", "ctrl+--window", "ctrl+v;sh", "a+b", "f99"] {
            assert!(!valid_key(key));
        }
        assert!(serde_json::from_str::<Command>(r#"{"type":"paste","shell":"sh"}"#).is_err());
        assert!(Command::Pointer {
            action: PointerAction::Move,
            dx: i32::MIN,
            dy: 0,
            button: Button::Left
        }
        .validate()
        .is_err());
    }
}
