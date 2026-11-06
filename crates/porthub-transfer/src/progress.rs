//! Compact transfer progress; no terminal dependency and no control sequences
//! in redirected output. Resumed bytes never inflate measured throughput.
use std::{
    io::{IsTerminal, Write},
    time::{Duration, Instant},
};
pub fn bytes(value: u64) -> String {
    const UNITS: [&str; 7] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    let mut number = value as f64;
    let mut unit = 0;
    while number >= 1024.0 && unit + 1 < UNITS.len() {
        number /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value} B")
    } else {
        format!("{number:.1} {}", UNITS[unit])
    }
}
pub fn duration(seconds: u64) -> String {
    if seconds >= 86400 {
        format!("{}d {:02}h", seconds / 86400, seconds % 86400 / 3600)
    } else if seconds >= 3600 {
        format!(
            "{}:{:02}:{:02}",
            seconds / 3600,
            seconds % 3600 / 60,
            seconds % 60
        )
    } else {
        format!("{:02}:{:02}", seconds / 60, seconds % 60)
    }
}
pub fn line(done: u64, total: Option<u64>, speed: f64) -> String {
    let speed = if speed.is_finite() && speed > 0.0 {
        speed
    } else {
        0.0
    };
    let rate = if speed > 0.0 {
        format!("{}/s", bytes(speed.min(u64::MAX as f64) as u64))
    } else {
        "0 B/s".into()
    };
    match total {
        Some(total) => {
            let left = total.saturating_sub(done);
            let percent = if total == 0 {
                100.0
            } else {
                (done as f64 / total as f64 * 100.0).min(100.0)
            };
            let eta = if left == 0 {
                "00:00".into()
            } else if speed > 0.0 {
                duration((left as f64 / speed).ceil().min(u64::MAX as f64) as u64)
            } else {
                "--:--".into()
            };
            format!(
                "{percent:5.1}%  {}/{}  {rate}  Left {}  ETA {eta}",
                bytes(done),
                bytes(total),
                bytes(left)
            )
        }
        None => format!(
            "{} downloaded  {rate}  Size unknown  ETA --:--",
            bytes(done)
        ),
    }
}
pub struct Reporter {
    enabled: bool,
    terminal: bool,
    start: Instant,
    last_sample: Instant,
    last_bytes: u64,
    speed: f64,
    last_output: Option<Instant>,
    width: usize,
    open: bool,
}
impl Reporter {
    pub fn new(enabled: bool, resumed: u64) -> Self {
        let now = Instant::now();
        Self {
            enabled,
            terminal: std::io::stderr().is_terminal()
                && std::env::var("TERM").as_deref() != Ok("dumb"),
            start: now,
            last_sample: now,
            last_bytes: resumed,
            speed: 0.0,
            last_output: None,
            width: 0,
            open: false,
        }
    }
    pub fn update(&mut self, done: u64, total: Option<u64>) {
        if !self.enabled {
            return;
        }
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_sample).as_secs_f64();
        if elapsed >= 0.1 {
            let instant = done.saturating_sub(self.last_bytes) as f64 / elapsed;
            self.speed = if self.speed == 0.0 {
                instant
            } else {
                0.3 * instant + 0.7 * self.speed
            };
            self.last_sample = now;
            self.last_bytes = done;
        }
        if !self.terminal
            && self
                .last_output
                .is_some_and(|at| now.duration_since(at) < Duration::from_secs(5))
        {
            return;
        }
        self.draw(&line(done, total, self.speed));
        self.last_output = Some(now);
    }
    fn draw(&mut self, text: &str) {
        let mut output = std::io::stderr().lock();
        if self.terminal {
            let padding = " ".repeat(self.width.saturating_sub(text.len()));
            let _ = write!(output, "\r{text}{padding}");
            let _ = output.flush();
            self.width = text.len();
            self.open = true;
        } else {
            let _ = writeln!(output, "[porthub-get] {text}");
        }
    }
    pub fn finish(&mut self, done: u64, total: Option<u64>, resumed: u64) {
        if !self.enabled {
            return;
        }
        let average =
            done.saturating_sub(resumed) as f64 / self.start.elapsed().as_secs_f64().max(0.001);
        self.draw(&line(done, total, average));
        self.end_line();
    }
    fn end_line(&mut self) {
        if self.open {
            let _ = writeln!(std::io::stderr());
            self.open = false;
        }
    }
}
impl Drop for Reporter {
    fn drop(&mut self) {
        self.end_line();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reports_size_rate_remaining_and_eta_in_human_units() {
        let output = line(
            64 * 1024 * 1024,
            Some(128 * 1024 * 1024),
            8.0 * 1024.0 * 1024.0,
        );
        for value in [
            "50.0%",
            "64.0 MiB/128.0 MiB",
            "8.0 MiB/s",
            "Left 64.0 MiB",
            "ETA 00:08",
        ] {
            assert!(output.contains(value), "{output}");
        }
        assert_eq!(duration(3661), "1:01:01");
        assert_eq!(duration(90000), "1d 01h");
    }
    #[test]
    fn unknown_size_and_stalls_never_invent_an_eta_or_emit_nonfinite_values() {
        assert!(line(1024, None, 0.0).contains("Size unknown  ETA --:--"));
        for speed in [0.0, f64::NAN, f64::INFINITY, -1.0] {
            let output = line(1024, Some(2048), speed);
            assert!(output.contains("0 B/s"));
            assert!(output.contains("ETA --:--"));
        }
        assert!(line(0, Some(0), 0.0).contains("100.0%"));
        assert!(line(2048, Some(1024), 1.0).contains("Left 0 B  ETA 00:00"));
    }
}
