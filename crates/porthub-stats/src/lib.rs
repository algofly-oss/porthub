//! Independent live dashboard. Collection adapters carry no agent credentials.
use anyhow::{ensure, Result};
use porthub_console::{InputReader, Screen};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::{IsTerminal, Write},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
#[derive(Clone)]
pub struct Options {
    pub manage_terminal: bool,
    pub once: bool,
    pub json: bool,
    pub interval: f64,
}
#[async_trait::async_trait]
pub trait Source: Send + Sync + 'static {
    async fn collect(&self) -> Result<Vec<Value>>;
}
fn number(row: &Value, key: &str) -> u64 {
    row[key].as_u64().unwrap_or(0)
}
fn bytes(value: f64) -> String {
    let mut value = value;
    let units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < units.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", units[unit])
}
fn clean(value: &str, limit: usize) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(limit)
        .collect()
}

fn render(
    rows: &[Value],
    width: usize,
    height: usize,
    paused: bool,
    selected: usize,
    details: bool,
) -> String {
    let mut lines = vec![
        format!("PortHub stats  {}", if paused { "PAUSED" } else { "LIVE" }),
        "".into(),
    ];
    let upload: f64 = rows
        .iter()
        .filter_map(|row| row["rates"]["sent_per_second"].as_f64())
        .sum();
    let download: f64 = rows
        .iter()
        .filter_map(|row| row["rates"]["received_per_second"].as_f64())
        .sum();
    let memory: u64 = rows
        .iter()
        .map(|row| number(&row["process"], "rss_bytes"))
        .sum();
    lines.push(format!(
        "{} agents   TX {}/s   RX {}/s   RAM {}",
        rows.len(),
        if rows.iter().any(|row| row["rates"].is_object()) {
            bytes(upload)
        } else {
            "—".into()
        },
        if rows.iter().any(|row| row["rates"].is_object()) {
            bytes(download)
        } else {
            "—".into()
        },
        if rows.iter().any(|row| row["process"].is_object()) {
            bytes(memory as f64)
        } else {
            "—".into()
        }
    ));
    lines.push("Public application payload; process resources belong to the agent only.".into());
    lines.push("".into());
    lines.push(format!(
        "  {:<16} {:<11} {:>7} {:>10} {:>10} {:>10}",
        "REGISTRATION", "STATE", "CPU %", "TX /s", "RX /s", "RSS"
    ));
    let terminal_details = details
        && rows
            .get(selected)
            .is_some_and(|row| row["terminal"]["measurements"].is_object());
    let visible = height
        .saturating_sub(if details {
            18 + if terminal_details { 4 } else { 0 }
        } else {
            9
        })
        .max(1);
    for (index, row) in rows
        .iter()
        .enumerate()
        .skip(selected.saturating_sub(visible - 1))
        .take(visible)
    {
        let id = clean(row["registration"].as_str().unwrap_or(""), 16);
        let state = if row["unavailable"] == true {
            "unavailable"
        } else {
            row["state"].as_str().unwrap_or("unknown")
        };
        let rate = |key: &str| {
            row["rates"][key]
                .as_f64()
                .map(bytes)
                .unwrap_or_else(|| "—".into())
        };
        let cpu = row["rates"]["cpu_percent"]
            .as_f64()
            .map(|cpu| format!("{cpu:.1}"))
            .unwrap_or_else(|| "—".into());
        lines.push(format!(
            "{} {:<16} {:<11} {:>7} {:>10} {:>10} {:>10}",
            if index == selected { ">" } else { " " },
            id,
            clean(state, 11),
            cpu,
            rate("sent_per_second"),
            rate("received_per_second"),
            row["process"]["rss_bytes"]
                .as_u64()
                .map(|rss| bytes(rss as f64))
                .unwrap_or_else(|| "—".into())
        ));
    }
    if rows.is_empty() {
        lines.push(
            "No registered agents. Use porthub ls, or --user for per-user registrations.".into(),
        );
    }
    if details {
        if let Some(row) = rows.get(selected) {
            lines.push("".into());
            lines.push(format!(
                "Selected agent: {}",
                clean(row["machine_id"].as_str().unwrap_or(""), 40)
            ));
            lines.push(format!(
                "PID {}   Uptime {}s   Version {}   Route {}",
                row["process"]["pid"],
                number(&row["process"], "uptime_seconds"),
                clean(row["agent_version"].as_str().unwrap_or(""), 24),
                clean(row["route"].as_str().unwrap_or(""), 30)
            ));
            lines.push(format!(
                "Channels {}   TX total {}   RX total {}   FDs {}",
                number(&row["traffic"], "active_channels"),
                bytes(number(&row["traffic"], "sent_bytes") as f64),
                bytes(number(&row["traffic"], "received_bytes") as f64),
                row["open_descriptors"]
            ));
            if terminal_details {
                let terminal = &row["terminal"]["measurements"];
                let totals = &terminal["counters"];
                lines.push(format!(
                    "Terminals {} sessions  {} guests  {} measured sessions",
                    number(terminal, "active_sessions"),
                    number(terminal, "active_participants"),
                    number(terminal, "active_reporting_sessions")
                ));
                lines.push(format!(
                    "Gateway payload in/out {} / {}",
                    bytes(number(terminal, "relay_received_payload_bytes") as f64),
                    bytes(number(terminal, "relay_sent_payload_bytes") as f64)
                ));
                if number(terminal, "reported_sessions") > 0 {
                    lines.push(format!(
                        "PTY bytes in/out {} / {} (includes redraws)",
                        bytes(number(totals, "input_bytes") as f64),
                        bytes(number(totals, "output_bytes") as f64)
                    ));
                    lines.push(format!(
                        "Direct UDP in/out {} / {}",
                        bytes(number(totals, "direct_udp_received_bytes") as f64),
                        bytes(number(totals, "direct_udp_sent_bytes") as f64)
                    ));
                } else {
                    lines.push("PTY bytes: not reported by session hosts".into());
                    lines.push("Direct UDP: not reported by session hosts".into());
                }
            }
            if let Some(services) = row["services"].as_array() {
                for service in services.iter().take(4) {
                    lines.push(format!(
                        "  {}  {}  {} active",
                        clean(service["name"].as_str().unwrap_or(""), 32),
                        service["health"]["state"].as_str().unwrap_or("unknown"),
                        number(&service["traffic"], "active_channels")
                    ));
                }
            }
        }
    }
    lines.push("".into());
    lines.push(
        "q quit | Space pause | ↑/↓ select | Enter details | t traffic | c CPU | m memory | n name"
            .into(),
    );
    lines
        .into_iter()
        .take(height)
        .map(|line| clean(&line, width))
        .collect::<Vec<_>>()
        .join("\r\n")
}

fn update_rates(
    rows: &mut [Value],
    previous: &mut BTreeMap<String, (Instant, Value)>,
    now: Instant,
) {
    for row in rows.iter_mut() {
        let id = row["registration"].as_str().unwrap_or("").to_owned();
        let rates=previous.get(&id).and_then(|(at,old)|{
                            if row["unavailable"]==true || old["unavailable"]==true || row["process"]["pid"]!=old["process"]["pid"] || row["process"]["start_time"]!=old["process"]["start_time"]{return None;}
                            let elapsed=now.duration_since(*at).as_secs_f64().max(0.001);
                            Some(json!({"sent_per_second":number(&row["traffic"],"sent_bytes").saturating_sub(number(&old["traffic"],"sent_bytes")) as f64/elapsed,
                                "received_per_second":number(&row["traffic"],"received_bytes").saturating_sub(number(&old["traffic"],"received_bytes")) as f64/elapsed,
                                "cpu_percent":number(&row["process"],"cpu_millis").saturating_sub(number(&old["process"],"cpu_millis")) as f64/(elapsed*10.0)}))
                        });
        previous.insert(id, (now, row.clone()));
        row["rates"] = rates.unwrap_or(Value::Null);
    }
    previous.retain(|id, _| {
        rows.iter()
            .any(|row| row["registration"].as_str() == Some(id.as_str()))
    });
}

pub async fn run(
    options: Options,
    source: Arc<dyn Source>,
    cancel: CancellationToken,
) -> Result<()> {
    ensure!(
        options.interval.is_finite() && (0.2..=60.0).contains(&options.interval),
        "interval must be between 0.2 and 60 seconds"
    );
    use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers};
    let interactive = !options.json
        && !options.once
        && std::io::stdin().is_terminal()
        && std::io::stdout().is_terminal();
    let _screen = if interactive && options.manage_terminal {
        Some(Screen::enter()?)
    } else {
        None
    };
    let (_input_reader, mut events) = if interactive {
        let (reader, receive) = InputReader::start();
        (Some(reader), Some(receive))
    } else {
        (None, None)
    };
    let mut previous: BTreeMap<String, (Instant, Value)> = BTreeMap::new();
    let mut tick = tokio::time::interval(Duration::from_secs_f64(options.interval));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut rows = Vec::new();
    let mut paused = false;
    let mut selected = 0usize;
    let mut details = true;
    let mut sort = 't';
    let mut pending: Option<tokio_util::task::AbortOnDropHandle<Result<Vec<Value>>>> = None;
    loop {
        let mut preserve = rows
            .get(selected)
            .and_then(|row: &Value| row["registration"].as_str())
            .map(str::to_owned);
        tokio::select! {
            _=cancel.cancelled()=>break,
            _=tick.tick()=>{
                if !paused && pending.is_none() {
                    let source=source.clone();
                    pending=Some(tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move{source.collect().await})));
                }
            }
            result=async{match &mut pending{Some(task)=>task.await,None=>std::future::pending().await}}=>{
                rows=result??;pending=None;
                update_rates(&mut rows,&mut previous,Instant::now());
                if options.json {println!("{}",json!({"agents":rows,"observed_at":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()}));}
                else if !interactive {println!("{}",render(&rows,160,200,false,0,true).replace('\r',""));}
                if options.once || !interactive && !options.json{break;}
            }
            event=async{match &mut events{Some(events)=>events.recv().await,None=>std::future::pending().await}}=>{
                match event {
                    Some(Ok(Event::Key(key))) if key.kind!=KeyEventKind::Release=>match key.code{
                        KeyCode::Char('q')|KeyCode::Esc=>break,
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL)=>break,
                        KeyCode::Char(' ')=>{paused=!paused;if paused{pending=None;}},
                        KeyCode::Up=>{selected=selected.saturating_sub(1);preserve=None;},KeyCode::Down=>{selected=(selected+1).min(rows.len().saturating_sub(1));preserve=None;},
                        KeyCode::Enter=>details=!details,
                        KeyCode::Char(key @ ('t'|'c'|'m'|'n'))=>sort=key,
                        _=>{},
                    },Some(Err(error))=>return Err(error.into()),_=>{},
                }
            }
        }
        if interactive {
            rows.sort_by(|a, b| {
                let metric = |row: &Value| match sort {
                    'c' => row["rates"]["cpu_percent"].as_f64().unwrap_or(0.0),
                    'm' => number(&row["process"], "rss_bytes") as f64,
                    _ => {
                        row["rates"]["sent_per_second"].as_f64().unwrap_or(0.0)
                            + row["rates"]["received_per_second"].as_f64().unwrap_or(0.0)
                    }
                };
                if sort == 'n' {
                    a["registration"].as_str().cmp(&b["registration"].as_str())
                } else {
                    metric(b)
                        .total_cmp(&metric(a))
                        .then_with(|| a["registration"].as_str().cmp(&b["registration"].as_str()))
                }
            });
            if let Some(id) = preserve {
                if let Some(index) = rows
                    .iter()
                    .position(|row| row["registration"].as_str() == Some(id.as_str()))
                {
                    selected = index;
                }
            }
            selected = selected.min(rows.len().saturating_sub(1));
            let (width, height) = crossterm::terminal::size()?;
            crossterm::execute!(
                std::io::stdout(),
                crossterm::cursor::MoveTo(0, 0),
                crossterm::terminal::Clear(crossterm::terminal::ClearType::All),
                crossterm::style::Print(render(
                    &rows,
                    usize::from(width),
                    usize::from(height),
                    paused,
                    selected,
                    details
                ))
            )?;
            std::io::stdout().flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rates_warm_up_and_reset_on_agent_restart_instead_of_spiking() {
        let first = json!({"registration":"fixture","process":{"pid":12,"start_time":10,"cpu_millis":100},"traffic":{"sent_bytes":100,"received_bytes":200}});
        let second = json!({"registration":"fixture","process":{"pid":12,"start_time":10,"cpu_millis":600},"traffic":{"sent_bytes":1100,"received_bytes":2200}});
        let mut previous = BTreeMap::new();
        let at = Instant::now();
        let mut rows = vec![first];
        update_rates(&mut rows, &mut previous, at);
        assert!(rows[0]["rates"].is_null());
        let mut rows = vec![second];
        update_rates(&mut rows, &mut previous, at + Duration::from_secs(1));
        assert_eq!(rows[0]["rates"]["sent_per_second"], 1000.0);
        assert_eq!(rows[0]["rates"]["received_per_second"], 2000.0);
        assert_eq!(rows[0]["rates"]["cpu_percent"], 50.0);
        rows[0]["process"]["start_time"] = json!(20);
        update_rates(&mut rows, &mut previous, at + Duration::from_secs(2));
        assert!(
            rows[0]["rates"].is_null(),
            "PID reuse must begin a fresh rate baseline"
        );
    }
    #[test]
    fn screen_fits_normal_ssh_terminal_and_scrolls_selected_registration_into_view() {
        let rows=(0..12).map(|index|json!({"registration":format!("agent{index:02}"),"state":"running","process":{"rss_bytes":1048576}})).collect::<Vec<_>>();
        let output = render(&rows, 80, 24, false, 11, true);
        assert!(output.contains("> agent11"));
        assert!(output.contains("RSS"));
        assert!(output.lines().all(|line| line.chars().count() <= 80));
        assert!(output.lines().count() <= 24);
        assert_eq!(clean("safe\u{1b}[31m\nname", 30), "safe[31mname");
        let mut measured = rows;
        measured[11]["terminal"] = json!({"measurements":{"active_sessions":2,"active_participants":4,"active_reporting_sessions":1,"reported_sessions":1,"counters":{"input_bytes":7,"output_bytes":11,"direct_udp_sent_bytes":13,"direct_udp_received_bytes":17}}});
        let output = render(&measured, 80, 24, false, 11, true);
        assert!(output.contains("Terminals 2 sessions"));
        assert!(output.contains("Gateway payload in/out"));
        assert!(output.contains("Direct UDP in/out"));
        assert!(output.contains("q quit"));
        assert!(
            output.lines().all(|line| line.chars().count() <= 80) && output.lines().count() <= 24
        );
    }
}
