//! An owner view is an attachment to private control, never a new shell.
use super::{
    participant_control::{fetch, Snapshot},
    Job,
};
use crate::terminal_ui::{InputReader, Screen};
use anyhow::{ensure, Result};
use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers};
use std::{
    io::{IsTerminal, Write},
    time::{Duration, Instant},
};
use tokio_util::task::AbortOnDropHandle;

fn render(
    job: &Job,
    snapshot: &Snapshot,
    selected: usize,
    confirm: Option<u64>,
    message: &str,
    width: usize,
    height: usize,
) -> String {
    let mut lines = vec![
        format!("Participants · {}", job.name),
        format!(
            "{} · {} guest(s)",
            if snapshot.connected {
                "Connected"
            } else {
                "Reconnecting"
            },
            snapshot.members.len()
        ),
        "↑/↓ select · k remove · q close view".into(),
        String::new(),
    ];
    let visible = height.saturating_sub(8).max(1);
    let offset = selected.saturating_sub(visible.saturating_sub(1));
    for (index, member) in snapshot
        .members
        .iter()
        .enumerate()
        .skip(offset)
        .take(visible)
    {
        let age = porthub_terminal::protocol::now()
            .saturating_sub(member.last_active_at)
            .max(0);
        let text = format!(
            "{} {} {} {}s",
            if index == selected { ">" } else { " " },
            member.id,
            if member.read_only { "read" } else { "write" },
            age
        );
        lines.push(text);
    }
    if snapshot.members.is_empty() {
        lines.push("No guests attached.".into());
    }
    if let Some(id) = confirm {
        lines.push(format!("Remove {id}? y / n"));
    } else {
        lines.push("Removing a guest leaves the shell running.".into());
    }
    lines.push(message.into());
    lines
        .into_iter()
        .take(height.saturating_sub(1).max(1))
        .map(|line| {
            line.chars()
                .filter(|c| !c.is_control())
                .take(width.saturating_sub(1).max(1))
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}
pub(super) async fn run(job: Job) -> Result<()> {
    ensure!(
        std::io::stdin().is_terminal() && std::io::stdout().is_terminal(),
        "--watch needs an interactive terminal; use --json for scripts"
    );
    let _screen = Screen::enter()?;
    let (_reader, mut events) = InputReader::start();
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut snapshot = Snapshot::default();
    let mut selected = 0usize;
    let mut confirm = None;
    let mut message = String::new();
    let mut pending: Option<AbortOnDropHandle<Result<Snapshot>>> = None;
    let mut removal: Option<(u64, Instant)> = None;
    loop {
        let selected_id = snapshot.members.get(selected).map(|member| member.id);
        tokio::select! {
            _=interval.tick()=>{
                if pending.is_none(){let job=job.clone();pending=Some(AbortOnDropHandle::new(tokio::spawn(async move{fetch(&job,None).await})));}
            }
            result=async{match &mut pending{Some(task)=>task.await,None=>std::future::pending().await}}=>{
                pending=None;
                match result {
                    Ok(Ok(next))=>{
                        snapshot=next;
                        if let Some(id)=selected_id {if let Some(index)=snapshot.members.iter().position(|member|member.id==id){selected=index;}}
                        selected=selected.min(snapshot.members.len().saturating_sub(1));
                        if let Some((id,started))=removal {
                            if !snapshot.members.iter().any(|member|member.id==id){message="Guest removed; other attachments are unchanged.".into();removal=None;}
                            else if started.elapsed()>Duration::from_secs(5){message="Removal not confirmed; check gateway before retrying.".into();removal=None;}
                        }else{message.clear();}
                    }
                    Ok(Err(_))|Err(_)=>{snapshot.connected=false;message="Owner control unavailable; retrying. q closes this view.".into();}
                }
            }
            event=events.recv()=>{
                match event {
                    Some(Ok(Event::Key(key))) if key.kind!=KeyEventKind::Release => match key.code {
                        KeyCode::Char('q')=>break,
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL)=>break,
                        KeyCode::Esc=>{if confirm.take().is_none(){break;}},
                        KeyCode::Up=>{selected=selected.saturating_sub(1);confirm=None;},
                        KeyCode::Down=>{selected=(selected+1).min(snapshot.members.len().saturating_sub(1));confirm=None;},
                        KeyCode::Char('k')|KeyCode::Delete if snapshot.connected && removal.is_none()=>{confirm=snapshot.members.get(selected).map(|member|member.id);},
                        KeyCode::Char('n')=>{confirm=None;},
                        KeyCode::Char('y')=>{if let Some(id)=confirm.take(){
                            let job=job.clone();pending=Some(AbortOnDropHandle::new(tokio::spawn(async move{fetch(&job,Some(id)).await})));
                            removal=Some((id,Instant::now()));message="Removal requested; waiting for participant update.".into();
                        }},
                        _=>{},
                    },
                    Some(Err(error))=>return Err(error.into()),None=>break,_=>{},
                }
            }
        }
        let (width, height) = crossterm::terminal::size()?;
        crossterm::execute!(
            std::io::stdout(),
            crossterm::cursor::MoveTo(0, 0),
            crossterm::terminal::Clear(crossterm::terminal::ClearType::All),
            crossterm::style::Print(render(
                &job,
                &snapshot,
                selected,
                confirm,
                &message,
                usize::from(width),
                usize::from(height)
            ))
        )?;
        std::io::stdout().flush()?;
    }
    Ok(())
}
