//! Native TTY relay path, also used when a direct transport is unavailable.
//! This runner owns no shell. Its return or cancellation drops only the guest.
use super::{tty::Terminal, Guest};
use anyhow::{bail, Context, Result};
use porthub_terminal::{protocol::*, viewer_history::Pager};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

pub struct End {
    pub reason: String,
    pub retryable: bool,
}
/// One attachment only. Recovery is the caller's decision, using a fresh
/// delivery state; arbitrary buffered shell input must not cross attachments.
pub async fn run<S: AsyncRead + AsyncWrite + Unpin>(
    guest: &mut Guest<S>,
    terminal: &Terminal,
    welcome: &ViewerEvent,
) -> Result<End> {
    let ViewerEvent::Welcome {
        history_snapshots,
        read_only,
        ..
    } = welcome
    else {
        bail!("native terminal requires an authenticated welcome");
    };
    anyhow::ensure!(*read_only == guest.read_only(), "terminal role mismatch");
    let mut size = terminal.size()?;
    guest
        .send(&ViewerInput::Resize {
            cols: size.0,
            rows: size.1,
        })
        .await?;
    let mut pager = Pager::new(size.0, size.1);
    pager.capabilities(*history_snapshots);
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut input = [0; 16384];
    loop {
        tokio::select! {
            count=terminal.read(&mut input)=>{
                let count=count.context("native terminal input failed")?;
                if count==0 {return Ok(End {reason:"local terminal closed".into(),retryable:false});}
                if *read_only {
                    if pager.feed(&input[..count]) {guest.send(&ViewerInput::Redraw).await?;}
                } else {
                    guest.send(&ViewerInput::Input {data:encode_data(&input[..count])}).await?;
                }
            },
            _=tick.tick()=>{
                let next=terminal.size()?;
                if size!=next {
                    size=next;
                    pager.resize(size.0,size.1);
                    guest.send(&ViewerInput::Resize {cols:size.0,rows:size.1}).await?;
                }
                if *read_only {
                    if let Some(request)=pager.request() {guest.send(&request).await?;}
                }
            },
            event=guest.next_event()=>match event? {
                ViewerEvent::Output {data}=>{
                    let bytes=decode_data(&data)?;
                    if !*read_only || !pager.active {write(terminal,&bytes).await?;}
                },
                ViewerEvent::History {page} if *read_only=>{
                    if let Some(bytes)=pager.page(page)? {write(terminal,&bytes).await?;}
                },
                ViewerEvent::Closed {reason,retryable}=>return Ok(End {reason,retryable}),
                ViewerEvent::Presence {..}|ViewerEvent::Recovery {..}=>{},
                _=>bail!("unexpected terminal event on legacy relay attachment"),
            }
        }
    }
}
async fn write(terminal: &Terminal, bytes: &[u8]) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), terminal.write_all(bytes))
        .await
        .context("local terminal output stalled")??;
    Ok(())
}
