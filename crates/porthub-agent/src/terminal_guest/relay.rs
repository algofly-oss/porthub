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
    Box::pin(run_with_udp(guest, terminal, welcome, None)).await
}
/// The caller must approve the concrete UDP socket using its exit/privacy
/// policy. Normal CLI relay joins never discover or open that socket implicitly.
pub async fn run_with_udp<S: AsyncRead + AsyncWrite + Unpin>(
    guest: &mut Guest<S>,
    terminal: &Terminal,
    welcome: &ViewerEvent,
    socket: Option<tokio::net::UdpSocket>,
) -> Result<End> {
    Box::pin(run_with_policy(guest, terminal, welcome, socket, None)).await
}
pub(crate) async fn run_with_policy<S: AsyncRead + AsyncWrite + Unpin>(
    guest: &mut Guest<S>,
    terminal: &Terminal,
    welcome: &ViewerEvent,
    mut socket: Option<tokio::net::UdpSocket>,
    mut permission: Option<crate::terminal_policy::Permission>,
) -> Result<End> {
    if permission
        .as_ref()
        .is_some_and(|permission| !permission.allowed())
    {
        socket = None;
        permission = None;
    }
    let ViewerEvent::Welcome {
        history_snapshots,
        read_only,
        direct_transport,
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
    let mut direct = match socket {
        Some(socket) => {
            anyhow::ensure!(
                *direct_transport,
                "gateway did not approve direct terminal transport"
            );
            let (mut transport, offer) =
                porthub_terminal::direct::viewer::Transport::offer(socket, *read_only)?;
            if let Some(permission) = &permission {
                transport.require_permission(permission.guard());
            }
            guest.send(&offer).await?;
            Some(transport)
        }
        None => None,
    };
    let mut pager = Pager::new(size.0, size.1);
    pager.capabilities(*history_snapshots);
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut input = [0; 16384];
    loop {
        if permission
            .as_ref()
            .is_some_and(|permission| !permission.allowed())
        {
            if let Some(transport) = &mut direct {
                send(guest, transport.fallback()?).await?;
            }
            permission = None;
        }
        let limit = if *read_only {
            input.len()
        } else {
            direct
                .as_ref()
                .map_or(input.len(), |transport| transport.input_capacity())
        };
        tokio::select! {
            changed=async {match &mut permission {Some(permission)=>permission.receiver.changed().await,None=>std::future::pending().await}}=>{
                if changed.is_err() || permission.as_ref().is_some_and(|permission|!permission.allowed()) {
                    if let Some(transport)=&mut direct {send(guest,transport.fallback()?).await?;}
                    permission=None;
                }
            },
            count=terminal.read(&mut input[..limit]),if limit>0=>{
                let count=count.context("native terminal input failed")?;
                if count==0 {return Ok(End {reason:"local terminal closed".into(),retryable:false});}
                if *read_only {
                    if pager.feed(&input[..count]) {guest.send(&ViewerInput::Redraw).await?;}
                } else if let Some(transport)=&mut direct {
                    send(guest,transport.input(&input[..count])?).await?;
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
            routed=async {match &mut direct {Some(transport)=>transport.network().await,None=>std::future::pending().await}}=>{
                let routed=routed.map_err(|error| {
                    if error.downcast_ref::<porthub_terminal::direct::viewer::Stalled>().is_some() {
                        anyhow::Error::from(super::Failure::Disconnected("native terminal delivery stalled"))
                    } else {error}
                })?;
                send(guest,routed).await?;
            },
            event=guest.next_event()=>match event? {
                ViewerEvent::Output {data}=>{
                    let bytes=match &direct {Some(transport)=>transport.legacy_output(&data)?,None=>decode_data(&data)?};
                    if !*read_only || !pager.active {write(terminal,&bytes).await?;}
                },
                ViewerEvent::History {page} if *read_only=>{
                    if let Some(bytes)=pager.page(page)? {write(terminal,&bytes).await?;}
                },
                ViewerEvent::Closed {reason,retryable}=>return Ok(End {reason,retryable}),
                ViewerEvent::DirectAnswer {answer}=>{
                    let transport=direct.as_mut().context("unexpected native terminal answer")?;
                    send(guest,transport.answer(&answer)?).await?;
                },
                ViewerEvent::DirectUnavailable {request}=>{
                    let transport=direct.as_mut().context("unexpected native terminal negotiation reply")?;
                    send(guest,transport.unavailable(request)?).await?;
                },
                ViewerEvent::Delivery {packet}=>{
                    direct.as_mut().context("unexpected sequenced terminal frame")?.receipt(packet.decode()?)?;
                },
                ViewerEvent::Presence {..}|ViewerEvent::Recovery {..}=>{},
                _=>bail!("unexpected terminal event on legacy relay attachment"),
            }
        }
        if let Some(transport) = &mut direct {
            while let Some(frame) = transport.next_output() {
                let sequence = frame.sequence();
                if !*read_only || !pager.active {
                    write(terminal, frame.payload()).await?;
                }
                // A frozen history view deliberately discards live-screen
                // updates. Its snapshot is independent; redraw on returning.
                transport.commit_output(sequence)?;
            }
            send(guest, transport.acknowledge_output()?).await?;
        }
    }
}
async fn send<S: AsyncRead + AsyncWrite + Unpin>(
    guest: &mut Guest<S>,
    inputs: Vec<ViewerInput>,
) -> Result<()> {
    for input in inputs {
        guest.send(&input).await?;
    }
    Ok(())
}
async fn write(terminal: &Terminal, bytes: &[u8]) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), terminal.write_all(bytes))
        .await
        .context("local terminal output stalled")??;
    Ok(())
}
