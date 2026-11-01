//! Bounded native relay attachment recovery. Recovery never falls back to the
//! original invitation and never replays old or offline keystrokes.
use super::{relay, tty::Terminal, Guest, Invitation, NetworkGuest, Recovery};
use anyhow::{bail, Context, Result};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

#[async_trait::async_trait]
pub trait Connector {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send;
    async fn connect(
        &mut self,
        recovery: &mut Option<Recovery>,
        cols: u16,
        rows: u16,
    ) -> Result<(Guest<Self::Stream>, porthub_terminal::protocol::ViewerEvent)>;
}
struct Gateway<'a>(&'a Invitation);
#[async_trait::async_trait]
impl Connector for Gateway<'_> {
    type Stream = tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>;
    async fn connect(
        &mut self,
        recovery: &mut Option<Recovery>,
        cols: u16,
        rows: u16,
    ) -> Result<(NetworkGuest, porthub_terminal::protocol::ViewerEvent)> {
        NetworkGuest::connect_resumable(self.0, recovery, cols, rows).await
    }
}
pub async fn join_relay(value: &str) -> Result<()> {
    let invitation = Invitation::parse(value)?;
    // Install termination handlers before changing the local terminal mode.
    let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let terminal = Terminal::open()?;
    let mut gateway = Gateway(&invitation);
    tokio::select! {
        result=run(&mut gateway,&terminal)=>{result?;},
        _=hangup.recv()=>{},
        _=terminate.recv()=>{},
        _=interrupt.recv()=>{},
    }
    Ok(())
}
pub async fn run<C: Connector>(connector: &mut C, terminal: &Terminal) -> Result<relay::End> {
    let size = terminal.size()?;
    let (mut guest, mut welcome) = connector.connect(&mut None, size.0, size.1).await?;
    loop {
        match relay::run(&mut guest, terminal, &welcome).await {
            Ok(end) if !end.retryable => return Ok(end),
            Err(error) if !super::retryable(&error) => return Err(error),
            _ => {}
        }
        let mut recovery = Some(
            guest
                .take_recovery()
                .context("terminal recovery unavailable; join again")?,
        );
        let deadline = recovery
            .as_ref()
            .and_then(|recovery| recovery.deadline)
            .context("terminal recovery deadline unavailable")?;
        // Close the previous attachment before attempting its replacement.
        drop(guest);
        tokio::time::timeout(
            Duration::from_secs(3),
            terminal.write_all(
                b"\r\n[PortHub reconnecting. Offline keys are discarded; Ctrl+C cancels.]\r\n",
            ),
        )
        .await
        .context("local terminal output stalled")??;
        let reconnect = async {
            let mut delay = Duration::from_millis(250);
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    bail!("terminal recovery window expired; join again");
                }
                let size = terminal.size()?;
                let attempt = tokio::time::timeout(
                    remaining,
                    connector.connect(&mut recovery, size.0, size.1),
                )
                .await;
                match attempt {
                    Ok(Ok(connected)) => return Ok(connected),
                    Ok(Err(error)) if !super::retryable(&error) => return Err(error),
                    _ => {}
                }
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    bail!("terminal recovery window expired; join again");
                }
                tokio::time::sleep(delay.min(remaining)).await;
                delay = (delay * 2).min(Duration::from_secs(2));
            }
        };
        tokio::pin!(reconnect);
        let mut discard = [0; 16384];
        let connected = loop {
            tokio::select! {
                result=&mut reconnect=>break result?,
                count=terminal.read(&mut discard)=>{
                    let count=count?;
                    if count==0 || discard[..count].contains(&3) {
                        return Ok(relay::End {reason:"reconnect cancelled locally".into(),retryable:false});
                    }
                },
            }
        };
        // A just-completed connect and a readable TTY can be ready in the same
        // select. Discard that final offline tail before enabling the new shell.
        terminal.discard_offline_input()?;
        (guest, welcome) = connected;
    }
}
