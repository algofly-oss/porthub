//! Native-read-only source bridge. No caller supplies bytes or an opaque grant.
use super::flow_authority::{Context, LocalAuthority, Side};
use super::*;
use porthub_network::tcp_stream::tagged;
/// Read the installed atomic pair view. No IO or transport re-entry is allowed.
pub(crate) type Current = Arc<dyn Fn() -> Option<Arc<LocalAuthority>> + Send + Sync>;
pub(crate) struct Source {
    context: Context,
    side: Side,
    native: Arc<tagged::Connection>,
    sender: Sender,
    owner: Option<Owner>,
    current: Current,
    finished: bool,
    terminal: Option<SendPermit>,
}
impl Source {
    pub(crate) fn new(
        context: Context,
        side: Side,
        connection: BoundedSourceConnection,
        gate: Gate,
        budget: Budget,
        native: Arc<tagged::Connection>,
        current: Current,
    ) -> Result<Self> {
        let local =
            current().ok_or_else(|| anyhow::anyhow!("native source authority unavailable"))?;
        context.bind_source(&local, side, &connection, &gate, &native)?;
        let peer = connection.peer().clone();
        let (sender, owner) = start(peer, connection, gate, budget, context.data_flow(side))?;
        Ok(Self {
            context,
            side,
            native,
            sender,
            owner: Some(owner),
            current,
            finished: false,
            terminal: None,
        })
    }
    /// The retained native read owns its original stack/generation/tuple and
    /// first-byte witness. A fresh current policy is only an additional veto.
    pub(crate) async fn send_next(&mut self) -> Result<[u8; HEADER]> {
        ensure!(!self.finished, "native source already sent FIN");
        // No fixed grant is renewed by an idle wait. Only a non-authorizing
        // current-owner veto runs while awaiting the next first-origin read.
        let context = self.context.clone();
        let side = self.side;
        let current = self.current.clone();
        let gate = self.sender.gate.state.clone();
        let idle = SendPermit::control(move || {
            if !gate.alive.load(Ordering::SeqCst) {
                return false;
            }
            current().is_some_and(|now| context.authorize(&now, side).is_ok())
        });
        let read = idle.during(self.native.read_chunk()).await??;
        ensure!(
            self.native.owns_read(&read),
            "native source read is foreign or retired"
        );
        let now =
            (self.current)().ok_or_else(|| anyhow::anyhow!("native source policy unavailable"))?;
        let at_issue = self.context.authorize(&now, self.side)?;
        let original = SendPermit::combine(vec![read.admission(), at_issue]);
        let context = self.context.clone();
        let side = self.side;
        let current = self.current.clone();
        let permit = original
            .constrain(move || current().is_some_and(|now| context.authorize(&now, side).is_ok()));
        let terminal = read.eof();
        let terminal_permit = permit.clone();
        let sender = &self.sender;
        let result = read
            .deliver(|bytes, eof| async move {
                ensure!(eof == terminal, "native source EOF changed");
                if eof {
                    ensure!(bytes.is_empty(), "native FIN contains DATA");
                    sender.send_fin(permit).await
                } else {
                    sender.send(bytes, permit).await
                }
            })
            .await?;
        self.finished = terminal;
        if terminal {
            self.terminal = Some(SendPermit::combine(vec![
                terminal_permit,
                self.sender.gate.state.parent.clone(),
            ]));
        }
        Ok(result)
    }
    pub(super) fn counterpart(&self, receiver: &super::receiver::Receiver) -> bool {
        let other = match self.side {
            Side::Initiator => Side::Acceptor,
            Side::Acceptor => Side::Initiator,
        };
        receiver.agrees(&self.native, &self.context.data_flow(other))
    }
    pub(super) fn terminal(&self) -> Option<SendPermit> {
        self.terminal.clone()
    }
    pub(super) fn native(&self) -> Arc<tagged::Connection> {
        self.native.clone()
    }
    pub(crate) async fn shutdown(&mut self) -> Result<()> {
        if let Some(owner) = self.owner.take() {
            owner.shutdown().await?;
        }
        Ok(())
    }
}
impl Drop for Source {
    fn drop(&mut self) {
        // A successfully published FIN is a half-close. The duplex owner must
        // keep the other direction alive; abandoning DATA still retires it.
        if !self.finished {
            self.native.retire();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use porthub_network::tcp_stream;
    use tokio::{
        io::AsyncWriteExt,
        time::{timeout, Duration},
    };
    // Actual smoltcp ingress is exercised without a TUN, OS route, or host input.
    #[tokio::test]
    async fn native_bridge_read_preserves_first_origin_and_exact_owner_before_any_body_callback(
    ) -> Result<()> {
        let (handle, mut output, runner) = tagged::stack()?;
        let (peer, mut input, peer_runner) = tcp_stream::stack()?;
        let stop = CancellationToken::new();
        let a = tokio::spawn(runner.run(stop.clone()));
        let b = tokio::spawn(peer_runner.run(stop.clone()));
        let start = std::time::Instant::now();
        let permit = SendPermit::bounded(
            || true,
            move || Duration::from_secs(15).checked_sub(start.elapsed()),
        );
        let flow = tcp_stream::Flow {
            source: "10.234.249.2:443".parse()?,
            destination: "10.234.249.1:42000".parse()?,
        };
        let h = handle.clone();
        let p = permit.clone();
        let connecting = tokio::spawn(async move { h.connect(flow, p).await });
        let syn = timeout(Duration::from_secs(1), output.recv())
            .await?
            .unwrap();
        let other = peer.clone();
        let accepting = tokio::spawn(async move {
            syn.deliver(|bytes| async move { other.accept_syn(bytes).await })
                .await
        });
        handle.incoming(
            timeout(Duration::from_secs(1), input.recv())
                .await?
                .unwrap(),
            permit.clone(),
        )?;
        let ack = timeout(Duration::from_secs(1), output.recv())
            .await?
            .unwrap();
        let other = peer.clone();
        ack.deliver(|bytes| async move { other.packet(bytes) })
            .await?;
        let native = Arc::new(connecting.await??);
        let (_, mut app) = accepting.await??;
        let cancel = stop.clone();
        let h = handle.clone();
        let original = permit.clone();
        let pump = tokio::spawn(async move {
            loop {
                tokio::select! {_=cancel.cancelled()=>break,p=output.recv()=>match p{Some(p)=>{let other=peer.clone();p.deliver(|bytes|async move{other.packet(bytes)}).await?;},None=>break},p=input.recv()=>match p{Some(p)=>{h.incoming(p,original.clone())?;},None=>break}}
            }
            Ok::<_, anyhow::Error>(())
        });
        let result = async {
            app.write_all(b"exact-native-body").await?;
            let read = timeout(Duration::from_secs(1), native.read_chunk()).await??;
            ensure!(
                native.owns_read(&read) && read.admission().remaining().is_some(),
                "native source lost sealed first-origin ownership"
            );
            let admission = read.admission();
            native.retire();
            let called = Arc::new(AtomicBool::new(false));
            let seen = called.clone();
            ensure!(
                read.deliver(|_, _| {
                    seen.store(true, Ordering::SeqCst);
                    async { Ok(()) }
                })
                .await
                .is_err(),
                "retired first-origin admitted"
            );
            // The actual read's origin becomes invalid; no fresh body grant can repair it.
            ensure!(
                !admission.valid(),
                "native owner retirement did not revoke read witness"
            );
            ensure!(
                !called.load(Ordering::SeqCst),
                "retired read invoked body callback"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        stop.cancel();
        timeout(Duration::from_secs(1), pump).await???;
        timeout(Duration::from_secs(1), a).await???;
        timeout(Duration::from_secs(1), b).await???;
        result
    }
}
