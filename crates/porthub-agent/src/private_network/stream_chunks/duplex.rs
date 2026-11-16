//! Joined DATA/FIN owners. Still private and not production-negotiated.
use super::*;
use super::{
    receiver::{Access, Receiver},
    source::Source,
};
use porthub_network::tcp_stream::tagged;
/// Each invocation captures the current original receiver-credit admission.
/// It cannot replace the first-origin of source reads or an outstanding credit.
pub(crate) type Admission = Arc<dyn Fn() -> Option<Access> + Send + Sync>;
pub(crate) struct Duplex {
    source: Source,
    receiver: Receiver,
    admission: Admission,
    native: Arc<tagged::Connection>,
}
impl Duplex {
    pub(crate) fn new(source: Source, receiver: Receiver, admission: Admission) -> Result<Self> {
        ensure!(
            source.counterpart(&receiver),
            "duplex halves do not share exact native generation and reciprocal flow"
        );
        let native = source.native();
        Ok(Self {
            source,
            receiver,
            admission,
            native,
        })
    }
    pub(crate) async fn run(&mut self) -> Result<()> {
        let source = &mut self.source;
        let receiver = &mut self.receiver;
        let admission = self.admission.clone();
        let outgoing = async {
            loop {
                let h = source.send_next().await?;
                if &h[..4] == b"PHF2" {
                    return Ok::<_, anyhow::Error>(());
                }
            }
        };
        let incoming = async {
            loop {
                let original = admission()
                    .ok_or_else(|| anyhow::anyhow!("duplex receiver original unavailable"))?;
                let h = receiver.receive(original).await?;
                if &h[..4] == b"PHF2" {
                    return Ok::<_, anyhow::Error>(());
                }
            }
        };
        let result = tokio::try_join!(outgoing, incoming);
        if result.is_err() {
            self.native.retire();
            self.receiver.retire();
            let _ = self.source.shutdown().await;
        }
        result?;
        // Neither successful half-close alone may tear down the other direction.
        // Both terminal receipts have now crossed real native ACK boundaries.
        Ok(())
    }
    /// Retained owners must outlive terminal receipt ACKs. The runtime's
    /// bounded drain/peer-completion protocol is still an integration contract;
    /// returning run() is not permission to destroy the peer's receipt socket.
    pub(crate) fn drain_authority(&self) -> Result<SendPermit> {
        let source = self
            .source
            .terminal()
            .ok_or_else(|| anyhow::anyhow!("source FIN not acknowledged"))?;
        let receiver = self
            .receiver
            .terminal()
            .ok_or_else(|| anyhow::anyhow!("receiver FIN not acknowledged"))?;
        let permit = SendPermit::combine(vec![source, receiver]);
        ensure!(
            permit.remaining().is_some(),
            "completed flow has no original drain bound"
        );
        Ok(permit)
    }
    /// Conservative bounded retirement when there is no authenticated remote
    /// completion signal. This retains only existing witnesses, never a fresh
    /// timeout. It is an intermediate cleanup strategy, not throughput proof.
    pub(crate) async fn drain_to_original_deadline(&mut self) -> Result<()> {
        let authority = self.drain_authority();
        if let Ok(permit) = &authority {
            let _ = permit.during(std::future::pending::<()>()).await;
        }
        let cleanup = self.shutdown().await;
        authority?;
        cleanup
    }
    pub(crate) async fn shutdown(&mut self) -> Result<()> {
        self.native.retire();
        self.receiver.retire();
        self.source.shutdown().await
    }
}
impl Drop for Duplex {
    fn drop(&mut self) {
        self.native.retire();
    }
}

#[cfg(test)]
#[path = "duplex_tests.rs"]
mod tests;
