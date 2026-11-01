//! A viewer can briefly queue its entire replay window plus ACKs and control
//! messages. A separate byte quota keeps larger frames bounded independently.
use crate::{delivery, protocol::ViewerEvent};
use std::sync::Arc;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
const MESSAGES: usize = delivery::MAX_FRAMES * 2 + 64;
const BYTES: usize = 1024 * 1024;
struct Queued {
    event: ViewerEvent,
    _permit: OwnedSemaphorePermit,
}
#[derive(Clone)]
pub(crate) struct Sender {
    inner: mpsc::Sender<Queued>,
    quota: Arc<Semaphore>,
}
pub struct Receiver {
    inner: mpsc::Receiver<Queued>,
}
pub(crate) fn channel() -> (Sender, Receiver) {
    let (send, receive) = mpsc::channel(MESSAGES);
    (
        Sender {
            inner: send,
            quota: Arc::new(Semaphore::new(BYTES)),
        },
        Receiver { inner: receive },
    )
}
fn charge(event: &ViewerEvent) -> usize {
    use ViewerEvent::*;
    let heap = match event {
        Delivery { packet } => packet.0.capacity(),
        DirectAnswer { answer } => {
            answer.description.0.capacity()
                + answer.input_epoch.capacity()
                + answer.output_epoch.capacity()
        }
        History { page } => {
            page.data.capacity()
                + page.pane.as_ref().map_or(0, String::capacity)
                + page.snapshot.as_ref().map_or(0, String::capacity)
                + page.error.as_ref().map_or(0, String::capacity)
        }
        Recovery { session, token, .. } => session.capacity() + token.capacity(),
        Welcome { name, .. } => name.capacity(),
        Output { data } => data.capacity(),
        Presence { members, .. } => {
            members.capacity() * std::mem::size_of::<crate::protocol::Participant>()
        }
        Closed { reason, .. } => reason.capacity(),
        DirectUnavailable { .. } | Ping => 0,
    };
    heap.saturating_add(std::mem::size_of::<Queued>() + 32)
}
impl Sender {
    pub(crate) fn try_send(
        &self,
        event: ViewerEvent,
    ) -> Result<(), mpsc::error::TrySendError<ViewerEvent>> {
        use mpsc::error::TrySendError;
        if self.inner.is_closed() {
            return Err(TrySendError::Closed(event));
        }
        let amount = charge(&event).min(u32::MAX as usize) as u32;
        let Ok(permit) = self.quota.clone().try_acquire_many_owned(amount) else {
            return Err(TrySendError::Full(event));
        };
        self.inner
            .try_send(Queued {
                event,
                _permit: permit,
            })
            .map_err(|error| match error {
                TrySendError::Closed(queued) => TrySendError::Closed(queued.event),
                TrySendError::Full(queued) => TrySendError::Full(queued.event),
            })
    }
}
impl Receiver {
    pub async fn recv(&mut self) -> Option<ViewerEvent> {
        self.inner.recv().await.map(|queued| queued.event)
    }
    pub fn try_recv(&mut self) -> Result<ViewerEvent, mpsc::error::TryRecvError> {
        self.inner.try_recv().map(|queued| queued.event)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn byte_budget_is_released_on_drain_rejection_and_receiver_drop() {
        let (send, mut receive) = channel();
        let initial = send.quota.available_permits();
        let frame = || ViewerEvent::Output {
            data: "x".repeat(16 * 1024),
        };
        let mut count = 0;
        while send.try_send(frame()).is_ok() {
            count += 1;
        }
        assert!(
            count > 0 && count < MESSAGES,
            "byte quota must bound large frames first"
        );
        assert!(receive.try_recv().is_ok());
        assert!(
            send.try_send(frame()).is_ok(),
            "draining must release bytes"
        );
        drop(receive);
        assert_eq!(
            send.quota.available_permits(),
            initial,
            "closing must release every queued permit"
        );
        assert!(matches!(
            send.try_send(frame()),
            Err(mpsc::error::TrySendError::Closed(_))
        ));
    }
    #[test]
    fn tiny_control_messages_still_have_a_fixed_count_limit() {
        let (send, _receive) = channel();
        for _ in 0..MESSAGES {
            send.try_send(ViewerEvent::Ping).unwrap();
        }
        assert!(matches!(
            send.try_send(ViewerEvent::Ping),
            Err(mpsc::error::TrySendError::Full(_))
        ));
    }
}
