//! Waiting for an event that must arrive.
//!
//! rtnetlink queues a notification on every subscribed socket before it
//! acknowledges the change that caused it. A test that subscribes first
//! and then makes the change on another connection has the event queued
//! by the time that call returns, so an event that never arrives is a
//! bug, not timing — and these helpers fail on it instead of accepting it.

use std::collections::VecDeque;
use std::fmt::Debug;
use std::time::Duration;

use tokio_stream::{Stream, StreamExt};

/// How many skipped events a timeout message shows.
const SHOWN: usize = 10;

/// Read `s` until an event matches `pred` and return it. Events that do
/// not match are skipped; a stream error is returned as is.
///
/// Fails with an `InvalidMessage` naming `what`, and the
/// last events skipped, when `within` passes or the stream ends first.
pub async fn expect_event<S, T>(
    s: &mut S,
    within: Duration,
    what: &str,
    pred: impl FnMut(&T) -> bool,
) -> nlink::Result<T>
where
    S: Stream<Item = nlink::Result<T>> + Unpin,
    T: Debug,
{
    expect_event_without(s, within, what, pred, |_| false).await
}

/// Like [`expect_event`], and fail if an event matching `forbidden`
/// arrives before the expected one.
///
/// Delivery to one socket is ordered, so the expected event works as a
/// barrier: anything forbidden that was going to arrive has arrived by
/// then. That makes this a negative check without a sleep.
pub async fn expect_event_without<S, T>(
    s: &mut S,
    within: Duration,
    what: &str,
    mut pred: impl FnMut(&T) -> bool,
    mut forbidden: impl FnMut(&T) -> bool,
) -> nlink::Result<T>
where
    S: Stream<Item = nlink::Result<T>> + Unpin,
    T: Debug,
{
    let mut skipped: VecDeque<String> = VecDeque::new();
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let next = tokio::time::timeout_at(deadline, s.next()).await;
        let event = match next {
            Ok(Some(event)) => event?,
            Ok(None) => return Err(missing(what, "the stream ended", &skipped)),
            Err(_elapsed) => {
                return Err(missing(what, &format!("{within:?} passed"), &skipped));
            }
        };
        if forbidden(&event) {
            return Err(nlink::Error::invalid_message(format!(
                "expected {what}, but first got a forbidden event: {event:?}"
            )));
        }
        if pred(&event) {
            return Ok(event);
        }
        if skipped.len() == SHOWN {
            skipped.pop_front();
        }
        skipped.push_back(format!("{event:?}"));
    }
}

fn missing(what: &str, why: &str, skipped: &VecDeque<String>) -> nlink::Error {
    let shown = if skipped.is_empty() {
        "no other event arrived".to_string()
    } else {
        format!("skipped:\n  {}", Vec::from(skipped.clone()).join("\n  "))
    };
    nlink::Error::invalid_message(format!("expected {what}, but {why}; {shown}"))
}
