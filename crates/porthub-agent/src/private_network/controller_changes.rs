//! Change notifications only wake authenticated sync; they never authorize traffic.
use crate::{control::Control, private_profile::Profile};
use std::{sync::Arc, time::Duration};
use tokio::sync::{watch, Notify};

pub(super) async fn listen(
    control: Arc<Control>,
    profile: Profile,
    instance: String,
    mut cursor: watch::Receiver<Option<uuid::Uuid>>,
    wake: Arc<Notify>,
) {
    loop {
        let since = *cursor.borrow_and_update();
        let Some(since) = since else {
            if cursor.changed().await.is_err() {
                break;
            }
            continue;
        };
        let body = serde_json::json!({"peer_id":profile.peer_id,"token":profile.token,"instance":instance,"since":since.to_string()});
        let request = control.request(
            reqwest::Method::POST,
            "access/private/changes",
            Some(body),
            &[],
        );
        let reply = tokio::select! {
            changed = cursor.changed() => { if changed.is_err() {break;} continue; }
            reply = request => reply,
        };
        if matches!(reply, Err(crate::control::Failure::Rejected(401 | 403))) {
            wake.notify_one();
        }
        if let Ok(reply) = reply {
            let next = reply
                .json()
                .ok()
                .and_then(|v| uuid::Uuid::parse_str(v["cursor"].as_str()?).ok());
            if let Some(next) =
                next.filter(|_| reply.authenticated_tls || profile.allow_insecure_http_for_tests)
            {
                if next == since {
                    continue;
                }
                wake.notify_one();
                // Coalesce edits until a successful sync observes the new cursor.
                if cursor.changed().await.is_err() {
                    break;
                }
                continue;
            }
        }
        tokio::select! {
            changed = cursor.changed() => if changed.is_err() { break; },
            _ = tokio::time::sleep(Duration::from_secs(5)) => {},
        }
    }
}
