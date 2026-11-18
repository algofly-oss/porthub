//! Fault injection ONLY in explicitly owned netns test processes. Never grants
//! authority: release removes a veto, while native ACK/Plan remain mandatory.
use super::super::{authority_event::Authority, controller::Event, exit_forwarding::Readiness};
use anyhow::{ensure, Result};
use porthub_network::policy::PairResponse;
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
pub(super) struct Gate {
    root: PathBuf,
    own: String,
    held: Option<Authority<PairResponse>>,
    start: Option<Instant>,
    pair_released: bool,
    native_released: bool,
    wait_observed: bool,
}
impl Gate {
    pub(super) fn new(path: &Path, own: &str) -> Result<Option<Self>> {
        if std::env::var("PORTHUB_TEST_PROVIDER_GATE").as_deref() != Ok("1") {
            return Ok(None);
        }
        ensure!(
            std::env::var("PORTHUB_TEST_OWNED_NETNS").as_deref() == Ok("1")
                && Path::new("/.dockerenv").is_file()
                && path.parent() == Some(Path::new("/state")),
            "provider fixture gate requires owned netns"
        );
        Ok(Some(Self {
            root: PathBuf::from("/state"),
            own: own.into(),
            held: None,
            start: None,
            pair_released: false,
            native_released: false,
            wait_observed: false,
        }))
    }
    pub(super) fn waiting(&mut self, generation: u64) {
        if !self.wait_observed {
            self.wait_observed = true;
            super::provider_fixture_phase("retained_wait_native", generation, 1);
        }
    }
    pub(super) fn active(&self) -> bool {
        !self.pair_released || !self.native_released
    }
    pub(super) fn intercept(&mut self, pair: &Authority<PairResponse>) -> bool {
        if self.pair_released
            || !pair
                .value
                .lease
                .as_ref()
                .and_then(|lease| lease.exit.as_ref())
                .is_some_and(|exit| exit.router == self.own)
        {
            return false;
        }
        if self.held.is_none() {
            self.held = Some(pair.clone());
            self.start = Some(Instant::now());
            eprintln!("native_fixture_gate phase=pair_held");
        }
        true
    }
    pub(super) fn poll(
        &mut self,
        events: &tokio::sync::mpsc::Sender<Event>,
        ready: &Readiness,
    ) -> Result<()> {
        ensure!(
            self.start
                .is_none_or(|start| start.elapsed() < Duration::from_secs(20))
                || !self.active(),
            "provider fixture handshake timed out"
        );
        if !self.pair_released && self.root.join("release-pair").is_file() {
            if let Some(pair) = self.held.take() {
                pair.check()?;
                match events.try_send(Event::Pair(pair)) {
                    Ok(()) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Full(Event::Pair(pair))) => {
                        self.held = Some(pair);
                        return Ok(());
                    }
                    Err(_) => anyhow::bail!("provider fixture pair owner stopped"),
                }
            }
            self.pair_released = true;
            eprintln!("native_fixture_gate phase=pair_released");
        }
        if !self.native_released && self.root.join("release-native").is_file() {
            ready.fixture_withhold(false);
            self.native_released = true;
            eprintln!("native_fixture_gate phase=native_veto_released");
        }
        Ok(())
    }
}
