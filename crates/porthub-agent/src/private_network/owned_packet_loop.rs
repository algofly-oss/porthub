//! Actual production local-host routing on macOS. Never fabricates TCP/UDP
//! responses: only the unchanged packet read from the same owned utun is
//! reinjected. Other destinations remain subject to the remote policy pipeline.
use super::authority_event::Authority;
use anyhow::{ensure, Result};
use std::{
    net::Ipv4Addr,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
pub(super) enum Read {
    Remote(usize),
    Local,
}
pub(super) struct OwnedPacketLoop {
    own: Ipv4Addr,
    generation: u64,
    active: AtomicBool,
}
// Not a public injection API. Only actual native read ingress can reach delivery.
trait PacketIo: Sync {
    fn generation(&self) -> u64;
    fn read<'a>(
        &'a self,
        bytes: &'a mut [u8],
    ) -> impl std::future::Future<Output = Result<usize>> + Send + 'a;
    fn write<'a>(
        &'a self,
        bytes: &'a [u8],
    ) -> impl std::future::Future<Output = Result<()>> + Send + 'a;
}
impl OwnedPacketLoop {
    pub(super) fn new(own: Ipv4Addr, index: u32) -> Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        ensure!(own.is_private() && index != 0, "invalid local packet owner");
        let generation = NEXT
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(1))
            .map_err(|_| anyhow::anyhow!("native source generation exhausted"))?;
        Ok(Self {
            own,
            generation,
            active: AtomicBool::new(true),
        })
    }
    fn generation(&self) -> u64 {
        self.generation
    }
    pub(super) fn retire(&self) {
        self.active.store(false, Ordering::SeqCst);
    }
    fn check(
        &self,
        io: &impl PacketIo,
        authority: &Authority<()>,
        deadline: std::time::Instant,
    ) -> Result<()> {
        ensure!(
            self.active.load(Ordering::SeqCst) && self.generation == io.generation(),
            "native packet source retired or replaced"
        );
        ensure!(
            deadline > std::time::Instant::now(),
            "local base policy lease expired"
        );
        authority.check()
    }
    async fn guarded<T>(
        &self,
        io: &impl PacketIo,
        authority: &Authority<()>,
        deadline: std::time::Instant,
        cancel: &CancellationToken,
        operation: impl std::future::Future<Output = Result<T>>,
    ) -> Result<T> {
        tokio::pin!(operation);
        let mut tick = tokio::time::interval(std::time::Duration::from_millis(25));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let poll = std::future::poll_fn(|cx| {
                if let Err(error) = self.check(io, authority, deadline) {
                    return std::task::Poll::Ready(Err(error));
                }
                operation.as_mut().poll(cx)
            });
            tokio::select! {biased;_=cancel.cancelled()=>anyhow::bail!("native packet owner cancelled"),result=poll=>return result,_=tick.tick()=>self.check(io,authority,deadline)?}
        }
    }
    /// One real native read per call: yields to the runtime select after each local
    /// packet, preserving fairness and allowing control/retirement to cancel writes.
    /// The borrowed owner never escapes and cannot keep a retired Tun alive.
    #[cfg(target_os = "macos")]
    pub(super) async fn read_next(
        &self,
        io: &super::device::Tun,
        authority: &Authority<()>,
        deadline: std::time::Instant,
        cancel: &CancellationToken,
        bytes: &mut [u8],
    ) -> Result<Read> {
        self.read_next_io(io, authority, deadline, cancel, bytes)
            .await
    }
    // Private generic implementation: production callers cannot supply an
    // invented native ingress, source generation, or packet buffer producer.
    async fn read_next_io(
        &self,
        io: &impl PacketIo,
        authority: &Authority<()>,
        deadline: std::time::Instant,
        cancel: &CancellationToken,
        bytes: &mut [u8],
    ) -> Result<Read> {
        let size = self
            .guarded(io, authority, deadline, cancel, io.read(bytes))
            .await?;
        ensure!(
            size <= bytes.len() && size <= porthub_mesh::MAX_PACKET,
            "native packet exceeds MTU"
        );
        self.check(io, authority, deadline)?;
        if local(&bytes[..size], self.own) {
            // Local-host semantics, like kernel local routes on Linux/Windows; no remote
            // peer grant is manufactured and no remote ingress calls this branch.
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                self.guarded(io, authority, deadline, cancel, io.write(&bytes[..size])),
            )
            .await
            .map_err(|_| anyhow::anyhow!("owned local packet write exceeded bound"))??;
            self.check(io, authority, deadline)?;
            Ok(Read::Local)
        } else {
            Ok(Read::Remote(size))
        }
    }
}
impl Drop for OwnedPacketLoop {
    fn drop(&mut self) {
        self.retire();
    }
}
fn local(bytes: &[u8], own: Ipv4Addr) -> bool {
    let Some(packet) = porthub_network::policy::Packet::parse(bytes) else {
        return false;
    };
    packet.source() == own && packet.destination() == own
}
#[cfg(target_os = "macos")]
impl PacketIo for super::device::Tun {
    fn generation(&self) -> u64 {
        self.packet_loop().generation()
    }
    async fn read(&self, bytes: &mut [u8]) -> Result<usize> {
        super::device::Tun::read(self, bytes).await
    }
    async fn write(&self, bytes: &[u8]) -> Result<()> {
        super::device::Tun::write(self, bytes).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "private-sparse")]
    use std::sync::Arc;
    use std::{
        sync::{atomic::AtomicU64, Mutex},
        time::Duration,
    };
    struct Fake {
        generation: AtomicU64,
        packet: Mutex<Option<Vec<u8>>>,
        written: Mutex<Vec<Vec<u8>>>,
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
        blocked: bool,
    }
    impl Fake {
        fn new(owner: &OwnedPacketLoop, packet: Vec<u8>, blocked: bool) -> Self {
            Self {
                generation: AtomicU64::new(owner.generation()),
                packet: Mutex::new(Some(packet)),
                written: Mutex::new(Vec::new()),
                entered: tokio::sync::Notify::new(),
                release: tokio::sync::Notify::new(),
                blocked,
            }
        }
    }
    impl PacketIo for Fake {
        fn generation(&self) -> u64 {
            self.generation.load(Ordering::SeqCst)
        }
        async fn read(&self, out: &mut [u8]) -> Result<usize> {
            let p = self.packet.lock().unwrap().take().unwrap();
            out[..p.len()].copy_from_slice(&p);
            Ok(p.len())
        }
        async fn write(&self, p: &[u8]) -> Result<()> {
            self.entered.notify_one();
            if self.blocked {
                self.release.notified().await;
            }
            self.written.lock().unwrap().push(p.to_vec());
            Ok(())
        }
    }
    fn own() -> Ipv4Addr {
        Ipv4Addr::new(10, 254, 251, 1)
    }
    fn udp(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let mut b = vec![0; 28];
        b[0] = 0x45;
        b[2..4].copy_from_slice(&28u16.to_be_bytes());
        b[8] = 64;
        b[9] = 17;
        b[12..16].copy_from_slice(&src.octets());
        b[16..20].copy_from_slice(&dst.octets());
        b[20..22].copy_from_slice(&12345u16.to_be_bytes());
        b[22..24].copy_from_slice(&23456u16.to_be_bytes());
        b[24..26].copy_from_slice(&8u16.to_be_bytes());
        let mut sum: u32 = b[..20]
            .chunks_exact(2)
            .map(|p| u16::from_be_bytes([p[0], p[1]]) as u32)
            .sum();
        while sum >> 16 != 0 {
            sum = (sum & 65535) + (sum >> 16);
        }
        b[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
        b
    }
    fn authority(owner: &super::super::authority_event::Owner) -> Authority<()> {
        #[cfg(feature = "private-sparse")]
        let witness = Some(
            super::super::authority_clock::RequestWindow::start(Arc::new(
                super::super::authority_clock::NativeClock,
            ))
            .unwrap(),
        );
        #[cfg(not(feature = "private-sparse"))]
        let witness = None;
        Authority::new(
            (),
            witness,
            chrono::Utc::now() + chrono::Duration::seconds(15),
        )
        .retired_with(owner.domain())
    }
    #[tokio::test]
    async fn same_real_read_bytes_are_injected_once_without_transport_fabrication() {
        let owner = OwnedPacketLoop::new(own(), 12).unwrap();
        let p = udp(own(), own());
        let io = Fake::new(&owner, p.clone(), false);
        let base = super::super::authority_event::Owner::new();
        let a = authority(&base);
        let mut b = [0; 1500];
        assert!(matches!(
            owner
                .read_next_io(
                    &io,
                    &a,
                    std::time::Instant::now() + Duration::from_secs(15),
                    &CancellationToken::new(),
                    &mut b
                )
                .await
                .unwrap(),
            Read::Local
        ));
        assert_eq!(*io.written.lock().unwrap(), [p]);
    }
    #[tokio::test]
    async fn remote_or_spoofed_packets_remain_in_remote_policy_pipeline() {
        let owner = OwnedPacketLoop::new(own(), 12).unwrap();
        let base = super::super::authority_event::Owner::new();
        for (src, dst) in [
            (own(), Ipv4Addr::new(10, 254, 251, 2)),
            (Ipv4Addr::new(10, 254, 251, 2), own()),
            (Ipv4Addr::LOCALHOST, own()),
        ] {
            let io = Fake::new(&owner, udp(src, dst), false);
            let mut b = [0; 1500];
            assert!(matches!(
                owner
                    .read_next_io(
                        &io,
                        &authority(&base),
                        std::time::Instant::now() + Duration::from_secs(15),
                        &CancellationToken::new(),
                        &mut b
                    )
                    .await
                    .unwrap(),
                Read::Remote(28)
            ));
            assert!(io.written.lock().unwrap().is_empty());
        }
    }
    #[tokio::test]
    async fn denied_remote_peer_stays_denied_after_actual_local_dispatch() {
        let owner = OwnedPacketLoop::new(own(), 12).unwrap();
        let base = super::super::authority_event::Owner::new();
        let a = authority(&base);
        let remote = Ipv4Addr::new(10, 254, 251, 2);
        let mut policy = porthub_network::policy::Engine::default();
        let snapshot = serde_json::json!({"workspace":"fixture","self":"local","revision":1,"expires_at":chrono::Utc::now()+chrono::Duration::seconds(15),"peers":[{"id":"local","ip":own(),"fingerprint":"a","instance":"a","hostname":"local"},{"id":"remote","ip":remote,"fingerprint":"b","instance":"b","hostname":"remote"}],"grants":[]});
        policy
            .apply(serde_json::from_value(snapshot).unwrap())
            .unwrap();
        let local_io = Fake::new(&owner, udp(own(), own()), false);
        let mut bytes = [0; 1500];
        assert!(matches!(
            owner
                .read_next_io(
                    &local_io,
                    &a,
                    std::time::Instant::now() + Duration::from_secs(15),
                    &CancellationToken::new(),
                    &mut bytes
                )
                .await
                .unwrap(),
            Read::Local
        ));
        let remote_io = Fake::new(&owner, udp(own(), remote), false);
        let Read::Remote(n) = owner
            .read_next_io(
                &remote_io,
                &a,
                std::time::Instant::now() + Duration::from_secs(15),
                &CancellationToken::new(),
                &mut bytes,
            )
            .await
            .unwrap()
        else {
            panic!("denied remote packet was reflected")
        };
        assert!(!policy.check(&bytes[..n], "remote", false));
        assert!(remote_io.written.lock().unwrap().is_empty());
    }
    #[test]
    fn malformed_fragmented_bad_checksum_and_non_own_are_not_local() {
        let p = udp(own(), own());
        assert!(local(&p, own()));
        for n in 0..p.len() {
            assert!(!local(&p[..n], own()));
        }
        let mut bad = p.clone();
        bad[10] ^= 1;
        assert!(!local(&bad, own()));
        let mut bad = p;
        bad[6] = 0x20;
        assert!(!local(&bad, own()));
    }
    #[tokio::test]
    async fn retired_source_and_foreign_generation_never_deliver() {
        for replaced in [false, true] {
            let owner = OwnedPacketLoop::new(own(), 12).unwrap();
            let io = Fake::new(&owner, udp(own(), own()), false);
            if replaced {
                io.generation.fetch_add(1, Ordering::SeqCst);
            } else {
                owner.retire();
            }
            let base = super::super::authority_event::Owner::new();
            assert!(owner
                .read_next_io(
                    &io,
                    &authority(&base),
                    std::time::Instant::now() + Duration::from_secs(15),
                    &CancellationToken::new(),
                    &mut [0; 1500]
                )
                .await
                .is_err());
            assert!(io.written.lock().unwrap().is_empty());
        }
    }
    #[tokio::test]
    async fn backpressured_write_stops_on_base_source_generation_or_cancel() {
        for cause in 0..4 {
            let owner = OwnedPacketLoop::new(own(), 12).unwrap();
            let io = Fake::new(&owner, udp(own(), own()), true);
            let base = super::super::authority_event::Owner::new();
            let a = authority(&base);
            let cancel = CancellationToken::new();
            let mut b = [0; 1500];
            let op = owner.read_next_io(
                &io,
                &a,
                std::time::Instant::now() + Duration::from_secs(15),
                &cancel,
                &mut b,
            );
            tokio::pin!(op);
            tokio::select! {r=&mut op=>panic!("unexpected completion {r:?}"),_=io.entered.notified()=>{}}
            match cause {
                0 => base.revoke(),
                1 => owner.retire(),
                2 => {
                    io.generation.fetch_add(1, Ordering::SeqCst);
                }
                _ => cancel.cancel(),
            };
            assert!(tokio::time::timeout(Duration::from_millis(200), &mut op)
                .await
                .unwrap()
                .is_err());
            assert!(io.written.lock().unwrap().is_empty());
        }
    }
    #[tokio::test]
    async fn queued_legacy_base_deadline_still_expires_without_request_clock() {
        let owner = OwnedPacketLoop::new(own(), 12).unwrap();
        let io = Fake::new(&owner, udp(own(), own()), true);
        let base = super::super::authority_event::Owner::new();
        let a = Authority::new((), None, chrono::Utc::now() + chrono::Duration::seconds(60))
            .retired_with(base.domain());
        let cancel = CancellationToken::new();
        let mut bytes = [0; 1500];
        let op = owner.read_next_io(
            &io,
            &a,
            std::time::Instant::now() + Duration::from_millis(10),
            &cancel,
            &mut bytes,
        );
        tokio::pin!(op);
        tokio::select! {r=&mut op=>panic!("unexpected completion {r:?}"),_=io.entered.notified()=>{}}
        tokio::time::sleep(Duration::from_millis(20)).await;
        io.release.notify_one();
        assert!(op.await.is_err());
        assert!(io.written.lock().unwrap().is_empty());
    }
    #[tokio::test(start_paused = true)]
    async fn unchanged_live_owner_does_not_allow_unbounded_write_backpressure() {
        let owner = OwnedPacketLoop::new(own(), 12).unwrap();
        let io = Fake::new(&owner, udp(own(), own()), true);
        let base = super::super::authority_event::Owner::new();
        let a = authority(&base);
        let cancel = CancellationToken::new();
        let mut bytes = [0; 1500];
        let op = owner.read_next_io(
            &io,
            &a,
            std::time::Instant::now() + Duration::from_secs(15),
            &cancel,
            &mut bytes,
        );
        tokio::pin!(op);
        tokio::select! {r=&mut op=>panic!("unexpected completion {r:?}"),_=io.entered.notified()=>{}}
        tokio::time::advance(Duration::from_millis(2001)).await;
        assert!(op.await.is_err());
        assert!(io.written.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn cancelled_pending_native_read_never_reaches_write() {
        struct Idle(u64);
        impl PacketIo for Idle {
            fn generation(&self) -> u64 {
                self.0
            }
            async fn read(&self, _: &mut [u8]) -> Result<usize> {
                std::future::pending().await
            }
            async fn write(&self, _: &[u8]) -> Result<()> {
                panic!("pending read cannot authorize bytes")
            }
        }
        let owner = OwnedPacketLoop::new(own(), 12).unwrap();
        let io = Idle(owner.generation());
        let base = super::super::authority_event::Owner::new();
        let cancel = CancellationToken::new();
        let a = authority(&base);
        let mut bytes = [0; 1500];
        let op = owner.read_next_io(
            &io,
            &a,
            std::time::Instant::now() + Duration::from_secs(15),
            &cancel,
            &mut bytes,
        );
        tokio::pin!(op);
        tokio::select! {r=&mut op=>panic!("unexpected completion {r:?}"),_=tokio::time::sleep(Duration::from_millis(1))=>{}}
        cancel.cancel();
        assert!(tokio::time::timeout(Duration::from_millis(100), op)
            .await
            .unwrap()
            .is_err());
    }
    #[cfg(feature = "private-sparse")]
    #[tokio::test]
    async fn queued_original_expiry_is_not_renewed_by_fresh_authority() {
        struct Clock(AtomicU64);
        impl super::super::authority_clock::SuspendClock for Clock {
            fn elapsed_since_boot(&self) -> Result<Duration> {
                Ok(Duration::from_millis(self.0.load(Ordering::SeqCst)))
            }
        }
        let clock = Arc::new(Clock(AtomicU64::new(0)));
        let witness = super::super::authority_clock::RequestWindow::start(clock.clone()).unwrap();
        let base = super::super::authority_event::Owner::new();
        let a = Authority::new(
            (),
            Some(witness),
            chrono::Utc::now() + chrono::Duration::seconds(60),
        )
        .retired_with(base.domain());
        let owner = OwnedPacketLoop::new(own(), 12).unwrap();
        let io = Fake::new(&owner, udp(own(), own()), true);
        let cancel = CancellationToken::new();
        let mut b = [0; 1500];
        let op = owner.read_next_io(
            &io,
            &a,
            std::time::Instant::now() + Duration::from_secs(15),
            &cancel,
            &mut b,
        );
        tokio::pin!(op);
        tokio::select! {r=&mut op=>panic!("unexpected completion {r:?}"),_=io.entered.notified()=>{}}
        clock.0.store(16000, Ordering::SeqCst);
        let fresh = super::super::authority_clock::RequestWindow::start(clock).unwrap();
        let fresh = Authority::new(
            (),
            Some(fresh),
            chrono::Utc::now() + chrono::Duration::seconds(60),
        );
        assert!(fresh.check().is_ok());
        io.release.notify_one();
        assert!(op.await.is_err());
        assert!(io.written.lock().unwrap().is_empty());
    }
}
