//! One-shot transport diagnostic. Exchange the private SDP files over SSH.
//! Does not enumerate, bind or forward any physical USB device.
use anyhow::{ensure, Context, Result};
use std::{
    path::Path,
    time::{Duration, Instant},
};
// The embedded transport module receives no machine profile in this diagnostic.
mod control {
    pub struct Control;
    impl Control {
        pub fn direct_interface_allowed(&self, _: &str, _: std::net::IpAddr) -> bool {
            true
        }
    }
}
#[path = "../src/usb/direct.rs"]
mod direct;
async fn read(path: &Path) -> Result<String> {
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            if let Ok(bytes) = std::fs::read_to_string(path) {
                return Ok::<_, anyhow::Error>(bytes);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await?
}
#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 4,
        "usage: usb-direct-diagnostic offer|answer INPUT_SDP OUTPUT_SDP"
    );
    let candidates = direct::Candidates::gather(None).await?;
    let peer = match args[1].as_str() {
        "offer" => {
            let (mut peer, sdp) = candidates.offer()?;
            porthub_agent::profile::write_private(Path::new(&args[3]), sdp.as_bytes(), false)?;
            let answer = read(Path::new(&args[2])).await?;
            peer.accept_answer(Instant::now(), &answer)?;
            peer
        }
        "answer" => {
            let offer = read(Path::new(&args[2])).await?;
            let (peer, sdp) = candidates.answer(&offer)?;
            porthub_agent::profile::write_private(Path::new(&args[3]), sdp.as_bytes(), false)?;
            peer
        }
        _ => anyhow::bail!("Use offer or answer"),
    };
    let mut transport = candidates.run(peer);
    let started = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        transport
            .connected
            .take()
            .context("Missing direct readiness")?,
    )
    .await?;
    if result.is_err() {
        transport.stopped().await?;
        anyhow::bail!("Direct engine stopped before readiness");
    }
    eprintln!(
        "Authenticated direct channel ready in {:.3}s",
        started.elapsed().as_secs_f64()
    );
    let started = Instant::now();
    if args[1] == "offer" {
        for _ in 0..64 {
            transport.send.send(vec![0x5a; 16384]).await?;
        }
        let response = tokio::time::timeout(Duration::from_secs(20), transport.incoming.recv())
            .await?
            .context("Peer closed")?;
        println!("{}", String::from_utf8(response)?);
    } else {
        let mut bytes = 0;
        while bytes < 1048576 {
            let data = tokio::time::timeout(Duration::from_secs(20), transport.incoming.recv())
                .await?
                .context("Peer closed")?;
            ensure!(data.iter().all(|v| *v == 0x5a), "Corrupt diagnostic stream");
            bytes += data.len();
        }
        let response=serde_json::json!({"bytes":bytes,"seconds":started.elapsed().as_secs_f64(),"route":"direct-dtls"}).to_string();
        transport.send.send(response.into_bytes()).await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}
