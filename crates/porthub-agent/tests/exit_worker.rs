#![cfg(all(target_os = "linux", feature = "netns-tests"))]
use anyhow::{ensure, Context, Result};
use std::{collections::BTreeMap, net::IpAddr, time::Duration};
use tokio::{io::{AsyncBufReadExt, AsyncWriteExt, BufReader}, net::TcpStream};
use tokio_util::sync::CancellationToken;

async fn wait_for_selection(mode: &str) -> Result<()> {
    let expected: porthub_mesh::exit_policy::Selection = serde_json::from_value(serde_json::json!(mode))?;
    let mut updates = porthub_agent::private_network::exit_selection::test_selection_updates();
    tokio::time::timeout(Duration::from_secs(30), updates.wait_for(|state| *state == Some((expected, 2))))
        .await.context("exit mode did not reach packet-path selection")??;
    Ok(())
}

type Stream = BufReader<TcpStream>;
async fn open(target: &str) -> Result<(Stream, IpAddr)> {
    let mut stream = BufReader::new(tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(target)).await.context("TCP connect timeout")??);
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(3), stream.read_line(&mut line)).await.context("TCP response timeout")??;
    Ok((stream, line.trim().parse()?))
}
async fn ping(stream: &mut Stream) -> Result<IpAddr> {
    stream.get_mut().write_all(b"ping\n").await?;
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(3), stream.read_line(&mut line)).await.context("TCP response timeout")??;
    Ok(line.trim().parse()?)
}
async fn consumer(target: &str) -> Result<()> {
    let expected: Vec<IpAddr> = ["203.0.113.2", "203.0.113.3"].into_iter().map(|s| s.parse().unwrap()).collect();
    tokio::time::timeout(Duration::from_secs(60), async {
        let mut seen = std::collections::BTreeSet::new();
        loop {
            if let Ok((_, ip)) = open(target).await { ensure!(expected.contains(&ip), "traffic bypassed the exits"); seen.insert(ip); }
            if seen.len() == 2 { return Ok::<_,anyhow::Error>(()); }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }).await??;
    println!("both exits reached; opening persistent connection");
    let (mut established, original) = open(target).await.context("open persistent connection")?;
    for mode in ["round_robin", "sticky", "random"] {
        established.get_mut().write_all(format!("mode:{mode}\n").as_bytes()).await?;
        let mut confirmation = String::new(); established.read_line(&mut confirmation).await?;
        ensure!(confirmation.trim() == "updated", "mode update failed");
        wait_for_selection(mode).await?;
        let count = if mode == "random" { 64 } else { 16 };
        let mut counts = BTreeMap::new();
        for index in 0..count {
            let (_, ip) = open(target).await.with_context(|| format!("new {mode} connection {index}"))?;
            ensure!(expected.contains(&ip), "traffic bypassed the exits");
            *counts.entry(ip).or_insert(0usize) += 1;
            ensure!(ping(&mut established).await.with_context(|| format!("persistent connection during {mode} iteration {index}"))? == original, "established connection changed exit");
        }
        match mode {
            "round_robin" => ensure!(counts.len() == 2 && counts.values().all(|n| *n == 8), "uneven round robin: {counts:?}"),
            "sticky" => ensure!(counts.len() == 1, "sticky changed exits: {counts:?}"),
            _ => ensure!(counts.len() == 2, "random did not use both exits: {counts:?}"),
        }
        println!("{mode}: {count} new connections verified; established connection preserved");
        let (mut half_closed, exit) = open(target).await?;
        half_closed.get_mut().shutdown().await?;
        let mut final_reply = String::new();
        tokio::time::timeout(Duration::from_secs(3), half_closed.read_line(&mut final_reply)).await??;
        ensure!(final_reply.trim().parse::<IpAddr>()? == exit, "half-closed connection lost its final reply");
        final_reply.clear();
        ensure!(tokio::time::timeout(Duration::from_secs(3), half_closed.read_line(&mut final_reply)).await?? == 0, "server close was not delivered");
        println!("{mode}: half-close preserved final response and orderly shutdown");
    }
    let offline = expected.iter().find(|ip| **ip != original).unwrap();
    established.get_mut().write_all(format!("offline:{offline}\n").as_bytes()).await?;
    let mut confirmation = String::new(); established.read_line(&mut confirmation).await?;
    ensure!(confirmation.trim() == "updated", "exit shutdown failed");
    tokio::time::sleep(Duration::from_secs(20)).await;
    for _ in 0..16 {
        let (_, ip) = open(target).await.context("new connection after exit shutdown")?;
        ensure!(ip == original, "offline exit remained eligible");
        ensure!(ping(&mut established).await? == original, "healthy established flow broke");
    }
    println!("offline exit excluded: 16 new connections used the surviving exit; established connection preserved");
    Ok(())
}

#[tokio::test]
#[ignore = "worker for verify-exit-network.py; disposable owned namespace only"]
async fn isolated_exit_worker() -> Result<()> {
    ensure!(std::env::var("PORTHUB_TEST_OWNED_NETNS").as_deref() == Ok("1") && std::path::Path::new("/.dockerenv").is_file(), "requires owned test container");
    let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).try_init();
    let profile = std::env::var("PORTHUB_TEST_PROFILE")?;
    let path = std::path::PathBuf::from("/state/profile.json");
    porthub_agent::profile::write_private(&path, profile.as_bytes(), false)?;
    let cancel = CancellationToken::new();
    let runtime = porthub_agent::private_network::runtime::run(path, cancel.clone());
    tokio::pin!(runtime);
    let role = std::env::var("PORTHUB_TEST_ROLE")?;
    let result = if role == "http-consumer" {
        tokio::select! {
            result = http_consumer() => result,
            result = &mut runtime => anyhow::bail!("agent stopped: {result:?}"),
        }
    } else if role == "consumer" {
        let target = std::env::var("PORTHUB_TEST_TARGET")?;
        tokio::select! {
            result = consumer(&target) => result,
            result = &mut runtime => anyhow::bail!("agent stopped: {result:?}"),
        }
    } else {
        let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            _ = terminate.recv() => Ok(()),
            _ = tokio::time::sleep(Duration::from_secs(420)) => Ok(()),
            result = &mut runtime => anyhow::bail!("agent stopped: {result:?}"),
        }
    };
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), runtime).await??;
    result
}


async fn http_consumer() -> Result<()> {
    let expected: Vec<IpAddr> = serde_json::from_str(&std::env::var("PORTHUB_TEST_EXIT_IPS")?)?;
    ensure!(expected.len() == 2 && expected[0] != expected[1], "test requires distinct exit addresses");
    let control = std::env::var("PORTHUB_TEST_CONTROL_URL")?;
    let key = std::env::var("PORTHUB_TEST_CONTROL_KEY")?;
    let probe = reqwest::Client::builder().no_proxy().pool_max_idle_per_host(0).timeout(Duration::from_secs(10)).build()?;
    let management = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(10)).build()?;
    async fn observed(client: &reqwest::Client) -> Result<IpAddr> {
        Ok(client.get("https://api4.ipify.org").send().await?.error_for_status()?.text().await?.trim().parse()?)
    }
    tokio::time::timeout(Duration::from_secs(120), async {
        let mut seen = std::collections::BTreeSet::new();
        loop {
            let netlink = nlink::netlink::Connection::<nlink::netlink::Route>::new()?;
            if netlink.get_rules_v4().await?.iter().any(|rule| rule.priority() == 22600) {
                if let Ok(ip) = observed(&probe).await {
                    ensure!(expected.contains(&ip), "unexpected exit identity");
                    seen.insert(ip);
                }
                if seen.len() == 2 { return Ok::<_, anyhow::Error>(()); }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }).await.context("both live exits did not become ready")??;
    println!("Both real exit addresses verified (addresses omitted)");
    for mode in ["round_robin", "sticky", "random"] {
        management.post(format!("{control}/_test/mode")).header("x-test-key", &key).json(&serde_json::json!({"mode":mode})).send().await?.error_for_status()?;
        wait_for_selection(mode).await?;
        let count = if mode == "random" { 16 } else { 8 };
        let mut counts = [0usize; 2];
        for _ in 0..count {
            let ip = observed(&probe).await?;
            let index = expected.iter().position(|candidate| *candidate == ip).context("unexpected exit identity")?;
            counts[index] += 1;
        }
        match mode {
            "round_robin" => ensure!(counts == [4,4], "round robin distribution mismatch: {counts:?}"),
            "sticky" => ensure!(counts.contains(&8), "sticky exit changed: {counts:?}"),
            _ => ensure!(counts.iter().all(|count| *count > 0), "random did not use both exits"),
        }
        println!("{mode}: verified connection distribution {counts:?}");
    }
    Ok(())
}
