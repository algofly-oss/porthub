//! Three-namespace lab topology — showcasing `nlink::lab`.
//!
//! Builds a central bridged namespace (`hq`) with two client
//! namespaces (`alpha`, `beta`) connected via veth pairs on a shared
//! bridge, all inside transient `LabNamespace`s that clean up when the
//! example returns.
//!
//! Run modes:
//!
//! ```bash
//! # Print the topology diagram + usage (no privileges)
//! cargo run -p nlink --features lab --example lab_three_namespace
//!
//! # Build the topology, bring everything up, addresses, dump, teardown.
//! # Requires root (CAP_NET_ADMIN).
//! sudo cargo run -p nlink --features lab --example lab_three_namespace -- --apply
//! ```
//!
//! The topology after `--apply`:
//!
//! ```text
//!                ┌──────────────────┐
//!                │   ns: hq         │
//!                │   br0 10.0.0.1/24│
//!                │   ├── hq_alpha   │   veth    ┌───────────────┐
//!                │   │     <- - - - │ - - - - ->│ ns: alpha     │
//!                │   │              │           │ alpha0 10.0.0.2│
//!                │   └── hq_beta    │   veth    ├───────────────┤
//!                │         <- - - - │ - - - - ->│ ns: beta      │
//!                │                  │           │ beta0 10.0.0.3 │
//!                └──────────────────┘           └───────────────┘
//! ```
//!
//! The demo never touches the host's real network state — everything
//! lives in the three transient namespaces.

use nlink::lab::{LabBridge, LabNamespace, LabVeth, with_namespace};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let do_apply = std::env::args().any(|a| a == "--apply");

    print_overview();

    if !do_apply {
        println!();
        println!("Re-run with `--apply` (as root) to actually build the topology.");
        return Ok(());
    }

    if !nlink::lab::is_root() {
        eprintln!("--apply requires root (CAP_NET_ADMIN). Aborting.");
        std::process::exit(1);
    }

    run_topology().await
}

async fn run_topology() -> nlink::Result<()> {
    println!();
    println!("=== Building topology ===");

    // Use the manual LabNamespace API for the clients so we can pass
    // references into connect builders. Wrap the whole thing in a
    // single `with_namespace` call for the hq ns to keep the example
    // terse — cleanup happens on return from the closure.
    with_namespace("hq", |hq| async move {
        let alpha = LabNamespace::new("alpha")?;
        let beta = LabNamespace::new("beta")?;

        // Create the two veth pairs: local end in hq, peer end in the client.
        LabVeth::new("hq_alpha", "alpha0")
            .peer_in(&alpha)
            .create_in(&hq)
            .await?;
        LabVeth::new("hq_beta", "beta0")
            .peer_in(&beta)
            .create_in(&hq)
            .await?;

        // Bridge the hq-side ports.
        let br = LabBridge::new(&hq, "br0")
            .create()
            .await?
            .add_port("hq_alpha")
            .await?
            .add_port("hq_beta")
            .await?
            .up()
            .await?;

        // Address + bring-up via the command-style helpers.
        hq.add_addr(br.name(), "10.0.0.1/24")?;
        hq.link_up("hq_alpha")?;
        hq.link_up("hq_beta")?;

        alpha.add_addr("alpha0", "10.0.0.2/24")?;
        alpha.link_up("alpha0")?;

        beta.add_addr("beta0", "10.0.0.3/24")?;
        beta.link_up("beta0")?;

        println!("\n  --- Post-setup inventory ---");
        for (label, ns) in [
            ("hq", hq.name()),
            ("alpha", alpha.name()),
            ("beta", beta.name()),
        ] {
            println!();
            println!("  [{label}] namespace: {ns}");
            // Use the convenience helper: run `ip -br addr` in the ns and print.
            match alpha_level_addr_dump(ns) {
                Ok(s) => {
                    for line in s.lines() {
                        println!("    {line}");
                    }
                }
                Err(e) => eprintln!("    <dump failed: {e}>"),
            }
        }

        println!();
        println!("Done. Namespaces are about to be deleted as we unwind.");
        Ok(())
    })
    .await
}

fn alpha_level_addr_dump(ns_name: &str) -> nlink::Result<String> {
    let mut cmd = std::process::Command::new("ip");
    cmd.args(["-br", "addr"]);
    let output = nlink::netlink::namespace::spawn_output(ns_name, cmd)?;
    if !output.status.success() {
        return Err(nlink::Error::invalid_message(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn print_overview() {
    println!("=== lab::LabNamespace + LabBridge + LabVeth demo ===\n");
    println!("Builds three namespaces (hq, alpha, beta) bridged on br0:\n");
    println!(
        "                ┌──────────────────┐
                │   ns: hq         │
                │   br0 10.0.0.1/24│
                │   ├── hq_alpha   │   veth    ┌───────────────┐
                │   │     <- - - - │ - - - - ->│ ns: alpha     │
                │   │              │           │ alpha0 10.0.0.2│
                │   └── hq_beta    │   veth    ├───────────────┤
                │         <- - - - │ - - - - ->│ ns: beta      │
                │                  │           │ beta0 10.0.0.3 │
                └──────────────────┘           └───────────────┘"
    );
    println!();
    println!("Built with (abridged):");
    println!(
        r#"    use nlink::lab::{{LabNamespace, LabBridge, LabVeth, with_namespace}};

    with_namespace("hq", |hq| async move {{
        let alpha = LabNamespace::new("alpha")?;
        let beta  = LabNamespace::new("beta")?;

        LabVeth::new("hq_alpha", "alpha0").peer_in(&alpha).create_in(&hq).await?;
        LabVeth::new("hq_beta",  "beta0" ).peer_in(&beta ).create_in(&hq).await?;

        LabBridge::new(&hq, "br0")
            .create().await?
            .add_port("hq_alpha").await?
            .add_port("hq_beta" ).await?
            .up().await?;

        hq.add_addr("br0", "10.0.0.1/24")?;
        alpha.add_addr("alpha0", "10.0.0.2/24")?;
        beta.add_addr("beta0", "10.0.0.3/24")?;
        // ... link_up on each ...
        Ok(())
    }}).await"#
    );
}
