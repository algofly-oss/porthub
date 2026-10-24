//! Strongly-typed `NetworkConfig` round-trip through JSON (the
//! `serde` feature, #108).
//!
//! The declarative `NetworkConfig` is `Serialize` + a **validating**
//! `Deserialize`: it round-trips through JSON/YAML while staying
//! strongly typed in memory. Addresses and routes use CIDR strings
//! (with `default` for the default route), MACs use the canonical
//! `aa:bb:cc:dd:ee:ff` form, and parsing runs the same validation as
//! the builders — so a bad prefix or MAC is a deserialize *error*,
//! not a silently-wrong config.
//!
//! Most of this example is pure (no kernel access) and runs as an
//! ordinary user. The optional kernel step is gated behind `--apply`
//! and needs `CAP_NET_ADMIN`:
//!
//!   cargo run --features serde --example config_round_trip
//!   sudo -E cargo run --features serde --example config_round_trip -- --apply
//!
//! Build only:
//!   cargo build --features serde --example config_round_trip

use nlink::netlink::config::NetworkConfig;

#[tokio::main]
async fn main() -> nlink::Result<()> {
    // -- Step 1: load a typed config from a JSON document ---------
    //
    // The same shape works from a file (`std::fs::read_to_string`)
    // or, with a serde YAML crate such as `serde_norway`, from
    // YAML. Links use the externally-tagged `link-type`; unit kinds
    // (bridge) are bare strings, kinds with fields (veth) are
    // `{ "veth": { … } }`.
    let json = r#"{
        "links": [
            { "name": "br0",   "link-type": "bridge", "state": "up" },
            { "name": "veth0", "link-type": { "veth": { "peer": "veth1" } }, "master": "br0" }
        ],
        "addresses": [
            { "dev": "br0", "address": "10.0.0.1/24" },
            { "dev": "br0", "address": "2001:db8::1/64" }
        ],
        "routes": [
            { "destination": "default",      "gateway": "10.0.0.254" },
            { "destination": "10.10.0.0/16", "dev": "br0", "type": "blackhole" }
        ]
    }"#;

    let cfg = NetworkConfig::from_json_str(json)?;
    println!(
        "parsed: {} link(s), {} address(es), {} route(s)",
        cfg.links().len(),
        cfg.addresses().len(),
        cfg.routes().len(),
    );

    // -- Step 2: round-trip back to JSON --------------------------
    //
    // The typed values render back to their human forms (CIDR
    // strings, the `default` keyword, MAC strings). Re-parsing the
    // output yields an identical config.
    let pretty = cfg.to_json_string_pretty()?;
    println!("\n--- re-serialized ---\n{pretty}");

    // -- Step 3: validation is enforced on the way in -------------
    //
    // A `/99` prefix is invalid for IPv4 — deserialization surfaces
    // it as an error instead of accepting a nonsense config.
    let bad = NetworkConfig::from_json_str(
        r#"{ "addresses": [{ "dev": "br0", "address": "10.0.0.1/99" }] }"#,
    );
    match bad {
        Ok(_) => println!("\nunexpected: bad prefix was accepted"),
        Err(e) => println!("\nrejected bad config (as intended): {e}"),
    }

    // -- Step 4 (optional): converge the kernel to this config ----
    //
    // Gated behind `--apply` so the example is safe to run as a
    // normal user. Mirrors `examples/config/declarative.rs`.
    if std::env::args().any(|a| a == "--apply") {
        use nlink::netlink::{Connection, Route};
        let conn = Connection::<Route>::new()?;
        let diff = cfg.diff(&conn).await?;
        println!("\n{} change(s) pending", diff.change_count());
        let result = cfg.apply(&conn).await?;
        println!("applied {} change(s)", result.changes_made);
    } else {
        println!("\n(re-run with `--apply` as root to diff/apply against the kernel)");
    }

    Ok(())
}
