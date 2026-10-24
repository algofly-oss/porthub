//! Kernel-side socket filtering with ss-style expressions (#163).
//!
//! `FilterExpr` parses the `ss(8)` filter grammar; the library
//! compiles as much of it as possible into an
//! `INET_DIAG_REQ_BYTECODE` program (plus `idiag_states` hoisting
//! for `state` predicates) so non-matching sockets never cross into
//! userspace. `compile_filter` is shown explicitly here so you can
//! see WHAT goes kernel-side; in normal use just set
//! `InetFilter::expr` (or `.filter_expr(...)` on the builder) and the
//! dump path does all of this — including the client-side backstop
//! when the kernel-side lowering over-approximates.
//!
//! Also demonstrates `with_cc_info()`: typed BBR/DCTCP/vegas
//! congestion-control state on `InetSocket::cc_info`.
//!
//! Unprivileged. Run with:
//! cargo run -p nlink --features sockdiag --example sockdiag_filter_expr [expr...]
//!
//! ```bash
//! cargo run -p nlink --features sockdiag --example sockdiag_filter_expr -- \
//!     '( sport = :443 or sport = :22 ) and state established'
//! ```

use nlink::{
    netlink::{Connection, SockDiag},
    sockdiag::{CcInfo, FilterExpr, SocketFilter, compile_filter},
};

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let expr_str = if args.is_empty() {
        "state listening and not sport = :22".to_string()
    } else {
        args.join(" ")
    };

    let expr = FilterExpr::parse(&expr_str)
        .map_err(nlink::netlink::Error::invalid_message)?;

    // Introspect the kernel-side lowering.
    let compiled = compile_filter(&expr);
    println!("expression : {expr_str}");
    println!(
        "states mask: {} (hoisted into the request header)",
        compiled
            .states
            .map(|m| format!("{m:#06x}"))
            .unwrap_or_else(|| "none".into())
    );
    println!(
        "bytecode   : {} (INET_DIAG_REQ_BYTECODE program)",
        compiled
            .bytecode
            .as_ref()
            .map(|b| format!("{} bytes", b.len()))
            .unwrap_or_else(|| "none".into())
    );
    println!(
        "exact      : {} (false ⇒ the dump path also applies the client-side backstop)\n",
        compiled.exact
    );

    // Run the filtered dump. The library re-compiles internally —
    // never attach a pre-compiled program yourself; composition with
    // the port shorthands must happen at the expression level.
    let conn = Connection::<SockDiag>::new()?;
    let filter = SocketFilter::tcp()
        .with_congestion()
        .with_cc_info()
        .filter_expr(expr)
        .build();
    let sockets = conn.query(&filter).await?;

    println!("{:<28} {:<28} {:<12} CC", "LOCAL", "REMOTE", "STATE");
    println!("{}", "-".repeat(84));
    for s in sockets.iter().filter_map(|s| s.as_inet()) {
        let cc = match (&s.congestion, &s.cc_info) {
            (Some(name), Some(CcInfo::Bbr(b))) => {
                format!("{name} (bw {} B/s, min_rtt {} µs)", b.bw, b.min_rtt_us)
            }
            (Some(name), Some(CcInfo::Dctcp(d))) => format!("{name} (alpha {})", d.alpha),
            (Some(name), Some(CcInfo::Vegas(v))) => format!("{name} (rtt {} µs)", v.rtt),
            (Some(name), _) => name.clone(),
            (None, _) => String::new(),
        };
        println!(
            "{:<28} {:<28} {:<12} {}",
            s.local.to_string(),
            s.remote.to_string(),
            s.state.name(),
            cc,
        );
    }
    println!("\n{} sockets matched", sockets.len());
    Ok(())
}
