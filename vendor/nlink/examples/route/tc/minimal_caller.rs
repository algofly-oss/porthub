//! The smallest program that calls netem's convenience wrappers — #310.
//!
//! Run with: cargo run -p nlink --example route_tc_minimal_caller -- --apply
//!
//! This example is deliberately tiny, and that is the point.
//!
//! Every `async fn` that awaits another embeds the callee's future in its
//! own, so rustc computes a caller's layout by recursing once per level.
//! nlink's request chain is deep enough that a program calling one of the
//! convenience wrappers used to fail to compile with
//! `error: queries overflow the depth limit!` — pointing at the caller's
//! own async block, never mentioning nlink, and fixable only by a
//! `recursion_limit` attribute in the caller's crate.
//!
//! The fix is a single `Box::pin` on `Connection::send_dump`, which ends
//! the recursion below every caller at once — every mutating helper reaches
//! the dump path too, resolving an interface name before it sends anything.
//! This example is what keeps it there: with that box removed it fails to
//! compile.
//!
//! It has to be *small*. Layout queries are cached, so a program that
//! touches nlink anywhere else computes these layouts on a shallow stack
//! first and hits the cache later — which is why nlink's own tests, its
//! binaries and its larger examples never saw the bug, and why adding
//! calls here weakens the guard rather than strengthening it.

use nlink::{
    Connection, Route, TcHandle,
    netlink::tc::{NetemConfig, PlugConfig},
};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    if !std::env::args().any(|a| a == "--apply") {
        println!("compile-only guard for #310; pass --apply to run it against dummy0");
        return Ok(());
    }

    let conn = Connection::<Route>::new()?;
    conn.apply_netem("dummy0", NetemConfig::new().build()).await?;
    conn.del_netem("dummy0").await?;
    conn.add_qdisc("dummy0", PlugConfig::new().build()).await?;
    conn.plug_buffer("dummy0", TcHandle::ROOT).await?;
    Ok(())
}
