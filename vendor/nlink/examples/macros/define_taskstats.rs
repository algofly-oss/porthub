//! Define a Generic Netlink family **end-to-end** with the
//! `nlink-macros` derives.
//!
//! Taskstats is the kernel's per-task accounting family — small,
//! frozen, real. The full declaration of a working
//! `Connection::<Taskstats>` + a typed `TaskstatsGet` request +
//! a typed `TaskstatsReply` is ~30 lines below; nothing else in
//! this file is wire-format plumbing.
//!
//! The headline shape is:
//!
//! ```text
//! let conn = Connection::<Taskstats>::new_async().await?;
//! let reply: TaskstatsReply =
//!     conn.send_typed(TaskstatsGet { pid: std::process::id() }).await?;
//! println!("returned PID: {}", reply.pid);
//! ```
//!
//! # Run modes
//!
//! ```bash
//! # Print API walkthrough (no privileges)
//! cargo run -p nlink --example macros_define_taskstats
//!
//! # Send a real request to the kernel's taskstats family.
//! # Requires CAP_NET_ADMIN (taskstats kernel ACL):
//! sudo cargo run -p nlink --example macros_define_taskstats -- --apply
//! ```
//!
//! # What this file proves
//!
//! 1. `#[genl_family(...)]` produces a real `Connection<P>` marker
//!    with `family_id` runtime-resolution wired in.
//! 2. `#[derive(GenlCommand)]` + `#[derive(GenlAttribute)]` give
//!    you typed kernel-constant enums.
//! 3. `#[derive(GenlMessage)]` covers the message body —
//!    request *and* reply — with one annotation per field.
//! 4. `conn.send_typed(req).await` closes the loop: one call, one
//!    typed reply, no manual builder/parser code.
//!
//! Compare against `crates/nlink/src/netlink/genl/wireguard/`,
//! `genl/macsec/`, `genl/devlink/` etc. — same wire format,
//! ~600 lines hand-rolled instead of ~30.

use nlink::macros::*;
use nlink::netlink::Connection;

// ---------------------------------------------------------------
// 1. Family marker — one line + one attribute.
//    The macro emits the `Connection<Taskstats>::new_async()`
//    machinery (ProtocolState + AsyncProtocolInit + GenlFamily +
//    the sealed-trait impls) automatically.
// ---------------------------------------------------------------

#[genl_family(name = "TASKSTATS", version = 1)]
pub struct Taskstats;

// ---------------------------------------------------------------
// 2. Typed command + attribute enums. Same shape as every other
//    in-tree GENL family, just expressed via derives.
//    See `linux/taskstats.h` for the upstream constants.
// ---------------------------------------------------------------

#[derive(GenlCommand, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_command(repr = "u8")]
pub enum TaskstatsCmd {
    Unspec = 0,
    Get = 1,
    New = 2,
}

#[derive(GenlAttribute, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_attribute(repr = "u16")]
pub enum TaskstatsCmdAttr {
    Unspec = 0,
    Pid = 1,
    Tgid = 2,
    RegisterCpumask = 3,
    DeregisterCpumask = 4,
}

#[derive(GenlAttribute, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_attribute(repr = "u16")]
pub enum TaskstatsType {
    Unspec = 0,
    Pid = 1,
    Tgid = 2,
    Stats = 3,
    AggrPid = 4,
    AggrTgid = 5,
    Null = 6,
}

// ---------------------------------------------------------------
// 3. Request body — one struct, one annotation per field.
// ---------------------------------------------------------------

#[derive(GenlMessage, Debug, Default)]
#[genl_message(cmd = TaskstatsCmd::Get)]
pub struct TaskstatsGet {
    #[genl_attr(TaskstatsCmdAttr::Pid)]
    pub pid: u32,
}

// ---------------------------------------------------------------
// 4. Reply body. The kernel wraps reply attributes inside an
//    "aggregate" nested attribute (`AGGR_PID`), so a fully-typed
//    parse needs `#[derive(NetlinkAttrs)]` (deferred — see
//    `nlink::macros::NetlinkAttrs` doc). For this example we
//    decode the *unwrapped* attrs (`TaskstatsType::Pid` etc.)
//    that several kernel paths also emit directly, and capture
//    the 328-byte `struct taskstats` as `Vec<u8>` for callers to
//    parse with zerocopy if they need the fields.
// ---------------------------------------------------------------

#[derive(GenlMessage, Debug, Default)]
#[genl_message(cmd = TaskstatsCmd::New)]
pub struct TaskstatsReply {
    #[genl_attr(TaskstatsType::Pid)]
    pub pid: u32,
    #[genl_attr(TaskstatsType::Tgid)]
    pub tgid: u32,
    /// Raw `struct taskstats` payload. Layout in
    /// `linux/taskstats.h` — accounting fields like
    /// `ac_utime`, `ac_stime`, `read_bytes`, etc.
    #[genl_attr(TaskstatsType::Stats)]
    pub stats: Vec<u8>,
}

// ---------------------------------------------------------------
// 5. Drive it.
// ---------------------------------------------------------------

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("--apply") => run_apply().await,
        _ => {
            print_overview();
            Ok(())
        }
    }
}

fn print_overview() {
    println!("=== Taskstats via nlink-macros ===\n");
    println!("Full family + message-type declaration in ~30 lines.");
    println!("Inspect this file for the canonical pattern.\n");
    println!("--- API walkthrough ---\n");
    println!("    // 1. Resolve family ID (CTRL_CMD_GETFAMILY)");
    println!("    let conn = Connection::<Taskstats>::new_async().await?;");
    println!();
    println!("    // 2. Build typed request, send, parse typed reply");
    println!("    let reply: TaskstatsReply =");
    println!("        conn.send_typed(TaskstatsGet {{");
    println!("            pid: std::process::id(),");
    println!("        }}).await?;");
    println!();
    println!("    println!(\"PID  : {{}}\", reply.pid);");
    println!("    println!(\"TGID : {{}}\", reply.tgid);");
    println!("    println!(\"stats payload: {{}} bytes\", reply.stats.len());\n");
    println!("--- What --apply does ---\n");
    println!("    Connects to NETLINK_GENERIC, resolves the \"TASKSTATS\"");
    println!("    family ID, sends TASKSTATS_CMD_GET for the current");
    println!("    PID, and prints the typed reply.\n");
    println!("    Requires CAP_NET_ADMIN — the kernel rejects queries");
    println!("    from unprivileged callers with EPERM. On read-only");
    println!("    runs without root, this binary prints this overview");
    println!("    and exits cleanly.");
}

async fn run_apply() -> nlink::Result<()> {
    println!("→ Connection::<Taskstats>::new_async()");
    let conn = match Connection::<Taskstats>::new_async().await {
        Ok(c) => c,
        Err(e) if e.is_not_found() => {
            eprintln!(
                "taskstats family not registered on this kernel — \
                 enable CONFIG_TASKSTATS"
            );
            return Err(e);
        }
        Err(e) => return Err(e),
    };
    println!("  family_id resolved");

    let my_pid = std::process::id();
    println!("→ send_typed(TaskstatsGet {{ pid: {my_pid} }})");
    let reply: TaskstatsReply = match conn
        .send_typed(TaskstatsGet { pid: my_pid })
        .await
    {
        Ok(r) => r,
        Err(e) if e.is_permission_denied() => {
            eprintln!(
                "EPERM — taskstats queries require CAP_NET_ADMIN. \
                 Re-run with sudo."
            );
            return Err(e);
        }
        Err(e) => return Err(e),
    };

    println!("\n=== TaskstatsReply ===");
    println!("  pid           : {}", reply.pid);
    println!("  tgid          : {}", reply.tgid);
    println!("  stats payload : {} bytes (struct taskstats)", reply.stats.len());

    Ok(())
}
