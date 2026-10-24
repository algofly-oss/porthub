//! Display Linux Audit subsystem status.
//!
//! This example queries the kernel audit subsystem for its current
//! configuration, including:
//! - Whether auditing is enabled/disabled/locked
//! - The audit daemon PID
//! - Rate limiting and backlog settings
//! - TTY auditing status
//! - Supported audit features
//!
//! Run with: cargo run --example audit_status
//!
//! Note: Reading audit status typically requires CAP_AUDIT_READ or root.

use nlink::netlink::{
    Audit, Connection,
    audit::{AuditFailureMode, AuditFeatures, AuditStatus, AuditTtyStatus},
};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    println!("Linux Audit Subsystem Status");
    println!("============================");
    println!();

    let conn = Connection::<Audit>::new()?;

    // Get main audit status
    match conn.get_status().await {
        Ok(status) => print_status(&status),
        Err(e) => {
            eprintln!("Failed to get audit status: {}", e);
            eprintln!("(Requires CAP_AUDIT_READ or root)");
        }
    }

    println!();

    // Get TTY auditing status
    match conn.get_tty_status().await {
        Ok(tty) => print_tty_status(&tty),
        Err(e) => {
            eprintln!("Failed to get TTY status: {}", e);
        }
    }

    println!();

    // Get audit features
    match conn.get_features().await {
        Ok(features) => print_features(&features),
        Err(e) => {
            eprintln!("Failed to get audit features: {}", e);
        }
    }

    Ok(())
}

fn print_status(status: &AuditStatus) {
    println!("Audit Status:");
    println!("  Enabled:        {}", format_enabled(status));
    println!(
        "  Failure mode:   {}",
        format_failure_mode(status.failure_mode())
    );
    println!("  Audit daemon:   {}", format_pid(status.pid));
    println!("  Rate limit:     {} msgs/sec", status.rate_limit);
    println!(
        "  Backlog:        {}/{}",
        status.backlog, status.backlog_limit
    );
    println!("  Lost messages:  {}", status.lost);
    println!("  Feature bitmap: 0x{:08x}", status.feature_bitmap);

    if status.backlog_wait_time > 0 {
        println!(
            "  Backlog wait:   {} ms (actual: {} ms)",
            status.backlog_wait_time, status.backlog_wait_time_actual
        );
    }
}

fn format_enabled(status: &AuditStatus) -> &'static str {
    if status.is_locked() {
        "locked (immutable)"
    } else if status.is_enabled() {
        "yes"
    } else {
        "no"
    }
}

fn format_failure_mode(mode: AuditFailureMode) -> &'static str {
    match mode {
        AuditFailureMode::Silent => "silent (discard)",
        AuditFailureMode::Printk => "printk (log to syslog)",
        AuditFailureMode::Panic => "panic (kernel panic)",
        AuditFailureMode::Unknown(_) => "unknown",
        _ => "unknown",
    }
}

fn format_pid(pid: u32) -> String {
    if pid == 0 {
        "none".to_string()
    } else {
        format!("PID {}", pid)
    }
}

fn print_tty_status(tty: &AuditTtyStatus) {
    println!("TTY Auditing:");
    println!(
        "  Enabled:        {}",
        if tty.enabled != 0 { "yes" } else { "no" }
    );
    println!(
        "  Log passwords:  {}",
        if tty.log_passwd != 0 { "yes" } else { "no" }
    );
}

fn print_features(features: &AuditFeatures) {
    println!("Audit Features:");
    println!("  Version:        {}", features.vers);
    println!("  Mask:           0x{:08x}", features.mask);
    println!("  Features:       0x{:08x}", features.features);
    println!("  Locked:         0x{:08x}", features.lock);

    // Decode known feature bits
    let feature_names = [
        (0x01, "backlog_limit"),
        (0x02, "backlog_wait_time"),
        (0x04, "executable_path"),
        (0x08, "exclude_extend"),
        (0x10, "sessionid_filter"),
        (0x20, "lost_reset"),
        (0x40, "filter_fs"),
    ];

    let active: Vec<&str> = feature_names
        .iter()
        .filter(|(bit, _)| features.features & bit != 0)
        .map(|(_, name)| *name)
        .collect();

    if !active.is_empty() {
        println!("  Active:         {}", active.join(", "));
    }
}
