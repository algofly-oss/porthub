//! Error handling patterns.
//!
//! This example demonstrates various error handling patterns
//! when working with netlink operations.
//!
//! Run with: cargo run -p nlink --example route_error_handling

use nlink::netlink::{Connection, Route};

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let conn = Connection::<Route>::new()?;

    println!("Error handling patterns:");
    println!("{}", "-".repeat(50));

    // Pattern 1: Check specific error types
    println!("\n1. Checking error types:");
    match conn.get_link_by_name("nonexistent_interface_12345").await {
        Ok(Some(link)) => println!("   Found: {:?}", link.name()),
        Ok(None) => println!("   Interface not found (expected)"),
        Err(e) => println!("   Error: {}", e),
    }

    // Pattern 2: Handle permission errors gracefully
    println!("\n2. Permission-aware operations:");
    match conn.del_link("lo").await {
        Ok(()) => println!("   Deleted lo (unexpected!)"),
        Err(e) if e.is_permission_denied() => {
            println!("   Permission denied - need root (expected)")
        }
        Err(e) if e.is_busy() => println!("   Device is busy"),
        Err(e) => println!("   Other error: {}", e),
    }

    // Pattern 3: Idempotent operations (delete if exists)
    println!("\n3. Idempotent delete:");
    match conn.del_qdisc("lo", nlink::TcHandle::ROOT).await {
        Ok(()) => println!("   Deleted root qdisc"),
        Err(e) if e.is_not_found() => println!("   No qdisc to delete (OK)"),
        Err(e) => println!("   Error: {}", e),
    }

    // Pattern 4: Get errno for detailed handling
    println!("\n4. Errno-based handling:");
    match conn.get_link_by_name("nonexistent").await {
        Ok(Some(_)) => {}
        Ok(None) => println!("   Interface not found (no errno)"),
        Err(e) => {
            if let Some(errno) = e.errno() {
                println!("   errno: {} ({})", errno, errno_name(errno));
            } else {
                println!("   No errno available: {}", e);
            }
        }
    }

    // Pattern 5: Semantic error types
    println!("\n5. Semantic errors:");
    use nlink::netlink::Error;

    // These show how semantic errors appear
    let examples = [
        Error::interface_not_found("eth99"),
        Error::namespace_not_found("myns"),
        Error::not_found(nlink::ErrorObject::TcClass {
            dev: "eth0".into(),
            classid: "1:a".into(),
        }),
    ];

    for err in &examples {
        println!("   {}", err);
    }

    // Pattern 6: Context with error conversion
    println!("\n6. Error conversion from utility types:");
    use nlink::util::parse::get_rate;

    match get_rate("invalid_rate") {
        Ok(rate) => println!("   Rate: {}", rate),
        Err(e) => {
            // ParseError converts to nlink::netlink::Error automatically
            let nlink_err: nlink::netlink::Error = e.into();
            println!("   Parse error converted: {}", nlink_err);
        }
    }

    // Pattern 7: Retry on transient errors
    println!("\n7. Retry pattern for busy resources:");
    let mut attempts = 0;
    loop {
        attempts += 1;
        match conn.get_links().await {
            Ok(links) => {
                println!("   Got {} links on attempt {}", links.len(), attempts);
                break;
            }
            Err(e) if e.is_busy() && attempts < 3 => {
                println!("   Busy, retrying...");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(e) => {
                println!("   Failed: {}", e);
                break;
            }
        }
    }

    println!("\nDone!");
    Ok(())
}

fn errno_name(errno: i32) -> &'static str {
    match errno {
        1 => "EPERM",
        2 => "ENOENT",
        3 => "ESRCH",
        13 => "EACCES",
        16 => "EBUSY",
        17 => "EEXIST",
        19 => "ENODEV",
        22 => "EINVAL",
        95 => "EOPNOTSUPP",
        _ => "?",
    }
}
