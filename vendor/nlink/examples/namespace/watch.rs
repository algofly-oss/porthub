//! Watch for namespace creation and deletion.
//!
//! This example demonstrates how to monitor network namespace lifecycle
//! events using the NamespaceWatcher (inotify-based) API.
//!
//! Run with: cargo run -p nlink --features namespace_watcher --example namespace_watch
//!
//! Then in another terminal:
//!   sudo ip netns add test1
//!   sudo ip netns del test1

#[cfg(feature = "namespace_watcher")]
use nlink::netlink::{NamespaceEvent, NamespaceWatcher};

#[cfg(feature = "namespace_watcher")]
#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    println!("Watching for namespace changes (Ctrl+C to stop)...\n");

    // Option 1: List existing namespaces and start watching atomically
    // This prevents race conditions where a namespace could be missed
    let (existing, mut watcher) = NamespaceWatcher::list_and_watch().await?;

    if existing.is_empty() {
        println!("No existing namespaces found.");
    } else {
        println!("Existing namespaces:");
        for ns in &existing {
            println!("  {}", ns);
        }
    }
    println!();
    println!("Watching for changes...");
    println!("{}", "-".repeat(40));

    while let Some(event) = watcher.recv().await? {
        match event {
            NamespaceEvent::Created { name } => {
                println!("[+] Namespace created: {}", name);
            }
            NamespaceEvent::Deleted { name } => {
                println!("[-] Namespace deleted: {}", name);
            }
            NamespaceEvent::DirectoryCreated => {
                println!("[*] /var/run/netns/ directory created");
            }
            NamespaceEvent::DirectoryDeleted => {
                println!("[*] /var/run/netns/ directory deleted");
            }
            // The enum is non_exhaustive — handle future variants gracefully.
            other => {
                println!("[?] Unknown event: {:?}", other);
            }
        }
    }

    Ok(())
}

#[cfg(not(feature = "namespace_watcher"))]
fn main() {
    eprintln!("This example requires the 'namespace_watcher' feature.");
    eprintln!(
        "Run with: cargo run -p nlink --features namespace_watcher --example namespace_watch"
    );
}
