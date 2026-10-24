//! Blocking access to netlink, for code that cannot `.await` (#533): a
//! `Drop` that undoes what it made, a synchronous test runner, a CLI with
//! no runtime of its own.
//!
//! A [`Connection`] owns a worker thread with a current-thread tokio
//! runtime and the async [`crate::Connection`] on it. A call sends the
//! work there and waits on a channel, so it never starts a runtime on the
//! calling thread: it is safe in plain synchronous code and in a `Drop`
//! that runs inside a tokio runtime, where `Runtime::block_on` panics
//! ("Cannot start a runtime from within a runtime"). The calling thread is
//! blocked meanwhile; on a single-threaded runtime that is every task, for
//! as long as the call takes.
//!
//! [`Connection::run`] takes any async work against the connection; the
//! common dumps and the `del_*_if_exists` deletes have methods of their
//! own.
//!
//! ```no_run
//! # fn example() -> nlink::Result<()> {
//! use nlink::Route;
//! use nlink::blocking::Connection;
//!
//! /// Deletes the link it made, even when dropped inside a tokio runtime.
//! struct LinkGuard {
//!     conn: Connection<Route>,
//!     name: String,
//! }
//!
//! impl Drop for LinkGuard {
//!     fn drop(&mut self) {
//!         let _ = self.conn.del_link_if_exists(&self.name);
//!     }
//! }
//!
//! let conn = Connection::<Route>::new()?;
//! for link in conn.get_links()? {
//!     println!("{}", link.name_or("?"));
//! }
//! // Anything else the async connection does:
//! let mtu = conn.run(|c| Box::pin(async move {
//!     Ok::<_, nlink::Error>(c.get_link_by_name("lo").await?.and_then(|l| l.mtu()))
//! }))?;
//! # let _ = mtu;
//! # Ok(())
//! # }
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::mpsc;
use std::thread;

use crate::netlink::messages::{AddressMessage, LinkMessage, RouteMessage, TcMessage};
use crate::netlink::namespace::NetnsRef;
use crate::netlink::{ProtocolState, construction::SyncConstructible};
use crate::netlink::{Nftables, Route};
use crate::{Error, Result, TcHandle};

/// Work for the worker: run against the connection on its runtime.
type Job<P> = Box<dyn FnOnce(&crate::Connection<P>, &tokio::runtime::Runtime) + Send>;

/// A synchronous handle on a [`crate::Connection`], run on a worker thread
/// of its own. See the [module docs](self).
pub struct Connection<P: ProtocolState> {
    jobs: Option<mpsc::Sender<Job<P>>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl<P> Connection<P>
where
    P: ProtocolState + Default + SyncConstructible + 'static,
{
    /// A connection in the calling process's namespace.
    pub fn new() -> Result<Self> {
        Self::spawn(crate::Connection::<P>::new)
    }

    /// A connection in the namespace `netns` names.
    pub fn in_netns(netns: NetnsRef) -> Result<Self> {
        Self::spawn(move || netns.open()?.connection::<P>())
    }
}

impl<P: ProtocolState + 'static> Connection<P> {
    /// Start the worker, make the connection there with `make`, and wait
    /// until it is made.
    fn spawn(make: impl FnOnce() -> Result<crate::Connection<P>> + Send + 'static) -> Result<Self> {
        let (jobs, inbox) = mpsc::channel::<Job<P>>();
        let (ready, started) = mpsc::channel::<Result<()>>();
        let worker = thread::Builder::new()
            .name("nlink-blocking".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = ready.send(Err(Error::from(e)));
                        return;
                    }
                };
                // The socket registers with this runtime's reactor.
                let made = {
                    let _entered = rt.enter();
                    make()
                };
                let conn = match made {
                    Ok(conn) => conn,
                    Err(e) => {
                        let _ = ready.send(Err(e));
                        return;
                    }
                };
                let _ = ready.send(Ok(()));
                for job in inbox {
                    job(&conn, &rt);
                }
            })
            .map_err(Error::from)?;
        match started.recv() {
            Ok(Ok(())) => Ok(Self {
                jobs: Some(jobs),
                worker: Some(worker),
            }),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(Error::invalid_message("the blocking connection's worker died starting")),
        }
    }

    /// Run `f` against the async connection on the worker, and wait for
    /// what it returns. The future need not be `Send`: it runs where the
    /// connection lives.
    ///
    /// # Panics
    ///
    /// If `f` panicked on the worker, which is then gone; so does every
    /// call after it.
    pub fn run<T, F>(&self, f: F) -> T
    where
        T: Send + 'static,
        F: for<'c> FnOnce(&'c crate::Connection<P>) -> Pin<Box<dyn Future<Output = T> + 'c>> + Send + 'static,
    {
        let (answer, answered) = mpsc::channel();
        let job: Job<P> = Box::new(move |conn, rt| {
            let _ = answer.send(rt.block_on(f(conn)));
        });
        self.jobs
            .as_ref()
            .expect("the sender lives until drop")
            .send(job)
            .expect("the blocking connection's worker is gone: an earlier call panicked");
        answered
            .recv()
            .expect("the blocking connection's worker is gone: the call panicked")
    }
}

impl<P: ProtocolState> Drop for Connection<P> {
    fn drop(&mut self) {
        // The worker ends when its inbox closes.
        drop(self.jobs.take());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl<P: ProtocolState> std::fmt::Debug for Connection<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("blocking::Connection")
            .field("protocol", &std::any::type_name::<P>())
            .finish_non_exhaustive()
    }
}

impl Connection<Route> {
    /// Every link.
    pub fn get_links(&self) -> Result<Vec<LinkMessage>> {
        self.run(|c| Box::pin(c.get_links()))
    }

    /// Every address.
    pub fn get_addresses(&self) -> Result<Vec<AddressMessage>> {
        self.run(|c| Box::pin(c.get_addresses()))
    }

    /// Every route.
    pub fn get_routes(&self) -> Result<Vec<RouteMessage>> {
        self.run(|c| Box::pin(c.get_routes()))
    }

    /// Every qdisc.
    pub fn get_qdiscs(&self) -> Result<Vec<TcMessage>> {
        self.run(|c| Box::pin(c.get_qdiscs()))
    }

    /// Delete link `name`: `Ok(false)` if it was not there.
    pub fn del_link_if_exists(&self, name: &str) -> Result<bool> {
        let name = name.to_string();
        self.run(move |c| Box::pin(async move { c.del_link_if_exists(name.as_str()).await }))
    }

    /// Delete an address from link `dev`: `Ok(false)` if it was not there.
    pub fn del_address_if_exists(&self, dev: &str, address: std::net::IpAddr, prefix_len: u8) -> Result<bool> {
        let dev = dev.to_string();
        self.run(move |c| {
            Box::pin(async move { c.del_address_if_exists(dev.as_str(), address, prefix_len).await })
        })
    }

    /// Delete the qdisc at `parent` on `dev`: `Ok(false)` if there was none.
    pub fn del_qdisc_if_exists(&self, dev: &str, parent: TcHandle) -> Result<bool> {
        let dev = dev.to_string();
        self.run(move |c| Box::pin(async move { c.del_qdisc_if_exists(dev.as_str(), parent).await }))
    }

    /// Delete a route: `Ok(false)` if it was not there.
    pub fn del_route_if_exists<R: crate::RouteConfig + Send + 'static>(&self, route: R) -> Result<bool> {
        self.run(move |c| Box::pin(async move { c.del_route_if_exists(route).await }))
    }
}

impl Connection<Nftables> {
    /// Every table.
    pub fn list_tables(&self) -> Result<Vec<crate::netlink::nftables::Table>> {
        self.run(|c| Box::pin(c.list_tables()))
    }

    /// The rules of a table, with their counters.
    pub fn list_rules(
        &self,
        table: &str,
        family: crate::netlink::nftables::Family,
    ) -> Result<Vec<crate::netlink::nftables::RuleInfo>> {
        let table = table.to_string();
        self.run(move |c| Box::pin(async move { c.list_rules(&table, family).await }))
    }

    /// Delete a table, and everything in it: `Ok(false)` if it was not
    /// there.
    pub fn del_table_if_exists(&self, name: &str, family: crate::netlink::nftables::Family) -> Result<bool> {
        let name = name.to_string();
        self.run(move |c| Box::pin(async move { c.del_table_if_exists(name.as_str(), family).await }))
    }
}
