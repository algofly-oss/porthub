//! TC verbs with defined semantics: `conn.tc(dev).qdisc(parent)…` (#515).
//!
//! ```no_run
//! # async fn example() -> nlink::Result<()> {
//! # let conn = nlink::Connection::<nlink::Route>::new()?;
//! use std::time::Duration;
//! use nlink::netlink::tc::{HtbQdiscConfig, NetemConfig};
//! use nlink::netlink::tc_verbs::Parent;
//!
//! let eth0 = conn.tc("eth0");
//! eth0.qdisc(Parent::Root).handle(1).create(HtbQdiscConfig::new().default_class(0x10)).await?;
//! // Nothing happens when the live qdisc already is the spec.
//! let netem = NetemConfig::new().delay(Duration::from_millis(10));
//! eth0.qdisc(Parent::Root).apply(netem).await?;
//! eth0.qdisc(Parent::Root).delete().await?;
//! # Ok(())
//! # }
//! ```
//!
//! | verb | the slot is empty | the same kind | another kind |
//! |---|---|---|---|
//! | [`create`](QdiscAt::create) | creates | `EEXIST` | `EEXIST` |
//! | [`change`](QdiscAt::change) | not found | changed in place, or refused when the kind cannot change it | refused |
//! | [`replace`](QdiscAt::replace) | creates | changed in place, or recreated | replaced |
//! | [`apply`](QdiscAt::apply) | creates | nothing if it matches, else as `replace` | replaced |
//! | [`delete`](QdiscAt::delete) | not found | deleted | deleted |
//!
//! A replace never leaves the slot bare: a qdisc that cannot change in place
//! is grafted over, in the same request ([`Connection::replace_qdisc`]).

use super::{
    connection::Connection,
    error::{Error, ErrorObject, Result},
    interface_ref::InterfaceRef,
    messages::TcMessage,
    protocol::Route,
    tc::{InPlace, QdiscConfig},
    tc_handle::TcHandle,
    tc_spec::QdiscSpec,
};

/// Where a qdisc or filter hangs (#515).
///
/// The kernel names the ingress hook and the clsact qdisc with one value
/// (`TC_H_INGRESS == TC_H_CLSACT`), and a filter on a clsact with two more;
/// `TcHandle` makes them constants that are easy to mix up. These are the
/// places by what they are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Parent {
    /// The device's root: the qdisc slot egress traffic meets first.
    Root,
    /// The ingress hook, where an `ingress` or `clsact` qdisc sits; as a
    /// filter parent, an `ingress` qdisc.
    Ingress,
    /// A clsact's ingress hook, a filter parent.
    ClsactIngress,
    /// A clsact's egress hook, a filter parent.
    ClsactEgress,
    /// A class of a classful qdisc (`1:10`): the slot of its leaf qdisc.
    Class(TcHandle),
}

impl Parent {
    /// The kernel's value for it.
    pub const fn handle(self) -> TcHandle {
        match self {
            Self::Root => TcHandle::ROOT,
            Self::Ingress => TcHandle::INGRESS,
            Self::ClsactIngress => TcHandle::CLSACT_INGRESS,
            Self::ClsactEgress => TcHandle::CLSACT_EGRESS,
            Self::Class(h) => h,
        }
    }
}

impl From<TcHandle> for Parent {
    fn from(h: TcHandle) -> Self {
        match h {
            h if h == TcHandle::ROOT => Self::Root,
            h if h == TcHandle::INGRESS => Self::Ingress,
            h if h == TcHandle::CLSACT_INGRESS => Self::ClsactIngress,
            h if h == TcHandle::CLSACT_EGRESS => Self::ClsactEgress,
            h => Self::Class(h),
        }
    }
}

impl Connection<Route> {
    /// The TC verbs for `dev` (#515). See [`tc_verbs`](super::tc_verbs).
    pub fn tc(&self, dev: impl Into<InterfaceRef>) -> Tc<'_> {
        Tc {
            conn: self,
            dev: dev.into(),
        }
    }
}

/// One device's traffic control: [`Connection::tc`].
#[derive(Clone)]
pub struct Tc<'a> {
    conn: &'a Connection<Route>,
    dev: InterfaceRef,
}

#[nlink_macros::send_futures]
impl<'a> Tc<'a> {
    /// The qdisc slot at `parent`.
    pub fn qdisc(&self, parent: Parent) -> QdiscAt<'a> {
        QdiscAt {
            conn: self.conn,
            dev: self.dev.clone(),
            parent,
            handle: None,
        }
    }

    /// Every qdisc on the device.
    pub async fn qdiscs(&self) -> Result<Vec<TcMessage>> {
        let ifindex = self.conn.resolve_interface(&self.dev).await?;
        self.conn.get_qdiscs_by_index(ifindex).await
    }
}

/// A qdisc slot, and what to do with it: [`Tc::qdisc`].
#[derive(Clone)]
#[must_use = "a slot does nothing until a verb runs on it"]
pub struct QdiscAt<'a> {
    conn: &'a Connection<Route>,
    dev: InterfaceRef,
    parent: Parent,
    handle: Option<TcHandle>,
}

impl std::fmt::Debug for Tc<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tc")
            .field("dev", &self.dev)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for QdiscAt<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QdiscAt")
            .field("dev", &self.dev)
            .field("parent", &self.parent)
            .field("handle", &self.handle)
            .finish_non_exhaustive()
    }
}

#[nlink_macros::send_futures]
impl QdiscAt<'_> {
    /// The handle a new qdisc gets: its major (`1` for `1:`). Without one,
    /// a classful kind at the root gets `1:` and the others the kernel's
    /// choice.
    pub fn handle(mut self, major: u16) -> Self {
        self.handle = Some(TcHandle::major_only(major));
        self
    }

    async fn ifindex(&self) -> Result<u32> {
        self.conn.resolve_interface(&self.dev).await
    }

    /// The slot, for `Error::object` (#718).
    fn object(&self, kind: Option<&str>) -> ErrorObject {
        ErrorObject::Qdisc {
            dev: self.dev.to_string(),
            parent: Some(self.parent.handle().to_string()),
            kind: kind.map(str::to_string),
        }
    }

    /// The qdisc in the slot, if one was configured (the kernel's default
    /// root, handle 0, is not).
    pub async fn get(&self) -> Result<Option<TcMessage>> {
        let ifindex = self.ifindex().await?;
        let parent = self.parent.handle();
        Ok(self
            .conn
            .get_qdiscs_by_index(ifindex)
            .await?
            .into_iter()
            .find(|q| q.parent() == parent && q.handle().as_raw() != 0))
    }

    /// Create `spec` in the slot; `EEXIST` when it holds a configured
    /// qdisc already.
    pub async fn create(&self, spec: impl QdiscConfig) -> Result<()> {
        let object = self.object(Some(spec.kind()));
        let ifindex = self.ifindex().await?;
        self.conn
            .add_qdisc_by_index_full(ifindex, self.parent.handle(), self.handle, spec)
            .await
            .map_err(|e| e.refine_object(object))
    }

    /// Change the live qdisc's parameters to `spec`'s, in place.
    ///
    /// The slot must hold a qdisc of `spec`'s kind that can take the
    /// change: an empty slot is not found, and another kind, or one that
    /// only a recreate can change (htb, sfq, fq_codel with other `flows`),
    /// is refused — [`replace`](Self::replace) does those.
    pub async fn change(&self, spec: impl QdiscConfig) -> Result<()> {
        let object = self.object(Some(spec.kind()));
        self.change_unnamed(spec).await.map_err(|e| e.refine_object(object))
    }

    async fn change_unnamed(&self, spec: impl QdiscConfig) -> Result<()> {
        let Some(live) = self.get().await? else {
            return Err(Error::not_found(self.object(Some(spec.kind()))));
        };
        if live.kind() != Some(spec.kind()) {
            return Err(Error::not_supported(format!(
                "change: the qdisc at {:?} is {}, not {}; replace it",
                self.parent,
                live.kind().unwrap_or("?"),
                spec.kind()
            )));
        }
        if spec.in_place(&live) == InPlace::Recreate {
            return Err(Error::not_supported(format!(
                "change: this {} cannot be changed in place (no change operation, or a \
                 parameter only creation takes); replace it",
                spec.kind()
            )));
        }
        let ifindex = self.ifindex().await?;
        self.conn
            .change_qdisc_by_index_full(ifindex, self.parent.handle(), Some(live.handle()), spec)
            .await
    }

    /// Put `spec` in the slot, whatever is there: created, changed in place,
    /// or grafted over the live qdisc in one request
    /// ([`Connection::replace_qdisc`]).
    pub async fn replace(&self, spec: impl QdiscConfig) -> Result<()> {
        let object = self.object(Some(spec.kind()));
        let ifindex = self.ifindex().await?;
        self.conn
            .replace_qdisc_by_index_full(ifindex, self.parent.handle(), self.handle, spec)
            .await
            .map_err(|e| e.refine_object(object))
    }

    /// Make the slot hold `spec`: nothing when the live qdisc already is
    /// it ([`QdiscSpec::matches`]), else a [`replace`](Self::replace).
    /// Returns whether anything changed.
    pub async fn apply(&self, spec: impl Into<QdiscSpec>) -> Result<bool> {
        let spec = spec.into();
        if let Some(live) = self.get().await?
            && spec.matches(&live)
            && self.handle.is_none_or(|h| h == live.handle())
        {
            return Ok(false);
        }
        self.replace(spec).await?;
        Ok(true)
    }

    /// Delete whatever qdisc is in the slot. At [`Parent::Ingress`] that is
    /// an `ingress` or a `clsact`; [`delete_kind`](Self::delete_kind) names
    /// the one meant.
    pub async fn delete(&self) -> Result<()> {
        let ifindex = self.ifindex().await?;
        self.conn
            .del_qdisc_by_index_full(ifindex, self.parent.handle(), self.handle)
            .await
            .map_err(|e| e.refine_object(self.object(None)))
    }

    /// Delete the qdisc in the slot only if it is a `kind`; the kernel
    /// refuses another, and the error says what is there.
    pub async fn delete_kind(&self, kind: &str) -> Result<()> {
        let ifindex = self.ifindex().await?;
        self.conn
            .del_qdisc_kind_by_index(ifindex, self.parent.handle(), self.handle, kind)
            .await
            .map_err(|e| e.refine_object(self.object(Some(kind))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_parent_is_the_kernels_value_and_back() {
        for p in [
            Parent::Root,
            Parent::Ingress,
            Parent::ClsactIngress,
            Parent::ClsactEgress,
            Parent::Class(TcHandle::new(1, 0x10)),
        ] {
            assert_eq!(Parent::from(p.handle()), p);
        }
        // The kernel's one value for the ingress hook and the clsact qdisc.
        assert_eq!(Parent::from(TcHandle::CLSACT), Parent::Ingress);
    }
}
