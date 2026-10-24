//! Printable implementation for TcMessage.

use std::io::Write;

use crate::{
    netlink::messages::TcMessage,
    output::{OutputOptions, Printable},
};

impl Printable for TcMessage {
    fn print_text<W: Write>(&self, w: &mut W, opts: &OutputOptions) -> std::io::Result<()> {
        let dev = crate::util::get_ifname_or_index(self.ifindex());

        write!(
            w,
            "qdisc {} {} dev {} ",
            self.kind().unwrap_or(""),
            self.handle(),
            dev
        )?;

        let parent = self.parent();
        if parent.is_root() {
            write!(w, "root ")?;
        } else if parent.is_ingress() {
            write!(w, "ingress ")?;
        } else if !parent.is_unspec() {
            write!(w, "parent {} ", parent)?;
        }

        write!(w, "refcnt 2")?; // placeholder

        // The options in tc(8) syntax, as `tc qdisc show` prints them (#515).
        if let Some(options) = self.options() {
            let text = options.to_string();
            if !text.is_empty() {
                write!(w, " {text}")?;
            }
        }

        writeln!(w)?;

        if opts.stats {
            writeln!(
                w,
                " Sent {} bytes {} pkt (dropped {}, overlimits {} requeues {})",
                self.bytes(),
                self.packets(),
                self.drops(),
                self.overlimits(),
                self.requeues()
            )?;
            writeln!(w, " backlog {}b {}p", self.backlog(), self.qlen())?;
        }

        Ok(())
    }

    fn to_json(&self) -> serde_json::Value {
        let dev = crate::util::get_ifname_or_index(self.ifindex());

        serde_json::json!({
            "dev": dev,
            "kind": self.kind().unwrap_or(""),
            "handle": self.handle().to_string(),
            "parent": self.parent().to_string(),
            "bytes": self.bytes(),
            "packets": self.packets(),
            "drops": self.drops(),
            "overlimits": self.overlimits(),
            "requeues": self.requeues(),
            "qlen": self.qlen(),
            "backlog": self.backlog(),
        })
    }
}
