//! Native netlink rules, with atomic reconciliation and persistent counters.
//! Never requests a global flush or purges other tables.
use crate::Policy;
use anyhow::{ensure, Result};
use nlink::netlink::{
    nftables::{
        config::NftablesConfig, BaseChain, CtState, Family, FilterHook, ObjectConfig, ObjectState,
        PacketField, Priority, SetElement, SetKeyType,
    },
    Connection, Nftables,
};
use std::{collections::BTreeMap, time::Duration};

pub fn rules(
    policies: &BTreeMap<u16, Policy>,
    table: &str,
    ttl: Duration,
) -> Result<NftablesConfig> {
    ensure!(
        table == "porthub" || table.starts_with("porthub_") || table == "rathole",
        "firewall table must belong to PortHub"
    );
    ensure!(
        table.len() <= 64
            && table
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
        "invalid PortHub table name"
    );
    ensure!(
        ttl.as_secs() > 0 && ttl.as_secs() <= 86400,
        "invalid recent-address timeout"
    );
    for (&port, policy) in policies {
        ensure!(port > 0, "invalid firewall port");
        ensure!(
            policy.allowed_ips.len() <= 4096,
            "too many allowed addresses"
        );
        ensure!(
            !policy.is_public || policy.allowed_ips.is_empty(),
            "public policies cannot contain an allowlist"
        );
    }
    Ok(NftablesConfig::new().table(table, Family::Inet, |mut t| {
        t = t
            .chain("input", |c| {
                c.base(BaseChain::filter(FilterHook::Input, Priority::Filter))
                    .exclusive()
            })
            .chain("output", |c| {
                c.base(BaseChain::filter(FilterHook::Output, Priority::Filter))
                    .exclusive()
            });
        for (&port, policy) in policies {
            let incoming = format!("cnt_in_{port}");
            let outgoing = format!("cnt_out_{port}");
            let dropped = format!("cnt_drop_{port}");
            let recent = format!("recent_{port}");
            let recent_out = format!("recent_out_{port}");
            for name in [&incoming, &outgoing, &dropped] {
                t = t.object(name, ObjectConfig::Counter);
            }
            for name in [&recent, &recent_out] {
                t = t.set(name, |s| {
                    s.key_type(SetKeyType::Ipv4Addr)
                        .dynamic()
                        .size(4096)
                        .timeout(ttl)
                });
            }
            t = t.rule_keyed("input", format!("recent_{port}"), |r| {
                r.match_tcp_dport(port)
                    .match_ct_state(CtState::NEW)
                    .update_in_set(PacketField::Ip4Saddr, &recent, Some(ttl))
            });
            if !policy.allowed_ips.is_empty() {
                let allow = format!("allow_{port}");
                let blocked = format!("blocked_{port}");
                t = t
                    .set(&allow, |s| {
                        s.key_type(SetKeyType::Ipv4Addr)
                            .elements(policy.allowed_ips.iter().copied().map(SetElement::ipv4))
                    })
                    .set(&blocked, |s| {
                        s.key_type(SetKeyType::Ipv4Addr)
                            .dynamic()
                            .size(4096)
                            .timeout(ttl)
                    })
                    .rule_keyed("input", format!("allow_{port}"), |r| {
                        r.match_tcp_dport(port)
                            .match_saddr_in_set(&allow)
                            .counter_named(&incoming)
                            .accept()
                    })
                    .rule_keyed("input", format!("track_blocked_{port}"), |r| {
                        r.match_tcp_dport(port)
                            .match_ct_state(CtState::NEW)
                            .update_in_set(PacketField::Ip4Saddr, &blocked, Some(ttl))
                    })
                    .rule_keyed("input", format!("drop_{port}"), |r| {
                        r.match_tcp_dport(port).counter_named(&dropped).drop()
                    });
            } else {
                // Preserve the existing policy contract: an empty allowlist
                // does not restrict the port, even if its metadata is private.
                t = t.rule_keyed("input", format!("allow_{port}"), |r| {
                    r.match_tcp_dport(port).counter_named(&incoming).accept()
                });
            }
            t = t
                .rule_keyed("output", format!("recent_out_{port}"), |r| {
                    r.match_tcp_sport(port).update_in_set(
                        PacketField::Ip4Daddr,
                        &recent_out,
                        Some(ttl),
                    )
                })
                .rule_keyed("output", format!("count_out_{port}"), |r| {
                    r.match_tcp_sport(port).counter_named(&outgoing).accept()
                });
        }
        t
    }))
}

pub struct Kernel {
    connection: Connection<Nftables>,
    table: String,
    ttl: Duration,
}
impl Kernel {
    pub fn new(table: &str, ttl: Duration) -> Result<Self> {
        rules(&BTreeMap::new(), table, ttl)?;
        Ok(Self {
            connection: Connection::<Nftables>::new()?,
            table: table.into(),
            ttl,
        })
    }
    pub async fn apply(&self, policies: &BTreeMap<u16, Policy>) -> Result<usize> {
        let config = rules(policies, &self.table, self.ttl)?;
        let diff = config.diff(&self.connection).await?;
        Ok(diff.apply(&self.connection).await?)
    }
    pub async fn counters(&self) -> Result<BTreeMap<String, u64>> {
        let mut counters = BTreeMap::new();
        for object in self
            .connection
            .list_objects_in(&self.table, Family::Inet)
            .await?
        {
            if let ObjectState::Counter { bytes, .. } = object.state {
                counters.insert(object.name, bytes);
            }
        }
        Ok(counters)
    }
}

impl Kernel {
    pub async fn recent(
        &self,
        port: u16,
        direction: &str,
        window: Duration,
    ) -> Result<Vec<String>> {
        let prefix = match direction {
            "in" => "recent",
            "out" => "recent_out",
            "drop" => "blocked",
            _ => anyhow::bail!("invalid firewall counter direction"),
        };
        let elements = self
            .connection
            .list_set_elements(&self.table, &format!("{prefix}_{port}"), Family::Inet)
            .await?;
        let mut ips = Vec::new();
        for element in elements {
            if element
                .expiration()
                .is_some_and(|left| left.saturating_add(window) < self.ttl)
            {
                continue;
            }
            if let Ok(bytes) = <[u8; 4]>::try_from(element.key()) {
                ips.push(std::net::Ipv4Addr::from(bytes).to_string());
            }
        }
        ips.sort();
        ips.dedup();
        Ok(ips)
    }
}
