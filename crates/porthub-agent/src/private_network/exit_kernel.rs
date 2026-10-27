//! Linux exit NAT scoped to the registration's exclusively owned TUN.
//! Never flushes another table or changes global IP forwarding settings.
use anyhow::{ensure, Result};
use nlink::netlink::{
    nftables::{config::NftablesConfig, BaseChain, CtState, Family, FilterHook, NatHook, Priority, Rule},
    Connection, Nftables,
};
use std::{collections::BTreeSet, net::Ipv4Addr};

pub struct Kernel {
    connection: Connection<Nftables>,
    interface: String,
    table: String,
}

impl Kernel {
    pub fn new(interface: &str) -> Result<Self> {
        ensure!(
            interface.len() == 10
                && interface.starts_with("ph")
                && interface[2..].bytes().all(|c| c.is_ascii_hexdigit()),
            "invalid exit interface"
        );
        Ok(Self {
            connection: Connection::<Nftables>::new()?,
            interface: interface.into(),
            table: format!("porthub_exit_{interface}"),
        })
    }

    pub async fn apply(&self, clients: &BTreeSet<Ipv4Addr>) -> Result<()> {
        ensure!(
            clients.len() <= 4096 && clients.iter().all(Ipv4Addr::is_private),
            "invalid exit clients"
        );
        if clients.is_empty() {
            return self.clear().await;
        }
        let rules = NftablesConfig::new().table(&self.table, Family::Ip, |mut table| {
            table = table
                .chain("forward", |chain| {
                    chain
                        .base(BaseChain::filter(FilterHook::Forward, Priority::Filter))
                        .exclusive()
                })
                .chain("nat", |chain| {
                    chain
                        .base(BaseChain::nat(NatHook::Postrouting, Priority::SrcNat))
                        .exclusive()
                });
            for client in clients {
                table = table
                    .rule_keyed("forward", format!("out_{client}"), |rule| {
                        rule.match_iif(&self.interface)
                            .match_oif_not(&self.interface)
                            .match_saddr_v4(*client, 32)
                            .accept()
                    })
                    .rule_keyed("forward", format!("in_{client}"), |rule| {
                        rule.match_oif(&self.interface)
                            .match_daddr_v4(*client, 32)
                            .match_ct_state(CtState::ESTABLISHED | CtState::RELATED)
                            .accept()
                    })
                    .rule_keyed("nat", format!("masq_{client}"), |rule| {
                        rule.match_iif(&self.interface)
                            .match_oif_not(&self.interface)
                            .match_saddr_v4(*client, 32)
                            .masquerade()
                    });
            }
            table
        });
        super::nft::apply(&rules, &self.connection).await?;
        self.docker_forwarding(clients).await?;
        super::exit_forwarding::update(&self.interface, true).await?;
        // Per-interface forwarding is sufficient for packets entering this TUN.
        // The setting disappears with the nonpersistent TUN on process exit.
        if let Err(error) = tokio::fs::write(
            format!("/proc/sys/net/ipv4/conf/{}/forwarding", self.interface),
            b"1\n",
        )
        .await
        {
            let _ = self
                .connection
                .del_table_if_exists(self.table.as_str(), Family::Ip)
                .await;
            return Err(error.into());
        }
        Ok(())
    }

    // Docker's iptables-nft FORWARD policy also evaluates packets accepted by
    // our own table. Use its documented extension chain, preserving every
    // foreign rule and the host's default drop policy.
    pub(super) async fn docker_forwarding(&self, clients: &BTreeSet<Ipv4Addr>) -> Result<()> {
        let _lock = super::exit_forwarding::lock().await?;
        let chains = self.connection.list_chains().await?;
        if !chains.iter().any(|chain| chain.family == Family::Ip
            && chain.table == "filter" && chain.name == "DOCKER-USER" && chain.hook.is_none()) {
            return Ok(());
        }
        let prefix = format!("porthub-exit:{}:", self.interface);
        let current = self.connection.list_rules("filter", Family::Ip).await?;
        let current = current.iter().filter(|rule| rule.chain == "DOCKER-USER").collect::<Vec<_>>();
        let owned = |rule: &&nlink::netlink::nftables::RuleInfo| rule.comment_text.as_deref().is_some_and(|text| text.starts_with(&prefix));
        let mut desired = Vec::new();
        for client in clients {
            desired.push(Rule::new("filter", "DOCKER-USER").family(Family::Ip)
                .match_iif(&self.interface).match_oif_not(&self.interface)
                .match_saddr_v4(*client, 32).accept().comment(&format!("{prefix}out:{client}")));
            desired.push(Rule::new("filter", "DOCKER-USER").family(Family::Ip)
                .match_oif(&self.interface).match_daddr_v4(*client, 32)
                .match_ct_state(CtState::ESTABLISHED | CtState::RELATED)
                .accept().comment(&format!("{prefix}in:{client}")));
        }
        if current.iter().filter(|rule| owned(rule)).count() == desired.len()
            && desired.iter().all(|wanted| current.iter().any(|rule|
                rule.comment_text.as_deref() == wanted.comment_ref() && rule.nft_syntax() == wanted.nft_syntax())) {
            return Ok(());
        }
        // Older Docker versions end this chain with RETURN. Insert immediately
        // before it, after user restrictions; never bypass an administrator's DROP.
        let before = current.iter().find(|rule| !owned(rule)
            && rule.nft_syntax().as_deref() == Some("return")).map(|rule| rule.handle);
        let mut transaction = self.connection.transaction();
        for rule in current.iter().filter(|rule| owned(rule)) {
            transaction = transaction.del_rule("filter", "DOCKER-USER", Family::Ip, rule.handle);
        }
        for rule in desired {
            transaction = match before {
                Some(handle) => transaction.insert_rule_before(rule, handle),
                None => transaction.add_rule(rule),
            };
        }
        transaction.commit(&self.connection).await?;
        Ok(())
    }

    pub async fn clear(&self) -> Result<()> {
        self.docker_forwarding(&BTreeSet::new()).await?;
        // Removing NAT first prevents new translated flows even if the interface
        // has already disappeared and its per-interface setting cannot be reset.
        self.connection
            .del_table_if_exists(self.table.as_str(), Family::Ip)
            .await?;
        let path = format!("/proc/sys/net/ipv4/conf/{}/forwarding", self.interface);
        let restore = super::exit_forwarding::update(&self.interface, false).await;
        let reset = match tokio::fs::write(path, b"0\n").await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        };
        restore?;
        reset
    }
}
