//! Linux exit NAT scoped to the registration's exclusively owned TUN.
//! Never flushes another table or changes global IP forwarding settings.
use anyhow::{ensure, Result};
use nlink::netlink::{
    nftables::{config::NftablesConfig, BaseChain, CtState, Family, FilterHook, NatHook, Priority},
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
        rules
            .diff(&self.connection)
            .await?
            .apply(&self.connection)
            .await?;
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

    pub async fn clear(&self) -> Result<()> {
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
