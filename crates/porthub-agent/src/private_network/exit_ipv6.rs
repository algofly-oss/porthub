//! An IPv4 exit must not silently leak new internet connections over IPv6.
//! Filter packets rather than source-address routing: Linux may select an IPv6
//! source before policy lookup, including for a socket that was never bound.
use anyhow::{ensure, Result};
use nlink::netlink::{
    nftables::{config::NftablesConfig, BaseChain, CtState, Family, FilterHook, Priority},
    Connection, Nftables, Route,
};
use std::{collections::BTreeSet, net::IpAddr};

fn table(name: &str) -> Result<String> {
    ensure!(
        name.len() == 10
            && name.starts_with("ph")
            && name[2..].bytes().all(|c| c.is_ascii_hexdigit()),
        "invalid exit owner"
    );
    Ok(format!("porthub_exit6_{name}"))
}

pub async fn apply(routes: &Connection<Route>, name: &str) -> Result<()> {
    apply_mode(routes, name, false).await
}

pub async fn apply_mode(routes: &Connection<Route>, name: &str, bypass: bool) -> Result<()> {
    let name = table(name)?;
    // Preserve directly attached LAN prefixes, not routes through another
    // gateway (which could include a split default such as two /1 routes).
    let mut local = BTreeSet::new();
    for route in routes.get_routes_for_table(254).await? {
        if route.dst_len() > 0 && route.gateway().is_none() && route.oif().is_some() {
            if let Some(IpAddr::V6(address)) = route.destination() {
                local.insert((*address, route.dst_len()));
            }
        }
    }
    ensure!(local.len() <= 4096, "too many local IPv6 routes");
    let connection = Connection::<Nftables>::new()?;
    let rules = NftablesConfig::new().table(&name, Family::Ip6, |table| {
        let mut table = table
            .chain("output", |chain| {
                chain
                    .base(BaseChain::filter(FilterHook::Output, Priority::Filter))
                    .exclusive()
            })
            .chain("forward", |chain| {
                chain
                    .base(BaseChain::filter(FilterHook::Forward, Priority::Filter))
                    .exclusive()
            })
            .chain("containers", |chain| chain.exclusive())
            .rule_keyed("forward", "docker", |rule| {
                rule.match_iif_prefix("docker")
                    .jump("containers".parse().unwrap())
            })
            .rule_keyed("forward", "compose", |rule| {
                rule.match_iif_prefix("br-")
                    .jump("containers".parse().unwrap())
            });
        for chain in ["output", "containers"] {
            table = table
                .rule_keyed(chain, "established", |rule| {
                    rule.match_ct_state(CtState::ESTABLISHED | CtState::RELATED)
                        .accept()
                })
                .rule_keyed(chain, "loopback", |rule| rule.match_oif("lo").accept())
                .rule_keyed(chain, "link_local", |rule| {
                    rule.match_daddr_v6("fe80::".parse().unwrap(), 10).accept()
                })
                .rule_keyed(chain, "multicast", |rule| {
                    rule.match_daddr_v6("ff00::".parse().unwrap(), 8).accept()
                });
            for (address, prefix) in &local {
                table = table.rule_keyed(chain, format!("lan_{address}_{prefix}"), |rule| {
                    rule.match_daddr_v6(*address, *prefix).accept()
                });
            }
            table = if bypass {
                // Preserve connection tracking while allowing opt-in fallback.
                table.rule_keyed(chain, "allow_direct_fallback", |rule| rule.accept())
            } else {
                table.rule_keyed(chain, "reject_new_internet", |rule| rule.reject())
            };
        }
        table
    });
    rules.diff(&connection).await?.apply(&connection).await?;
    Ok(())
}

pub async fn clear(name: &str) -> Result<()> {
    Connection::<Nftables>::new()?
        .del_table_if_exists(table(name)?.as_str(), Family::Ip6)
        .await?;
    Ok(())
}
