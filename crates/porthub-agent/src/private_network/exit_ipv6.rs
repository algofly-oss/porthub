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
            .rule_keyed("output", "established", |rule| {
                rule.match_ct_state(CtState::ESTABLISHED | CtState::RELATED)
                    .accept()
            })
            .rule_keyed("output", "loopback", |rule| rule.match_oif("lo").accept())
            .rule_keyed("output", "link_local", |rule| {
                rule.match_daddr_v6("fe80::".parse().unwrap(), 10).accept()
            })
            .rule_keyed("output", "multicast", |rule| {
                rule.match_daddr_v6("ff00::".parse().unwrap(), 8).accept()
            });
        for (address, prefix) in local {
            table = table.rule_keyed("output", format!("lan_{address}_{prefix}"), |rule| {
                rule.match_daddr_v6(address, prefix).accept()
            });
        }
        if bypass {
            // Retain the conntrack rule and hooks while allowing new traffic,
            // so direct connections remain established when exit routing resumes.
            table.rule_keyed("output", "allow_direct_fallback", |rule| rule.accept())
        } else {
            table.rule_keyed("output", "reject_new_internet", |rule| rule.reject())
        }
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
