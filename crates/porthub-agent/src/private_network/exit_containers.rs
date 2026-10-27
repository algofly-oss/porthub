//! Standard Docker bridges follow the host exit without changing Docker routes.
//! Conntrack pins forwarded connections across normal-internet fallback changes.
use super::exit_routes::{FIRST, PROTOCOL};
use anyhow::{ensure, Result};
use nlink::netlink::{
    nftables::{
        config::NftablesConfig, BaseChain, CtState, Family, FilterHook, NatHook, Priority, Rule,
        TcpFlags,
    },
    rule::RuleBuilder,
    Connection, Nftables,
};

fn table(name: &str) -> Result<String> {
    ensure!(
        name.len() == 10
            && name.starts_with("ph")
            && name[2..].bytes().all(|c| c.is_ascii_hexdigit()),
        "invalid container exit owner"
    );
    Ok(format!("porthub_containers_{name}"))
}
fn marks(index: u32) -> Result<(u32, u32)> {
    ensure!(
        index > 0 && index < 0x1000_0000,
        "invalid container exit interface"
    );
    Ok((0x5000_0000 | index, 0x6000_0000 | index))
}
pub(super) fn routes(index: u32, table: u32) -> Result<[RuleBuilder; 2]> {
    let (exit, direct) = marks(index)?;
    Ok([
        RuleBuilder::v4()
            .priority(FIRST + 66)
            .protocol(PROTOCOL)
            .fwmark(exit)
            .table(table),
        RuleBuilder::v4()
            .priority(FIRST + 67)
            .protocol(PROTOCOL)
            .fwmark(direct)
            .table(254),
    ])
}
pub(super) async fn apply(name: &str, index: u32, bypass: bool) -> Result<()> {
    let table = table(name)?;
    let (exit, direct) = marks(index)?;
    let selected = if bypass { direct } else { exit };
    let connection = Connection::<Nftables>::new()?;
    let config = NftablesConfig::new().table(&table, Family::Ip, |table| {
        table
            .chain("incoming", |chain| {
                chain
                    .base(BaseChain::filter(FilterHook::Prerouting, Priority::Mangle))
                    .exclusive()
            })
            .chain("classify", |chain| chain.exclusive())
            .chain("forward", |chain| {
                chain
                    .base(BaseChain::filter(FilterHook::Forward, Priority::Filter))
                    .exclusive()
            })
            .chain("nat", |chain| {
                chain
                    .base(BaseChain::nat(NatHook::Postrouting, Priority::SrcNat))
                    .exclusive()
            })
            // An explicit packet mark belongs to another router/VPN. Never
            // overwrite it or an existing foreign conntrack mark.
            .rule_keyed("incoming", "docker", |rule| {
                rule.match_iif_prefix("docker")
                    .match_mark(0)
                    .jump("classify".parse().unwrap())
            })
            .rule_keyed("incoming", "compose", |rule| {
                rule.match_iif_prefix("br-")
                    .match_mark(0)
                    .jump("classify".parse().unwrap())
            })
            .rule_keyed("classify", "existing_exit", |rule| {
                rule.match_ct_mark(exit).set_mark(exit).accept()
            })
            .rule_keyed("classify", "existing_direct", |rule| {
                rule.match_ct_mark(direct).set_mark(direct).accept()
            })
            // Keep pre-existing and incoming published-port connections on
            // their original route. Only new outgoing connections select exits.
            .rule_keyed("classify", "preserve_existing", |rule| {
                rule.match_ct_mark(0)
                    .match_ct_state(CtState::ESTABLISHED | CtState::RELATED)
                    .set_ct_mark(direct)
                    .set_mark(direct)
                    .accept()
            })
            .rule_keyed("classify", "new_connection", |rule| {
                rule.match_ct_mark(0)
                    .set_ct_mark(selected)
                    .set_mark(selected)
                    .accept()
            })
            // Bridged containers retain their own larger interface MTU. Bound
            // both SYN directions to the exit envelope before accepting them;
            // otherwise the remote sender's TLS records can exceed the tunnel
            // packet limit even though small requests and DNS work.
            .rule_keyed("forward", "mss_out", |rule| {
                rule.match_oif(name)
                    .match_ct_mark(exit)
                    .match_tcp_flags(TcpFlags::SYN, TcpFlags::SYN | TcpFlags::RST)
                    .clamp_tcp_mss((porthub_mesh::MAX_PACKET - 20 - 40) as u16)
            })
            .rule_keyed("forward", "mss_reply", |rule| {
                rule.match_iif(name)
                    .match_ct_mark(exit)
                    .match_tcp_flags(TcpFlags::SYN, TcpFlags::SYN | TcpFlags::RST)
                    .clamp_tcp_mss((porthub_mesh::MAX_PACKET - 20 - 40) as u16)
            })
            .rule_keyed("forward", "out", |rule| {
                rule.match_oif(name).match_ct_mark(exit).accept()
            })
            .rule_keyed("forward", "reply", |rule| {
                rule.match_iif(name)
                    .match_ct_mark(exit)
                    .match_ct_state(CtState::ESTABLISHED | CtState::RELATED)
                    .accept()
            })
            .rule_keyed("nat", "translate", |rule| {
                rule.match_oif(name).match_ct_mark(exit).masquerade()
            })
    });
    config.diff(&connection).await?.apply(&connection).await?;
    docker_rules(&connection, name, Some(exit)).await?;
    // Only the owned ephemeral TUN needs return-path forwarding. Existing
    // Docker bridge forwarding and global host sysctls remain managed by Docker.
    tokio::fs::write(format!("/proc/sys/net/ipv4/conf/{name}/forwarding"), b"1\n").await?;
    Ok(())
}
async fn docker_rules(
    connection: &Connection<Nftables>,
    name: &str,
    mark: Option<u32>,
) -> Result<()> {
    if !connection.list_chains().await?.iter().any(|chain| {
        chain.family == Family::Ip
            && chain.table == "filter"
            && chain.name == "DOCKER-USER"
            && chain.hook.is_none()
    }) {
        return Ok(());
    }
    let prefix = format!("porthub-container:{name}:");
    let current = connection.list_rules("filter", Family::Ip).await?;
    let current: Vec<_> = current
        .iter()
        .filter(|rule| rule.chain == "DOCKER-USER")
        .collect();
    let owned = |rule: &&nlink::netlink::nftables::RuleInfo| {
        rule.comment_text
            .as_deref()
            .is_some_and(|comment| comment.starts_with(&prefix))
    };
    let desired = mark
        .map(|mark| {
            vec![
                Rule::new("filter", "DOCKER-USER")
                    .family(Family::Ip)
                    .match_oif(name)
                    .match_ct_mark(mark)
                    .accept()
                    .comment(&format!("{prefix}out")),
                Rule::new("filter", "DOCKER-USER")
                    .family(Family::Ip)
                    .match_iif(name)
                    .match_ct_mark(mark)
                    .match_ct_state(CtState::ESTABLISHED | CtState::RELATED)
                    .accept()
                    .comment(&format!("{prefix}reply")),
            ]
        })
        .unwrap_or_default();
    if current.iter().filter(|rule| owned(rule)).count() == desired.len()
        && desired.iter().all(|wanted| {
            current.iter().any(|rule| {
                rule.comment_text.as_deref() == wanted.comment_ref()
                    && rule.nft_syntax() == wanted.nft_syntax()
            })
        })
    {
        return Ok(());
    }
    // Respect explicit user DROP rules, inserting only before Docker's RETURN.
    let before = current
        .iter()
        .find(|rule| !owned(rule) && rule.nft_syntax().as_deref() == Some("return"))
        .map(|rule| rule.handle);
    let mut transaction = connection.transaction();
    for rule in current.iter().filter(|rule| owned(rule)) {
        transaction = transaction.del_rule("filter", "DOCKER-USER", Family::Ip, rule.handle);
    }
    for rule in desired {
        transaction = match before {
            Some(handle) => transaction.insert_rule_before(rule, handle),
            None => transaction.add_rule(rule),
        };
    }
    transaction.commit(connection).await?;
    Ok(())
}
pub(super) async fn clear(name: &str) -> Result<()> {
    let connection = Connection::<Nftables>::new()?;
    docker_rules(&connection, name, None).await?;
    connection
        .del_table_if_exists(table(name)?.as_str(), Family::Ip)
        .await?;
    // The interface is exclusively owned and disappears with the registration.
    // It can also serve other exit clients; their forwarding stays available.
    Ok(())
}
