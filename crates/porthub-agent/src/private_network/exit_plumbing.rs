//! Local native intent projection, never a source of packet authorization.
use porthub_network::policy::{ExitRole, ExitRoute, PairLease, Snapshot};

pub(crate) fn provider_clients(view:&Snapshot,own:&str)->std::collections::BTreeSet<std::net::Ipv4Addr>{
    view.exit_routes.iter().filter(|route|route.routing_peers.iter().any(|peer|peer==own)).flat_map(|route|&route.clients)
        .filter_map(|id|view.peers.iter().find(|peer|&peer.id==id).map(|peer|peer.ip)).collect()
}

pub(crate) fn online_peers(view:&Snapshot)->std::collections::HashSet<String> {view.peers.iter().filter(|peer|peer.online).map(|peer|peer.id.clone()).collect()}

pub(crate) fn project(base: &Snapshot, leases: &[PairLease]) -> Snapshot {
    let mut projected = base.clone();
    let Some(sparse) = &base.sparse else {
        return projected;
    };
    let Some(own) = base.peers.iter().find(|peer| peer.id == base.self_) else {
        return projected;
    };
    for intent in &sparse.exit_intents {
        let mut clients = Vec::new();
        let mut routers = Vec::new();
        match intent.role {
            ExitRole::Client => clients.push(base.self_.clone()),
            ExitRole::Router => routers.push(base.self_.clone()),
        }
        for lease in leases {
            let Some(exit) = &lease.exit else {
                continue;
            };
            if lease.workspace != base.workspace
                || lease.self_ != base.self_
                || lease.local.id != own.id
                || lease.local.ip != own.ip
                || lease.local.fingerprint != own.fingerprint
                || lease.local.instance != own.instance
                || exit.route_id != intent.id
                || Some(exit.epoch.as_str()) != sparse.exit_epoch.as_deref()
                || exit.traffic_mode != intent.traffic_mode
            {
                continue;
            }
            match intent.role {
                ExitRole::Client if exit.client == base.self_ && exit.router == lease.peer.id => {
                    routers.push(lease.peer.id.clone())
                }
                ExitRole::Router if exit.router == base.self_ && exit.client == lease.peer.id => {
                    clients.push(lease.peer.id.clone())
                }
                _ => continue,
            }
            if !projected.peers.iter().any(|peer| peer.id == lease.peer.id) {
                projected.peers.push(lease.peer.clone());
            }
        }
        clients.sort();
        clients.dedup();
        routers.sort();
        routers.dedup();
        projected.exit_routes.push(ExitRoute {
            id: intent.id.clone(),
            name: intent.name.clone(),
            clients,
            routing_peers: routers,
            tor_enabled: intent.tor_enabled,
            tor_circuit_groups: intent.tor_circuit_groups,
            selection: intent.selection,
            traffic_mode: intent.traffic_mode,
            allow_direct_fallback: intent.allow_direct_fallback,
            masquerade: intent.masquerade,
            block_lan_access: intent.block_lan_access,
        });
    }
    projected
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixtures(role: ExitRole) -> (Snapshot, PairLease) {
        let peer = |id: &str, ip: &str| {
            serde_json::from_value(serde_json::json!({"id":id,"ip":ip,"fingerprint":format!("fp-{id}"),"instance":format!("instance-{id}"),"hostname":format!("{id}.phub")})).unwrap()
        };
        let base:Snapshot=serde_json::from_value(serde_json::json!({"workspace":"w","self":"a","revision":1,"expires_at":chrono::Utc::now()+chrono::Duration::seconds(30),"peers":[peer("a","10.203.0.2")],"grants":[],
            "sparse":{"protocol":1,"epoch":"a".repeat(64),"exit_epoch":"e".repeat(64),"selection_epoch":"c".repeat(64),"exit_intents":[{"id":"route","name":"Exit","role":role,"selection":"round_robin","traffic_mode":"all","allow_direct_fallback":false,"tor_enabled":false,"tor_circuit_groups":4,"masquerade":false,"block_lan_access":false,"lan_networks":["192.168.4.0/24"]}]}})).unwrap();
        let pair = PairLease {
            workspace: "w".into(),
            self_: "a".into(),
            epoch: "a".repeat(64),
            expires_at: base.expires_at,
            revision: 1,
            acl: None,
            grants: vec![],
            local: base.peers[0].clone(),
            peer: peer("b", "10.203.0.3"),
            exit: Some(porthub_network::policy::ExitPair {
                epoch: "e".repeat(64),
                route_id: "route".into(),
                client: if role == ExitRole::Client { "a" } else { "b" }.into(),
                router: if role == ExitRole::Router { "a" } else { "b" }.into(),
                traffic_mode: porthub_mesh::exit_policy::TrafficMode::All,
            }),
        };
        (base, pair)
    }
    #[test]
    fn projection_discovers_local_intent_without_granting_cached_subset_authority() {
        let (base, pair) = fixtures(ExitRole::Client);
        let empty = project(&base, &[]);
        assert_eq!(empty.exit_routes[0].clients, ["a"]);
        assert!(empty.exit_routes[0].routing_peers.is_empty());
        let active = project(&base, &[pair.clone()]);
        assert_eq!(active.exit_routes[0].routing_peers, ["b"]);
        assert_eq!(active.peers.len(), 2);
        assert!(active.grants.is_empty());
        assert!(!active.exit_routes[0].masquerade && !active.exit_routes[0].block_lan_access);
        assert!(base.exit_routes.is_empty());
        assert_eq!(base.peers.len(), 1);
        for change in 0..5 {
            let mut changed = pair.clone();
            match change {
                0 => changed.workspace = "foreign".into(),
                1 => changed.local.instance = "other".into(),
                2 => changed.exit.as_mut().unwrap().epoch = "f".repeat(64),
                3 => changed.exit.as_mut().unwrap().router = "other".into(),
                _ => changed.exit.as_mut().unwrap().route_id = "other".into(),
            };
            assert!(project(&base, &[changed]).exit_routes[0]
                .routing_peers
                .is_empty());
        }
    }
    #[test]
    fn router_nat_clients_follow_only_current_accepted_exit_metadata() {
        let (base, pair) = fixtures(ExitRole::Router);
        let active = project(&base, &[pair]);
        assert_eq!(active.exit_routes[0].routing_peers, ["a"]);
        assert_eq!(active.exit_routes[0].clients, ["b"]);
        assert!(project(&base, &[]).exit_routes[0].clients.is_empty());
    }
    #[test]
    fn projected_pair_metadata_survives_self_only_base_and_withdraws_offline_peer() {
        let(base,mut lease)=fixtures(porthub_network::policy::ExitRole::Client);
        assert_eq!(base.peers.len(),1);lease.peer.online=true;
        let projected=project(&base,&[lease.clone()]);let online=online_peers(&projected);
        assert!(online.contains(&lease.peer.id));assert!(!online_peers(&base).contains(&lease.peer.id));
        let route=&projected.exit_routes[0];let mut table=porthub_network::exit_selection::FlowTable::<u64>::new(base.self_.clone());
        table.configure(route.routing_peers.iter().filter(|id|online.contains(*id)).cloned(),route.selection);
        assert!(table.available(&lease.peer.id));
        lease.peer.online=false;let offline=project(&base,&[lease.clone()]);
        assert!(!online_peers(&offline).contains(&lease.peer.id),"offline projection must replace, not accumulate, old online markers");
    }
}
