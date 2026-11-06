//! Read-only diagnosis: transport reachability is never reported as authorization.
use anyhow::Result;
use serde::Serialize;
use std::{net::SocketAddr, path::Path, time::Duration};
#[derive(Serialize)]
pub struct PathReport {
    pub path: crate::outbound::Candidate,
    pub tcp: &'static str,
    pub verified_tls: &'static str,
}
#[derive(Serialize)]
pub struct Report {
    pub inventory: serde_json::Value,
    pub dns: &'static str,
    pub paths: Vec<PathReport>,
    pub control: String,
    pub public_tunnel: String,
    pub private_network: String,
    pub relay: String,
    pub advice: Vec<&'static str>,
}
pub async fn diagnose(path: &Path) -> Result<Report> {
    let private = crate::private_network::is_profile(path)?;
    let control = if private {
        crate::control::Control::new_private(&crate::private_profile::Profile::load(path)?)?
    } else {
        crate::control::Control::new(crate::profile::Profile::load(path)?)?
    };
    let settings = crate::outbound::Settings::from_env()?;
    let url = url::Url::parse(&control.profile().server)?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("gateway hostname missing"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("gateway port missing"))?;
    let interfaces: Vec<_> = getifaddrs::getifaddrs()?.filter_map(|interface|interface.address.ip_addr().map(|address|serde_json::json!({"interface":interface.name,"index":interface.index,"address":address,"up":interface.flags.contains(getifaddrs::InterfaceFlags::UP)}))).take(256).collect();
    let mut inventory = serde_json::json!({"interfaces":interfaces});
    #[cfg(target_os = "linux")]
    {
        let kernel = nlink::netlink::Connection::<nlink::netlink::Route>::new()?;
        match tokio::time::timeout(Duration::from_secs(2),kernel.get_routes()).await {
            Ok(Ok(routes))=>inventory["routes"]=serde_json::json!(routes.iter().take(512).map(|route|serde_json::json!({"destination":route.destination(),"prefix":route.dst_len(),"gateway":route.gateway(),"interface_index":route.oif(),"table":route.table_id(),"metric":route.priority(),"type":format!("{:?}",route.route_type())})).collect::<Vec<_>>()),
            _=>inventory["routes_error"]=serde_json::json!("route inventory unavailable"),
        }
    }
    let mut report = Report {
        inventory,
        dns: "failed",
        paths: vec![],
        control: "not tested".into(),
        public_tunnel: "not observed".into(),
        private_network: "not observed".into(),
        relay: "not observed; requires an authorized live peer".into(),
        advice: vec![],
    };
    let destinations: Vec<SocketAddr> = match tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::lookup_host((host.trim_matches(['[', ']']), port)),
    )
    .await
    {
        Ok(Ok(addresses)) => {
            report.dns = "resolved";
            addresses.take(16).collect()
        }
        _ => {
            report.advice.push("Check the configured resolver and VPN DNS policy; DNS configuration was not changed.");
            vec![]
        }
    };
    let paths = tokio::time::timeout(
        Duration::from_secs(3),
        crate::outbound::discover(&settings, &destinations),
    )
    .await??;
    for candidate in paths.into_iter().take(8) {
        let socket = if candidate.source.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };
        let connected = match socket.bind(SocketAddr::new(candidate.source, 0)) {
            Ok(()) => matches!(
                tokio::time::timeout(
                    Duration::from_secs(2),
                    socket.connect(candidate.destination)
                )
                .await,
                Ok(Ok(_))
            ),
            Err(_) => false,
        };
        let mut tls = "not tested";
        if connected && url.scheme() == "https" {
            let http = reqwest::Client::builder()
                .local_address(candidate.source)
                .resolve_to_addrs(host, &[candidate.destination])
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(2))
                .timeout(Duration::from_secs(3))
                .build()?;
            // No enrollment credentials are sent to the homepage. Any HTTP
            // response proves verified TLS only, never agent connectivity.
            tls = if http
                .head(format!(
                    "{}://{}",
                    url.scheme(),
                    url[url::Position::BeforeHost..url::Position::AfterPort].to_owned()
                ))
                .send()
                .await
                .is_ok()
            {
                "verified"
            } else {
                "failed; check certificate trust, hostname, clock, or proxy"
            };
        }
        report.paths.push(PathReport {
            path: candidate,
            tcp: if connected {
                "connected"
            } else {
                "failed; check permitted source route and gateway firewall"
            },
            verified_tls: tls,
        });
    }
    report.control =
        match tokio::time::timeout(Duration::from_secs(40), control.log_requested()).await {
            Ok(Ok(_)) => "authenticated identity verified".into(),
            Ok(Err(error)) => error.to_string(),
            Err(_) => "authenticated request timed out".into(),
        };
    if let Ok(status) = crate::runtime::status(path) {
        report.public_tunnel = if private {
            "not configured in this profile".into()
        } else {
            format!(
                "{}; {} ports; route {}",
                status.state, status.service_count, status.route
            )
        };
        if let Some(details) = status.private_status {
            report.relay = match details.relay_ready {
                Some(true) => "authenticated carrier ready",
                Some(false) => "unavailable; check relay gateway and permitted source paths",
                None => "not observed by this agent version",
            }
            .into();
            report.private_network = details.display();
        }
    }
    #[cfg(target_os = "linux")]
    {
        report
            .advice
            .push(crate::private_prerequisites::dns_status());
        let resolver =
            std::path::Path::new("/usr/lib/systemd/system/systemd-resolved.service").exists();
        if !resolver {
            report.advice.push("Private DNS requires systemd-resolved. Install it using the administrator-approved package source, then start the service.");
        }
        if resolver {
            let active = tokio::process::Command::new("systemctl")
                .args(["is-active", "--quiet", "systemd-resolved.service"])
                .output();
            if !matches!(tokio::time::timeout(Duration::from_secs(2),active).await,Ok(Ok(output)) if output.status.success())
            {
                report.advice.push("systemd-resolved is installed but not active; ask the administrator to start it and check service restrictions.");
            }
        }
        let synchronized = tokio::process::Command::new("timedatectl")
            .args(["show", "--property=NTPSynchronized", "--value"])
            .output();
        if !matches!(tokio::time::timeout(Duration::from_secs(2),synchronized).await, Ok(Ok(output)) if output.status.success() && output.stdout.starts_with(b"yes"))
        {
            report.advice.push("Clock synchronization is unavailable or unconfirmed. Expired private-policy leases are rejected; check the configured NTP source.");
        }
    }
    if report.paths.is_empty() {
        report.advice.push("No eligible path: check explicit source/interface preferences and administrator routing policy. No host routes were changed.");
    }
    Ok(report)
}
