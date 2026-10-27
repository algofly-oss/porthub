//! Accept the URL-based configurations emitted by PortHub, while preserving
//! upstream typed Rathole configuration. Endpoint choice happens outside data
//! forwarding; each resulting config names one endpoint for all session channels.
use crate::Config;
use anyhow::{Context, Result};
use std::time::{Duration, Instant};
use url::Url;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteKind {
    Primary,
    Fallback,
    Origin,
}
#[derive(Clone)]
pub struct Candidate {
    pub config: Config,
    pub kind: RouteKind,
    pub endpoint: String,
}
impl std::fmt::Debug for Candidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Candidate")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}
impl Candidate {
    pub async fn probe(&self, timeout: Duration) -> Result<Duration> {
        let start = Instant::now();
        tokio::time::timeout(
            timeout,
            rathole::probe_client_transport(self.config.clone()),
        )
        .await
        .context("tunnel reachability check timed out")??;
        Ok(start.elapsed())
    }
}
#[derive(Clone, Debug)]
pub struct ClientPlan {
    pub candidates: Vec<Candidate>,
}
impl ClientPlan {
    /// Applies only to gateway transport sockets, never the forwarded service.
    pub fn bind_source(&mut self, source: std::net::IpAddr) {
        for candidate in &mut self.candidates {
            if let Some(client) = &mut candidate.config.client { client.transport.tcp.source_address = Some(source); }
        }
    }
}
fn string(table: &mut toml::value::Table, key: &str) -> Result<Option<String>> {
    match table.remove(key) {
        None => Ok(None),
        Some(toml::Value::String(value)) => Ok(Some(value)),
        _ => anyhow::bail!("{key} must be a string"),
    }
}
fn url(value: &str) -> Result<Url> {
    let url = Url::parse(value).context("invalid tunnel endpoint")?;
    anyhow::ensure!(
        ["http", "https", "ws", "wss"].contains(&url.scheme())
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "invalid tunnel endpoint"
    );
    Ok(url)
}
fn table(value: &mut toml::Value) -> Result<&mut toml::value::Table> {
    value.as_table_mut().context("invalid client configuration")
}
fn candidate(
    template: &toml::Value,
    endpoint: &str,
    kind: RouteKind,
    pin: Option<&str>,
    host: Option<&str>,
) -> Result<Candidate> {
    let mut value = template.clone();
    let client = table(value.get_mut("client").context("missing client section")?)?;
    if endpoint.contains("://") {
        let parsed = url(endpoint)?;
        let tls = ["https", "wss"].contains(&parsed.scheme());
        anyhow::ensure!(
            pin.is_none() || tls,
            "origin pin requires encrypted transport"
        );
        let address = format!(
            "{}:{}",
            parsed.host().context("missing endpoint host")?,
            parsed
                .port_or_known_default()
                .context("missing endpoint port")?
        );
        client.insert("remote_addr".into(), address.into());
        let transport = client
            .entry("transport")
            .or_insert_with(|| toml::Value::Table(Default::default()));
        let transport = table(transport)?;
        let mode = transport
            .get("type")
            .and_then(toml::Value::as_str)
            .unwrap_or("tcp");
        anyhow::ensure!(
            ["tcp", "websocket"].contains(&mode),
            "URL endpoints require TCP or websocket transport"
        );
        transport.insert("type".into(), "websocket".into());
        let mut path = parsed.path().to_owned();
        if let Some(query) = parsed.query() {
            path.push('?');
            path.push_str(query);
        }
        let mut websocket = toml::value::Table::new();
        websocket.insert("tls".into(), tls.into());
        websocket.insert("path".into(), path.into());
        websocket.insert("porthub_framing".into(), true.into());
        // CDN-compatible WebSocket is the canonical default; direct HTTP(S)
        // endpoints can use the bounded native streaming Upgrade protocol.
        websocket.insert(
            "http_upgrade".into(),
            ["http", "https"].contains(&parsed.scheme()).into(),
        );
        if let Some(host) = host {
            websocket.insert("host".into(), host.into());
        }
        transport.insert("websocket".into(), websocket.into());
        if tls {
            let tls_config = transport
                .entry("tls")
                .or_insert_with(|| toml::Value::Table(Default::default()));
            let tls_config = table(tls_config)?;
            let name = if let Some(host) = host {
                let host = Url::parse(&format!("https://{host}"))?;
                anyhow::ensure!(
                    host.username().is_empty()
                        && host.password().is_none()
                        && host.path() == "/"
                        && host.query().is_none()
                        && host.fragment().is_none(),
                    "invalid origin Host"
                );
                host.host_str().context("invalid origin Host")?.to_owned()
            } else {
                match parsed.host().unwrap() {
                    url::Host::Domain(host) => host.to_owned(),
                    url::Host::Ipv4(ip) => ip.to_string(),
                    url::Host::Ipv6(ip) => ip.to_string(),
                }
            };
            tls_config.insert("hostname".into(), name.into());
            if let Some(pin) = pin {
                tls_config.insert("spki_sha256".into(), pin.into());
            }
        }
    } else {
        anyhow::ensure!(
            pin.is_none() && host.is_none(),
            "origin must be an HTTPS URL"
        );
    }
    let mut config = Config::from_str(&toml::to_string(&value)?)?;
    // Go's dialer treats unspecified target addresses as local. Windows sockets
    // reject a connect to 0.0.0.0, so preserve that behavior explicitly here.
    for service in config.client.as_mut().unwrap().services.values_mut() {
        for (unspecified, loopback) in [("0.0.0.0:", "127.0.0.1:"), ("[::]:", "[::1]:")] {
            if let Some(port) = service.local_addr.strip_prefix(unspecified) {
                anyhow::ensure!(
                    port.parse::<u16>().is_ok_and(|port| port > 0),
                    "invalid local service port"
                );
                service.local_addr = format!("{loopback}{port}");
                break;
            }
        }
    }
    Ok(Candidate {
        config,
        kind,
        endpoint: endpoint.into(),
    })
}
impl ClientPlan {
    pub async fn choose(&self, timeout: Duration) -> Candidate {
        self.available(timeout)
            .await
            .unwrap_or_else(|| self.candidates[0].clone())
    }
    /// A background recovery must not replace a working selection with the
    /// unverified primary when every reachability check fails.
    pub async fn available(&self, timeout: Duration) -> Option<Candidate> {
        let plan = self;
        if plan.candidates[0]
            .config
            .client
            .as_ref()
            .is_some_and(|c| c.services.is_empty())
        {
            return Some(plan.candidates[0].clone());
        }
        let mut probes = tokio::task::JoinSet::new();
        for (index, candidate) in plan.candidates.iter().cloned().enumerate() {
            probes.spawn(async move { (index, candidate.probe(timeout).await) });
        }
        let mut best: Option<(usize, Duration)> = None;
        while let Some(result) = probes.join_next().await {
            if let Ok((index, Ok(elapsed))) = result {
                // Prefer a verified direct origin when it is available; other routes
                // are measured once during setup, never between parallel data channels.
                let origin = plan.candidates[index].kind == RouteKind::Origin;
                if best.is_none_or(|(previous, time)| {
                    (origin && plan.candidates[previous].kind != RouteKind::Origin)
                        || (origin == (plan.candidates[previous].kind == RouteKind::Origin)
                            && elapsed < time)
                }) {
                    best = Some((index, elapsed));
                }
            }
        }
        best.map(|(index, _)| plan.candidates[index].clone())
    }
    pub fn parse(input: &str) -> Result<Self> {
        let mut value: toml::Value =
            toml::from_str(input).context("invalid tunnel configuration")?;
        anyhow::ensure!(
            value.get("server").is_none(),
            "agent configuration cannot include a server section"
        );
        let client = table(value.get_mut("client").context("missing client section")?)?;
        client
            .entry("services")
            .or_insert_with(|| toml::Value::Table(Default::default()));
        let remote = client
            .get("remote_addr")
            .and_then(toml::Value::as_str)
            .context("missing remote endpoint")?
            .to_owned();
        let fallback = string(client, "fallback_addr")?;
        let fallbacks = match client.remove("fallback_addrs") {
            None => Vec::new(),
            Some(toml::Value::Array(values)) => values
                .into_iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .context("fallback must be a URL string")
                })
                .collect::<Result<Vec<_>>>()?,
            _ => anyhow::bail!("fallback_addrs must be a URL array"),
        };
        anyhow::ensure!(
            fallbacks.len() <= 8,
            "at most eight tunnel fallbacks are allowed"
        );
        let direct = string(client, "direct_addr")?;
        let pin = string(client, "direct_spki_sha256")?;
        let proxy_fallback = match client.remove("direct_proxy_fallback") {
            None => false,
            Some(toml::Value::Boolean(value)) => value,
            _ => anyhow::bail!("invalid origin CA fallback setting"),
        };
        let host = string(client, "direct_host")?;
        anyhow::ensure!(
            (pin.is_none() || direct.is_some())
                && (host.is_none() || direct.is_some())
                && (!proxy_fallback || direct.is_some()),
            "origin metadata requires an endpoint"
        );
        if let Some(pin) = &pin {
            anyhow::ensure!(
                pin.len() == 64 && pin.bytes().all(|c| c.is_ascii_hexdigit()),
                "invalid origin SHA256 key pin"
            );
        }
        let mut candidates = vec![candidate(&value, &remote, RouteKind::Primary, None, None)?];
        for fallback in fallbacks
            .into_iter()
            .chain(fallback)
            .filter(|v| !v.is_empty())
        {
            url(&fallback)?;
            if !candidates
                .iter()
                .any(|candidate| candidate.endpoint == fallback)
            {
                candidates.push(candidate(
                    &value,
                    &fallback,
                    RouteKind::Fallback,
                    None,
                    None,
                )?);
            }
        }
        if let Some(direct) = direct {
            let parsed = url(&direct)?;
            anyhow::ensure!(
                ["http", "https", "ws", "wss"].contains(&parsed.scheme()),
                "invalid origin scheme"
            );
            anyhow::ensure!(
                pin.is_none() || ["https", "wss"].contains(&parsed.scheme()),
                "an HTTP origin cannot carry a TLS pin"
            );
            candidates.push(candidate(
                &value,
                &direct,
                RouteKind::Origin,
                pin.as_deref(),
                host.as_deref(),
            )?);
            if proxy_fallback {
                if pin.is_some() {
                    candidates.push(candidate(
                        &value,
                        &direct,
                        RouteKind::Origin,
                        None,
                        host.as_deref(),
                    )?);
                }
                let mut websocket = parsed.clone();
                websocket
                    .set_scheme(if ["https", "wss"].contains(&parsed.scheme()) {
                        "wss"
                    } else {
                        "ws"
                    })
                    .map_err(|_| anyhow::anyhow!("invalid proxy transport"))?;
                if websocket.as_str() != direct {
                    candidates.push(candidate(
                        &value,
                        websocket.as_str(),
                        RouteKind::Origin,
                        None,
                        host.as_deref(),
                    )?);
                }
            }
        }
        Ok(Self { candidates })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn url_configuration_preserves_session_endpoint_path_and_authentication() {
        let plan=ClientPlan::parse(r#"[client]
remote_addr="wss://porthub.example/prefix/api/tunnel?mode=1"
fallback_addrs=["https://fallback.example/api/tunnel","wss://porthub.example/prefix/api/tunnel?mode=1"]
direct_addr="https://192.0.2.1:8346/api/tunnel"
direct_spki_sha256="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
direct_host="porthub.example"
[client.services.shell]
token="secret"
local_addr="127.0.0.1:22"
"#).unwrap();
        assert_eq!(plan.candidates.len(), 3);
        let primary = plan.candidates[0].config.client.as_ref().unwrap();
        assert_eq!(primary.remote_addr, "porthub.example:443");
        let ws = primary.transport.websocket.as_ref().unwrap();
        assert_eq!(ws.path, "/prefix/api/tunnel?mode=1");
        assert!(ws.tls && ws.porthub_framing && !ws.http_upgrade);
        let origin = plan.candidates[2].config.client.as_ref().unwrap();
        assert_eq!(origin.remote_addr, "192.0.2.1:8346");
        assert_eq!(
            origin.transport.tls.as_ref().unwrap().hostname.as_deref(),
            Some("porthub.example")
        );
        assert!(origin.transport.tls.as_ref().unwrap().spki_sha256.is_some());
        assert_eq!(
            origin.transport.websocket.as_ref().unwrap().host.as_deref(),
            Some("porthub.example")
        );
        assert_eq!(primary.services, origin.services);
    }
    #[test]
    fn unspecified_local_targets_work_portably_and_service_free_configs_are_valid() {
        let plan =
            ClientPlan::parse("[client]\nremote_addr='wss://[::1]:443/api/tunnel'\n").unwrap();
        let client = plan.candidates[0].config.client.as_ref().unwrap();
        assert!(client.services.is_empty());
        assert_eq!(client.remote_addr, "[::1]:443");
        assert_eq!(
            client.transport.tls.as_ref().unwrap().hostname.as_deref(),
            Some("::1")
        );
        let plan=ClientPlan::parse("[client]\nremote_addr='ws://example/api/tunnel'\n[client.services.local]\ntoken='secret'\nlocal_addr='0.0.0.0:22'\n").unwrap();
        assert_eq!(
            plan.candidates[0].config.client.as_ref().unwrap().services["local"].local_addr,
            "127.0.0.1:22"
        );
    }
    #[test]
    fn rejects_pins_without_endpoints_credentialed_urls_and_invalid_configuration() {
        for value in [
            "remote_addr='wss://user:secret@example/api/tunnel'",
            "remote_addr='wss://example/api/tunnel#fragment'",
            "remote_addr='wss://example/api/tunnel'\ndirect_spki_sha256='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'",
            "remote_addr='wss://example/api/tunnel'\ndirect_spki_sha256='bad'",
        ] {
            assert!(ClientPlan::parse(&format!("[client]\n{value}\n[client.services]\n")).is_err());
        }
    }
}

#[cfg(test)]
mod advertised_origin_tests {
    use super::*;
    #[test]
    fn operator_http_origin_and_https_termination_use_the_explicit_scheme_and_port() {
        let plan=ClientPlan::parse("[client]\nremote_addr='wss://porthub.example/api/tunnel'\ndirect_addr='http://192.0.2.5:18445/api/tunnel'\ndirect_host='porthub.example'\n[client.services]\n").unwrap();
        let direct = plan
            .candidates
            .last()
            .unwrap()
            .config
            .client
            .as_ref()
            .unwrap();
        assert_eq!(direct.remote_addr, "192.0.2.5:18445");
        assert!(!direct.transport.websocket.as_ref().unwrap().tls);
        let base=format!("[client]\nremote_addr='wss://porthub.example/api/tunnel'\ndirect_addr='https://192.0.2.5:18446/api/tunnel'\ndirect_spki_sha256='{}'\ndirect_host='porthub.example'\n", "AB".repeat(32));
        assert_eq!(ClientPlan::parse(&base).unwrap().candidates.len(), 2);
        let with_ca = ClientPlan::parse(&(base + "direct_proxy_fallback=true\n")).unwrap();
        assert_eq!(with_ca.candidates.len(), 4);
        assert!(with_ca.candidates[1]
            .config
            .client
            .as_ref()
            .unwrap()
            .transport
            .tls
            .as_ref()
            .unwrap()
            .spki_sha256
            .is_some());
        assert!(with_ca.candidates[2]
            .config
            .client
            .as_ref()
            .unwrap()
            .transport
            .tls
            .as_ref()
            .unwrap()
            .spki_sha256
            .is_none());
    }
}
