use anyhow::{Context, Result};

#[derive(Clone)]
pub struct Config {
    pub private_transport: crate::private_transport::Settings,
    pub listen: String,
    pub external_port_range: Option<(u16, u16)>,
    pub firewall_socket: Option<std::path::PathBuf>,
    pub firewall_base_url: String,
    pub firewall_api_key: String,
    pub firewall_timeout: std::time::Duration,
    pub ui_upstream: String,
    pub ui_root: String,
    pub mongo_uri: String,
    pub mongo_database: String,
    pub session_cookie: String,
    pub signup_disabled: bool,
    pub service_domain: String,
    pub proxy_domain_suffix: String,
    pub telegram_base_url: String,
    pub machine_online_ttl_millis: i64,
    pub machine_offline_alert_grace_millis: i64,
    pub client_version: String,
    pub client_binary_dir: Option<std::path::PathBuf>,
    pub gateway_public_ip: Option<String>,
    pub gateway_advertised_url: Option<String>,
    pub gateway_ip_sources: Vec<String>,
    pub gateway_config_path: Option<std::path::PathBuf>,
    pub edge_socket: Option<std::path::PathBuf>,
    pub web_routes_config_path: Option<std::path::PathBuf>,
    pub web_activity_log_path: Option<std::path::PathBuf>,
    pub public_base_url: String,
    pub rathole_server_address: String,
    pub rathole_port: Option<u16>,
    pub tunnel_http_base_url: String,
    pub tunnel_fallback_base_urls: Vec<String>,
    pub long_poll_timeout: std::time::Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            private_transport: Default::default(),
            listen: "127.0.0.1:47080".into(),
            external_port_range: None,
            firewall_socket: None,
            firewall_base_url: String::new(),
            firewall_api_key: String::new(),
            firewall_timeout: std::time::Duration::from_secs(5),
            ui_upstream: String::new(),
            ui_root: String::new(),
            mongo_uri: String::new(),
            mongo_database: String::new(),
            session_cookie: "porthub_session".into(),
            signup_disabled: false,
            service_domain: String::new(),
            proxy_domain_suffix: String::new(),
            telegram_base_url: "https://api.telegram.org".into(),
            machine_online_ttl_millis: 300_000,
            machine_offline_alert_grace_millis: 60_000,
            client_version: String::new(),
            client_binary_dir: None,
            gateway_public_ip: None,
            gateway_advertised_url: None,
            gateway_config_path: None,
            edge_socket: None,
            web_routes_config_path: None,
            web_activity_log_path: None,
            public_base_url: String::new(),
            rathole_server_address: String::new(),
            rathole_port: None,
            tunnel_http_base_url: String::new(),
            tunnel_fallback_base_urls: Vec::new(),
            long_poll_timeout: std::time::Duration::from_secs(25),
            gateway_ip_sources: vec![
                "https://api.ipify.org".into(),
                "https://checkip.amazonaws.com".into(),
            ],
        }
    }
}

fn env(name: &str, fallback: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| fallback.into())
}

impl Config {
    pub fn load() -> Result<Self> {
        let signup_disabled = match env("SIGNUP_DISABLED", "false")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "true" | "yes" | "on" | "1" => true,
            "false" | "no" | "off" | "0" => false,
            _ => anyhow::bail!("invalid SIGNUP_DISABLED"),
        };
        let session_cookie = env("SESSION_COOKIE_NAME", "porthub_session");
        anyhow::ensure!(
            session_cookie
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c)),
            "invalid session cookie name"
        );
        let ui_upstream = env("PORTHUB_UI_UPSTREAM", "");
        let ui_root = env("PORTHUB_UI_ROOT", "");
        anyhow::ensure!(
            ui_root.is_empty() || ui_upstream.is_empty(),
            "choose static UI assets or a development UI upstream"
        );
        if !ui_root.is_empty() {
            anyhow::ensure!(
                std::path::Path::new(&ui_root).is_dir(),
                "static UI directory is missing"
            );
        }
        if !ui_upstream.is_empty() {
            let url = reqwest::Url::parse(&ui_upstream).context("invalid UI upstream")?;
            anyhow::ensure!(
                url.scheme() == "http"
                    && url.host_str().is_some()
                    && url.path() == "/"
                    && url.query().is_none()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.fragment().is_none(),
                "UI upstream must be an HTTP origin without a path or credentials"
            );
        }
        let gateway_advertised_url=std::env::var("PORTHUB_GATEWAY_ADVERTISED_URL").ok()
            .filter(|value|!value.trim().is_empty())
            .map(|value|crate::gateway_origin::advertised_url(&value).map(|url|url.to_string().trim_end_matches('/').to_owned()))
            .transpose().context("PORTHUB_GATEWAY_ADVERTISED_URL must be an HTTP(S) origin URL including the external port")?;
        let gateway_public_ip = std::env::var("PORTHUB_GATEWAY_PUBLIC_IP")
            .ok()
            .filter(|s| !s.trim().is_empty());
        if let Some(ip) = &gateway_public_ip {
            anyhow::ensure!(
                crate::gateway_origin::advertised_ipv4(ip).is_some(),
                "PORTHUB_GATEWAY_PUBLIC_IP must be a unicast IPv4 address"
            );
        }
        let gateway_ip_sources: Vec<String> = env(
            "PORTHUB_GATEWAY_IP_SOURCES",
            "https://api.ipify.org,https://checkip.amazonaws.com",
        )
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
        anyhow::ensure!(
            gateway_ip_sources.len() <= 4,
            "at most four gateway IP discovery sources are allowed"
        );
        for source in &gateway_ip_sources {
            let url = reqwest::Url::parse(source).context("invalid gateway IP source URL")?;
            anyhow::ensure!(
                url.scheme() == "https"
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.fragment().is_none(),
                "gateway IP sources require HTTPS URLs without credentials or fragments"
            );
        }
        let poll_seconds = env("MACHINE_CONFIG_LONG_POLL_TIMEOUT_SECONDS", "25")
            .parse::<f64>()
            .context("invalid MACHINE_CONFIG_LONG_POLL_TIMEOUT_SECONDS")?;
        anyhow::ensure!(
            poll_seconds.is_finite() && poll_seconds > 0.,
            "invalid MACHINE_CONFIG_LONG_POLL_TIMEOUT_SECONDS"
        );
        let duration_millis = |name: &str, fallback: &str| -> Result<i64> {
            let seconds = env(name, fallback)
                .parse::<f64>()
                .with_context(|| format!("invalid {name}"))?;
            anyhow::ensure!(
                seconds.is_finite() && seconds >= 0. && seconds <= (i64::MAX / 1000) as f64,
                "invalid {name}"
            );
            Ok((seconds * 1000.) as i64)
        };
        let machine_online_ttl_millis = duration_millis("MACHINE_ONLINE_TTL_SECONDS", "300")?;
        let machine_offline_alert_grace_millis =
            duration_millis("MACHINE_OFFLINE_ALERT_GRACE_SECONDS", "60")?;
        let port_start = env("EXTERNAL_PORT_RANGE_START", "");
        let port_end = env("EXTERNAL_PORT_RANGE_END", "");
        let external_port_range = if port_start.trim().is_empty() && port_end.trim().is_empty() {
            None
        } else {
            let start: u16 = port_start
                .trim()
                .parse()
                .context("EXTERNAL_PORT_RANGE_START must be between 1 and 65535")?;
            let end: u16 = port_end
                .trim()
                .parse()
                .context("EXTERNAL_PORT_RANGE_END must be between 1 and 65535")?;
            anyhow::ensure!(
                start > 0 && start <= end,
                "EXTERNAL_PORT_RANGE_START/END must be ordered nonzero ports"
            );
            Some((start, end))
        };
        let firewall_base_url = env("FIREWALL_BASE_URL", "");
        if !firewall_base_url.is_empty() {
            let url = url::Url::parse(&firewall_base_url)?;
            anyhow::ensure!(
                ["http", "https"].contains(&url.scheme())
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none(),
                "invalid firewall URL"
            );
        }
        let firewall_seconds = env("FIREWALL_REQUEST_TIMEOUT_SECONDS", "5")
            .parse::<f64>()
            .context("invalid firewall timeout")?;
        anyhow::ensure!(
            firewall_seconds.is_finite() && firewall_seconds > 0.,
            "invalid firewall timeout"
        );
        let gateway_config_path: Option<std::path::PathBuf> =
            std::env::var_os("PORTHUB_GATEWAY_CONFIG_PATH")
                .filter(|value| !value.is_empty())
                .map(Into::into);
        let edge_socket: Option<std::path::PathBuf> = std::env::var_os("PORTHUB_EDGE_SOCKET")
            .filter(|value| !value.is_empty())
            .map(Into::into);
        if let Some(socket) = &edge_socket {
            anyhow::ensure!(
                socket.is_absolute()
                    && gateway_config_path
                        .as_ref()
                        .is_some_and(|path| path.is_absolute()),
                "edge IPC requires absolute socket and gateway configuration paths"
            );
        }
        Ok(Self {
            private_transport: crate::private_transport::Settings::load(),
            external_port_range,
            firewall_socket: std::env::var_os("FIREWALL_SOCKET")
                .filter(|v| !v.is_empty())
                .map(Into::into),
            firewall_base_url,
            firewall_api_key: env("FW_API_KEY", &env("FIREWALL_API_KEY", "")),
            firewall_timeout: std::time::Duration::from_secs_f64(firewall_seconds.min(30.)),
            web_activity_log_path: std::env::var_os("PORTHUB_WEB_ACTIVITY_LOG_PATH")
                .filter(|p| !p.is_empty())
                .map(Into::into),
            web_routes_config_path: std::env::var_os("PORTHUB_WEB_ROUTES_CONFIG_PATH")
                .filter(|p| !p.is_empty())
                .map(Into::into),
            public_base_url: env("PORT_HUB_PUBLIC_BASE_URL", ""),
            rathole_server_address: env("RATHOLE_SERVER_ADDRESS", ""),
            rathole_port: std::env::var("RATHOLE_PORT")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .map(|value| value.parse())
                .transpose()
                .context("invalid RATHOLE_PORT")?,
            tunnel_http_base_url: env("PORT_HUB_HTTP_BASE_URL", ""),
            tunnel_fallback_base_urls: env("PORT_HUB_FALLBACK_BASE_URLS", "")
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect(),
            long_poll_timeout: std::time::Duration::from_secs_f64(poll_seconds.clamp(1., 300.)),
            gateway_config_path,
            edge_socket,
            gateway_public_ip,
            gateway_advertised_url,
            gateway_ip_sources,
            listen: env("PORTHUB_API_LISTEN", "127.0.0.1:47080"),
            ui_upstream,
            ui_root,
            mongo_uri: std::env::var("MONGO_DATABASE_URI")
                .context("MONGO_DATABASE_URI required")?,
            mongo_database: std::env::var("MONGO_DATABASE_NAME")
                .context("MONGO_DATABASE_NAME required")?,
            session_cookie,
            signup_disabled,
            service_domain: env("PORT_HUB_SERVICE_DOMAIN", ""),
            proxy_domain_suffix: env("WEB_PROXY_DOMAIN_SUFFIX", ""),
            telegram_base_url: env("PORTHUB_TELEGRAM_API_URL", "https://api.telegram.org"),
            machine_online_ttl_millis,
            machine_offline_alert_grace_millis,
            client_version: env(
                "PORTHUB_VERSION",
                option_env!("PORTHUB_VERSION").unwrap_or(""),
            ),
            client_binary_dir: Some(
                env(
                    "PORTHUB_CLIENT_BINARY_DIR",
                    &env("CLIENT_BINARY_DIR", "/app/client-bin"),
                )
                .into(),
            ),
        })
    }
}
