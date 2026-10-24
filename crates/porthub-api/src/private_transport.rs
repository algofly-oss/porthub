//! Gateway-provisioned ICE settings, parsed once. TURN REST credentials are
//! scoped to the authenticated peer and retain the existing 12-hour lifetime.
use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{json, Value};
use sha1::Sha1;

#[derive(Clone, Default)]
pub struct Settings {
    servers: Vec<Value>,
    pub relay_routes: Vec<String>,
    secret: String,
}
impl Settings {
    pub fn load() -> Self {
        Self::parse(
            &std::env::var("PORTHUB_PRIVATE_ICE_SERVERS").unwrap_or_default(),
            &std::env::var("PORTHUB_RELAY_ROUTES").unwrap_or_default(),
            &std::env::var("PORTHUB_RELAY_SECRET").unwrap_or_default(),
        )
    }
    pub fn parse(raw: &str, routes: &str, secret: &str) -> Self {
        let servers = if raw.len() <= 65_536 {
            serde_json::from_str::<Vec<Value>>(raw)
                .unwrap_or_default()
                .into_iter()
                .take(32)
                .filter(|v| {
                    v.is_object()
                        && v["urls"].as_array().is_some_and(|urls| {
                            urls.len() <= 16
                                && urls.iter().all(|u| {
                                    u.as_str().is_some_and(|u| {
                                        u.len() <= 2048
                                            && matches!(
                                                u.split(':').next(),
                                                Some("stun" | "turn" | "turns")
                                            )
                                    })
                                })
                        })
                })
                .collect()
        } else {
            Vec::new()
        };
        let relay_routes = routes
            .split(',')
            .map(str::trim)
            .map(|s| s.trim_end_matches('/'))
            .filter(|s| {
                s.len() <= 2048
                    && url::Url::parse(s).is_ok_and(|u| {
                        matches!(u.scheme(), "http" | "https")
                            && u.host_str().is_some()
                            && u.username().is_empty()
                            && u.password().is_none()
                            && u.query().is_none()
                            && u.fragment().is_none()
                    })
            })
            .take(4)
            .map(str::to_owned)
            .collect();
        Self {
            servers,
            relay_routes,
            secret: secret.into(),
        }
    }
    pub fn enabled(&self) -> bool {
        self.secret.chars().count() >= 32
    }
    pub fn turn_password(&self, username: &str) -> Option<String> {
        let (expiry, peer) = username.split_once(':')?;
        let expiry = expiry.parse::<i64>().ok()?;
        let now = chrono::Utc::now().timestamp();
        if !self.enabled()
            || expiry < now
            || expiry > now + 13 * 3600
            || peer.is_empty()
            || peer.len() > 60
            || !peer
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_:".contains(&byte))
        {
            return None;
        }
        let mut mac = Hmac::<Sha1>::new_from_slice(self.secret.as_bytes()).ok()?;
        mac.update(username.as_bytes());
        Some(STANDARD.encode(mac.finalize().into_bytes()))
    }
    pub fn verify_turn_credential(&self, username: &str, credential: &str) -> bool {
        use subtle::ConstantTimeEq;
        self.turn_password(username)
            .is_some_and(|expected| bool::from(expected.as_bytes().ct_eq(credential.as_bytes())))
    }
    pub fn ice(&self, peer: &str, now: i64) -> Vec<Value> {
        let mut servers = self.servers.clone();
        if self.secret.chars().count() >= 32 && !peer.is_empty() {
            let username = format!("{}:{peer}", now.saturating_add(12 * 3600));
            let mut mac = Hmac::<Sha1>::new_from_slice(self.secret.as_bytes())
                .expect("HMAC accepts arbitrary key lengths");
            mac.update(username.as_bytes());
            servers.push(json!({"urls":["turn:relay.porthub.invalid:443?transport=tcp"],"username":username,"credential":STANDARD.encode(mac.finalize().into_bytes())}));
        }
        servers
    }
}
