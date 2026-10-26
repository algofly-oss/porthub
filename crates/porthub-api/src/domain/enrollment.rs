//! Stable private addresses and idempotent default enrollment. Existing invited
//! workspace enrollment and explicit ownership revocation always take precedence.
use crate::{
    error::{ApiError, ApiResult},
    input::Model,
    store, App,
};
use axum::http::StatusCode;
use futures_util::TryStreamExt;
use mongodb::{
    bson::{doc, DateTime, Document},
    options::IndexOptions,
    IndexModel,
};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, net::Ipv4Addr};

#[derive(Clone, Copy, Debug)]
pub struct Network {
    base: u32,
    bits: u8,
}

impl Network {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        let invalid = "Enter a network CIDR such as 10.203.0.0/24";
        let (address, suffix) = value.split_once('/').unwrap_or((value, "32"));
        if address.contains(':') {
            let (address, _) = address.split_once('%').unwrap_or((address, ""));
            let address = u128::from(address.parse::<std::net::Ipv6Addr>().map_err(|_| invalid)?);
            let suffix = if value.contains('/') { suffix } else { "128" };
            if suffix.is_empty() || !suffix.bytes().all(|c| c.is_ascii_digit()) {
                return Err(invalid);
            }
            let bits = suffix.parse::<u32>().map_err(|_| invalid)?;
            if bits > 128 {
                return Err(invalid);
            }
            let mask = u128::MAX.checked_shl(128 - bits).unwrap_or(0);
            if address & mask != address {
                return Err(invalid);
            }
            return Err("Choose an RFC1918 IPv4 range between /16 and /28");
        }
        let address = u32::from(address.parse::<Ipv4Addr>().map_err(|_| invalid)?);
        let bits = if suffix.contains('.') {
            let mut mask = u32::from(suffix.parse::<Ipv4Addr>().map_err(|_| invalid)?);
            if mask.leading_ones() + mask.trailing_zeros() != 32 {
                mask = !mask;
            }
            if mask.leading_ones() + mask.trailing_zeros() != 32 {
                return Err(invalid);
            }
            mask.leading_ones() as u8
        } else {
            if suffix.is_empty() || !suffix.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid);
            }
            suffix.parse::<u8>().map_err(|_| invalid)?
        };
        if bits > 32 {
            return Err(invalid);
        }
        let mask = u32::MAX.checked_shl(32 - u32::from(bits)).unwrap_or(0);
        if address & mask != address {
            return Err(invalid);
        }
        let address_ip = Ipv4Addr::from(address);
        if !(16..=28).contains(&bits) || !address_ip.is_private() {
            return Err("Choose an RFC1918 IPv4 range between /16 and /28");
        }
        Ok(Self {
            base: address,
            bits,
        })
    }

    pub fn cidr(self) -> String {
        format!("{}/{}", Ipv4Addr::from(self.base), self.bits)
    }

    pub fn contains(self, ip: Ipv4Addr) -> bool {
        let mask = u32::MAX << (32 - self.bits);
        u32::from(ip) & mask == self.base
    }

    pub fn overlaps(self, other: Self) -> bool {
        self.contains(Ipv4Addr::from(other.base)) || other.contains(Ipv4Addr::from(self.base))
    }

    pub fn allocate(self, machine_id: &str, occupied: &HashSet<String>) -> ApiResult<String> {
        let count = (1u32 << (32 - self.bits)) - 2;
        let digest = Sha256::digest(machine_id.as_bytes());
        let start = (u64::from_be_bytes(digest[..8].try_into().unwrap()) % u64::from(count)) as u32;
        for offset in 0..count {
            let ip = Ipv4Addr::from(self.base + (start + offset) % count + 1).to_string();
            if !occupied.contains(&ip) {
                return Ok(ip);
            }
        }
        Err(ApiError::bad_request("The private address range is full"))
    }
}

pub fn preferences(document: &Document) -> ApiResult<(Network, String)> {
    preferences_value(store::document(document))
}

pub fn preferences_value(value: serde_json::Value) -> ApiResult<(Network, String)> {
    let mut model = Model::new(value)?;
    let cidr = if model.field(&["cidr"]).is_some() {
        model.required_string("cidr")
    } else {
        "10.203.0.0/24".into()
    };
    let network = Network::parse(&cidr);
    if model.field_valid("cidr") {
        if let Err(message) = network {
            model.add("cidr", message, "value_error");
        }
    }
    let suffix = if model.field(&["dns_suffix"]).is_some() {
        model.required_string("dns_suffix")
    } else {
        "phub".into()
    };
    model.string_length("dns_suffix", &suffix, 3, Some(120));
    let suffix = suffix
        .trim()
        .to_lowercase()
        .trim_end_matches('.')
        .to_owned();
    if model.field_valid("dns_suffix") {
        let message = if !suffix.contains('.') && !["phub", "internal"].contains(&suffix.as_str()) {
            Some("Use phub, internal, or a full domain you own such as lan.example.com")
        } else if suffix.split('.').any(|part| {
            part.is_empty()
                || part.len() > 63
                || !part
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                || part.starts_with('-')
                || part.ends_with('-')
        }) {
            Some("Enter a domain suffix such as phub")
        } else if ["local", "localhost"]
            .iter()
            .any(|name| suffix == *name || suffix.ends_with(&format!(".{name}")))
        {
            Some("This suffix is reserved for local OS networking")
        } else {
            None
        };
        if let Some(message) = message {
            model.add("dns_suffix", message, "value_error");
        }
    }
    model.finish()?;
    Ok((network.expect("validated network"), suffix))
}

pub async fn ensure(app: &App, machine: &Document) -> ApiResult<()> {
    let _network_guard = app.private_network_lock.lock().await;
    if machine.get_bool("private_owner_revoked").unwrap_or(false) {
        return Ok(());
    }
    let owner = machine
        .get("user_id")
        .ok_or_else(ApiError::unauthenticated)?;
    if app.collection("users").find_one(doc! {"_id":owner,"account_deletion":{"$exists":false}}).await?.is_none() {
        return Ok(());
    }
    let machine_id = machine.get("_id").ok_or_else(ApiError::unauthenticated)?;
    let peers = app.collection("private_peers");
    if peers
        .find_one(doc! {"machine_id":machine_id,"owner_id":owner})
        .await?
        .is_some()
    {
        return Ok(());
    }
    let document = super::private_networks::ensure_locked(app, &store::id(Some(owner))).await?;
    let (network, _) = preferences(&document)?;
    peers
        .create_index(
            IndexModel::builder()
                .keys(doc! {"workspace_id":1,"ip":1})
                .options(IndexOptions::builder().unique(true).build())
                .build(),
        )
        .await?;
    let id = format!("{}:{}", store::id(Some(owner)), store::id(Some(machine_id)));
    for _ in 0..8 {
        let enrolled: Vec<Document> = peers
            .find(doc! {"workspace_id":owner})
            .await?
            .try_collect()
            .await?;
        if enrolled.iter().any(|peer| store::string(peer, "_id") == id) {
            return Ok(());
        }
        let occupied = enrolled
            .iter()
            .map(|peer| store::string(peer, "ip").to_owned())
            .collect();
        let ip = network.allocate(&store::id(Some(machine_id)), &occupied)?;
        let now = DateTime::now();
        let result = peers
            .update_one(
                doc! {"_id":&id},
                doc! {"$setOnInsert":{
                "workspace_id":owner,"owner_id":owner,"machine_id":machine_id,"ip":ip,
                "enabled":true,"revision":0,"created_at":now,"updated_at":now}},
            )
            .upsert(true)
            .await;
        match result {
            Ok(_) => return Ok(()),
            Err(error) if duplicate(&error) => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(ApiError::new(
        StatusCode::CONFLICT,
        "private address allocation changed; retry",
    ))
}

fn duplicate(error: &mongodb::error::Error) -> bool {
    use mongodb::error::{ErrorKind, WriteFailure};
    match error.kind.as_ref() {
        ErrorKind::Write(WriteFailure::WriteError(error)) => error.code == 11000,
        ErrorKind::Command(error) => error.code == 11000,
        _ => false,
    }
}
