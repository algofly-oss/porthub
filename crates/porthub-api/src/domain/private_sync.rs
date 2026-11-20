use crate::{error::ApiResult, input::Model, input_compat};
use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use std::{collections::BTreeMap, sync::LazyLock};

#[derive(Serialize)]
pub struct Description {
    pub r#type: String,
    pub sdp: String,
}
#[derive(Serialize)]
pub struct Signal {
    pub to: String,
    pub session: String,
    pub description: Description,
}
#[derive(Serialize)]
pub struct Sync {
    #[serde(skip_serializing_if="is_false")]
    pub virtual_host_provider:bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sparse: Option<super::private_pairs::Request>,
    // Separate root capability: older gateways ignore unknown root fields,
    // while the existing sparse Request intentionally denies unknown fields.
    #[serde(skip_serializing_if="Option::is_none")]
    pub exit_pair_protocol: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub exit_pick:Option<porthub_network::policy::ExitPickRequest>,
    #[serde(skip_serializing_if="is_false")]
    pub exit_ready:bool,
    #[serde(skip_serializing_if="Option::is_none")]
    pub native_repair:Option<porthub_network::native_repair::Request>,
    pub peer_id: String,
    pub token: String,
    pub fingerprint: String,
    pub instance: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub stream_transport: String,
    #[serde(skip_serializing_if="is_false")]
    pub tor_exit: bool,
    #[serde(skip_serializing_if="Vec::is_empty")]
    pub lan_networks: Vec<String>,
    #[serde(skip_serializing_if="is_false")]
    pub lan_exit: bool,
    #[serde(skip_serializing_if="is_false")]
    pub application_proxy: bool,
    #[serde(skip_serializing_if="is_false")]
    pub pinned_relay: bool,
    pub signals: Vec<Signal>,
    pub acks: Vec<String>,
    pub paths: BTreeMap<String, String>,
}
fn is_false(value:&bool)->bool {!*value}
static SESSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A[a-zA-Z0-9-]{16,64}\n?\z").unwrap());
static FINGERPRINT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}\z").unwrap());
fn string(model: &mut Model, key: &str, min: usize, max: usize) -> String {
    let value = model.required_string(key);
    model.string_length(key, &value, min, Some(max));
    value
}
fn session(model: &mut Model, key: &str) -> String {
    let value = model.required_string(key);
    model.regex(key, "^[a-zA-Z0-9-]{16,64}$", SESSION.is_match(&value));
    value
}
pub fn parse(raw: Value) -> ApiResult<Sync> {
    let raw = input_compat::dictionary(raw.clone())
        .map(Value::Object)
        .unwrap_or(raw);
    let sparse=raw.get("sparse").filter(|v| !v.is_null()).map(|v|serde_json::from_value::<super::private_pairs::Request>(v.clone()).map_err(|_| crate::error::ApiError::bad_request("Invalid sparse private request"))).transpose()?;
    if let Some(request)=&sparse { request.validate()?; }
    let exit_pair_protocol=if cfg!(feature="private-sparse") {
        match raw.get("exit_pair_protocol").filter(|value|!value.is_null()) {
            None=>None,
            Some(value) if value.as_u64()==Some(1)&&sparse.is_some()=>Some(1),
            Some(_)=>return Err(crate::error::ApiError::bad_request("Exit pair capability requires negotiated private protocol1")),
        }
    }else{None};
    let exit_ready=if cfg!(feature="private-sparse") {
        match raw.get("exit_ready") {None=>false,Some(value) if exit_pair_protocol==Some(1)=>value.as_bool().ok_or_else(||crate::error::ApiError::bad_request("Invalid exit native readiness"))?,Some(_)=>return Err(crate::error::ApiError::bad_request("Exit readiness requires explicit capability"))}
    }else{false};
    let exit_pick=if cfg!(feature="private-sparse") {
        raw.get("exit_pick").filter(|v|!v.is_null()).map(|v|{
            if exit_pair_protocol!=Some(1){return Err(crate::error::ApiError::bad_request("Exit picker requires explicit capability"));}
            let request:porthub_network::policy::ExitPickRequest=serde_json::from_value(v.clone()).map_err(|_|crate::error::ApiError::bad_request("Invalid exit picker request"))?;
            request.validate().map_err(|_|crate::error::ApiError::bad_request("Invalid exit picker scope or budget"))?;Ok(request)
        }).transpose()?
    }else{None};
    let native_repair=raw.get("native_repair").filter(|v|!v.is_null()).map(|v|serde_json::from_value::<porthub_network::native_repair::Request>(v.clone()).map_err(|_|crate::error::ApiError::bad_request("Invalid native repair request"))).transpose()?;
    if let Some(repair)=&native_repair{
        repair.validate().map_err(|_|crate::error::ApiError::bad_request("Invalid native repair scope"))?;
        if !cfg!(feature="private-sparse")||sparse.is_none(){return Err(crate::error::ApiError::bad_request("Native repair requires negotiated private networking"));}
    }
    let virtual_host_provider=match raw.get("virtual_host_provider"){
        None=>false, Some(v) if v.as_u64()==Some(1)=>true, Some(_)=>return Err(crate::error::ApiError::bad_request("Unsupported virtual host provider capability")),
    };
    let mut model = Model::new(raw)?;
    let peer_id = string(&mut model, "peer_id", 0, 60);
    let token = string(&mut model, "token", 32, 200);
    let fingerprint = string(&mut model, "fingerprint", 95, 95);
    if model.field_valid("fingerprint") && !FINGERPRINT.is_match(&fingerprint) {
        model.add(
            "fingerprint",
            "A SHA-256 certificate fingerprint is required",
            "value_error",
        );
    }
    let instance = session(&mut model, "instance");
    if model.field(&["tor_exit"]).is_some_and(|value| !value.is_boolean()) { model.add("tor_exit", "Expected a boolean", "type_error.bool"); }
    let tor_exit = if model.field(&["tor_exit"]).is_some() { model.required_bool("tor_exit") } else { false };
    let lan_networks = model.string_list("lan_networks", 32);
    if model.field(&["lan_exit"]).is_some_and(|value| !value.is_boolean()) {
        model.add("lan_exit", "Expected a boolean", "type_error.bool");
    }
    let lan_exit = model.optional_bool("lan_exit").unwrap_or(false);
    if model.field(&["application_proxy"]).is_some_and(|value|!value.is_boolean()) {
        model.add("application_proxy","Expected a boolean","type_error.bool");
    }
    let pinned_relay = if model.field(&["pinned_relay"]).is_some() {
        model.required_bool("pinned_relay")
    } else { false };
    let application_proxy=model.optional_bool("application_proxy").unwrap_or(false);
    for network in &lan_networks {
        if network.parse::<porthub_mesh::lan_routes::Network>().is_err() {
            model.add("lan_networks", "Expected a canonical private IPv4 network prefix", "value_error");
        }
    }
    let transports:&[&str]=if cfg!(feature="private-sparse"){&["","quic1","quic2-origin","quic3-credit"]}else{&["","quic1"]};
    let stream_transport = model.literal("stream_transport", "", transports);
    if matches!(stream_transport.as_str(),"quic2-origin"|"quic3-credit")&&sparse.is_none(){model.add("stream_transport","Origin transport requires sparse negotiation","value_error");}
    let mut signals = Vec::new();
    for mut child in model.objects("signals", false, 0, 16) {
        if !child.is_valid() {
            model.merge(child);
            continue;
        }
        let to = string(&mut child, "to", 1, 60);
        let session = session(&mut child, "session");
        if let Some(mut description) = child.required_object("description") {
            let kind = if description.field(&["type"]).is_none() {
                description.required_string("type")
            } else {
                description.literal("type", "", &["offer", "answer", "candidate"])
            };
            let sdp = string(&mut description, "sdp", 1, 65536);
            child.merge(description);
            signals.push(Signal {
                to,
                session,
                description: Description { r#type: kind, sdp },
            });
        }
        model.merge(child);
    }
    let acks = model.string_list("acks", 128);
    let mut paths = BTreeMap::new();
    if model.field(&["paths"]).is_some() {
        if let Some(mut child) = model.required_object("paths") {
            for key in child.keys() {
                let value = child.literal(&key, "", &["direct", "relay", "connecting"]);
                paths.insert(key, value);
            }
            model.merge(child);
        }
    }
    model.finish()?;
    Ok(Sync {
        virtual_host_provider,
        sparse,
        exit_pair_protocol,
        exit_pick,
        exit_ready,
        peer_id,
        token,
        native_repair,
        fingerprint: fingerprint.to_ascii_uppercase(),
        instance,
        stream_transport,
        tor_exit,
        lan_networks,
        lan_exit,
        application_proxy,
        pinned_relay,
        signals,
        acks,
        paths,
    })
}

#[cfg(test)]
mod transport_tests {
    use super::*;
    #[test]
    fn exit_capability_is_explicit_scoped_and_legacy_ignorable() {
        let ordinary=body("");assert!(parse(ordinary.clone()).ok().expect("valid ordinary sync").exit_pair_protocol.is_none());
        let mut scoped=body("quic3-credit");scoped["exit_pair_protocol"]=serde_json::json!(1);
        if cfg!(feature="private-sparse") {
            assert_eq!(parse(scoped.clone()).ok().expect("valid exit capability").exit_pair_protocol,Some(1));
            for value in [serde_json::json!(0),serde_json::json!(2),serde_json::json!(true),serde_json::json!("1")] {
                scoped["exit_pair_protocol"]=value;assert!(parse(scoped.clone()).is_err());
            }
            let mut unscoped=ordinary;unscoped["exit_pair_protocol"]=serde_json::json!(1);assert!(parse(unscoped).is_err());
        } else {
            let mut compatible=ordinary;compatible["exit_pair_protocol"]=serde_json::json!(1);
            assert!(parse(compatible).ok().expect("legacy ignores new root capability").exit_pair_protocol.is_none());
        }
    }
    fn body(mode:&str)->Value{let mut body=serde_json::json!({"peer_id":"peer","token":"fixture-credential-0123456789abcdef0123456789","fingerprint":vec!["AB";32].join(":"),"instance":"instance-0123456789","stream_transport":mode});if matches!(mode,"quic2-origin"|"quic3-credit"){body["sparse"]=serde_json::json!({"protocol":1,"sequence":1,"wanted":[]});}body}
    #[test]
    fn origin_transport_is_exact_feature_negotiated_and_legacy_values_remain_compatible(){
        assert!(parse(body("")).is_ok());assert!(parse(body("quic1")).is_ok());
        assert_eq!(parse(body("quic2-origin")).is_ok(),cfg!(feature="private-sparse"));
        assert_eq!(parse(body("quic3-credit")).is_ok(),cfg!(feature="private-sparse"));
        let mut unnegotiated=body("quic2-origin");unnegotiated.as_object_mut().unwrap().remove("sparse");assert!(parse(unnegotiated).is_err());
        for value in ["quic2","quic2-origin-any","QUIC2-ORIGIN","quic2-origin "]{assert!(parse(body(value)).is_err());}
    }
}
