//! Low-frequency report/control worker. Inventory is cached by the desktop
//! broker; polling never spawns a helper or opens a microphone.
use super::{broker, receiver};
use crate::{
    control::Control,
    features::{self, Feature},
};
use anyhow::Result;
use porthub_components::{
    media::Kind,
    media_forward::{Plan, Source},
    usb::State,
};
use serde_json::json;
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio_util::sync::CancellationToken;
pub struct Worker {
    cancel: CancellationToken,
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
struct Running {
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
    configuration: String,
    required: Feature,
}
impl Drop for Running {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}
pub fn start(profile: PathBuf, control: Arc<Control>, parent: CancellationToken) -> Worker {
    let cancel = parent.child_token();
    let stop = cancel.clone();
    tokio::spawn(async move {
        if let Err(error) = run(profile, control, stop).await {
            tracing::debug!(reason=%error,"Native media control stopped");
        }
    });
    Worker { cancel }
}
fn fixture_stage(profile: &std::path::Path, stage: &'static str, count: usize) {
    #[cfg(all(test, windows))]
    super::windows_e2e_fixture::diagnostic(profile, stage, count);
    #[cfg(not(all(test, windows)))]
    let _ = (profile, stage, count);
}
async fn run(profile: PathBuf, control: Arc<Control>, cancel: CancellationToken) -> Result<()> {
    let mut active = HashMap::<String, Running>::new();
    let mut discoveries = tokio::task::JoinSet::new();
    let states = Arc::new(Mutex::new(HashMap::<String, State>::new()));
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut policy = features::subscribe(&profile);
    let mut transport_policy = transport(&policy.borrow());
    loop {
        tokio::select! {biased;_=cancel.cancelled()=>break,changed=policy.changed()=>{if changed.is_err(){break;}let updated=transport(&policy.borrow());active.retain(|_,job|keep_session(job.required,transport_policy,&policy.borrow()));transport_policy=updated;},done=discoveries.join_next(),if !discoveries.is_empty()=>{if let Some(Ok(Err(error)))=done{tracing::debug!(reason=%error,"Explicit desktop media discovery unavailable");}},_=interval.tick()=>{
         active.retain(|_,job|!job.task.is_finished());
         let enabled=policy.borrow().clone();
         let sources=reported_sources(broker::inventory(&profile));let speaker_ready=sources.iter().any(|s|s.device.kind==Kind::Speaker&&s.device.can_request_capture());
         let reported:Vec<State>=states.lock().unwrap_or_else(|e|e.into_inner()).values().take(32).cloned().collect();
         let identity=super::config::refresh(&profile).borrow().clone();
         fixture_stage(&profile,"capability-start",0);let availability=broker::availability(&profile);let p=control.profile();let body=json!({"machine_id":p.machine_id,"token":p.token,"protocol":2,"microphone_unavailable_reason":availability.microphone_unavailable_reason,"camera_unavailable_reason":availability.camera_unavailable_reason,"speaker_enabled":enabled.enabled(Feature::MediaReceive),"speaker_receiver_available":enabled.enabled(Feature::MediaReceive)&&speaker_ready,"speaker_unavailable_reason":availability.speaker_unavailable_reason.or_else(||(!speaker_ready).then_some("No compatible desktop speaker endpoint is available".to_owned())),"camera_enabled":enabled.enabled(Feature::CameraShare),"camera_receiver_available":identity.is_some()&&super::video_receiver::available(),"camera_receiver_unavailable_reason":super::video_receiver::unavailable_reason().or_else(||identity.is_none().then_some("Receiver setup required")),"usb_enabled":enabled.enabled(Feature::Usb),"microphone_enabled":enabled.enabled(Feature::MicrophoneShare),"receive_enabled":enabled.enabled(Feature::MediaReceive),"receiver_available":identity.is_some()&&crate::usb::media_transport::receiver_available(),"receiver_identity":identity,"receiver_unavailable_reason":if !crate::usb::media_transport::receiver_available(){Some("Native USB media receiving is unavailable on this platform")}else if identity.is_none(){Some("Receiver setup required")}else{None},"sources":sources,"states":reported});
         fixture_stage(&profile,"report-start",0);
         let mut reply=tokio::select!{biased;_=cancel.cancelled()=>break,reply=control.request(reqwest::Method::POST,"media/client/report",Some(body.clone()),&[])=>reply};
         if matches!(reply,Err(crate::control::Failure::Rejected(400|422))){let legacy=legacy_report(body);reply=tokio::select!{biased;_=cancel.cancelled()=>break,reply=control.request(reqwest::Method::POST,"media/client/report",Some(legacy),&[])=>reply};}
         let value=match reply.and_then(|r|r.json()){Ok(value)=>{fixture_stage(&profile,"report-ok",0);value},Err(_)=>{fixture_stage(&profile,"report-error",0);active.clear();continue;}};
         if value["discover"]==true&&discoveries.is_empty()&&(enabled.enabled(Feature::MicrophoneShare)||(enabled.enabled(Feature::MediaReceive)||enabled.enabled(Feature::CameraShare))&&value["protocol"]==2){let profile=profile.clone();discoveries.spawn(async move{broker::discover(&profile).await.map(|_|())});}
         let mut plans=serde_json::from_value::<Vec<Plan>>(value["plans"].clone()).unwrap_or_default();
         fixture_stage(&profile,"plans-decoded",plans.len());
         if plans.len()>32{active.clear();continue;}
         plans.retain(|plan|plan.valid()&&(plan.kind()==Some(Kind::Microphone)||value["protocol"]==2));
         fixture_stage(&profile,"plans-eligible",plans.len());
         let ids:HashSet<_>=plans.iter().map(|p|p.id.clone()).collect();active.retain(|id,_|ids.contains(id));states.lock().unwrap_or_else(|e|e.into_inner()).retain(|id,_|ids.contains(id));
         for plan in plans {
          if !plan.valid()||plan.kind()!=Some(Kind::Microphone)&&value["protocol"]!=2{continue;}
          let source=plan.source==control.profile().machine_id;let destination=plan.destination==control.profile().machine_id;
          if !source&&!destination||!enabled.enabled(if source{if plan.kind()==Some(Kind::Camera){Feature::CameraShare}else if plan.kind()==Some(Kind::Speaker){Feature::MediaReceive}else{Feature::MicrophoneShare}}else{Feature::MediaReceive}){fixture_stage(&profile,"plan-skipped",1);continue;}
          let configuration=serde_json::to_string(&plan)?;
          if active.get(&plan.id).is_some_and(|old|old.configuration==configuration){continue;}
          fixture_stage(&profile,"plan-accepted",1);
          active.remove(&plan.id);let stop=cancel.child_token();let task_stop=stop.clone();let profile=profile.clone();let control=control.clone();let statuses=states.clone();let id=plan.id.clone();
          statuses.lock().unwrap_or_else(|e|e.into_inner()).insert(id.clone(),State{id:id.clone(),state:"connecting".into(),error:None});
          let plan_id=plan.id.clone();let required=if source{if plan.kind()==Some(Kind::Camera){Feature::CameraShare}else if plan.kind()==Some(Kind::Speaker){Feature::MediaReceive}else{Feature::MicrophoneShare}}else{Feature::MediaReceive};
          let task=tokio::spawn(async move {
           let status_id=id.clone();let status_store=statuses.clone();let status=Arc::new(move |state:&str|{status_store.lock().unwrap_or_else(|e|e.into_inner()).insert(status_id.clone(),State{id:status_id.clone(),state:state.to_owned(),error:None});});
           fixture_stage(&profile,"session-start",1);
           let result=receiver::run(&profile,control,&plan,task_stop.clone(),status).await;
           fixture_stage(&profile,if result.is_ok(){"session-ok"}else{"session-error"},1);
           // No exception text containing a native endpoint/path is sent to a peer.
           let error=result.is_err()&&!task_stop.is_cancelled();
           let denied=result.as_ref().err().is_some_and(|e|e.is::<super::session::CaptureDenied>());
           statuses.lock().unwrap_or_else(|e|e.into_inner()).insert(id.clone(),State{id,state:if denied{"permission-denied"}else if error{"unavailable"}else{"stopped"}.into(),error:error.then(||"Native media session could not continue; inspect local agent diagnostics".into())});
           if let Err(error)=result{tracing::debug!(reason=%error,"Native media session stopped");}
          });
          active.insert(plan_id,Running{cancel:stop,task,configuration,required});
         }
        }}
    }
    active.clear();
    Ok(())
}

// The server selects only opaque source IDs. Keep the local native endpoint
// field out of the network copy; the authenticated broker/helper retains it.
fn legacy_report(mut value: serde_json::Value) -> serde_json::Value {
    value["protocol"] = json!(1);
    if let Some(object) = value.as_object_mut() {
        object.remove("camera_enabled");
        object.remove("speaker_enabled");
        object.remove("speaker_receiver_available");
        object.remove("speaker_unavailable_reason");
        object.remove("microphone_unavailable_reason");
        object.remove("camera_unavailable_reason");
        object.remove("camera_receiver_available");
        object.remove("camera_receiver_unavailable_reason");
    }
    if let Some(rows) = value["sources"].as_array_mut() {
        rows.retain(|row| row["device"]["kind"] == "microphone");
    }
    value
}
fn reported_sources(local: Vec<broker::Source>) -> Vec<Source> {
    local
        .into_iter()
        .map(|source| {
            let mut device = source.device;
            device.native_id = device.id.clone();
            Source {
                uid: source.uid,
                desktop_session: source.desktop_session,
                device,
            }
        })
        .collect()
}
fn transport(policy: &features::Policy) -> [bool; 2] {
    [Feature::DirectConnections, Feature::PrivateNetwork].map(|f| policy.enabled(f))
}
fn keep_session(required: Feature, previous: [bool; 2], policy: &features::Policy) -> bool {
    policy.enabled(required) && transport(policy) == previous
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn network_inventory_retains_opaque_selection_without_uploading_native_endpoints() {
        use porthub_components::media::{CaptureState, Device, Kind};
        let native = "private-native-endpoint-with-hardware-serial";
        let original = broker::Source {
            uid: 1000,
            desktop_session: None,
            device: Device {
                id: porthub_components::media::stable_source_id(
                    Kind::Microphone,
                    "fixture",
                    native,
                ),
                name: "Explicit source".into(),
                kind: Kind::Microphone,
                backend: "pipewire".into(),
                native_id: native.into(),
                capture_available: false,
                capture_state: CaptureState::PermissionUnknown,
                unavailable_reason: None,
            },
        };
        let rows = reported_sources(vec![original.clone()]);
        assert!(rows[0].valid());
        assert_eq!(rows[0].device.native_id, rows[0].device.id);
        assert!(!serde_json::to_string(&rows).unwrap().contains(native));
        assert_eq!(
            original.device.native_id, native,
            "Local exact-device resolution must retain its native endpoint"
        );
    }
    #[test]
    fn independent_capabilities_do_not_restart_unrelated_media_sessions() {
        let mut policy = features::Policy::default();
        let previous = transport(&policy);
        policy.disabled.insert(Feature::Keyboard, true);
        assert!(keep_session(Feature::MicrophoneShare, previous, &policy));
        assert!(keep_session(Feature::MediaReceive, previous, &policy));
        policy.disabled.insert(Feature::Usb, true);
        assert!(keep_session(Feature::MediaReceive, previous, &policy));
        policy.disabled.insert(Feature::MicrophoneShare, true);
        assert!(!keep_session(Feature::MicrophoneShare, previous, &policy));
        assert!(keep_session(Feature::MediaReceive, previous, &policy));
        policy.disabled.insert(Feature::PrivateNetwork, true);
        assert!(!keep_session(Feature::MediaReceive, previous, &policy));
    }
    #[test]
    fn legacy_report_keeps_microphones_and_strips_unnegotiated_camera_capabilities() {
        let value = legacy_report(
            json!({"protocol":2,"camera_enabled":true,"camera_receiver_available":true,"camera_receiver_unavailable_reason":null,"microphone_unavailable_reason":null,"camera_unavailable_reason":null,"sources":[{"device":{"kind":"microphone"}},{"device":{"kind":"camera"}}]}),
        );
        assert_eq!(value["protocol"], 1);
        assert_eq!(value["sources"].as_array().unwrap().len(), 1);
        assert!(
            value.get("camera_enabled").is_none()
                && value.get("camera_receiver_available").is_none()
        );
    }
}
