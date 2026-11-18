use anyhow::{ensure, Result};
use pipewire as pw;
use porthub_components::media::{Device, Kind};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    rc::Rc,
    time::{Duration, Instant},
};
fn supported_version(version: &str) -> bool {
    let parts = version
        .split('.')
        .take(3)
        .map(|v| {
            v.chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .parse::<u32>()
                .ok()
        })
        .collect::<Option<Vec<_>>>();
    parts.is_some_and(|v| v.len() == 3 && (v[0], v[1], v[2]) >= (0, 3, 68))
}
fn endpoint_name(hardware: Option<&str>, node: &str) -> String {
    if let Some(card) = hardware.and_then(|s| s.strip_prefix("alsa_card.")) {
        if let Some(profile) = node
            .strip_prefix(&format!("alsa_input.{card}."))
            .or_else(|| node.strip_prefix(&format!("alsa_output.{card}.")))
        {
            if let Some((base, suffix)) = profile.rsplit_once('.') {
                if [
                    "analog-stereo",
                    "analog-mono",
                    "mono-fallback",
                    "iec958-stereo",
                ]
                .contains(&base)
                    && !suffix.is_empty()
                    && suffix.bytes().all(|b| b.is_ascii_digit())
                {
                    return base.into();
                }
            }
            return profile.into();
        }
    }
    node.into()
}
#[derive(Clone)]
struct Node {
    device: Device,
    parent: Option<u32>,
    endpoint: Option<String>,
    serial: Option<String>,
}
struct Snapshot {
    devices: Vec<Device>,
    targets: BTreeMap<String, String>,
}
fn snapshot(nodes: BTreeMap<u32, Node>, hardware: BTreeMap<u32, String>) -> Snapshot {
    let mut names = BTreeMap::<String, usize>::new();
    let mut serials = BTreeMap::<String, usize>::new();
    for node in nodes.values() {
        *names.entry(node.device.native_id.clone()).or_default() += 1;
        if let Some(serial) = &node.serial {
            *serials.entry(serial.clone()).or_default() += 1;
        }
    }
    let mut result = BTreeMap::<String, (Device, Option<String>)>::new();
    for node in nodes.into_values() {
        let mut device = node.device;
        let native = node.parent.and_then(|id| hardware.get(&id));
        let endpoint = node
            .endpoint
            .unwrap_or_else(|| endpoint_name(native.map(String::as_str), &device.native_id));
        device.id = porthub_components::media::stable_source_id(
            device.kind,
            native.map(String::as_str).unwrap_or(&device.native_id),
            &endpoint,
        );
        let ambiguous = names.get(&device.native_id).copied().unwrap_or(0) > 1
            || node
                .serial
                .as_ref()
                .is_some_and(|s| serials.get(s).copied().unwrap_or(0) > 1);
        if ambiguous {
            device.capture_state = porthub_components::media::CaptureState::Unsupported;
            device.unavailable_reason = Some(
                "Ambiguous native source identity; refresh after duplicate OS nodes are resolved"
                    .into(),
            );
        } else if matches!(device.kind, Kind::Microphone | Kind::Speaker) && node.serial.is_none() {
            device.capture_state = porthub_components::media::CaptureState::Unsupported;
            device.unavailable_reason =
                Some("Native source instance identity is unavailable".into());
        }
        if let Some((old, target)) = result.get_mut(&device.id) {
            old.capture_state = porthub_components::media::CaptureState::Unsupported;
            old.unavailable_reason = Some(
                "Ambiguous native source identity; refresh after duplicate OS nodes are resolved"
                    .into(),
            );
            *target = None;
        } else {
            result.insert(device.id.clone(), (device, node.serial));
        }
    }
    let mut devices = Vec::new();
    let mut targets = BTreeMap::new();
    for (id, (device, target)) in result {
        if device.can_request_capture() {
            if let Some(target) = target {
                targets.insert(id, target);
            }
        }
        devices.push(device);
    }
    Snapshot { devices, targets }
}
fn insert_bounded<V>(map: &mut BTreeMap<u32, V>, id: u32, value: V) -> bool {
    if map.len() >= 256 && !map.contains_key(&id) {
        return false;
    }
    map.insert(id, value);
    true
}
fn collect(loop_: &pw::main_loop::MainLoopRc, core: &pw::core::CoreRc) -> Result<Snapshot> {
    let raw = unsafe { pw::sys::pw_get_library_version() };
    ensure!(!raw.is_null(), "PipeWire library version unavailable");
    ensure!(
        supported_version(unsafe { std::ffi::CStr::from_ptr(raw) }.to_str()?),
        "PipeWire 0.3.68 or later is required"
    );
    let registry = core.get_registry()?;
    let rows = Rc::new(RefCell::new(BTreeMap::<u32, Node>::new()));
    let result = rows.clone();
    let removed = rows.clone();
    let hardware = Rc::new(RefCell::new(BTreeMap::new()));
    let devices = hardware.clone();
    let removed_devices = hardware.clone();
    let overflow = Rc::new(Cell::new(false));
    let overflow_event = overflow.clone();
    let listener=registry.add_listener_local().global(move |global| {
        let Some(props)=global.props else{return};
        if global.type_==pw::types::ObjectType::Device {
            if let Some(name)=props.get("device.name").filter(|v|!v.is_empty()&&v.len()<=512) {if !insert_bounded(&mut devices.borrow_mut(),global.id,name.to_owned()){overflow_event.set(true);}}
            return;
        }
        if global.type_!=pw::types::ObjectType::Node{return;}
        let Some(class)=props.get("media.class")else{return};
        let kind=match class{"Audio/Source"=>Kind::Microphone,"Audio/Sink"=>Kind::Speaker,"Video/Source"=>Kind::Camera,_=>return};
        let Some(name)=props.get("node.name").filter(|s|!s.is_empty()&&s.len()<=512)else{return};
        let label=props.get("node.description").unwrap_or(name).chars().filter(|c|!c.is_control()).take(256).collect();
        let parent=props.get("device.id").and_then(|s|s.parse::<u32>().ok());
        let endpoint=props.get("device.profile.name").map(str::to_owned);
        let serial=props.get("object.serial").and_then(|s|s.parse::<u64>().ok()).filter(|s|*s>0).map(|s|s.to_string());
        let device=Device{id:String::new(),name:label,kind,backend:"pipewire".into(),native_id:name.into(),capture_available:false,capture_state:if matches!(kind,Kind::Microphone|Kind::Speaker){porthub_components::media::CaptureState::PermissionUnknown}else{porthub_components::media::CaptureState::Unsupported},unavailable_reason:Some("Source enumerated; explicit capture session and permissions have not been verified".into())};
        // Global IDs preserve simultaneous duplicate names for ambiguity checks.
        if !insert_bounded(&mut result.borrow_mut(),global.id,Node{device,parent,endpoint,serial}) {overflow_event.set(true);}
    }).global_remove(move |id|{removed.borrow_mut().remove(&id);removed_devices.borrow_mut().remove(&id);}).register();
    let done = Rc::new(RefCell::new(false));
    let done_event = done.clone();
    let pending = core.sync(0)?;
    let daemon_supported = Rc::new(RefCell::new(false));
    let daemon_version = daemon_supported.clone();
    let info_listener = core
        .add_listener_local()
        .info(move |info| *daemon_version.borrow_mut() = supported_version(info.version()))
        .register();
    let completion = core
        .add_listener_local()
        .done(move |id, seq| {
            if id == pw::core::PW_ID_CORE && seq == pending {
                *done_event.borrow_mut() = true;
            }
        })
        .register();
    let started = Instant::now();
    while !*done.borrow() && started.elapsed() < Duration::from_secs(3) {
        loop_
            .loop_()
            .iterate(pw::loop_::Timeout::Finite(Duration::from_millis(50)));
    }
    ensure!(
        *done.borrow(),
        "PipeWire inventory timed out without a complete graph snapshot"
    );
    ensure!(
        !overflow.get(),
        "PipeWire graph exceeds complete snapshot bound"
    );
    ensure!(
        *daemon_supported.borrow(),
        "PipeWire server 0.3.68 or later is required"
    );
    drop((completion, listener, info_listener));
    let nodes = std::mem::take(&mut *rows.borrow_mut());
    let hardware = std::mem::take(&mut *hardware.borrow_mut());
    Ok(snapshot(nodes, hardware))
}
pub fn inventory() -> Result<Vec<Device>> {
    pw::init();
    let loop_ = pw::main_loop::MainLoopRc::new(None)?;
    let context = pw::context::ContextRc::new(&loop_, None)?;
    let core = context.connect_rc(None)?;
    Ok(collect(&loop_, &core)?.devices)
}
/// Resolve a fresh graph instance on the SAME core that will create the stream.
/// A removed/replaced node cannot inherit this object.serial selector; capture
/// fails closed instead of relinking another node with a reused node.name.
pub(crate) fn capture_target(
    loop_: &pw::main_loop::MainLoopRc,
    core: &pw::core::CoreRc,
    selected: &str,
) -> Result<String> {
    selected_target(&collect(loop_, core)?, selected, Kind::Microphone)
}
pub(crate) fn playback_target(
    loop_: &pw::main_loop::MainLoopRc,
    core: &pw::core::CoreRc,
    selected: &str,
) -> Result<String> {
    selected_target(&collect(loop_, core)?, selected, Kind::Speaker)
}
fn selected_target(snapshot: &Snapshot, selected: &str, kind: Kind) -> Result<String> {
    let device = snapshot
        .devices
        .iter()
        .find(|d| {
            (if selected.starts_with("media:") {
                d.id == selected
            } else {
                d.native_id == selected
            }) && d.kind == kind
        })
        .ok_or_else(|| {
            anyhow::anyhow!("Requested microphone is not present in the source session")
        })?;
    ensure!(
        device.can_request_capture(),
        "Native source identity is ambiguous or unavailable"
    );
    snapshot
        .targets
        .get(&device.id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Native source instance identity unavailable"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn hardware_endpoint_identity_survives_generated_node_suffixes_without_merging_profiles() {
        let hardware = "alsa_card.pci-0000_00_1f.3";
        assert_eq!(
            super::endpoint_name(
                Some(hardware),
                "alsa_input.pci-0000_00_1f.3.analog-stereo.2"
            ),
            "analog-stereo"
        );
        assert_ne!(
            super::endpoint_name(
                Some(hardware),
                "alsa_input.pci-0000_00_1f.3.analog-stereo.2"
            ),
            super::endpoint_name(Some(hardware), "alsa_input.pci-0000_00_1f.3.iec958-stereo")
        );
        assert_eq!(super::endpoint_name(None, "virtual.0"), "virtual.0");
    }
    #[test]
    fn runtime_version_bounds_reject_old_or_unparseable_backends() {
        for version in [
            "0.3.48", "0.3.49", "0.3.64", "0.3.65", "0.3.67", "unknown", "1.2",
        ] {
            assert!(!super::supported_version(version));
        }
        for version in ["0.3.68", "1.2.0", "1.4.2-dev"] {
            assert!(super::supported_version(version));
        }
    }
    fn node(name: &str, serial: Option<&str>, parent: u32) -> super::Node {
        super::Node {
            device: porthub_components::media::Device {
                id: String::new(),
                name: name.into(),
                kind: porthub_components::media::Kind::Microphone,
                backend: "pipewire".into(),
                native_id: name.into(),
                capture_available: false,
                capture_state: porthub_components::media::CaptureState::PermissionUnknown,
                unavailable_reason: None,
            },
            parent: Some(parent),
            endpoint: Some("analog-stereo".into()),
            serial: serial.map(str::to_owned),
        }
    }
    fn hardware() -> std::collections::BTreeMap<u32, String> {
        [(1, "alsa_card.cardA".into()), (2, "alsa_card.cardB".into())]
            .into_iter()
            .collect()
    }
    #[test]
    fn capture_pins_fresh_graph_serial_without_changing_persistent_source_id() {
        let first = super::snapshot(
            [(10, node("input.A", Some("401"), 1))]
                .into_iter()
                .collect(),
            hardware(),
        );
        let id = first.devices[0].id.clone();
        assert_eq!(
            super::selected_target(&first, &id, porthub_components::media::Kind::Microphone)
                .unwrap(),
            "401"
        );
        let replacement = super::snapshot(
            [(11, node("input.A", Some("402"), 1))]
                .into_iter()
                .collect(),
            hardware(),
        );
        assert_eq!(replacement.devices[0].id, id);
        assert_eq!(
            super::selected_target(
                &replacement,
                &id,
                porthub_components::media::Kind::Microphone
            )
            .unwrap(),
            "402"
        );
        assert_eq!(
            super::selected_target(&first, &id, porthub_components::media::Kind::Microphone)
                .unwrap(),
            "401",
            "Old session target stays pinned to its graph instance"
        );
        assert!(super::selected_target(
            &super::snapshot(Default::default(), hardware()),
            &id,
            porthub_components::media::Kind::Microphone
        )
        .is_err());
    }
    #[test]
    fn duplicate_names_serials_and_stable_endpoints_fail_closed() {
        for nodes in [
            [
                (10, node("same", Some("401"), 1)),
                (11, node("same", Some("402"), 2)),
            ],
            [
                (10, node("input.A", Some("401"), 1)),
                (11, node("input.B", Some("401"), 2)),
            ],
            [
                (10, node("input.A", Some("401"), 1)),
                (11, node("input.A.2", Some("402"), 1)),
            ],
        ] {
            let s = super::snapshot(nodes.into_iter().collect(), hardware());
            assert!(s.targets.is_empty());
            assert!(s.devices.iter().all(|d| !d.can_request_capture()));
            for d in &s.devices {
                assert!(super::selected_target(
                    &s,
                    &d.id,
                    porthub_components::media::Kind::Microphone
                )
                .is_err());
            }
        }
    }
    #[test]
    fn missing_instance_serial_and_source_id_spoof_do_not_capture() {
        let s = super::snapshot(
            [(10, node("input.A", None, 1))].into_iter().collect(),
            hardware(),
        );
        assert!(s.targets.is_empty());
        assert!(super::selected_target(
            &s,
            &s.devices[0].id,
            porthub_components::media::Kind::Microphone
        )
        .is_err());
        let id = porthub_components::media::stable_source_id(
            porthub_components::media::Kind::Microphone,
            "alsa_card.cardA",
            "analog-stereo",
        );
        let s = super::snapshot(
            [(10, node(&id, Some("501"), 2))].into_iter().collect(),
            hardware(),
        );
        assert!(
            super::selected_target(&s, &id, porthub_components::media::Kind::Microphone).is_err(),
            "A node named like another source ID cannot substitute for that stable ID"
        );
    }
    #[test]
    fn playback_selection_pins_speaker_instance_and_never_substitutes_microphone() {
        use porthub_components::media::Kind;
        let mut speaker = node("alsa_output.cardA.analog-stereo", Some("601"), 1);
        speaker.device.kind = Kind::Speaker;
        let snapshot = super::snapshot([(20, speaker)].into_iter().collect(), hardware());
        let id = &snapshot.devices[0].id;
        assert_eq!(
            super::selected_target(&snapshot, id, Kind::Speaker).unwrap(),
            "601"
        );
        assert!(super::selected_target(&snapshot, id, Kind::Microphone).is_err());
        assert!(super::selected_target(&snapshot, "default", Kind::Speaker).is_err());
        assert_eq!(
            super::endpoint_name(Some("alsa_card.cardA"), "alsa_output.cardA.analog-stereo.2"),
            "analog-stereo"
        );
    }
    #[test]
    fn graph_limit_cannot_hide_duplicate_identity_or_parent() {
        let mut rows = std::collections::BTreeMap::new();
        for id in 0..256 {
            assert!(super::insert_bounded(&mut rows, id, id));
        }
        assert!(!super::insert_bounded(&mut rows, 256, 256));
        assert_eq!(rows.len(), 256);
        assert!(!rows.contains_key(&256));
        assert!(super::insert_bounded(&mut rows, 255, 999));
        assert_eq!(rows[&255], 999);
    }
}
