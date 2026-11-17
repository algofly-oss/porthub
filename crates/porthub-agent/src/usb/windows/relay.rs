//! Owned UDE attachment inspection. Never adopts externally attached devices.
//! The pinned0.9.8.1 unplug ABI is port-only: another local controller client changing a port between
//! query/unplug cannot be atomically fenced by this userspace protocol.
use super::*;
#[path = "relay_descriptor.rs"]
mod descriptor;
use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    CM_DRP_ADDRESS, CM_DRP_DRIVER, CM_Get_Child, CM_Get_DevNode_Registry_PropertyW,
    CM_Get_Device_Interface_List_SizeW, CM_Get_Device_Interface_ListW, CM_Get_Sibling,
};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Row {
    port: i32,
    hash: u32,
    busid: String,
    service: String,
    host: String,
    devid: u32,
    speed: u32,
    serial: [u8; 16],
    iserial: u8,
    events: u8,
    vendor: u16,
    product: u16,
}
const ROW_SIZE: usize = 1132;
pub(super) fn lifecycle() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}
fn text(bytes: &[u8]) -> Result<String> {
    let end = bytes
        .iter()
        .position(|v| *v == 0)
        .context("Unterminated UDE field")?;
    // Bytes following the C terminator are not part of the field.
    Ok(std::str::from_utf8(&bytes[..end])?.to_owned())
}
fn parse(bytes: &[u8]) -> Result<Vec<Row>> {
    ensure!(
        bytes.len() >= 4 && (bytes.len() - 4) % ROW_SIZE == 0,
        "Invalid UDE inventory length"
    );
    ensure!(
        (bytes.len() - 4) / ROW_SIZE <= 1024,
        "UDE inventory exceeds bound"
    );
    let mut rows = Vec::new();
    for b in bytes[4..].chunks_exact(ROW_SIZE) {
        let port = i32::from_le_bytes(b[..4].try_into()?);
        ensure!(
            port > 0 && !rows.iter().any(|r: &Row| r.port == port),
            "Invalid or duplicate UDE port"
        );
        rows.push(Row {
            port,
            hash: u32::from_le_bytes(b[4..8].try_into()?),
            busid: text(&b[8..40])?,
            service: text(&b[40..72])?,
            host: text(&b[72..1097])?,
            devid: u32::from_le_bytes(b[1100..1104].try_into()?),
            speed: u32::from_le_bytes(b[1104..1108].try_into()?),
            serial: b[1112..1128].try_into()?,
            iserial: b[1128],
            events: b[1129],
            vendor: u16::from_le_bytes(b[1108..1110].try_into()?),
            product: u16::from_le_bytes(b[1110..1112].try_into()?),
        });
    }
    Ok(rows)
}
fn inventory(driver: &File) -> Result<Vec<Row>> {
    // Mirrors0.9.8.1 get_imported_devices: header4, aligned row1132.
    for count in [4, 8, 16, 32, 64, 128, 256, 512, 1024] {
        let mut bytes = vec![0u8; 4 + count * ROW_SIZE];
        bytes[..4].copy_from_slice(&(4u32 + ROW_SIZE as u32).to_le_bytes());
        let mut returned = 0;
        let ok = unsafe {
            DeviceIoControl(
                driver.as_raw_handle(),
                0x0022e008,
                bytes.as_ptr().cast(),
                4,
                bytes.as_mut_ptr().cast(),
                bytes.len() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok != 0 {
            ensure!(
                returned as usize <= bytes.len(),
                "UDE inventory response exceeds buffer"
            );
            return parse(&bytes[..returned as usize]);
        }
        let error = std::io::Error::last_os_error();
        ensure!(
            error.raw_os_error() == Some(122),
            "Cannot inspect UDE imports: {error}"
        );
    }
    anyhow::bail!("UDE inventory exceeds maximum")
}
fn owned<'a>(rows: &'a [Row], port: i32, busid: &str, service: &str) -> Result<&'a Row> {
    ensure!(port > 0, "Refusing nonpositive UDE port");
    let row = rows
        .iter()
        .find(|r| r.port == port)
        .context("Owned UDE import missing")?;
    ensure!(
        row.host == "127.0.0.1" && row.busid == busid && row.service == service,
        "UDE import ownership changed"
    );
    Ok(row)
}
fn instance(node: u32) -> Result<String> {
    let mut name = [0u16; 512];
    ensure!(
        unsafe { CM_Get_Device_IDW(node, name.as_mut_ptr(), name.len() as u32, 0) } == 0,
        "Cannot identify imported PnP node"
    );
    let end = name
        .iter()
        .position(|v| *v == 0)
        .context("PnP identifier exceeds bound")?;
    Ok(String::from_utf16(&name[..end])?)
}
fn address(node: u32) -> Option<u32> {
    let (mut value, mut kind, mut size) = (0u32, 0u32, 4u32);
    (unsafe {
        CM_Get_DevNode_Registry_PropertyW(
            node,
            CM_DRP_ADDRESS,
            &mut kind,
            (&mut value as *mut u32).cast(),
            &mut size,
            0,
        )
    } == 0
        && kind == 4
        && size == 4)
        .then_some(value)
}
fn children(node: u32) -> Result<Vec<u32>> {
    let mut child = 0;
    let status = unsafe { CM_Get_Child(&mut child, node, 0) };
    if status == 13 {
        return Ok(vec![]);
    } // CR_NO_SUCH_DEVNODE
    ensure!(status == 0, "Cannot enumerate imported PnP ancestry");
    let mut rows = Vec::new();
    loop {
        ensure!(
            rows.len() < 1024 && !rows.contains(&child),
            "PnP enumeration exceeds bound"
        );
        rows.push(child);
        let mut next = 0;
        let status = unsafe { CM_Get_Sibling(&mut next, child, 0) };
        if status == 13 {
            break;
        }
        ensure!(status == 0, "Cannot enumerate imported PnP sibling");
        child = next;
    }
    Ok(rows)
}
fn driver_key(node: u32) -> Result<String> {
    let (mut kind, mut size) = (0u32, 2048u32);
    let mut value = [0u16; 1024];
    ensure!(
        unsafe {
            CM_Get_DevNode_Registry_PropertyW(
                node,
                CM_DRP_DRIVER,
                &mut kind,
                value.as_mut_ptr().cast(),
                &mut size,
                0,
            )
        } == 0
            && kind == 1
            && size >= 2
            && size <= 2048
            && size % 2 == 0,
        "Cannot inspect imported PnP driver key"
    );
    let end = value[..size as usize / 2]
        .iter()
        .position(|c| *c == 0)
        .context("Unterminated imported driver key")?;
    ensure!(end > 0, "Imported driver key unavailable");
    Ok(String::from_utf16(&value[..end])?)
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct HubConnection {
    key: String,
    configuration: u8,
    configurations: u8,
    vendor: u16,
    product: u16,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct PnpImport {
    instance: String,
    hub: u32,
    connection: HubConnection,
}
fn hub_file(hub: u32) -> Result<File> {
    const HUB: GUID = GUID::from_u128(0xf18a0e88_c30c_11d0_8815_00a0c906bed8);
    let id = instance(hub)?;
    let name = id.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let mut size = 0;
    ensure!(
        unsafe { CM_Get_Device_Interface_List_SizeW(&mut size, &HUB, name.as_ptr(), 0) } == 0
            && (2..=32768).contains(&size),
        "Imported hub interface unavailable"
    );
    let mut names = vec![0u16; size as usize];
    ensure!(
        unsafe { CM_Get_Device_Interface_ListW(&HUB, name.as_ptr(), names.as_mut_ptr(), size, 0) }
            == 0,
        "Cannot inspect imported hub interface"
    );
    let paths = names
        .split(|v| *v == 0)
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>();
    ensure!(paths.len() == 1, "Imported hub interface is ambiguous");
    let path = paths[0].iter().copied().chain(Some(0)).collect::<Vec<_>>();
    let raw = unsafe {
        CreateFileW(
            path.as_ptr(),
            0x40000000,
            3,
            std::ptr::null(),
            3,
            0x80,
            std::ptr::null_mut(),
        )
    };
    ensure!(
        raw != INVALID_HANDLE_VALUE,
        "Cannot open imported hub metadata"
    );
    Ok(unsafe { File::from_raw_handle(raw) })
}
fn hub_query(file: &File, code: u32, port: i32, bytes: &mut [u8]) -> Result<usize> {
    bytes[..4].copy_from_slice(&(port as u32).to_le_bytes());
    let mut returned = 0;
    ensure!(
        unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                code,
                bytes.as_ptr().cast(),
                bytes.len() as u32,
                bytes.as_mut_ptr().cast(),
                bytes.len() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        } != 0
            && returned as usize <= bytes.len(),
        "Cannot inspect imported hub connection"
    );
    Ok(returned as usize)
}
fn hub_connection(hub: u32, port: i32) -> Result<Option<HubConnection>> {
    let file = hub_file(hub)?;
    let mut connection = [0u8; 4096];
    let n = hub_query(&file, 2229320, port, &mut connection)?;
    ensure!(
        n >= 35 && u32::from_le_bytes(connection[..4].try_into()?) == port as u32,
        "Invalid imported hub response: returned={} expected_index={} actual_index={:?} status={:?}",
        n, port,
        (n>=4).then(||u32::from_le_bytes(connection[..4].try_into().unwrap())),
        (n>=35).then(||u32::from_le_bytes(connection[31..35].try_into().unwrap()))
    );
    match u32::from_le_bytes(connection[31..35].try_into()?) {
        0 => return Ok(None), // NoDeviceConnected
        1 => {}               // DeviceConnected
        _ => anyhow::bail!("Imported hub connection is not settled"),
    }
    let mut key = vec![0u8; 32768];
    let n = hub_query(&file, 2229280, port, &mut key)?;
    ensure!(n >= 10, "Imported hub key response truncated");
    let length = u32::from_le_bytes(key[4..8].try_into()?) as usize;
    ensure!(
        length >= 10 && length <= n && length % 2 == 0,
        "Invalid imported hub key length"
    );
    let wide = key[8..length]
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect::<Vec<_>>();
    let end = wide
        .iter()
        .position(|c| *c == 0)
        .context("Unterminated imported hub key")?;
    ensure!(end > 0, "Imported hub driver key unavailable");
    Ok(Some(HubConnection {
        key: String::from_utf16(&wide[..end])?,
        configuration: connection[22],
        configurations: connection[21],
        vendor: u16::from_le_bytes([connection[12], connection[13]]),
        product: u16::from_le_bytes([connection[14], connection[15]]),
    }))
}
fn port_instances(controller: u32, port: i32) -> Result<Vec<PnpImport>> {
    ensure!(port > 0, "Refusing nonpositive UDE port");
    let mut matches = Vec::new();
    // Pinned UDE plugin assigns its positive port to a USB2/USB3 root-hub
    // connection. Bind to that exact controller, not friendly names or VID/PID.
    let mut hubs = 0;
    for hub in children(controller)? {
        let id = instance(hub)?.to_ascii_uppercase();
        if !id.starts_with("USB\\ROOT_HUB") {
            continue;
        }
        hubs += 1;
        let connection = hub_connection(hub, port)?;
        let mut candidates = Vec::new();
        for node in children(hub)? {
            let address = address(node).context("Cannot inspect imported PnP port")?;
            if address == port as u32 {
                let key = driver_key(node)?;
                ensure!(
                    connection
                        .as_ref()
                        .is_some_and(|expected| expected.key.eq_ignore_ascii_case(&key)),
                    "Imported hub/PnP association changed"
                );
                candidates.push(instance(node)?);
            }
        }
        ensure!(
            if connection.is_some() {
                candidates.len() == 1
            } else {
                candidates.is_empty()
            },
            "Imported hub/PnP presence is not settled"
        );
        if let Some(connection) = connection {
            matches.extend(candidates.into_iter().map(|instance| PnpImport {
                instance,
                hub,
                connection: connection.clone(),
            }));
        }
    }
    ensure!(hubs > 0, "Owned UDE root hub unavailable");
    Ok(matches)
}
fn imported_location(controller: u32, row: &Row) -> Result<PnpImport> {
    let mut candidates = port_instances(controller, row.port)?;
    let id = select_instance(candidates.iter().map(|c| c.instance.clone()).collect(), row)?;
    let found = candidates.remove(0);
    ensure!(
        found.instance == id
            && found.connection.vendor == row.vendor
            && found.connection.product == row.product,
        "Imported hub identity changed"
    );
    Ok(found)
}
fn select_instance(mut matches: Vec<String>, row: &Row) -> Result<String> {
    ensure!(
        matches.len() == 1,
        "Imported PnP port is absent or ambiguous"
    );
    let id = matches.remove(0);
    let prefix = format!("USB\\VID_{:04X}&PID_{:04X}", row.vendor, row.product);
    ensure!(
        id.to_ascii_uppercase().starts_with(&prefix),
        "Imported PnP identity changed"
    );
    Ok(id)
}
fn settled(rows: &[Row], expected: Option<&Row>, port: i32, foreign: &[Row]) -> Result<bool> {
    ensure!(
        foreign.iter().all(|r| rows.contains(r))
            && rows
                .iter()
                .filter(|r| r.port != port)
                .all(|r| foreign.contains(r)),
        "Foreign UDE inventory changed during detach"
    );
    match rows.iter().find(|r| r.port == port) {
        None => Ok(true),
        Some(row) => {
            ensure!(Some(row) == expected, "UDE port replaced during detach");
            Ok(false)
        }
    }
}

// A hub can still report transitional metadata after its controller row has
// disappeared. An inspection error never proves absence: retain its bounded
// diagnostic and require a later complete valid observation within the budget.
fn detach_settlement_ready(
    controller_absent: bool,
    inspect: impl FnOnce() -> Result<bool>,
    expired: bool,
    last_error: &mut Option<String>,
) -> Result<bool> {
    if controller_absent {
        match inspect() {
            Ok(true) => return Ok(true),
            Ok(false) => {},
            Err(error) => *last_error=Some(format!("{error:#}").chars().take(512).collect()),
        }
    }
    ensure!(!expired,"Owned UDE/PnP detach did not settle; last inspection error {:?}",last_error);
    Ok(false)
}

#[derive(Clone,Debug,PartialEq,Eq)]
struct CmTree { controller:String, edges:Vec<(String,String)> }
fn cm_foreign_projection(tree:&CmTree,hub:&str,owned:&str)->Result<CmTree> {
    ensure!(tree.edges.len()<=4096 && hub!=owned && owned!=tree.controller,"Invalid owned CM projection");
    let mut ids=std::collections::HashSet::new();
    for (_,child) in &tree.edges {ensure!(ids.insert(child),"Ambiguous CM instance identity");}
    ensure!(tree.edges.iter().any(|(parent,child)|parent==&tree.controller&&child==hub)
        &&tree.edges.iter().any(|(parent,child)|parent==hub&&child==owned),"Owned CM hub association changed");
    let mut removed=std::collections::HashSet::from([owned.to_owned()]);
    for _ in 0..=tree.edges.len() {
        let before=removed.len();
        for (parent,child) in &tree.edges {if removed.contains(parent){removed.insert(child.clone());}}
        if removed.len()==before {break;}
    }
    ensure!(!removed.contains(hub)&&!removed.contains(&tree.controller),"Cyclic owned CM projection");
    let mut edges=tree.edges.iter().filter(|(_,child)|!removed.contains(child)).cloned().collect::<Vec<_>>();
    edges.sort();
    Ok(CmTree{controller:tree.controller.clone(),edges})
}
fn cm_absent(expected:&CmTree,current:&CmTree)->bool {expected==current}

fn pnp_baseline(controller: u32) -> Result<Vec<String>> {
    let mut rows = Vec::new();
    let mut hubs = 0;
    for hub in children(controller)? {
        let id = instance(hub)?;
        if !id.to_ascii_uppercase().starts_with("USB\\ROOT_HUB") {
            continue;
        }
        hubs += 1;
        rows.push(id);
        for node in children(hub)? {
            rows.push(instance(node)?);
        }
    }
    ensure!(hubs > 0, "Owned UDE root hub unavailable");
    rows.sort();
    Ok(rows)
}
// Complete present CM ancestry scoped to the held controller. No post-unplug
// hub IOCTL is needed for this independent proof; any read error is unproven.
fn cm_tree(controller:u32)->Result<CmTree> {
    let root=instance(controller)?;
    let mut edges=Vec::new();let mut pending=vec![(controller,root.clone(),0usize)];
    let mut seen=std::collections::HashSet::from([root.clone()]);
    while let Some((node,parent,depth))=pending.pop() {
        ensure!(depth<=32,"Owned CM ancestry exceeds depth bound");
        for child in children(node)? {
            let id=instance(child)?;
            ensure!(seen.insert(id.clone())&&edges.len()<4096,"Owned CM ancestry ambiguous or exceeds bound");
            edges.push((parent.clone(),id.clone()));pending.push((child,id,depth+1));
        }
    }
    edges.sort();Ok(CmTree{controller:root,edges})
}
fn ready_cm_projection(controller:u32,row:&Row)->Result<CmTree> {
    let location=imported_location(controller,row)?;
    let hub=instance(location.hub)?;
    cm_foreign_projection(&cm_tree(controller)?,&hub,&location.instance)
}
pub(super) struct Intent {
    driver: File,
    controller: u32,
    busid: String,
    service: String,
    before: Vec<Row>,
    pnp: Vec<String>,
}
impl Intent {
    pub(super) fn capture(
        driver: &File,
        controller: u32,
        busid: &str,
        service: &str,
    ) -> Result<Self> {
        let before = inventory(driver)?;
        ensure!(
            !before
                .iter()
                .any(|r| r.busid == busid && r.host == "127.0.0.1" && r.service == service),
            "UDE import capability already exists"
        );
        Ok(Self {
            driver: driver.try_clone()?,
            controller,
            busid: busid.into(),
            service: service.into(),
            before,
            pnp: pnp_baseline(controller)?,
        })
    }
    pub(super) fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            driver: self.driver.try_clone()?,
            controller: self.controller,
            busid: self.busid.clone(),
            service: self.service.clone(),
            before: self.before.clone(),
            pnp: self.pnp.clone(),
        })
    }
    pub(super) fn absent_port(&self, port: i32) -> Result<bool> {
        ensure!(port > 0, "Invalid retired UDE port");
        let rows = inventory(&self.driver)?;
        if rows
            .iter()
            .any(|r| r.busid == self.busid && r.host == "127.0.0.1" && r.service == self.service)
        {
            return Ok(false);
        }
        if rows.iter().any(|r| r.port == port) {
            return Ok(false);
        }
        Ok(port_instances(self.controller, port)?.is_empty())
    }
    pub(super) fn absent(&self) -> Result<bool> {
        let rows = inventory(&self.driver)?;
        if rows
            .iter()
            .any(|r| r.busid == self.busid && r.host == "127.0.0.1" && r.service == self.service)
        {
            return Ok(false);
        }
        // A failed/pending PLUG has no trustworthy positive port. Its fence
        // clears only when the exact pre-PLUG native/PnP baseline is restored.
        Ok(rows == self.before && pnp_baseline(self.controller)? == self.pnp)
    }
}
pub(crate) struct StorageSnapshot {
    disks: Option<Vec<DiskNode>>,
}
impl StorageSnapshot {
    pub(crate) fn capture() -> Self {
        Self {
            disks: disk_ancestry(),
        }
    }
}
fn read_active_configuration(
    location: &PnpImport,
    port: i32,
) -> Result<Result<descriptor::Configuration, String>> {
    ensure!(
        location.connection.configuration > 0
            && (1..=8).contains(&location.connection.configurations),
        "Imported active configuration unavailable or exceeds bound"
    );
    let file = hub_file(location.hub)?;
    fn read(file: &File, port: i32, index: u8, length: usize) -> Result<Vec<u8>> {
        ensure!(
            (9..=65535).contains(&length),
            "Imported configuration length exceeds bound"
        );
        // USB_DESCRIPTOR_REQUEST header is12 bytes (Data[0]), not the Rust
        // generated flexible-array placeholder's sizeof13. USBView uses this
        // exact standard IN GET_DESCRIPTOR(configuration,index) handshake.
        let mut bytes = vec![0u8; 12 + length];
        bytes[4] = 0x80;
        bytes[5] = 6;
        bytes[6] = index;
        bytes[7] = 2;
        bytes[10..12].copy_from_slice(&(length as u16).to_le_bytes());
        let returned = hub_query(file, 2229264, port, &mut bytes)?;
        ensure!(
            returned == 12 + length,
            "Imported configuration response is truncated"
        );
        Ok(bytes[12..returned].to_vec())
    }
    for index in 0..location.connection.configurations {
        let header = read(&file, port, index, 9)?;
        ensure!(
            header[0] == 9 && header[1] == 2,
            "Invalid imported configuration header"
        );
        if header[5] != location.connection.configuration {
            continue;
        }
        let total = u16::from_le_bytes([header[2], header[3]]) as usize;
        let bytes = read(&file, port, index, total)?;
        ensure!(
            bytes.get(5) == Some(&location.connection.configuration),
            "Imported active configuration changed"
        );
        return Ok(descriptor::validate(&bytes).map_err(|error| error.to_string()));
    }
    anyhow::bail!("Imported active configuration was not found")
}
#[derive(Clone)]
pub(crate) struct Marker {
    display_probe: Arc<std::sync::atomic::AtomicBool>,
    state: Arc<Mutex<AttachState>>,
    device: Device,
    display_classes: Arc<Mutex<Option<(u8, Result<descriptor::Configuration, String>)>>>,
}
impl Marker {
    #[cfg(test)]
    pub(crate) fn pending_test(device: Device) -> Self {
        Self::new(
            Arc::new(Mutex::new(AttachState {
                cancelled: false,
                settled: false,
                port: None,
                attach_finished: false,
                retired_port: None,
                cleanup_running: false,
                cleanup_failed: false,
                intent: None,
            })),
            device,
        )
    }
    #[cfg(test)]
    pub(crate) fn settle_test(&self) {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).settled = true;
    }
    pub(super) fn new(state: Arc<Mutex<AttachState>>, device: Device) -> Self {
        Self {
            state,
            device,
            display_classes: Arc::new(Mutex::new(None)),
            display_probe: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
    pub(crate) fn settled(&self) -> bool {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).settled
    }
    pub(crate) fn retire(&self) {
        super::retire_attachment(&self.state);
    }
    #[cfg(test)]
    pub(crate) fn late_success_test(&self, cleanup_ok: bool) -> Result<()> {
        // Inert ordinary temporary File, never a controller/device handle.
        let port = Port {
            driver: tempfile::tempfile()?,
            port: 3,
            controller: 0,
            busid: "inert".into(),
            service: "0".into(),
            detached: false,
        };
        ensure!(
            super::complete_attachment(&self.state, port),
            "Late completion was not marked canceled"
        );
        let (port, intent) =
            super::retirement_work(&self.state).context("Late owned cleanup was lost")?;
        super::finish_retirement(&self.state, port, intent, |port| {
            port.detached = true;
            if cleanup_ok {
                Ok(())
            } else {
                anyhow::bail!("inert cleanup busy")
            }
        });
        Ok(())
    }
    fn confirm_absent(&self, observed: bool) -> bool {
        if !observed {
            return false;
        }
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.cancelled
            && state.attach_finished
            && !state.cleanup_running
            && state.port.is_none()
        {
            state.settled = true;
            true
        } else {
            false
        }
    }
    #[cfg(test)]
    pub(crate) fn reconcile_test(&self, observed: bool) -> bool {
        self.confirm_absent(observed)
    }
    pub(crate) fn reconcile_retired(&self) -> Result<bool> {
        let (intent, port) = {
            let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if state.settled {
                return Ok(true);
            }
            if !state.cancelled || !state.attach_finished || state.cleanup_running {
                return Ok(false);
            }
            (
                state.intent.as_ref().map(Intent::try_clone).transpose()?,
                state.retired_port,
            )
        };
        let Some(intent) = intent else {
            return Ok(false);
        };
        Ok(self.confirm_absent(if let Some(port) = port {
            intent.absent_port(port)?
        } else {
            intent.absent()?
        }))
    }
    pub(crate) fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }
    pub(crate) fn active(&self) -> bool {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        !state.cancelled && state.port.is_some()
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.validate_inner(&StorageSnapshot::capture(), true)
    }
    pub(crate) fn validate_with(&self, snapshot: &StorageSnapshot) -> Result<()> {
        self.validate_inner(snapshot, false)
    }
    fn validate_inner(&self, snapshot: &StorageSnapshot, fresh: bool) -> Result<()> {
        // Clone only our metadata handle/identity while locked; no OS/storage
        // enumeration is performed under the import or attachment state mutex.
        let (driver, controller, port, busid, service) = {
            let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            ensure!(!state.cancelled, "Imported UDE attachment ended");
            let held = state
                .port
                .as_ref()
                .context("Waiting for owned UDE attachment")?;
            (
                held.driver.try_clone()?,
                held.controller,
                held.port,
                held.busid.clone(),
                held.service.clone(),
            )
        };
        let _lifecycle = lifecycle()
            .try_lock()
            .map_err(|_| anyhow::anyhow!("UDE controller ownership is changing"))?;
        let rows = inventory(&driver)?;
        let row = owned(&rows, port, &busid, &service)?;
        ensure!(
            format!("{:04x}", row.vendor) == self.device.vendor
                && format!("{:04x}", row.product) == self.device.product,
            "UDE device identity changed"
        );
        let location = imported_location(controller, row)?;
        let instance = &location.instance;
        let cached = if fresh {
            None
        } else {
            self.display_classes
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone()
                .filter(|(value, _)| *value == location.connection.configuration)
        };
        let classes = if let Some((_, classes)) = cached {
            classes
        } else {
            if !fresh {
                self.start_report_probe();
                anyhow::bail!("Imported configuration inspection is pending");
            }
            let result = read_active_configuration(&location, port)?;
            *self
                .display_classes
                .lock()
                .unwrap_or_else(|p| p.into_inner()) =
                Some((location.connection.configuration, result.clone()));
            result
        };
        classes.map_err(anyhow::Error::msg)?;
        ensure!(
            has_disk_descendant(&instance, snapshot.disks.as_deref()) == Some(false),
            "Imported storage or unknown disk ancestry cannot be forwarded onward without exclusive volume protection"
        );
        ensure!(
            imported_location(controller, row)? == location,
            "Imported PnP ancestry changed during safety inspection"
        );
        ensure!(
            owned(&inventory(&driver)?, port, &busid, &service)? == row,
            "UDE attachment changed during safety inspection"
        );
        ensure!(
            self.active(),
            "Imported UDE attachment ended during safety inspection"
        );
        Ok(())
    }
    fn start_report_probe(&self) {
        use std::sync::atomic::Ordering;
        if self
            .display_probe
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            self.display_probe.store(false, Ordering::Release);
            return;
        };
        struct Reset(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Reset {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let reset = Reset(self.display_probe.clone());
        let marker = self.clone();
        runtime.spawn(async move {
            let _reset = reset;
            // At most one metadata-only descriptor probe per import; bounded
            // startup polling. Reporting never performs USB control IO itself.
            for _ in 0..15 {
                if !marker.active() {
                    break;
                }
                let probing = marker.clone();
                if matches!(
                    tokio::task::spawn_blocking(move || probing.probe_display_configuration())
                        .await,
                    Ok(Ok(()))
                ) {
                    break;
                }
                if !marker.active() {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }
    fn probe_display_configuration(&self) -> Result<()> {
        let (driver, controller, port, busid, service) = {
            let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            ensure!(!state.cancelled, "Imported UDE attachment ended");
            let held = state
                .port
                .as_ref()
                .context("Owned UDE attachment not ready")?;
            (
                held.driver.try_clone()?,
                held.controller,
                held.port,
                held.busid.clone(),
                held.service.clone(),
            )
        };
        let _lifecycle = lifecycle()
            .try_lock()
            .map_err(|_| anyhow::anyhow!("UDE ownership is changing"))?;
        let rows = inventory(&driver)?;
        let row = owned(&rows, port, &busid, &service)?;
        let location = imported_location(controller, row)?;
        let classes = read_active_configuration(&location, port)?;
        ensure!(
            self.active() && owned(&inventory(&driver)?, port, &busid, &service)? == row,
            "Owned UDE attachment changed during display inspection"
        );
        *self
            .display_classes
            .lock()
            .unwrap_or_else(|p| p.into_inner()) =
            Some((location.connection.configuration, classes));
        Ok(())
    }
}
impl Port {
    pub(super) fn detach(&mut self, wait: bool) -> Result<()> {
        if self.detached {
            return Ok(());
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        let _lifecycle = loop {
            if let Ok(lock) = lifecycle().try_lock() {
                break lock;
            }
            ensure!(
                wait && Instant::now() < deadline,
                "UDE controller cleanup already in progress"
            );
            std::thread::sleep(Duration::from_millis(25));
        };
        ensure!(self.port > 0, "Refusing nonpositive UDE port");
        let before = inventory(&self.driver)?;
        let expected = if before.iter().any(|r| r.port == self.port) {
            Some(owned(&before, self.port, &self.busid, &self.service)?.clone())
        } else {
            None
        };
        let foreign = before
            .iter()
            .filter(|r| r.port != self.port)
            .cloned()
            .collect::<Vec<_>>();
        // Only a fully associated READY import can use the independent CM
        // absence proof. Pending imports retain the original conservative path.
        let cm_expected=expected.as_ref().and_then(|row|ready_cm_projection(self.controller,row).ok());
        let mut unplug_error = None;
        if expected.is_some() {
            let mut data = [8u32, self.port as u32];
            let mut returned = 0;
            let ok = unsafe {
                DeviceIoControl(
                    self.driver.as_raw_handle(),
                    0x0022e004,
                    data.as_mut_ptr().cast(),
                    8,
                    std::ptr::null_mut(),
                    0,
                    &mut returned,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                unplug_error = Some(std::io::Error::last_os_error());
            }
        }
        // Once attempted, never issue another port-only operation from Drop.
        // Closing the carrier can concurrently remove this exact import; only
        // observed controller AND hub/PnP absence can resolve that race safely.
        self.detached = true;
        if !wait {
            if let Some(error) = unplug_error {
                anyhow::bail!("Owned UDE detach failed: {error}");
            }
            return Ok(());
        }
        let mut last_inspection_error=None;
        loop {
            let rows = inventory(&self.driver)?;
            // Ownership and foreign-row changes stay immediately fatal.
            let absent=settled(&rows, expected.as_ref(), self.port, &foreign)?;
            if detach_settlement_ready(absent,
                ||match cm_expected.as_ref() {
                    Some(expected)=>Ok(cm_absent(expected,&cm_tree(self.controller)?)),
                    None=>Ok(port_instances(self.controller,self.port)?.is_empty()),
                },
                Instant::now()>=deadline,&mut last_inspection_error)
                .with_context(||format!("Owned UDE detach unplug status {:?}",unplug_error.as_ref().and_then(|e|e.raw_os_error())))?
            {return Ok(());}
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn row(port: i32) -> Row {
        Row {
            port,
            hash: 42,
            busid: "1-private".into(),
            service: "12345".into(),
            host: "127.0.0.1".into(),
            devid: 1,
            speed: 3,
            serial: [0; 16],
            iserial: 1,
            events: 0,
            vendor: 0x10c4,
            product: 0xea60,
        }
    }
    #[test]
    fn owner_requires_positive_port_and_exact_tuple() {
        let rows = [row(3)];
        assert!(owned(&rows, 3, "1-private", "12345").is_ok());
        assert!(owned(&rows, 0, "1-private", "12345").is_err());
        assert!(owned(&rows, 3, "1-foreign", "12345").is_err());
        assert!(
            owned(
                &[Row {
                    host: "192.168.0.1".into(),
                    ..row(3)
                }],
                3,
                "1-private",
                "12345"
            )
            .is_err()
        );
    }
    #[test]
    fn detach_never_settles_with_owned_or_changed_foreign_rows() {
        let own = row(3);
        let foreign = row(4);
        assert!(
            !settled(
                &[own.clone(), foreign.clone()],
                Some(&own),
                3,
                &[foreign.clone()]
            )
            .unwrap()
        );
        assert!(settled(&[foreign.clone()], Some(&own), 3, &[foreign.clone()]).unwrap());
        assert!(settled(&[], Some(&own), 3, &[foreign.clone()]).is_err());
        assert!(
            settled(
                &[
                    Row {
                        hash: 43,
                        ..own.clone()
                    },
                    foreign.clone()
                ],
                Some(&own),
                3,
                &[foreign.clone()]
            )
            .is_err()
        );
        assert!(settled(&[own.clone()], None, 3, &[]).is_err());
    }
    #[test]
    fn detach_retries_unproven_hub_until_valid_absence() {
        let mut last=None;
        assert!(!detach_settlement_ready(true,||anyhow::bail!("Invalid imported hub response: index0"),false,&mut last).unwrap());
        assert!(last.as_ref().unwrap().contains("index0"));
        assert!(!detach_settlement_ready(true,||Ok(false),false,&mut last).unwrap());
        assert!(detach_settlement_ready(true,||Ok(true),false,&mut last).unwrap());
        assert!(!detach_settlement_ready(false,||panic!("Owned controller row still present"),false,&mut last).unwrap());
    }
    #[test]
    fn detach_permanent_mismatch_expires_without_proving_absence() {
        let mut last=None;
        for expired in [false,false,true] {
            let result=detach_settlement_ready(true,||anyhow::bail!("{}","x".repeat(1024)),expired,&mut last);
            assert_eq!(result.is_err(),expired);
            if !expired {assert!(!result.unwrap());}
            assert_eq!(last.as_ref().unwrap().len(),512);
        }
        assert!(detach_settlement_ready(false,||Ok(true),true,&mut last).is_err());
    }
    #[test]
    fn ready_cm_absence_requires_exact_foreign_tree_and_owned_subtree_removal() {
        let tree=CmTree{controller:"controller".into(),edges:vec![
            ("controller".into(),"hub".into()),("hub".into(),"owned".into()),
            ("owned".into(),"audio".into()),("hub".into(),"foreign".into())]};
        let expected=cm_foreign_projection(&tree,"hub","owned").unwrap();
        assert_eq!(expected.edges.len(),2);
        assert!(!cm_absent(&expected,&tree));
        assert!(cm_absent(&expected,&expected));
        let mut changed=expected.clone();changed.edges.pop();assert!(!cm_absent(&expected,&changed));
        let mut changed=expected.clone();changed.edges.push(("hub".into(),"replacement".into()));assert!(!cm_absent(&expected,&changed));
        let mut changed=expected.clone();changed.controller="different".into();assert!(!cm_absent(&expected,&changed));
    }
    #[test]
    fn ready_cm_projection_rejects_unknown_identity_hub_and_ambiguous_instances() {
        let tree=CmTree{controller:"controller".into(),edges:vec![
            ("controller".into(),"hub".into()),("hub".into(),"owned".into())]};
        assert!(cm_foreign_projection(&tree,"hub","unknown").is_err());
        assert!(cm_foreign_projection(&tree,"foreign-hub","owned").is_err());
        assert!(cm_foreign_projection(&tree,"hub","hub").is_err());
        let mut duplicate=tree.clone();duplicate.edges.push(("other".into(),"owned".into()));
        assert!(cm_foreign_projection(&duplicate,"hub","owned").is_err());
        let mut replacement=tree.clone();replacement.edges[1].1="replacement".into();
        assert!(cm_foreign_projection(&replacement,"hub","owned").is_err());
    }
    #[test]
    fn pnp_selection_rejects_missing_ambiguous_or_different_identity() {
        let own = row(3);
        let id = "USB\\VID_10C4&PID_EA60\\0001".to_string();
        assert_eq!(select_instance(vec![id.clone()], &own).unwrap(), id);
        assert!(select_instance(vec![], &own).is_err());
        assert!(select_instance(vec![id.clone(), id], &own).is_err());
        assert!(select_instance(vec!["USB\\VID_0781&PID_55A9\\foreign".into()], &own).is_err());
    }
    #[test]
    fn inventory_rejects_truncation_duplicate_ports_and_unterminated_strings() {
        assert!(parse(&[0; 3]).is_err());
        let mut bytes = vec![0u8; 4 + ROW_SIZE];
        bytes[4..8].copy_from_slice(&3i32.to_le_bytes());
        assert_eq!(parse(&bytes).unwrap().len(), 1);
        assert!(parse(&bytes[..bytes.len() - 1]).is_err());
        let copy = bytes[4..].to_vec();
        bytes.extend(copy);
        assert!(parse(&bytes).is_err());
        bytes.truncate(4 + ROW_SIZE);
        bytes[12..44].fill(b'a');
        assert!(parse(&bytes).is_err());
    }
}

#[cfg(test)]
pub(crate) struct FixtureBaseline {
    driver: File,
    controller: u32,
    rows: Vec<Row>,
    pnp: Vec<String>,
    volumes: String,
    image: File,
    image_sha: String,
    driver_version: String,
}
#[cfg(test)]
fn volume_fingerprint() -> Result<String> {
    let states = volume_states().context("Native volume baseline unavailable")?;
    let mut values = states
        .into_iter()
        .map(|v| {
            let mut disks = v.disks;
            if let Some(disks) = &mut disks {
                disks.sort_unstable();
            }
            (disks, v.offline, v.mounted)
        })
        .collect::<Vec<_>>();
    values.sort();
    use sha2::{Digest, Sha256};
    Ok(format!(
        "{:x}",
        Sha256::digest(format!("{values:?}").as_bytes())
    ))
}
#[cfg(test)]
fn fixture_hash(file: &mut File) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Seek, SeekFrom};
    file.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut count = 0usize;
    let mut bytes = [0u8; 65536];
    loop {
        let n = file.read(&mut bytes)?;
        if n == 0 {
            break;
        }
        count += n;
        ensure!(
            count <= 64 * 1024 * 1024,
            "Fixture driver image exceeds bound"
        );
        hash.update(&bytes[..n]);
    }
    ensure!(count > 0, "Fixture driver image empty");
    Ok(format!("{:x}", hash.finalize()))
}
#[cfg(test)]
pub(crate) async fn fixture_baseline() -> Result<FixtureBaseline> {
    ensure!(
        std::env::var("PORTHUB_PRIVATE_UDE_MAPPING_TEST").as_deref() == Ok("1")
            && std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
            && std::env::var("RUNNER_ENVIRONMENT").as_deref() == Ok("github-hosted"),
        "Explicit disposable hosted Windows fixture authorization required"
    );
    crate::service::require_administrator()?;
    let os =
        windows_registry::LOCAL_MACHINE.open("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")?;
    ensure!(
        os.get_string("CurrentBuildNumber")?.parse::<u32>()? >= 26100
            && os.get_string("ProductName")?.contains("Server"),
        "Disposable Windows Server2025 fixture required"
    );
    let state = std::path::PathBuf::from(
        std::env::var_os("ProgramData").context("ProgramData unavailable")?,
    )
    .join("PortHub");
    ensure!(
        !state.try_exists()?,
        "Fixture refuses existing PortHub shared state"
    );
    let (driver, controller) = controller_info()?;
    let key = driver_key(controller)?;
    let metadata = windows_registry::LOCAL_MACHINE
        .open(format!("SYSTEM\\CurrentControlSet\\Control\\Class\\{key}"))?;
    // Installer/product version0.9.8.1 is not necessarily the WDK INF's
    // stamped DriverVersion. Bind the exact package plus approved SYS digest.
    let package=windows_registry::LOCAL_MACHINE.options().read().access(0x0100).open("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{199505b0-b93d-4521-a8c7-897818e0205a}_is1")?;
    ensure!(
        package.get_string("DisplayName")? == "USBip 0.9.8.1"
            && package.get_string("DisplayVersion")? == "0.9.8.1",
        "Exact receiver package0.9.8.1 required"
    );
    let driver_version = metadata.get_string("DriverVersion")?;
    ensure!(
        driver_version.len() <= 64
            && driver_version.split('.').count() == 4
            && driver_version
                .split('.')
                .all(|part| part.parse::<u16>().is_ok()),
        "Invalid stamped driver version metadata"
    );
    let service =
        windows_registry::LOCAL_MACHINE.open("SYSTEM\\CurrentControlSet\\Services\\usbip2_ude")?;
    let image = service.get_string("ImagePath")?;
    let system =
        PathBuf::from(std::env::var_os("SystemRoot").context("Windows SystemRoot unavailable")?);
    let path = if let Some(rest) = image.strip_prefix("\\SystemRoot\\") {
        system.join(rest)
    } else {
        PathBuf::from(image.strip_prefix("\\??\\").unwrap_or(&image))
    };
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    let meta = std::fs::symlink_metadata(&path)?;
    ensure!(
        meta.is_file() && meta.file_attributes() & 0x400 == 0,
        "Fixture driver must be a regular non-reparse image"
    );
    let canonical = path.canonicalize()?;
    let allowed = system
        .join("System32")
        .join("DriverStore")
        .join("FileRepository")
        .canonicalize()?;
    let prefix = format!("{}\\", allowed.to_string_lossy().to_ascii_lowercase());
    ensure!(
        canonical
            .to_string_lossy()
            .to_ascii_lowercase()
            .starts_with(&prefix)
            && canonical
                .file_name()
                .is_some_and(|n| n.eq_ignore_ascii_case("usbip2_ude.sys")),
        "Fixture driver escaped exact DriverStore namespace"
    );
    let mut image = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x00200000)
        .open(&canonical)?;
    let image_sha = fixture_hash(&mut image)?;
    let expected = std::env::var("PORTHUB_PRIVATE_UDE_DRIVER_SHA256")?;
    ensure!(
        expected.len() == 64
            && expected.bytes().all(|b| b.is_ascii_hexdigit())
            && expected == image_sha,
        "Fixture driver hash does not match explicit approved pin"
    );
    let mut command = tokio::process::Command::new(
        system
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe"),
    );
    command.args(["-NoProfile","-NonInteractive","-Command",r#"$ErrorActionPreference='Stop';Import-Module -Name "$PSHOME\Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1" -ErrorAction Stop;if((Get-AuthenticodeSignature -LiteralPath $env:PORTHUB_FIXTURE_DRIVER).Status -ne 'Valid'){throw 'Fixture driver signature rejected'}"#]).env_remove("PSModulePath").env_remove("PSModuleAnalysisCachePath").env("PORTHUB_FIXTURE_DRIVER",&canonical).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).kill_on_drop(true);
    ensure!(
        tokio::time::timeout(Duration::from_secs(40), command.status())
            .await??
            .success(),
        "Fixture driver signature rejected"
    );
    let rows = inventory(&driver)?;
    ensure!(
        rows.is_empty(),
        "Disposable fixture requires an empty UDE controller"
    );
    let pnp = pnp_baseline(controller)?;
    let volumes = volume_fingerprint()?;
    Ok(FixtureBaseline {
        driver,
        controller,
        rows,
        pnp,
        volumes,
        image,
        image_sha,
        driver_version,
    })
}
#[cfg(test)]
impl FixtureBaseline {
    pub(crate) fn verify(&mut self) -> Result<serde_json::Value> {
        ensure!(
            inventory(&self.driver)? == self.rows,
            "Foreign controller inventory changed"
        );
        ensure!(
            pnp_baseline(self.controller)? == self.pnp,
            "Foreign controller PnP baseline changed"
        );
        ensure!(
            volume_fingerprint()? == self.volumes,
            "Volume metadata baseline changed"
        );
        ensure!(
            fixture_hash(&mut self.image)? == self.image_sha,
            "Signed fixture driver image changed"
        );
        Ok(
            serde_json::json!({"controller_rows":self.rows.len(),"controller_pnp_nodes":self.pnp.len(),"controller_foreign_unchanged":true,"volume_metadata_unchanged":true,"package_version":"0.9.8.1","driver_version":self.driver_version,"driver_sha256":self.image_sha,"driver_signature_valid":true}),
        )
    }
}
#[cfg(test)]
impl Marker {
    pub(crate) fn fixture_projection(&self) -> Result<serde_json::Value> {
        self.validate()?; // Exactly the authoritative production claim check.
        let held = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let port = held
            .port
            .as_ref()
            .context("Owned fixture port missing")?
            .port;
        let classes = self
            .display_classes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .and_then(|(_, c)| c.as_ref().ok())
            .copied()
            .context("Fixture configuration classification missing")?;
        Ok(
            serde_json::json!({"port":port,"controller_hub_pnp_identity_verified":true,"configuration":classes.value,"interfaces":classes.interfaces,"all_alternates_audio_hid":true,"disk_descendant":false}),
        )
    }
}
