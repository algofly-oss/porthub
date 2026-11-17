//! Native Windows Wintun device and explicit peer /32 routing.
use anyhow::{ensure, Context, Result};
use route_manager::{AsyncRouteManager, Route};
use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::Write,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
};
use tokio::sync::Mutex;
use tun_rs::DeviceBuilder;
use super::{native_ownership::{AdapterRecord,RouteStamp,RetiredRoute,HostAdmission,plan_hosts,capture_child,MAX_LEDGER_BYTES},windows_state};

fn save_record(path:&std::path::Path,record:&AdapterRecord)->Result<()>{let bytes=record.encode()?;windows_state::write_bytes_bounded(path,&bytes,MAX_LEDGER_BYTES)}

struct Ownership { path:PathBuf,record:std::sync::Mutex<AdapterRecord>,_lease:crate::profile::Lease }
fn stamp(route:&Route)->RouteStamp{RouteStamp{address:route.destination(),prefix:route.prefix(),gateway:route.gateway().filter(|g|!g.is_unspecified()),metric:route.metric().unwrap_or(0)}}
fn direct(address:IpAddr,prefix:u8)->RouteStamp{RouteStamp{address,prefix,gateway:None,metric:0}}
fn guid_hex(guid:&windows_sys::core::GUID)->String{format!("{:08x}{:04x}{:04x}{}",guid.data1,guid.data2,guid.data3,guid.data4.iter().map(|b|format!("{b:02x}")).collect::<String>())}
/// Includes unaddressed adapters: getifaddrs alone cannot prove name absence.
fn adapters()->Result<Vec<(String,String,u32,u32)>>{
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetIfTable2,FreeMibTable};
    let mut table=std::ptr::null_mut();
    ensure!(unsafe{GetIfTable2(&mut table)}==0&&!table.is_null(),"cannot inventory Windows adapters before ownership check");
    struct Guard(*mut core::ffi::c_void);impl Drop for Guard{fn drop(&mut self){unsafe{FreeMibTable(self.0)}}}
    let _guard=Guard(table.cast());
    let count=unsafe{(*table).NumEntries}as usize;ensure!(count<=65536,"Windows adapter inventory exceeds bound");
    let rows=unsafe{std::slice::from_raw_parts((*table).Table.as_ptr(),count)};
    let mut found=Vec::with_capacity(count);
    for row in rows {let end=row.Alias.iter().position(|c|*c==0).unwrap_or(row.Alias.len());found.push((String::from_utf16(&row.Alias[..end])?,guid_hex(&row.InterfaceGuid),row.InterfaceIndex,row.Mtu));}
    Ok(found)
}
fn native_source_pin(index:u32)->Result<super::native_owner::source::Pin>{
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetIfTable2,FreeMibTable};
    let mut table=std::ptr::null_mut();ensure!(unsafe{GetIfTable2(&mut table)}==0&&!table.is_null(),"cannot inspect source adapter identity");
    struct Guard(*mut core::ffi::c_void);impl Drop for Guard{fn drop(&mut self){unsafe{FreeMibTable(self.0)}}}let _guard=Guard(table.cast());
    let count=unsafe{(*table).NumEntries}as usize;ensure!(count<=65536,"source identity inventory exceeds bound");
    let row=unsafe{std::slice::from_raw_parts((*table).Table.as_ptr(),count)}.iter().find(|row|row.InterfaceIndex==index).context("owned source adapter disappeared")?;
    let end=row.Alias.iter().position(|c|*c==0).unwrap_or(row.Alias.len());
    let pin=super::native_owner::source::Pin::Windows{name:String::from_utf16(&row.Alias[..end])?,index,guid:guid_hex(&row.InterfaceGuid),luid:unsafe{row.InterfaceLuid.Value}};
    pin.validate()?;Ok(pin)
}
fn delete_source(index:u32,luid:u64,own:Ipv4Addr)->Result<()>{
        use windows_sys::Win32::{NetworkManagement::IpHelper::{MIB_UNICASTIPADDRESS_ROW,InitializeUnicastIpAddressEntry,DeleteUnicastIpAddressEntry},Networking::WinSock::AF_INET};
        let mut row:MIB_UNICASTIPADDRESS_ROW=unsafe{std::mem::zeroed()};unsafe{InitializeUnicastIpAddressEntry(&mut row)};
        row.InterfaceIndex=index;row.InterfaceLuid.Value=luid;
        row.Address.Ipv4.sin_family=AF_INET;row.Address.Ipv4.sin_addr.S_un.S_addr=u32::from_ne_bytes(own.octets());
        ensure!(unsafe{DeleteUnicastIpAddressEntry(&row)}==0,"cannot remove exact recovered source address");Ok(())

}
struct LiveSource<'a>(&'a Tun);
impl super::native_owner::source::ShutdownIo for LiveSource<'_>{
    fn identity(&self)->Result<super::native_owner::source::Pin>{native_source_pin(self.0.index)}
    fn addresses(&self)->Result<Vec<IpAddr>>{Ok(self.0.device.addresses()?)}
    fn remove(&self,own:Ipv4Addr)->Result<()>{
        let super::native_owner::source::Pin::Windows{index,luid,..}=&self.0.source_pin else{anyhow::bail!("Windows source pin missing")};
        delete_source(*index,*luid,own)
    }
    fn end_session(&self)->Result<()>{self.0.device.enabled(false)?;Ok(())}
}
struct RecoveredSource{pin:super::native_owner::source::Pin,index:u32,luid:u64}
impl super::native_owner::source::ShutdownIo for RecoveredSource{
    fn identity(&self)->Result<super::native_owner::source::Pin>{native_source_pin(self.index)}
    fn addresses(&self)->Result<Vec<IpAddr>>{Ok(getifaddrs::getifaddrs()?.filter(|row|row.index==Some(self.index)).filter_map(|row|row.address.ip_addr()).collect())}
    fn remove(&self,own:Ipv4Addr)->Result<()>{delete_source(self.index,self.luid,own)}
    // Caller owns BOTH normal native-source and Wintun ownership leases. The
    // previous process/owner's device/session drops before releasing its lease;
    // recovery never creates/enables a new Wintun session just to close it.
    fn end_session(&self)->Result<()>{Ok(())}
}
/// Called only under the common source-owner lease. A record is not native
/// absence: inventory/read errors and foreign/replaced adapters remain errors.
pub(super) fn recover_source_absence(profile:&std::path::Path,pin:&super::native_owner::source::Pin,own:Ipv4Addr)->Result<super::native_owner::source::Pin>{
    use super::native_owner::source::Pin;
    pin.validate()?;
    let state=windows_state::state_path(profile,".wintun-ownership.json")?;
    let _lease=crate::profile::Lease::acquire(&state)?;
    let native_adapters=adapters()?;
    let bytes=windows_state::read_bytes_bounded(&state,MAX_LEDGER_BYTES)?;
    let Some(bytes)=bytes else{ensure!(!native_adapters.iter().any(|(name,_,_,_)|name.eq_ignore_ascii_case(pin.name())),"unrecorded adapter occupies source intent; preserved");ensure!(matches!(pin,Pin::Intent{..}|Pin::Unknown),"source ownership record disappeared");
        ensure!(!getifaddrs::getifaddrs()?.any(|row|row.address.ip_addr()==Some(IpAddr::V4(own))),"unbound native source remains without ownership record");return Ok(pin.clone());};
    let mut record=AdapterRecord::decode(&bytes)?;
    let expected_name=if matches!(pin,Pin::Unknown){record.name.as_str()}else{pin.name()};
    record.validate(&windows_state::profile_binding(profile)?,expected_name,record.own,record.mtu)?;
    if record.own!=own {
        // Constructor recovery: the old source was cleared and the new record
        // checkpointed, but the process died before finishing native open.
        super::native_owner::inspect_rebound_source(profile,own,record.own,&record.guid)?;
        let Some((name,_,index,_))=native_adapters.iter().find(|(_,guid,_,_)|guid==&record.guid)else{return Ok(pin.clone());};
        ensure!(name==expected_name,"rebound adapter was renamed; preserved");
        let before=native_source_pin(*index)?;
        ensure!(!getifaddrs::getifaddrs()?.any(|row|row.index==Some(*index)&&row.address.ip_addr()==Some(IpAddr::V4(own))),"old source reappeared after fresh assignment intent");
        ensure!(native_source_pin(*index)?==before,"adapter changed during source absence recovery");return Ok(before);
    }
    if let Pin::Windows{guid,..}=pin{ensure!(guid==&record.guid,"retired adapter GUID no longer matches protected record");}
    let Some((name,_,index,mtu))=native_adapters.iter().find(|(_,guid,_,_)|guid==&record.guid)else{return Ok(pin.clone());};
    ensure!(name==expected_name,"retired adapter was renamed; preserved");
    let current=native_source_pin(*index)?;
    if &current!=pin {
        // A legitimate reboot/reopen may change LUID/index. Rebind ONLY after
        // the normal protected ownership/configuration/ledger checks, never by
        // alias alone, and never reassign or enable a source during recovery.
        let mut manager=route_manager::RouteManager::new()?;let rows=manager.list()?;
        let addresses:Vec<_>=getifaddrs::getifaddrs()?.filter(|row|row.index==Some(*index)).filter_map(|row|row.address.ip_addr()).collect();
        let native=rows.iter().filter(|row|row.if_index()==Some(*index)).map(stamp).collect();
        record.recover(&record.guid,&addresses,u16::try_from(*mtu)?,&native)?;
    }
    let Pin::Windows{luid,..}=current else{unreachable!()};
    let io=RecoveredSource{pin:current.clone(),index:*index,luid};
    super::native_owner::source::stop_checked(&io,&io.pin,own)?;
    // A crash can occur after source stop but before Drop's route cleanup.
    // Resume only CONFIRMED exact ownership, with durable retirement before
    // deletion. Existing ambiguous retiring/native rows remain fail-closed.
    let mut manager=route_manager::RouteManager::new()?;
    ensure!(native_source_pin(*index)?==current,"adapter changed before recovered route cleanup");
    let rows=manager.list()?;
    let native:std::collections::BTreeSet<_>=rows.iter().filter(|row|row.if_index()==Some(*index)).map(stamp).collect();
    let addresses=super::native_owner::source::ShutdownIo::addresses(&io)?;
    let candidates=record.recovery_routes(&record.guid,&addresses,u16::try_from(*mtu)?,&native)?;
    // An interrupted compound never adopts pending native rows: recover() above
    // already rejected those. Only a durable child ACK may be cleaned here.
    let interrupted:Vec<_>=record.pending.iter().filter(|r|r.prefix<32).cloned().collect();
    for parent in interrupted {
        let permits=record.retire_capture_attempt(&parent,&Default::default(),|next|save_record(&state,next))?;
        for permit in permits{let row=permit.into_stamp();ensure!(native_source_pin(*index)?==current,"adapter changed before interrupted compound cleanup");
            if manager.list()?.iter().any(|r|r.if_index()==Some(*index)&&stamp(r)==row){ensure!(native_source_pin(*index)?==current,"adapter changed before interrupted row deletion");manager.delete(&Route::new(row.address,row.prefix).with_if_index(*index).with_metric(row.metric))?;}
        }
        let child=capture_child(&parent)?;let retained=record.routes.contains(&child);let rows=manager.list()?;ensure!(native_source_pin(*index)?==current,"adapter changed after interrupted cleanup");
        ensure!(!rows.iter().any(|r|r.if_index()==Some(*index)&&(stamp(r)==parent||(!retained&&stamp(r)==child))),"unacknowledged compound row remains; preserved");
        if retained{ensure!(rows.iter().any(|r|r.if_index()==Some(*index)&&stamp(r)==child),"shared child disappeared during interrupted cleanup");}
        record.finish_capture(&parent,|next|save_record(&state,next))?;
    }
    // Ordinary uncreated intent cancellation is denial-only.
    for pending in record.pending.clone(){ensure!(!native.contains(&pending),"unacknowledged native row appeared during recovery");record.cancel_route(&pending,|next|save_record(&state,next))?;}
    // Compound cleanup changed native rows, so do not reuse the pre-cleanup view.
    let rows=manager.list()?;ensure!(native_source_pin(*index)?==current,"adapter changed after interrupted cleanup inventory");
    let native=rows.iter().filter(|row|row.if_index()==Some(*index)).map(stamp).collect();
    record.observe_missing(&native,|next|save_record(&state,next))?;
    // Retire confirmed compounds together. Shared ACK-owned children survive
    // until their final confirmed parent, including crash recovery cleanup.
    let parents:Vec<_>=record.routes.iter().filter(|r|r.prefix<32).cloned().collect();
    for parent in parents {
        ensure!(native_source_pin(*index)?==current,"adapter changed before recovered compound");
        let permits=record.retire_capture(&parent,|next|save_record(&state,next))?;
        for permit in permits {let row=permit.into_stamp();ensure!(native_source_pin(*index)?==current,"adapter changed before recovered compound delete");
            if manager.list()?.iter().any(|r|r.if_index()==Some(*index)&&stamp(r)==row){
                ensure!(native_source_pin(*index)?==current,"adapter changed during recovered compound delete");manager.delete(&Route::new(row.address,row.prefix).with_if_index(*index).with_metric(row.metric))?;
            }
        }
        let child=capture_child(&parent)?;let retained=record.routes.contains(&child);let rows=manager.list()?;
        ensure!(native_source_pin(*index)?==current,"adapter changed after recovered compound delete");
        ensure!(!rows.iter().any(|r|r.if_index()==Some(*index)&&(stamp(r)==parent||(!retained&&stamp(r)==child))),"recovered compound remains");
        if retained {ensure!(rows.iter().any(|r|r.if_index()==Some(*index)&&stamp(r)==child),"recovered shared child disappeared");}
        record.finish_capture(&parent,|next|save_record(&state,next))?;
    }
    for row in candidates {
        if !record.routes.contains(&row){continue;}
        ensure!(native_source_pin(*index)?==current,"adapter changed before owned route retirement");
        let permit=record.retire_route(&row,|next|save_record(&state,next))?;let retired=permit.into_stamp();
        let mut route=Route::new(retired.address,retired.prefix).with_if_index(*index).with_metric(retired.metric);
        if let Some(gateway)=retired.gateway{route=route.with_gateway(gateway);}
        ensure!(native_source_pin(*index)?==current,"adapter changed before exact route deletion");manager.delete(&route)?;
        let after=manager.list()?;ensure!(native_source_pin(*index)?==current,"adapter changed during exact route deletion");
        ensure!(!after.iter().any(|row|row.if_index()==Some(*index)&&stamp(row)==retired),"retired route remains after deletion");
        record.finish_retirement(&retired,|next|save_record(&state,next))?;
    }
    let after=manager.list()?;ensure!(native_source_pin(*index)?==current,"adapter changed after recovered route cleanup");
    let native=after.iter().filter(|row|row.if_index()==Some(*index)).map(stamp).collect();record.observe_missing(&native,|next|save_record(&state,next))?;
    Ok(current)
}
#[cfg(test)]
pub(super) fn fixture_adapter_exists(guid:&str)->Result<bool>{Ok(adapters()?.iter().any(|(_,present,_,_)|present==guid))}
pub(super) fn adapter_guid(index:u32)->Result<String>{adapters()?.into_iter().find(|(_,_,i,_)|*i==index).map(|(_,g,_,_)|g).ok_or_else(||anyhow::anyhow!("owned Windows adapter disappeared"))}

// Diagnostic-only: never changes admission, records or native routes.
#[cfg(test)]
fn fixture_recovery_failure(index:u32,stage:u8,r:&AdapterRecord,rows:&std::collections::BTreeSet<RouteStamp>){
    if std::env::var("PORTHUB_SPARSE_NATIVE_FIXTURE").as_deref()!=Ok("reviewed-disposable-desktop-v1"){return;}
    use std::sync::atomic::{AtomicBool,Ordering};
    static EMITTED:AtomicBool=AtomicBool::new(false);
    if EMITTED.swap(true,Ordering::Relaxed){return;}
    // Only this verified owned adapter; no global route or profile dump.
    let luid=(||{use windows_sys::Win32::NetworkManagement::IpHelper::{GetIfTable2,FreeMibTable};
        let mut table=std::ptr::null_mut();if unsafe{GetIfTable2(&mut table)}!=0||table.is_null(){return None;}
        struct Guard(*mut core::ffi::c_void);impl Drop for Guard{fn drop(&mut self){unsafe{FreeMibTable(self.0)}}}
        let _guard=Guard(table.cast());let n=unsafe{(*table).NumEntries}as usize;if n>65536{return None;}
        unsafe{std::slice::from_raw_parts((*table).Table.as_ptr(),n)}.iter().find(|row|row.InterfaceIndex==index).map(|row|unsafe{row.InterfaceLuid.Value})})();
    let baseline=r.baseline.clone().unwrap_or_default();
    let unknown:std::collections::BTreeSet<_>=rows.iter().filter(|v|!baseline.contains(*v)&&!r.routes.contains(*v)).cloned().collect();
    let missing:std::collections::BTreeSet<_>=r.routes.difference(rows).cloned().collect();
    let sets=[&baseline,&r.routes,&r.pending,&r.retiring,&unknown,&missing];
    let mut out=String::new();
    for (kind,set) in sets.into_iter().enumerate(){
        // Six sets x four rows, plus counts; all row fields are numeric network metadata.
        let sample:Vec<_>=set.iter().take(4).collect();
        if let Ok(line)=serde_json::to_string(&serde_json::json!({"stage":stage,"index":index,"luid":luid,"kind":kind,"count":set.len(),"rows":sample})){
            if out.len()+line.len()+1<=8192{out.push_str(&line);out.push('\n');}
        }
    }
    eprintln!("PORTHUB_NATIVE_ROUTE_LEDGER_DIAGNOSTIC\n{out}");
}
fn recover_record(index:u32,stage:u8,r:&mut AdapterRecord,guid:&str,addresses:&[IpAddr],mtu:u16,rows:&std::collections::BTreeSet<RouteStamp>)->Result<()>{
    let result=r.recover(guid,addresses,mtu,rows);
    #[cfg(test)] if result.is_err(){fixture_recovery_failure(index,stage,r,rows);}
    #[cfg(not(test))] let _=(index,stage);
    result
}

impl Ownership {
    fn verify(&self,index:u32,device:&tun_rs::AsyncDevice,native:&[Route])->Result<()>{
        let mut r=self.record.lock().unwrap_or_else(|p|p.into_inner());
        let rows=native.iter().filter(|route|route.if_index()==Some(index)).map(stamp).collect();
        recover_record(index,1,&mut r,&adapter_guid(index)?,&device.addresses()?,device.mtu()?,&rows)?;
        // Every verified complete inventory retires missing claims durably,
        // before any caller can prune caches, return early or mutate routes.
        r.observe_missing(&rows,|next|save_record(&self.path,next))?;Ok(())
    }
    fn reserve_capture(&self,parent:RouteStamp)->Result<(RouteStamp,bool)>{self.record.lock().unwrap_or_else(|p|p.into_inner()).reserve_capture(parent,|next|save_record(&self.path,next))}
    fn confirm_created(&self,row:RouteStamp,native:&[Route],index:u32)->Result<()>{let rows=native.iter().filter(|r|r.if_index()==Some(index)).map(stamp).collect();self.record.lock().unwrap_or_else(|p|p.into_inner()).confirm_created(row,&rows,|next|save_record(&self.path,next))}
    fn retire_capture(&self,parent:&RouteStamp)->Result<Vec<RetiredRoute>>{self.record.lock().unwrap_or_else(|p|p.into_inner()).retire_capture(parent,|next|save_record(&self.path,next))}
    fn retire_attempt(&self,parent:&RouteStamp,created:&std::collections::BTreeSet<RouteStamp>)->Result<Vec<RetiredRoute>>{self.record.lock().unwrap_or_else(|p|p.into_inner()).retire_capture_attempt(parent,created,|next|save_record(&self.path,next))}
    fn child_retained(&self,parent:&RouteStamp)->Result<bool>{let child=capture_child(parent)?;let r=self.record.lock().unwrap_or_else(|p|p.into_inner());Ok(r.routes.contains(&child)&&r.routes.iter().any(|p|capture_child(p).is_ok_and(|c|c==child)))}
    fn finish_capture(&self,parent:&RouteStamp)->Result<()>{self.record.lock().unwrap_or_else(|p|p.into_inner()).finish_capture(parent,|next|save_record(&self.path,next))}
    fn reserve(&self,value:RouteStamp)->Result<()>{let mut r=self.record.lock().unwrap_or_else(|p|p.into_inner());r.reserve_route(value,|next|save_record(&self.path,next))}
    fn confirm(&self,value:RouteStamp)->Result<()>{let mut r=self.record.lock().unwrap_or_else(|p|p.into_inner());r.confirm_route(value,|next|save_record(&self.path,next))}
    fn cancel(&self,value:&RouteStamp)->Result<()>{let mut r=self.record.lock().unwrap_or_else(|p|p.into_inner());r.cancel_route(value,|next|save_record(&self.path,next))}
    fn retire(&self,value:&RouteStamp)->Result<RetiredRoute>{let mut r=self.record.lock().unwrap_or_else(|p|p.into_inner());r.retire_route(value,|next|save_record(&self.path,next))}
    fn finish_retirement(&self,value:&RouteStamp)->Result<()>{let mut r=self.record.lock().unwrap_or_else(|p|p.into_inner());r.finish_retirement(value,|next|save_record(&self.path,next))}
}

async fn remove_retired(manager:&mut AsyncRouteManager,index:u32,permit:RetiredRoute)->Result<RouteStamp>{
    let stamp=permit.into_stamp();let mut route=Route::new(stamp.address,stamp.prefix).with_if_index(index).with_metric(stamp.metric);
    if let Some(gateway)=stamp.gateway{route=route.with_gateway(gateway);}
    manager.delete(&route).await.context("cannot remove durably retired native route; exact-owned repair may be required")?;Ok(stamp)
}


#[cfg(target_arch = "x86_64")]
const WINTUN: &[u8] = include_bytes!("../../assets/wintun/amd64/wintun.dll");
#[cfg(target_arch = "x86")]
const WINTUN: &[u8] = include_bytes!("../../assets/wintun/x86/wintun.dll");
#[cfg(target_arch = "aarch64")]
const WINTUN: &[u8] = include_bytes!("../../assets/wintun/arm64/wintun.dll");
#[cfg(target_arch = "arm")]
const WINTUN: &[u8] = include_bytes!("../../assets/wintun/arm/wintun.dll");
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "x86",
    target_arch = "aarch64",
    target_arch = "arm"
)))]
compile_error!(
    "PortHub private networking has no bundled Wintun for this Windows CPU architecture"
);

pub struct Tun {
    device: tun_rs::AsyncDevice,
    pub index: u32,
    pub name: String,
    source_pin: super::native_owner::source::Pin,
    own: Ipv4Addr,
    routes: Mutex<HashSet<Ipv4Addr>>,
    capture_routes: Mutex<std::collections::BTreeSet<porthub_mesh::lan_routes::Network>>,
    _driver: PathBuf,
    ownership:Ownership,
    _source_lease: super::native_owner::source::OwnerLease,
}

fn peer_routes(own: Ipv4Addr, peers: &[Ipv4Addr]) -> HashSet<Ipv4Addr> {
    // Windows creates the interface's own /32 when its address is assigned.
    // It is kernel-owned: adding it again fails with ERROR_OBJECT_ALREADY_EXISTS.
    peers.iter().copied().filter(|ip| *ip != own).collect()
}

fn conflicts_with_route(address: Ipv4Addr, route: &Route) -> bool {
    let prefix = route.prefix().min(32);
    if prefix == 0 {
        return false;
    }
    let IpAddr::V4(network) = route.destination() else {
        return false;
    };
    let mask = u32::MAX << (32 - u32::from(prefix));
    u32::from(address) & mask == u32::from(network) & mask
}

fn install_driver() -> Result<PathBuf> {
    let root = crate::service::windows_acl::managed_root()?;
    fs::create_dir_all(&root).context("cannot create PortHub state directory")?;
    crate::service::windows_acl::secure(&root, true)?;
    let directory = root.join("drivers");
    fs::create_dir_all(&directory).context("cannot create PortHub driver directory")?;
    crate::service::windows_acl::secure(&directory, true)?;
    let path = directory.join("wintun.dll");
    if path.exists() {
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "PortHub driver path is not a regular file"
        );
        ensure!(
            fs::read(&path)? == WINTUN,
            "installed PortHub Wintun does not match the bundled driver"
        );
        crate::service::windows_acl::secure(&path, false)?;
        return Ok(path);
    }
    let mut nonce = [0; 8];
    getrandom::fill(&mut nonce).context("cannot allocate private Wintun staging name")?;
    let temporary = directory.join(format!(
        "wintun-{}-{:016x}.tmp",
        std::process::id(),
        u64::from_le_bytes(nonce)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .context("cannot install bundled PortHub Wintun runtime")?;
    let publish = (|| -> Result<()> {
        file.write_all(WINTUN)?;
        file.sync_all()?;
        drop(file);
        fs::hard_link(&temporary, &path)
            .context("cannot publish bundled PortHub Wintun runtime")?;
        fs::remove_file(&temporary)?;
        Ok(())
    })();
    if publish.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    publish?;
    crate::service::windows_acl::secure(&path, false)?;
    Ok(path)
}

impl Tun {
    pub(super) fn own_ip(&self)->Ipv4Addr{self.own}
    pub(super) fn bind_source_lease(&self,lease:crate::profile::Lease)->Result<()>{self._source_lease.bind(lease)}
    pub(super) fn has_source_lease(&self)->Result<bool>{self._source_lease.held()}
    pub(super) fn source_pin(&self)->super::native_owner::source::Pin{self.source_pin.clone()}
    pub(super) fn stop_source_checked(&self)->Result<()>{super::native_owner::source::stop_checked(&LiveSource(self),&self.source_pin,self.own)}

    pub(super) async fn open_owned(profile:&std::path::Path,name:&str,own:Ipv4Addr,peers:&[Ipv4Addr],admission:HostAdmission)->Result<Self>{
        Self::open_inner(profile,name,own,peers,admission,None).await
    }
    pub(super) async fn open_owned_sparse(profile:&std::path::Path,name:&str,own:Ipv4Addr,peers:&[Ipv4Addr],pools:&[porthub_mesh::lan_routes::Network])->Result<Self>{
        Self::open_inner(profile,name,own,peers,HostAdmission::Sparse,Some(pools)).await
    }
    async fn open_inner(profile:&std::path::Path,name:&str,own:Ipv4Addr,peers:&[Ipv4Addr],admission:HostAdmission,pools:Option<&[porthub_mesh::lan_routes::Network]>)->Result<Self>{
        ensure!(own.is_private()&&peers.iter().all(Ipv4Addr::is_private),"invalid private interface address");
        plan_hosts(own,peers,admission,std::iter::empty())?; // deny oversized mode before any native mutation
        let path=windows_state::state_path(profile,".wintun-ownership.json")?;
        // A second caller must not treat a live owned adapter as a stale one.
        let ownership_lease=crate::profile::Lease::acquire(&path)?;
        let profile=profile.canonicalize()?;
        let binding=windows_state::profile_binding(&profile)?;
        let mut record:AdapterRecord=match windows_state::read_bytes_bounded(&path,MAX_LEDGER_BYTES)?{
            Some(bytes)=>AdapterRecord::decode(&bytes)?,None=>{let mut nonce=[0;16];getrandom::fill(&mut nonce)?;AdapterRecord{version:2,binding:binding.clone(),guid:format!("{:032x}",u128::from_be_bytes(nonce)),name:name.into(),own,mtu:porthub_mesh::MAX_PACKET as u16,baseline:None,routes:Default::default(),pending:Default::default(),retiring:Default::default()}},
        };
        record.validate(&binding,name,record.own,record.mtu)?;
        let native_adapters=adapters()?;
        let named:Vec<_>=native_adapters.iter().filter(|(alias,_,_,_)|alias.eq_ignore_ascii_case(name)).collect();ensure!(named.len()<=1,"ambiguous Windows adapter alias");
        ensure!(!native_adapters.iter().any(|(alias,guid,_,_)|guid==&record.guid&&alias!=name),"recorded adapter was renamed; it was not modified");
        let existing_index=named.first().map(|(_,_,i,_)|*i);
        if existing_index.is_some(){
            ensure!(record.mtu==porthub_mesh::MAX_PACKET as u16,"owned adapter MTU changed before source migration");
            if record.own!=own {super::native_owner::allow_source_rebind(&profile,record.own,own,&record.guid)?;}
        }
        if let Some((_,guid,_,_))=named.first(){ensure!(guid==&record.guid,"same-name Windows adapter is foreign; it was not modified");}
        let mut manager=AsyncRouteManager::new()?;let native=manager.list().await?;
        // Preflight before the builder can assign an address or change MTU.
        for route in &native{if route.if_index()!=existing_index&&conflicts_with_route(own,route){anyhow::bail!("private interface address conflicts with an existing LAN/VPN/VM route");}}
        if let Some((_,guid,index,mtu))=named.first(){
            let addresses:Vec<_>=getifaddrs::getifaddrs()?.filter(|i|i.index==Some(*index)).filter_map(|i|i.address.ip_addr()).collect();
            let current=native.iter().filter(|r|r.if_index()==Some(*index)).map(stamp).collect();
            recover_record(*index,2,&mut record,guid,&addresses,u16::try_from(*mtu)?,&current)?;
            record.observe_missing(&current,|next|save_record(&path,next))?;
            if record.own!=own {
                super::native_owner::allow_source_rebind(&profile,record.own,own,&record.guid)?;
                record.rebind_cleared_source(guid,&addresses,u16::try_from(*mtu)?,&current,own,|next|save_record(&path,next))?;
            }
        }
        if let Some(pools)=pools{
            let existing:Vec<_>=native.iter().filter_map(|r|match r.destination(){IpAddr::V4(address)=>Some(porthub_network::capture_routes::ExistingRoute{destination:address,prefix:r.prefix(),interface:r.if_index()}),_=>None}).collect();
            super::native_owner::conflict(porthub_network::capture_routes::audit(pools,own,peers,&existing,existing_index.unwrap_or(u32::MAX))?)?;
        }
        if existing_index.is_none(){record.reset_absent(own,porthub_mesh::MAX_PACKET as u16)?;}
        save_record(&path,&record)?; // protected intent precedes creation
        let driver=install_driver()?;
        let device=DeviceBuilder::new().name(name).device_guid(u128::from_str_radix(&record.guid,16)?).inherit_enable_state().wintun_file(driver.to_string_lossy().into_owned()).build_async().context("cannot open owned Windows private Wintun adapter")?;
        let index=device.if_index()?;
        ensure!(adapter_guid(index)?==record.guid&&device.name()?==name,"Wintun did not return the intended owned adapter; no address was assigned");
        if existing_index==Some(index){
            let current=manager.list().await?.iter().filter(|r|r.if_index()==Some(index)).map(stamp).collect();
            recover_record(index,3,&mut record,&adapter_guid(index)?,&device.addresses()?,device.mtu()?,&current)?;
            record.observe_missing(&current,|next|save_record(&path,next))?;
        }else if existing_index.is_some(){
            // The pinned builder may recreate an orphaned *already verified*
            // owned GUID. Recheck GUID/name above, then journal this fresh start.
            record.baseline=None;record.routes.clear();record.pending.clear();record.retiring.clear();save_record(&path,&record)?;
        }
        let source_pin=native_source_pin(index)?;
        ensure!(source_pin.name()==name,"owned adapter name changed before source configuration");
        device.set_network_address(own,32,None)?;device.set_mtu(porthub_mesh::MAX_PACKET as u16)?;device.enabled(true)?;
        let current:std::collections::BTreeSet<_>=manager.list().await?.iter().filter(|r|r.if_index()==Some(index)).map(stamp).collect();
        let present:std::collections::BTreeSet<_>=record.routes.intersection(&current).cloned().collect();
        if record.baseline.is_none(){record.baseline=Some(current.clone());}
        record.routes=present.clone();record.pending.clear();record.retiring.clear();save_record(&path,&record)?;
        let tun=Self{device,index,name:name.into(),source_pin,own,routes:Mutex::new(present.iter().filter_map(|r|if r.prefix==32&&r.metric==0{if let IpAddr::V4(ip)=r.address{Some(ip)}else{None}}else{None}).collect()),capture_routes:Mutex::new(present.iter().filter_map(|r|if r.prefix<32{if let IpAddr::V4(ip)=r.address{porthub_mesh::lan_routes::Network::from_address(ip,r.prefix).ok()}else{None}}else{None}).collect()),_driver:driver,_source_lease:Default::default(),ownership:Ownership{path,record:std::sync::Mutex::new(record),_lease:ownership_lease}};
        tun.update_routes_for(peers,admission).await?;Ok(tun)
    }

    /// Prefix capture does not authorize packets. Preserve foreign routes and isolate pool conflicts.
    pub async fn update_capture_routes(&self,pools:&[porthub_mesh::lan_routes::Network])->Result<porthub_network::capture_routes::CapturePlan>{
        use porthub_network::capture_routes::{self,ExistingRoute};
        let mut manager=AsyncRouteManager::new().context("cannot open capture route manager")?;
        let native=manager.list().await.context("cannot inspect capture routes")?;
        self.ownership.verify(self.index,&self.device,&native)?;
        let existing:Vec<_>=native.iter().filter_map(|r|match r.destination(){IpAddr::V4(address)=>Some(ExistingRoute{destination:address,prefix:r.prefix(),interface:r.if_index()}),_=>None}).collect();
        let plan=capture_routes::plan(pools,&existing,self.index)?;
        let wanted:std::collections::BTreeSet<_>=plan.accepted.iter().copied().collect();let mut owned=self.capture_routes.lock().await;
        for prefix in wanted.difference(&owned).copied().collect::<Vec<_>>(){
            let parent=direct(IpAddr::V4(prefix.address()),prefix.prefix());
            let before=manager.list().await?;self.check_route_identity()?;self.ownership.verify(self.index,&self.device,&before)?;
            let (child,create_child)=self.ownership.reserve_capture(parent.clone())?;
            let mut created=std::collections::BTreeSet::new();
            let attempt:Result<()>=async {
                for row in [if create_child{Some(child.clone())}else{None},Some(parent.clone())].into_iter().flatten(){
                    self.check_route_identity()?;
                    manager.add(&Route::new(row.address,row.prefix).with_if_index(self.index).with_metric(row.metric)).await.context("exclusive capture Create failed")?;
                    created.insert(row.clone()); // successful Create ACK survives a failed durable confirmation
                    self.check_route_identity()?;self.ownership.confirm_created(row,&manager.list().await?,self.index)?;
                }
                Ok(())
            }.await;
            if let Err(error)=attempt {
                let cleanup=async {let permits=self.ownership.retire_attempt(&parent,&created)?;self.remove_capture_rows(&mut manager,&parent,permits).await}.await;
                return Err(error.context(if cleanup.is_ok(){"capture compound rolled back"}else{"capture rollback incomplete; source retirement required"}));
            }
            owned.insert(prefix);
        }
        // Install the accepted new cover before withdrawing the old cover. A
        // failed expansion preserves the old capture until source retirement;
        // shared broadcast ownership prevents deleting the new cover's child.
        for prefix in owned.difference(&wanted).copied().collect::<Vec<_>>(){
            let parent=direct(IpAddr::V4(prefix.address()),prefix.prefix());
            let permits=self.ownership.retire_capture(&parent)?;
            self.remove_capture_rows(&mut manager,&parent,permits).await?;owned.remove(&prefix);
        }
        Ok(plan)
    }

    fn check_route_identity(&self)->Result<()>{ensure!(native_source_pin(self.index)?==self.source_pin,"owned adapter changed during capture transaction");Ok(())}
    async fn remove_capture_rows(&self,manager:&mut AsyncRouteManager,parent:&RouteStamp,permits:Vec<RetiredRoute>)->Result<()> {
        for permit in permits {let row=permit.into_stamp();self.check_route_identity()?;
            if manager.list().await?.iter().any(|r|r.if_index()==Some(self.index)&&stamp(r)==row){
                self.check_route_identity()?;manager.delete(&Route::new(row.address,row.prefix).with_if_index(self.index).with_metric(row.metric)).await?;
            }
        }
        let child=capture_child(parent)?;let retained=self.ownership.child_retained(parent)?;
        let rows=manager.list().await?;self.check_route_identity()?;
        ensure!(!rows.iter().any(|r|r.if_index()==Some(self.index)&&(stamp(r)==*parent||(!retained&&stamp(r)==child))),"capture parent/child absence not proven");
        if retained {ensure!(rows.iter().any(|r|r.if_index()==Some(self.index)&&stamp(r)==child),"shared capture child disappeared");}
        self.ownership.finish_capture(parent)
    }

    /// Revalidate retained host routes as well as broad capture prefixes. The
    /// packet owner calls this after route notifications and before exposing a new
    /// pair to DNS; it never reuses the additions-only legacy preflight.
    pub async fn reconcile_sparse(&self,pools:&[porthub_mesh::lan_routes::Network],peers:&[Ipv4Addr])->Result<porthub_network::capture_routes::SparseAudit>{
        use porthub_network::capture_routes::{self,ExistingRoute};
        plan_hosts(self.own,peers,HostAdmission::Sparse,std::iter::empty())?;
        let mut manager=AsyncRouteManager::new().context("cannot open sparse route audit")?;
        let native=manager.list().await.context("cannot inspect sparse route audit")?;
        self.ownership.verify(self.index,&self.device,&native)?;
        let existing:Vec<_>=native.iter().filter_map(|r|match r.destination(){IpAddr::V4(address)=>Some(ExistingRoute{destination:address,prefix:r.prefix(),interface:r.if_index()}),_=>None}).collect();
        let mut audit=super::native_owner::conflict(capture_routes::audit(pools,self.own,peers,&existing,self.index)?)?;
        // A route removed outside PortHub is not still a valid ownership claim.
        // Forget missing entries so an exclusive add can repair them, never adopt
        // an arbitrary existing entry just because it points at our interface.
        let present=|address:Ipv4Addr,prefix:u8|existing.iter().any(|r|r.destination==address&&r.prefix==prefix&&r.interface==Some(self.index));
        // Ownership.verify above already durably retired missing claims,
        // before these memory changes and the wanted-empty/unchanged fast exit.
        let current_peers={let mut held=self.routes.lock().await;held.retain(|ip|present(*ip,32));held.iter().copied().filter(|ip|*ip!=self.own).collect::<std::collections::BTreeSet<_>>()};
        let current_capture={let mut held=self.capture_routes.lock().await;held.retain(|p|present(p.address(),p.prefix()));held.clone()};
        if current_peers==audit.accepted_peers.iter().copied().collect()&&current_capture==audit.capture.accepted.iter().copied().collect(){return Ok(audit);}
        // Withdraw obsolete host entries first. Capture transitions are a single
        // add-before-remove compound update below; pre-withdrawing their old
        // cover would reopen a default-route gap during safe pool expansion.
        let retained_peers:Vec<_>=self.routes.lock().await.iter().copied().filter(|p|audit.accepted_peers.contains(p)).collect();
        self.update_routes_for(&retained_peers,HostAdmission::Sparse).await?;
        audit.capture=self.update_capture_routes(pools).await?;
        self.update_routes_for(&audit.accepted_peers,HostAdmission::Sparse).await?;
        Ok(audit)
    }

    pub async fn update_routes(&self,peers:&[Ipv4Addr])->Result<()>{self.update_routes_for(peers,HostAdmission::Legacy).await}
    async fn update_routes_for(&self,peers:&[Ipv4Addr],admission:HostAdmission)->Result<()>{
        let mut current=self.routes.lock().await;
        let plan=plan_hosts(self.own,peers,admission,current.iter().copied())?;
        let wanted=&plan.wanted;
        let mut routes = AsyncRouteManager::new().context("cannot open Windows route manager")?;
        let existing = routes
            .list()
            .await
            .context("cannot inspect Windows routes")?;
        self.ownership.verify(self.index,&self.device,&existing)?;
        for address in wanted {
            for route in &existing {
                if route.prefix() == 0 || route.if_index() == Some(self.index) {
                    continue;
                }
                if conflicts_with_route(*address, route) {
                    anyhow::bail!("private address conflicts with an existing network route");
                }
            }
        }
        // Revoke obsolete physical routes first. Only new policy members are
        // added next; unchanged authorized routes are retained. This bounds the
        // ledger to one admitted generation, even during legacy/sparse handover.
        for address in plan.removals {
            let permit=self.ownership.retire(&direct(IpAddr::V4(address),32))?;
            let retired=remove_retired(&mut routes,self.index,permit).await?;self.ownership.finish_retirement(&retired)?;
            current.remove(&address);
        }
        for address in plan.additions {
            let route = Route::new(IpAddr::V4(address), 32).with_if_index(self.index).with_metric(0);
            self.ownership.reserve(direct(IpAddr::V4(address),32))?;
            if let Err(error)=routes.add(&route).await{self.ownership.cancel(&direct(IpAddr::V4(address),32))?;return Err(error).context("cannot add Windows private host route");}
            self.ownership.confirm(direct(IpAddr::V4(address),32))?;
            current.insert(address);
        }
        Ok(())
    }

    pub async fn read(&self, buffer: &mut [u8]) -> Result<usize> {
        self.device
            .recv(buffer)
            .await
            .context("Windows Wintun read failed")
    }

    pub async fn write(&self, bytes: &[u8]) -> Result<()> {
        ensure!(
            bytes.len() <= porthub_mesh::MAX_PACKET,
            "private packet exceeds MTU"
        );
        ensure!(
            self.device
                .send(bytes)
                .await
                .context("Windows Wintun write failed")?
                == bytes.len(),
            "short private packet write"
        );
        Ok(())
    }
}

impl Drop for Tun {
    fn drop(&mut self) {
        if let Err(error)=self.stop_source_checked(){tracing::warn!("owned Windows source shutdown not acknowledged: {error}");return;}
        let Ok(mut manager)=route_manager::RouteManager::new()else{return;};
        let Ok(native)=manager.list()else{return;};
        if let Err(error)=self.ownership.verify(self.index,&self.device,&native){tracing::warn!("cannot verify/checkpoint owned Wintun state; shutdown preserves native configuration: {error}");return;}
        let routes=self.routes.get_mut().clone();let captures=self.capture_routes.get_mut().clone();
        for prefix in captures.iter(){
            let parent=direct(IpAddr::V4(prefix.address()),prefix.prefix());
            let outcome:Result<()>= (||{
                let permits=self.ownership.retire_capture(&parent)?;
                for permit in permits{let row=permit.into_stamp();self.check_route_identity()?;
                    if manager.list()?.iter().any(|r|r.if_index()==Some(self.index)&&stamp(r)==row){self.check_route_identity()?;manager.delete(&Route::new(row.address,row.prefix).with_if_index(self.index).with_metric(row.metric))?;}
                }
                let child=capture_child(&parent)?;let retained=self.ownership.child_retained(&parent)?;let rows=manager.list()?;self.check_route_identity()?;
                ensure!(!rows.iter().any(|r|r.if_index()==Some(self.index)&&(stamp(r)==parent||(!retained&&stamp(r)==child))),"Drop capture absence unproven");
                if retained{ensure!(rows.iter().any(|r|r.if_index()==Some(self.index)&&stamp(r)==child),"Drop shared child missing");}
                self.ownership.finish_capture(&parent)
            })();
            if let Err(error)=outcome{tracing::warn!("capture retirement incomplete: {error}");return;}
        }
        for (address,prefix) in routes.iter().map(|ip|(*ip,32)){
            let expected=direct(IpAddr::V4(address),prefix);
            // verify() already retired any observed absent row. Never create
            // a second removal intent (or delete a new external row) for it.
            if !native.iter().any(|r|r.if_index()==Some(self.index)&&stamp(r)==expected){continue;}
            let permit=match self.ownership.retire(&expected){Ok(permit)=>permit,Err(_)=>{tracing::warn!("could not durably retire Windows route; native entry preserved");continue;}};
            let retired=permit.into_stamp();
            let route=Route::new(retired.address,retired.prefix).with_if_index(self.index).with_metric(retired.metric);
            if manager.delete(&route).is_err(){tracing::warn!("could not remove durably retired Windows route; exact-owned repair may be required");}else if self.ownership.finish_retirement(&retired).is_err(){tracing::warn!("could not checkpoint Windows route retirement completion");}
        }
        // Exact source removal/session stop was acknowledged before route
        // cleanup. No second unguarded address mutation is performed here.

    }
}

#[cfg(test)]
mod tests {
    use super::conflicts_with_route;
    use route_manager::Route;
    use std::net::IpAddr;

    #[test]
    fn assigned_interface_address_is_not_an_explicit_peer_route() {
        let own = "10.254.250.254".parse().unwrap();
        let peer = "10.254.250.253".parse().unwrap();
        assert_eq!(super::peer_routes(own, &[own, peer, peer]), std::collections::HashSet::from([peer]));
    }

    #[test]
    fn route_preflight_detects_overlaps_but_allows_default_and_other_family_routes() {
        let lan = Route::new("192.168.80.0".parse::<IpAddr>().unwrap(), 24);
        assert!(conflicts_with_route("192.168.80.9".parse().unwrap(), &lan));
        assert!(!conflicts_with_route("10.203.0.9".parse().unwrap(), &lan));
        let default = Route::new("0.0.0.0".parse().unwrap(), 0);
        assert!(!conflicts_with_route(
            "10.203.0.9".parse().unwrap(),
            &default
        ));
        let ipv6 = Route::new("fd00::".parse().unwrap(), 64);
        assert!(!conflicts_with_route("10.203.0.9".parse().unwrap(), &ipv6));
    }
}
