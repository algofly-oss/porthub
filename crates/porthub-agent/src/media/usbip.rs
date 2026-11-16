//! Receiver-local virtual microphone USB/IP execution, after authenticated import.
//! No listener, authentication bypass or physical-device adapter lives here.
//! Wire layout: https://docs.kernel.org/usb/usbip_protocol.html
//! The receiver HCD owns the continuous frame clock; peer URB frame numbers are not deadlines.
use super::usb_audio::{IsoPacket, Microphone};
use anyhow::{ensure, Result};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::Instant,
};
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
const MAX_BYTES: usize = 1024 * 1024;
const MAX_PENDING: usize = 32;
const MAX_PACKETS: usize = 128;
#[cfg(test)]
static PRIVATE_ISO_ERRORS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
#[derive(Default)]
struct PrivateDistribution { bins: Vec<u64>, count:u64, max_us:u64 }
#[cfg(test)]
impl PrivateDistribution {
    fn add(&mut self,us:u64){if self.bins.is_empty(){self.bins.resize(1002,0)};self.bins[(us/100).min(1001) as usize]+=1;self.count+=1;self.max_us=self.max_us.max(us);}
    fn percentile(&self,percent:u64)->u64{let target=(self.count*percent).div_ceil(100);let mut count=0;for(i,n)in self.bins.iter().enumerate(){count+=n;if count>=target{return if i==1001{self.max_us}else{((i+1)*100-1) as u64}}}0}
    fn json(&self)->serde_json::Value{serde_json::json!({"count":self.count,"max_us":self.max_us,"p50_us_upper":self.percentile(50),"p95_us_upper":self.percentile(95),"p99_us_upper":self.percentile(99),"histogram_bin_us":100})}
}
#[cfg(test)]
#[derive(Default)]
struct PrivateTiming {lateness_unit: &'static str,lateness:PrivateDistribution, gaps:PrivateDistribution,last:Option<Instant>,frames:Vec<serde_json::Value>}
#[cfg(test)]
struct PrivateTimingReport(Arc<Mutex<PrivateTiming>>);
#[cfg(test)]
impl Drop for PrivateTimingReport {
    fn drop(&mut self){if std::env::var("PORTHUB_PRIVATE_UAC_CLASS_TEST").as_deref()!=Ok("1"){return}if let Ok(stats)=self.0.lock(){println!("PRIVATE_UAC_TIMING {}",serde_json::json!({"lateness_unit":stats.lateness_unit,"lateness":stats.lateness.json(),"completion_gap":stats.gaps.json()}));for frame in &stats.frames{println!("PRIVATE_UAC_FRAME {frame}");}}}
}
pub type SharedMicrophone = Arc<Mutex<Microphone>>;
struct Request {
    sequence: u32,
    input: bool,
    endpoint: u32,
    length: usize,
    interval: u32,
    #[cfg(test)]
    requested_frame:u32,
    setup: [u8; 8],
    data: Vec<u8>,
    packets: Vec<IsoPacket>,
    _permit: OwnedSemaphorePermit,
}
enum Command {
    Submit(Request),
    Unlink { sequence: u32, target: u32 },
}
fn word(h: &[u8], n: usize) -> u32 {
    u32::from_be_bytes(h[n..n + 4].try_into().unwrap())
}
async fn read<R: AsyncRead + Unpin>(
    r: &mut R,
    devid: u32,
    budget: Arc<Semaphore>,
) -> Result<Command> {
    let mut h = [0; 48];
    r.read_exact(&mut h).await?;
    #[cfg(test)]
    if std::env::var("PORTHUB_PRIVATE_UAC_CLASS_TEST").as_deref() == Ok("1") {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static SEEN: AtomicUsize = AtomicUsize::new(0);
        if SEEN.fetch_add(1, Ordering::Relaxed) < 64 {
            eprintln!("PRIVATE_UAC_URB cmd={} seq={} ep={} dir={} flags={:x} len={} start={} packets={} interval={} setup={:02x?}",word(&h,0),word(&h,4),word(&h,16),word(&h,12),word(&h,20),word(&h,24),word(&h,28),word(&h,32),word(&h,36),&h[40..48]);
        }
    }
    ensure!(
        word(&h, 8) == devid && word(&h, 12) <= 1 && word(&h, 16) <= 15,
        "Invalid virtual USB device or endpoint"
    );
    if word(&h, 0) == 2 {
        ensure!(word(&h, 16) == 0, "Invalid unlink endpoint");
        return Ok(Command::Unlink {
            sequence: word(&h, 4),
            target: word(&h, 20),
        });
    }
    ensure!(word(&h, 0) == 1, "Unsupported virtual USB command");
    let length = word(&h, 24) as usize;
    let count = match word(&h, 32) {
        u32::MAX => 0,
        n => n as usize,
    };
    ensure!(
        length <= MAX_BYTES && count <= MAX_PACKETS,
        "Virtual USB buffer limit exceeded"
    );
    let permit = budget.try_acquire_many_owned((length + count * 16).max(1) as u32)?;
    let input = word(&h, 12) == 1;
    let mut data = if input { vec![] } else { vec![0; length] };
    r.read_exact(&mut data).await?;
    let mut packets = Vec::with_capacity(count);
    let mut end = 0;
    for _ in 0..count {
        let mut d = [0; 16];
        r.read_exact(&mut d).await?;
        let offset = word(&d, 0);
        let size = word(&d, 4);
        ensure!(
            offset as usize >= end && size <= 96 && size % 2 == 0,
            "Invalid virtual ISO packet"
        );
        end = (offset as usize)
            .checked_add(size as usize)
            .ok_or_else(|| anyhow::anyhow!("ISO range overflow"))?;
        ensure!(end <= length, "ISO packet exceeds transfer buffer");
        packets.push(IsoPacket {
            offset,
            length: size,
        });
    }
    Ok(Command::Submit(Request {
        sequence: word(&h, 4),
        input,
        endpoint: word(&h, 16),
        length,
        interval: word(&h, 36),
        #[cfg(test)]
        requested_frame:word(&h,28),
        setup: h[40..48].try_into().unwrap(),
        data,
        packets,
        _permit: permit,
    }))
}
async fn reply<W: AsyncWrite + Unpin>(
    w: &mut W,
    command: u32,
    seq: u32,
    status: i32,
    data: &[u8],
    actual: usize,
    frame: u32,
    packets: &[IsoPacket],
) -> Result<()> {
    #[cfg(test)]
    if command == 3
        && !packets.is_empty()
        && status != 0
        && status != -108
        && std::env::var("PORTHUB_PRIVATE_UAC_CLASS_TEST").as_deref() == Ok("1")
    {
        PRIVATE_ISO_ERRORS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    #[cfg(test)]
    if std::env::var("PORTHUB_PRIVATE_UAC_CLASS_TEST").as_deref() == Ok("1") {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static SENT: AtomicUsize = AtomicUsize::new(0);
        if SENT.fetch_add(1, Ordering::Relaxed) < 64 {
            eprintln!("PRIVATE_UAC_REPLY cmd={command} seq={seq} status={status} actual={actual} frame={frame} packets={}",packets.len());
        }
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut h = [0; 48];
        h[..4].copy_from_slice(&command.to_be_bytes());
        h[4..8].copy_from_slice(&seq.to_be_bytes());
        h[20..24].copy_from_slice(&status.to_be_bytes());
        if command == 3 {
            h[24..28].copy_from_slice(&(actual as u32).to_be_bytes());
            h[28..32].copy_from_slice(&frame.to_be_bytes());
            h[32..36].copy_from_slice(&(packets.len() as u32).to_be_bytes());
            if status != 0 {
                h[36..40].copy_from_slice(&(packets.len() as u32).to_be_bytes());
            }
        }
        w.write_all(&h).await?;
        w.write_all(data).await?;
        for p in packets {
            w.write_all(&p.offset.to_be_bytes()).await?;
            w.write_all(&p.length.to_be_bytes()).await?;
            w.write_all(&(if status == 0 { p.length } else { 0 }).to_be_bytes())
                .await?;
            w.write_all(&status.to_be_bytes()).await?;
        }
        w.flush().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("Virtual USB reply deadline exceeded"))??;
    Ok(())
}
struct StopOnDrop(SharedMicrophone, watch::Sender<bool>);
impl Drop for StopOnDrop {
    fn drop(&mut self) {
        if let Ok(mut m) = self.0.lock() {
            m.stop();
        }
        self.1.send_replace(false);
    }
}
/// The trusted receiver-local adapter determines wire timing, never the peer.
#[derive(Clone, Copy)]
enum ReceiverHcd {
    LinuxVhci,
    WindowsUde,
}
impl ReceiverHcd {
    fn local() -> Self {
        if cfg!(windows) { Self::WindowsUde } else { Self::LinuxVhci }
    }
    fn accepts_interval(self, interval: u32) -> bool {
        // Pinned signed usbip-win2 v.0.9.8.1 patches full-speed ISO bInterval
        // 1 to high-speed exponent 4, then copies that patched descriptor into
        // the USB/IP interval field. Both encodings mean our fixed 1ms clock.
        // https://github.com/vadimgrn/usbip-win2/blob/55e1fa7f0c2157017b02dc1f3236e98169a535e4/drivers/ude/wsk_receive.cpp#L126-L132
        // https://github.com/vadimgrn/usbip-win2/blob/55e1fa7f0c2157017b02dc1f3236e98169a535e4/drivers/ude/proto.cpp#L85
        interval == match self { Self::LinuxVhci => 1, Self::WindowsUde => 4 }
    }
}

#[cfg(windows)]
mod native_clock {
    use super::*;
    use std::sync::{atomic::{AtomicBool,Ordering},mpsc::{sync_channel,SyncSender}};
    use windows_sys::Win32::{Foundation::{CloseHandle,HANDLE,WAIT_OBJECT_0},System::Threading::{CancelWaitableTimer,CreateEventW,CreateWaitableTimerExW,SetEvent,SetWaitableTimerEx,WaitForMultipleObjects,CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,TIMER_MODIFY_STATE,SYNCHRONIZATION_SYNCHRONIZE}};
    struct Handle(HANDLE);
    // Kernel synchronization handles may be shared across threads; each is closed once.
    unsafe impl Send for Handle {} unsafe impl Sync for Handle {}
    impl Handle {fn raw(&self)->HANDLE{self.0}}
    impl Drop for Handle {fn drop(&mut self){unsafe{CloseHandle(self.0);}}}
    struct Deadline {
        order:std::time::Instant,at:std::time::Instant,expires:Option<std::time::Instant>,
        work:Box<dyn FnMut(bool)->bool+Send>,abandoned:Arc<AtomicBool>,
        _permit:tokio::sync::OwnedSemaphorePermit,
    }
    struct Abandon {flag:Arc<AtomicBool>,wake:Arc<Handle>}
    impl Drop for Abandon {fn drop(&mut self){if !self.flag.swap(true,Ordering::AcqRel){unsafe{SetEvent(self.wake.raw());}}}}
    pub(super) struct Clock {
        sender:SyncSender<Deadline>,wake:Arc<Handle>,stop:Arc<AtomicBool>,
        quota:Arc<tokio::sync::Semaphore>,thread:Option<std::thread::JoinHandle<()>>,
    }
    impl Clock {
        pub(super) fn new()->Result<Self>{
            let wake=unsafe{CreateEventW(std::ptr::null(),0,0,std::ptr::null())};
            ensure!(!wake.is_null(),"Create receiver clock event: {}",std::io::Error::last_os_error());let wake=Arc::new(Handle(wake));
            let timer=unsafe{CreateWaitableTimerExW(std::ptr::null(),std::ptr::null(),CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,TIMER_MODIFY_STATE|SYNCHRONIZATION_SYNCHRONIZE)};
            ensure!(!timer.is_null(),"Create receiver high-resolution clock: {}",std::io::Error::last_os_error());let timer=Handle(timer);
            let (sender,receiver)=sync_channel::<Deadline>(MAX_PENDING);let stop=Arc::new(AtomicBool::new(false));
            let thread_wake=wake.clone();let thread_stop=stop.clone();
            let thread=std::thread::Builder::new().name("porthub-media-clock".into()).spawn(move || {
                let mut pending=Vec::<Deadline>::new();
                'scheduler: while !thread_stop.load(Ordering::Acquire){
                    while let Ok(deadline)=receiver.try_recv(){
                        // One shared permit covers channel AND pending storage.
                        if pending.len()>=MAX_PENDING{break 'scheduler}
                        pending.push(deadline);
                    }
                    pending.retain(|entry|!entry.abandoned.load(Ordering::Acquire));
                    pending.sort_by_key(|entry|entry.order);
                    // Preserve URB PCM order even when deadlines are overdue.
                    while pending.first().is_some_and(|entry|entry.at<=std::time::Instant::now()){
                        let mut deadline=pending.remove(0);
                        if deadline.abandoned.load(Ordering::Acquire){continue}
                        let expired=deadline.expires.is_some_and(|expires|std::time::Instant::now()>=expires);
                        if (deadline.work)(expired){deadline.abandoned.store(true,Ordering::Release);}
                        else{let now=std::time::Instant::now();deadline.expires.get_or_insert(now+Duration::from_millis(20));deadline.at=now+Duration::from_millis(1);pending.insert(0,deadline);break;}
                    }
                    let next=pending.first().map(|entry|entry.at);
                    if let Some(next)=next{let remaining=next.saturating_duration_since(std::time::Instant::now());if remaining.is_zero(){continue}
                        let due=-((remaining.as_nanos().div_ceil(100)).min(i64::MAX as u128) as i64).max(1);
                        if unsafe{SetWaitableTimerEx(timer.raw(),&due,0,None,std::ptr::null(),std::ptr::null(),0)}==0{break;}
                    }else{unsafe{CancelWaitableTimer(timer.raw());}}
                    let handles=[thread_wake.raw(),timer.raw()];
                    // No polling or global timer-resolution changes. Empty queues wait only on wake.
                    let result=unsafe{WaitForMultipleObjects(if next.is_some(){2}else{1},handles.as_ptr(),0,u32::MAX)};
                    if result!=WAIT_OBJECT_0 && !(next.is_some()&&result==WAIT_OBJECT_0+1){break;}
                }
                // Dropping work closes pending oneshots; native failures fail the stream closed.
            })?;
            Ok(Self{sender,wake,stop,quota:Arc::new(tokio::sync::Semaphore::new(MAX_PENDING)),thread:Some(thread)})
        }
        pub(super) async fn run_at<T:Send+'static>(&self,at:std::time::Instant,mut work:impl FnMut()->Result<Option<T>>+Send+'static)->Result<T>{
            let permit=self.quota.clone().try_acquire_owned().map_err(|_|anyhow::anyhow!("Receiver clock combined queue full"))?;
            let (reply,receive)=tokio::sync::oneshot::channel();let mut reply=Some(reply);
            let abandoned=Arc::new(AtomicBool::new(false));let _abandon=Abandon{flag:abandoned.clone(),wake:self.wake.clone()};
            let work=Box::new(move|expired|{
                if reply.as_ref().is_none_or(|reply|reply.is_closed()){return true}
                let result=if expired{Err(anyhow::anyhow!("Receiver clock callback contention deadline"))}else{work()};
                match result{Ok(None)=>false,result=>{let _=reply.take().unwrap().send(result.and_then(|value|value.ok_or_else(||anyhow::anyhow!("Missing receiver clock result"))));true}}
            });
            self.sender.try_send(Deadline{order:at,at,expires:None,work,abandoned,_permit:permit}).map_err(|_|anyhow::anyhow!("Receiver clock queue unavailable"))?;
            ensure!(unsafe{SetEvent(self.wake.raw())}!=0,"Wake receiver clock failed");
            receive.await.map_err(|_|anyhow::anyhow!("Receiver clock terminated"))?
        }
        pub(super) async fn wait_until(&self,at:std::time::Instant)->Result<()>{self.run_at(at,||Ok(Some(()))).await}
        #[cfg(test)] pub(super) fn available(&self)->usize{self.quota.available_permits()}
    }
    impl Drop for Clock {fn drop(&mut self){self.stop.store(true,Ordering::Release);unsafe{SetEvent(self.wake.raw());}if let Some(thread)=self.thread.take(){let _=thread.join();}}}
}

enum ScheduledSample { Packet(Vec<u8>), RetiredEpoch }
#[derive(Clone)]
struct ReceiverClock {
    #[cfg(windows)] native:Option<Arc<native_clock::Clock>>,
}
impl ReceiverClock {
    fn new(hcd:ReceiverHcd)->Result<Self>{
        #[cfg(windows)] let native=if matches!(hcd,ReceiverHcd::WindowsUde){Some(Arc::new(native_clock::Clock::new()?))}else{None};
        #[cfg(not(windows))] let _=hcd;
        Ok(Self{#[cfg(windows)] native})
    }
    async fn packet_at(&self,at:Instant,microphone:SharedMicrophone,length:usize,packet:IsoPacket,generation:u64)->Result<ScheduledSample>{
        tokio::time::sleep_until(at).await;
        let mut microphone=microphone.lock().map_err(|_|anyhow::anyhow!("Microphone engine poisoned"))?;
        if microphone.stream_generation()!=generation{return Ok(ScheduledSample::RetiredEpoch)}
        microphone.isochronous(length,&[packet]).map(|reply|ScheduledSample::Packet(reply.packed))
    }
    #[cfg(windows)]
    async fn native_transfer_at(&self,at:Instant,microphone:SharedMicrophone,length:usize,packets:Vec<IsoPacket>,generation:u64)->Result<ScheduledSample>{
        let clock=self.native.as_ref().ok_or_else(||anyhow::anyhow!("Missing native receiver clock"))?;
        clock.run_at(at.into_std(),move||{
            match microphone.try_lock(){
                Ok(mut microphone)=>{if microphone.stream_generation()!=generation{return Ok(Some(ScheduledSample::RetiredEpoch))}microphone.isochronous(length,&packets).map(|reply|Some(ScheduledSample::Packet(reply.packed)))},
                Err(std::sync::TryLockError::WouldBlock)=>Ok(None),
                Err(std::sync::TryLockError::Poisoned(_))=>anyhow::bail!("Microphone engine poisoned"),
            }
        }).await
    }
}

/// Caller must have authorized MediaReceive and completed identity-bound import.
/// The stream must stay receiver-local; remote transport carries PCM, not ISO URBs.
pub async fn serve<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    microphone: SharedMicrophone,
    devid: u32,
    streaming: watch::Sender<bool>,
    cancel: CancellationToken,
) -> Result<()> {
    serve_for_hcd(stream, microphone, devid, streaming, cancel, ReceiverHcd::local()).await
}
async fn serve_for_hcd<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S, microphone: SharedMicrophone, devid: u32, streaming: watch::Sender<bool>,
    cancel: CancellationToken, hcd: ReceiverHcd,
) -> Result<()> {
    let _stop = StopOnDrop(microphone.clone(), streaming.clone());
    tokio::select! {biased;
        _=cancel.cancelled()=>Ok(()),
        result=run(stream,microphone,devid,streaming,cancel.clone(),hcd)=>result,
    }
}
fn publish_demand(streaming:&watch::Sender<bool>,active:bool,force:bool){
    if force{streaming.send_replace(active);}else{streaming.send_if_modified(|current|{if *current==active{false}else{*current=active;true}});}
}
fn active_iso(pending:&HashMap<u32,(CancellationToken,u64)>,generation:u64)->bool{
    pending.values().any(|(token,epoch)|*epoch==generation&&!token.is_cancelled())
}
fn retire_demand(microphone:&SharedMicrophone,streaming:&watch::Sender<bool>,generation:&mut u64,epoch:&mut CancellationToken,next:&mut Instant,refill:&mut Option<Instant>)->Result<()>{
    let mut microphone=microphone.lock().map_err(|_|anyhow::anyhow!("Microphone engine poisoned"))?;
    microphone.retire_pcm_epoch();*generation=microphone.stream_generation();drop(microphone);
    publish_demand(streaming,false,false);
    epoch.cancel();*epoch=CancellationToken::new();*next=Instant::now();*refill=None;Ok(())
}
async fn run<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    microphone: SharedMicrophone,
    devid: u32,
    streaming: watch::Sender<bool>,
    cancel: CancellationToken,
    hcd: ReceiverHcd,
) -> Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::channel(MAX_PENDING);
    let budget = Arc::new(Semaphore::new(MAX_BYTES));
    let _reader = AbortOnDropHandle::new(tokio::spawn(async move {
        loop {
            let cmd = read(&mut reader, devid, budget.clone()).await;
            let failed = cmd.is_err();
            if tx.send(cmd).await.is_err() || failed {
                break;
            }
        }
    }));
    let mut pending = HashMap::<u32, (CancellationToken,u64)>::new();
    let mut jobs = JoinSet::new();
    let clock=ReceiverClock::new(hcd)?;
    let origin = Instant::now();
    let mut next = origin;
    let mut epoch = CancellationToken::new();
    let mut generation=microphone.lock().map_err(|_|anyhow::anyhow!("Microphone engine poisoned"))?.stream_generation();
    let mut refill:Option<Instant>=None;
    #[cfg(test)]
    let timing=Arc::new(Mutex::new(PrivateTiming{lateness_unit:if cfg!(windows)&&matches!(hcd,ReceiverHcd::WindowsUde){"iso_transfer_completion"}else{"individual_packet_deadline"},..PrivateTiming::default()}));
    #[cfg(test)]
    let _timing_report=PrivateTimingReport(timing.clone());
    loop {
        tokio::select! {
            _=cancel.cancelled()=>return Ok(()),
            command=rx.recv()=>{let Some(command)=command else{return Ok(());};match command? {
                Command::Unlink{sequence,target}=>{
                    let status=if let Some((token,_))=pending.get(&target).filter(|(token,_)|!token.is_cancelled()){token.cancel();-104}else{0};
                    let was_demanded=*streaming.borrow();
                    if !active_iso(&pending,generation)&&(was_demanded||refill.is_some()){retire_demand(&microphone,&streaming,&mut generation,&mut epoch,&mut next,&mut refill)?;}
                    reply(&mut writer,4,sequence,status,&[],0,0,&[]).await?;
                },
                Command::Submit(request)=>{
                    ensure!(!pending.contains_key(&request.sequence),"Duplicate pending virtual USB sequence");
                    if request.endpoint==0 {
                        ensure!(request.packets.is_empty(),"ISO descriptors on control endpoint");
                        ensure!(request.input==(request.setup[0]&0x80!=0) && request.length==u16::from_le_bytes([request.setup[6],request.setup[7]]) as usize,"Control setup disagrees with transfer");
                        let mut reset=false;
                        let result={let mut m=microphone.lock().map_err(|_|anyhow::anyhow!("Microphone engine poisoned"))?;
                        let result=m.control(request.setup,&request.data);
                        if m.stream_generation()!=generation {
                            generation=m.stream_generation();epoch.cancel();epoch=CancellationToken::new();next=Instant::now();refill=None;
                            // A real alternate/configuration reset retires the source epoch,
                            // including same-alt reset. Merely selecting alt1 never captures.
                            reset=true;
                        }
                        result};
                        if reset{publish_demand(&streaming,false,true);}
                        let (status,data)=match result {Ok(data)=>(0,data),Err(status)=>(status,vec![])};
                        ensure!(data.len()<=request.length,"Control reply exceeds requested buffer");
                        reply(&mut writer,3,request.sequence,status,if request.input{&data}else{&[]},if status!=0{0}else if request.input{data.len()}else{request.data.len()},0,&[]).await?;
                    } else if request.endpoint==1 && request.input && !request.packets.is_empty() {
                        // Like Linux xhci_get_isoc_start_frame, the receiver HCD
                        // schedules its next local frame and reports that actual frame.
                        // ALSA reuses returned start_frame values; treating them as new
                        // deadlines or rejecting them breaks ordinary continuous capture.
                        // https://github.com/torvalds/linux/blob/master/drivers/usb/host/xhci-ring.c
                        if !hcd.accepts_interval(request.interval) || request.packets.iter().all(|packet|packet.length==0) {reply(&mut writer,3,request.sequence,-22,&[],0,0,&request.packets).await?;continue;}
                        let (allowed,current_generation)={let engine=microphone.lock().map_err(|_|anyhow::anyhow!("Microphone engine poisoned"))?;(engine.streaming(),engine.stream_generation())};
                        if current_generation!=generation{generation=current_generation;epoch.cancel();epoch=CancellationToken::new();next=Instant::now();refill=None;publish_demand(&streaming,false,true);}
                        if !allowed {reply(&mut writer,3,request.sequence,-108,&[],0,0,&request.packets).await?;continue;}
                        ensure!(jobs.len()<MAX_PENDING,"Virtual USB request queue full");
                        let token=CancellationToken::new();pending.insert(request.sequence,(token.clone(),generation));
                        refill=None;publish_demand(&streaming,true,false);
                        let request_generation=generation;
                        let start=next.max(Instant::now());ensure!(start<=Instant::now()+Duration::from_secs(1),"Virtual ISO scheduling horizon exceeded");next=start+Duration::from_millis(request.packets.len() as u64);
                        let stream_epoch=epoch.clone();let m=microphone.clone();let frame=start.duration_since(origin).as_millis() as u32 & 2047;
                        let clock=clock.clone();
                        #[cfg(test)]
                        let timing=timing.clone();
                        jobs.spawn(async move {
                            let mut data=Vec::new();let mut status=0;
                            #[cfg(windows)]
                            if clock.native.is_some(){
                                let deadline=start+Duration::from_millis(request.packets.len() as u64);
                                let result=tokio::select!{biased;_=token.cancelled()=>return(request,frame,-104,vec![],true),_=stream_epoch.cancelled()=>return(request,frame,-108,vec![],false),result=clock.native_transfer_at(deadline,m.clone(),request.length,request.packets.clone(),request_generation)=>result};
                                #[cfg(test)] timing.lock().unwrap().lateness.add(Instant::now().saturating_duration_since(deadline).as_micros() as u64);
                                return match result{Ok(ScheduledSample::Packet(data))=>(request,frame,0,data,false),Ok(ScheduledSample::RetiredEpoch)=>(request,frame,-108,vec![],false),Err(_)=>(request,frame,-5,vec![],false)};
                            }
                            for (i,p) in request.packets.iter().enumerate() {
                                let result=tokio::select!{biased;_=token.cancelled()=>return(request,frame,-104,vec![],true),_=stream_epoch.cancelled()=>return(request,frame,-108,vec![],false),result=clock.packet_at(start+Duration::from_millis(i as u64+1),m.clone(),request.length,*p,request_generation)=>result};
                                #[cfg(test)]
                                timing.lock().unwrap().lateness.add(Instant::now().saturating_duration_since(start+Duration::from_millis(i as u64+1)).as_micros().min(u64::MAX as u128) as u64);
                                match result {Ok(ScheduledSample::Packet(packet))=>data.extend(packet),Ok(ScheduledSample::RetiredEpoch)=>{status=-108;break;},Err(_)=>{status=-5;break;}}
                            }
                            (request,frame,status,data,false)
                        });
                    } else {reply(&mut writer,3,request.sequence,-32,&[],0,0,&request.packets).await?;}
                }
            }},
            _=async{if let Some(deadline)=refill{tokio::time::sleep_until(deadline).await}else{std::future::pending::<()>().await}},if refill.is_some()=>{
                if !active_iso(&pending,generation){retire_demand(&microphone,&streaming,&mut generation,&mut epoch,&mut next,&mut refill)?;}else{refill=None;}
            },
            completion=jobs.join_next(),if !jobs.is_empty()=>{
                let (request,frame,status,data,cancelled)=completion.unwrap()?;
                // An UNLINK may already have removed the token while this completion was queued.
                let Some((token,completed_generation))=pending.remove(&request.sequence) else{continue};
                if token.is_cancelled()||cancelled{continue;}
                #[cfg(test)]
                {let now=Instant::now();let mut stats=timing.lock().unwrap();if let Some(previous)=stats.last{stats.gaps.add(now.saturating_duration_since(previous).as_micros() as u64)};stats.last=Some(now);if stats.frames.len()<64{stats.frames.push(serde_json::json!({"sequence":request.sequence,"requested_frame":request.requested_frame,"returned_frame":frame,"packets":request.packets.len(),"completion_us":now.saturating_duration_since(origin).as_micros(),"status":status}));}}
                reply(&mut writer,3,request.sequence,status,if status==0{&data}else{&[]},if status==0{data.len()}else{0},frame,&request.packets).await?;
                ensure!(status!=-5,"Receiver-local native clock failed");
                if status==0&&completed_generation==generation&&!active_iso(&pending,generation){refill=Some(Instant::now()+Duration::from_millis(100));}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::usb_audio::Identity;
    use super::*;
    fn submit(seq: u32, ep: u32, length: u32, packets: u32) -> Vec<u8> {
        let mut h = vec![0; 48];
        for (offset, value) in [
            (0, 1u32),
            (4, seq),
            (8, 0xffff0001),
            (12, 1),
            (16, ep),
            (24, length),
            (32, packets),
        ] {
            h[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        if ep == 1 {
            h[20..24].copy_from_slice(&2u32.to_be_bytes());
            h[36..40].copy_from_slice(&1u32.to_be_bytes());
            for i in 0..packets {
                h.extend((i * 96).to_be_bytes());
                h.extend(96u32.to_be_bytes());
                h.extend([0; 8]);
            }
        }
        h
    }
    async fn serve<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        stream:S, microphone:SharedMicrophone, devid:u32, streaming:watch::Sender<bool>, cancel:CancellationToken,
    )->Result<()>{super::serve_for_hcd(stream,microphone,devid,streaming,cancel,ReceiverHcd::LinuxVhci).await}
    fn fixture() -> (SharedMicrophone, watch::Sender<bool>) {
        let mut m = Microphone::new(
            Identity {
                vendor: 0,
                product: 1,
            },
            "WireOnlyTest".into(),
        )
        .unwrap();
        m.control([0, 9, 1, 0, 0, 0, 0, 0], &[]).unwrap();
        m.control([1, 11, 1, 0, 1, 0, 0, 0], &[]).unwrap();
        (Arc::new(Mutex::new(m)), watch::channel(false).0)
    }
    #[tokio::test]
    async fn parser_clock_metadata_uses_start_frame_not_transfer_length()->Result<()> {
        let (mut sender,mut receiver)=tokio::io::duplex(1024);
        let mut packet=submit(7,1,96,1);
        packet[28..32].copy_from_slice(&0x12345678u32.to_be_bytes());
        sender.write_all(&packet).await?;
        let Command::Submit(request)=read(&mut receiver,0xffff0001,Arc::new(Semaphore::new(MAX_BYTES))).await? else {panic!("Expected submit")};
        assert_eq!(request.length,96);assert_eq!(request.requested_frame,0x12345678);
        Ok(())
    }
    async fn wire_reply(client:&mut (impl AsyncRead+Unpin))->Result<(u32,i32,Vec<u8>)>{
        let mut header=[0;48];client.read_exact(&mut header).await?;
        let mut body=vec![0;word(&header,24) as usize+word(&header,32) as usize*16];client.read_exact(&mut body).await?;
        Ok((word(&header,4),word(&header,20) as i32,body))
    }
    fn control_request(sequence:u32,setup:[u8;8])->Vec<u8>{
        let mut request=submit(sequence,0,u16::from_le_bytes([setup[6],setup[7]]) as u32,0);
        request[12..16].copy_from_slice(&u32::from(setup[0]&0x80!=0).to_be_bytes());request[40..48].copy_from_slice(&setup);request
    }
    fn unlink_request(sequence:u32,target:u32)->Vec<u8>{
        let mut request=vec![0;48];for(offset,value)in[(0,2u32),(4,sequence),(8,0xffff0001),(20,target)]{request[offset..offset+4].copy_from_slice(&value.to_be_bytes());}request
    }
    #[tokio::test(start_paused=true)]
    async fn capture_requires_pending_iso_and_readonly_ep0_never_rotates_demand()->Result<()> {
        let engine=Arc::new(Mutex::new(Microphone::new(Identity{vendor:0,product:1},"ColdEnumeration".into())?));let(streaming,_)=watch::channel(false);let mut demand=streaming.subscribe();let cancel=CancellationToken::new();let(server,mut client)=tokio::io::duplex(16384);
        let task=tokio::spawn(serve(server,engine.clone(),0xffff0001,streaming,cancel.clone()));
        client.write_all(&control_request(1,[0x80,6,0,1,0,0,18,0])).await?;assert_eq!(wire_reply(&mut client).await?.1,0);assert!(!*demand.borrow());assert!(!demand.has_changed()?);
        client.write_all(&control_request(2,[0,9,1,0,0,0,0,0])).await?;assert_eq!(wire_reply(&mut client).await?.1,0);assert!(!*demand.borrow());
        client.write_all(&control_request(3,[1,11,1,0,1,0,0,0])).await?;assert_eq!(wire_reply(&mut client).await?.1,0);
        demand.borrow_and_update();assert!(!*demand.borrow(),"AS alt1 alone activated capture");
        let generation=engine.lock().unwrap().stream_generation();
        for sequence in 4..7 {client.write_all(&control_request(sequence,[0x80,6,0,1,0,0,18,0])).await?;assert_eq!(wire_reply(&mut client).await?.0,sequence);assert!(!demand.has_changed()?);}
        assert_eq!(engine.lock().unwrap().stream_generation(),generation);
        client.write_all(&submit(7,1,384,4)).await?;demand.changed().await?;assert!(*demand.borrow_and_update());
        client.write_all(&control_request(8,[0x80,6,0,1,0,0,18,0])).await?;
        let response=wire_reply(&mut client).await?;assert_eq!(response.0,8);assert!(!demand.has_changed()?);assert!(*demand.borrow());
        cancel.cancel();task.await??;Ok(())
    }
    #[tokio::test(start_paused=true)]
    async fn zero_byte_iso_descriptors_never_activate_capture()->Result<()> {
        let(engine,streaming)=fixture();let mut demand=streaming.subscribe();let cancel=CancellationToken::new();let(server,mut client)=tokio::io::duplex(16384);
        let generation=engine.lock().unwrap().stream_generation();let task=tokio::spawn(serve(server,engine.clone(),0xffff0001,streaming,cancel.clone()));
        let mut empty=submit(1,1,96,1);empty[52..56].fill(0);client.write_all(&empty).await?;
        let(sequence,status,_)=wire_reply(&mut client).await?;assert_eq!(sequence,1);assert_eq!(status,-22);assert!(!*demand.borrow());assert!(!demand.has_changed()?);assert_eq!(engine.lock().unwrap().stream_generation(),generation);
        client.write_all(&submit(2,1,96,1)).await?;demand.changed().await?;assert!(*demand.borrow_and_update());assert_eq!(wire_reply(&mut client).await?.1,0);
        cancel.cancel();task.await??;Ok(())
    }
    #[tokio::test(start_paused=true)]
    async fn natural_iso_refill_keeps_epoch_then_idle_grace_retires_pcm()->Result<()> {
        let(engine,streaming)=fixture();let mut demand=streaming.subscribe();let cancel=CancellationToken::new();let(server,mut client)=tokio::io::duplex(16384);
        let task=tokio::spawn(serve(server,engine.clone(),0xffff0001,streaming,cancel.clone()));
        client.write_all(&submit(1,1,96,1)).await?;demand.changed().await?;assert!(*demand.borrow_and_update());
        assert_eq!(wire_reply(&mut client).await?.0,1);tokio::task::yield_now().await;
        let generation=engine.lock().unwrap().stream_generation();
        tokio::time::advance(Duration::from_millis(50)).await;
        client.write_all(&control_request(9,[0x80,6,0,1,0,0,18,0])).await?;assert_eq!(wire_reply(&mut client).await?.0,9);assert!(!demand.has_changed()?);
        tokio::time::advance(Duration::from_millis(49)).await;assert!(*demand.borrow());assert!(!demand.has_changed()?);
        client.write_all(&submit(2,1,96,1)).await?;assert_eq!(wire_reply(&mut client).await?.0,2);tokio::task::yield_now().await;
        assert!(!demand.has_changed()?,"Natural refill restarted source epoch");assert_eq!(engine.lock().unwrap().stream_generation(),generation);
        engine.lock().unwrap().push_f32le(&0.5f32.to_le_bytes())?;
        tokio::time::advance(Duration::from_millis(101)).await;demand.changed().await?;assert!(!*demand.borrow_and_update());
        let mut microphone=engine.lock().unwrap();assert!(microphone.streaming());assert_ne!(microphone.stream_generation(),generation);let packet=microphone.isochronous(96,&[IsoPacket{offset:0,length:96}])?;assert!(packet.packed.iter().all(|value|*value==0));drop(microphone);
        cancel.cancel();task.await??;Ok(())
    }
    #[tokio::test(start_paused=true)]
    async fn last_unlink_stops_immediately_but_other_pending_iso_keeps_capture()->Result<()> {
        let(engine,streaming)=fixture();let mut demand=streaming.subscribe();let cancel=CancellationToken::new();let(server,mut client)=tokio::io::duplex(16384);
        let task=tokio::spawn(serve(server,engine.clone(),0xffff0001,streaming,cancel.clone()));
        client.write_all(&submit(1,1,384,4)).await?;demand.changed().await?;demand.borrow_and_update();
        client.write_all(&submit(2,1,384,4)).await?;
        client.write_all(&unlink_request(3,1)).await?;assert_eq!(wire_reply(&mut client).await?.1,-104);assert!(*demand.borrow());assert!(!demand.has_changed()?);
        let generation=engine.lock().unwrap().stream_generation();let start=Instant::now();
        client.write_all(&unlink_request(4,2)).await?;assert_eq!(wire_reply(&mut client).await?.1,-104);
        assert_eq!(start.elapsed(),Duration::ZERO);assert!(!*demand.borrow_and_update());assert_ne!(engine.lock().unwrap().stream_generation(),generation);
        cancel.cancel();task.await??;Ok(())
    }
    #[tokio::test(start_paused=true)]
    async fn revoke_stops_pending_capture_without_idle_grace()->Result<()> {
        let(engine,streaming)=fixture();let mut demand=streaming.subscribe();let cancel=CancellationToken::new();let(server,mut client)=tokio::io::duplex(16384);
        let task=tokio::spawn(serve(server,engine.clone(),0xffff0001,streaming,cancel.clone()));
        client.write_all(&submit(1,1,384,4)).await?;demand.changed().await?;assert!(*demand.borrow_and_update());
        let generation=engine.lock().unwrap().stream_generation();let now=Instant::now();cancel.cancel();task.await??;
        assert_eq!(now.elapsed(),Duration::ZERO);assert!(!*demand.borrow());assert!(!engine.lock().unwrap().streaming());assert_ne!(engine.lock().unwrap().stream_generation(),generation);Ok(())
    }
    #[tokio::test(start_paused=true)]
    async fn same_alt_reset_retires_capture_until_fresh_pending_and_samples_reject_old_generation()->Result<()> {
        let(engine,streaming)=fixture();let mut demand=streaming.subscribe();let cancel=CancellationToken::new();let(server,mut client)=tokio::io::duplex(16384);
        let task=tokio::spawn(serve(server,engine.clone(),0xffff0001,streaming,cancel.clone()));
        client.write_all(&submit(1,1,384,4)).await?;demand.changed().await?;demand.borrow_and_update();let old=engine.lock().unwrap().stream_generation();
        client.write_all(&control_request(2,[1,11,1,0,1,0,0,0])).await?;
        let mut replies=HashMap::new();for _ in 0..2 {let(sequence,status,_)=wire_reply(&mut client).await?;replies.insert(sequence,status);}
        assert_eq!(replies[&1],-108);assert_eq!(replies[&2],0);assert!(!*demand.borrow_and_update());assert_ne!(engine.lock().unwrap().stream_generation(),old);
        engine.lock().unwrap().push_f32le(&0.5f32.to_le_bytes())?;
        let clock=ReceiverClock::new(ReceiverHcd::LinuxVhci)?;
        assert!(matches!(clock.packet_at(Instant::now(),engine.clone(),96,IsoPacket{offset:0,length:96},old).await?,ScheduledSample::RetiredEpoch));
        client.write_all(&submit(3,1,96,1)).await?;demand.changed().await?;assert!(*demand.borrow_and_update());let(_,status,payload)=wire_reply(&mut client).await?;assert_eq!(status,0);assert!(payload[..96].iter().any(|value|*value!=0));
        cancel.cancel();task.await??;Ok(())
    }
    #[test]
    fn timing_histograms_are_bounded_and_quantiles_are_upper_bounds(){
        let mut stats=PrivateDistribution::default();
        assert_eq!(stats.percentile(99),0);
        for sample in 0..1000 {stats.add(sample)}
        assert_eq!(stats.count,1000);assert_eq!(stats.max_us,999);
        assert_eq!(stats.percentile(50),499);assert_eq!(stats.percentile(95),999);assert_eq!(stats.percentile(99),999);
        stats.add(u64::MAX);assert_eq!(stats.bins.len(),1002);assert_eq!(stats.max_us,u64::MAX);
    }
    async fn assert_ten_normalized_hcd_packets(hcd: ReceiverHcd) -> Result<(Duration, Duration)> {
        let (engine,streaming)=fixture();let cancel=CancellationToken::new();
        let _cancel_on_exit=cancel.clone().drop_guard();
        let (server,mut client)=tokio::io::duplex(16384);
        let task=tokio_util::task::AbortOnDropHandle::new(tokio::spawn(super::serve_for_hcd(server,engine,0xffff0001,streaming,cancel.clone(),hcd)));
        let (valid,foreign)=match hcd {ReceiverHcd::LinuxVhci=>(1,4),ReceiverHcd::WindowsUde=>(4,1)};
        let mut wrong=submit(1,1,960,10);wrong[36..40].copy_from_slice(&(foreign as u32).to_be_bytes());client.write_all(&wrong).await?;
        let mut header=[0;48];client.read_exact(&mut header).await?;assert_eq!(word(&header,20) as i32,-22);
        let mut rejected=[0;160];client.read_exact(&mut rejected).await?;
        let mut request=submit(2,1,960,10);request[36..40].copy_from_slice(&(valid as u32).to_be_bytes());
        let start=Instant::now();let wall_start=std::time::Instant::now();client.write_all(&request).await?;client.read_exact(&mut header).await?;
        let elapsed=(start.elapsed(),wall_start.elapsed());
        assert_eq!(word(&header,20),0);assert_eq!(word(&header,24),960);assert_eq!(word(&header,32),10);
        let mut payload=vec![1;1120];client.read_exact(&mut payload).await?;
        assert!(payload[..960].iter().all(|b|*b==0));
        for i in 0..10 {assert_eq!(word(&payload,960+i*16+8),96);assert_eq!(word(&payload,960+i*16+12),0);}
        cancel.cancel();task.await??;Ok(elapsed)
    }
    #[tokio::test(start_paused = true)]
    async fn local_hcd_normalizes_ten_windows_packets_without_relaxing_linux() -> Result<()> {
        // Windows UDE owns a real native timer, which intentionally does not
        // advance paused Tokio time. Its wire/clock integration is tested below.
        #[cfg(windows)] let portable=[ReceiverHcd::LinuxVhci];
        #[cfg(not(windows))] let portable=[ReceiverHcd::LinuxVhci,ReceiverHcd::WindowsUde];
        for hcd in portable {assert_eq!(assert_ten_normalized_hcd_packets(hcd).await?.0,Duration::from_millis(10));}
        for hcd in [ReceiverHcd::LinuxVhci,ReceiverHcd::WindowsUde] {
            for invalid in [0,2,3,5,8,u32::MAX] {assert!(!hcd.accepts_interval(invalid));}
        }
        Ok(())
    }
    #[cfg(windows)]
    #[tokio::test]
    async fn native_windows_hcd_normalizes_ten_packets_on_real_clock() -> Result<()> {
        let (_,wall)=tokio::time::timeout(Duration::from_secs(2),assert_ten_normalized_hcd_packets(ReceiverHcd::WindowsUde)).await??;
        assert!(wall>=Duration::from_millis(10),"Native UDE completed ten 1ms packets before their real deadline");
        assert!(wall<Duration::from_secs(2),"Native UDE exceeded the bounded test lifetime");
        Ok(())
    }
    #[tokio::test(start_paused = true)]
    async fn iso_is_paced_and_control_remains_responsive() -> Result<()> {
        let (engine, streaming) = fixture();
        let cancel = CancellationToken::new();
        let (server, mut client) = tokio::io::duplex(16384);
        let run = tokio::spawn(serve(
            server,
            engine.clone(),
            0xffff0001,
            streaming,
            cancel.clone(),
        ));
        client.write_all(&submit(1, 1, 384, 4)).await?;
        let mut control = submit(2, 0, 18, 0);
        control[40..48].copy_from_slice(&[0x80, 6, 0, 1, 0, 0, 18, 0]);
        client.write_all(&control).await?;
        let mut h = [0; 48];
        client.read_exact(&mut h).await?;
        assert_eq!(word(&h, 4), 2);
        assert_eq!(word(&h, 24), 18);
        let mut descriptor = [0; 18];
        client.read_exact(&mut descriptor).await?;
        assert_eq!(descriptor[0], 18);
        let start = Instant::now();
        client.read_exact(&mut h).await?;
        assert_eq!(word(&h, 4), 1);
        assert_eq!(word(&h, 24), 384);
        assert_eq!(word(&h, 32), 4);
        assert!(start.elapsed() >= Duration::from_millis(4));
        let mut payload = vec![1; 384 + 64];
        client.read_exact(&mut payload).await?;
        assert!(payload[..384].iter().all(|v| *v == 0));
        assert_eq!(word(&payload, 384 + 8), 96);
        assert_eq!(word(&payload, 384 + 12), 0);
        cancel.cancel();
        run.await??;
        assert!(!engine.lock().unwrap().streaming());
        Ok(())
    }
    #[tokio::test(start_paused = true)]
    async fn unlink_suppresses_late_submit_and_cancellation_stops_capture() -> Result<()> {
        let (engine, streaming) = fixture();
        let mut updates = streaming.subscribe();
        let cancel = CancellationToken::new();
        let (server, mut client) = tokio::io::duplex(16384);
        let run = tokio::spawn(serve(
            server,
            engine.clone(),
            0xffff0001,
            streaming,
            cancel.clone(),
        ));
        client.write_all(&submit(1, 1, 384, 4)).await?;
        let mut unlink = vec![0; 48];
        for (offset, value) in [(0, 2u32), (4, 2), (8, 0xffff0001), (20, 1)] {
            unlink[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        client.write_all(&unlink).await?;
        let mut h = [0; 48];
        client.read_exact(&mut h).await?;
        assert_eq!(word(&h, 0), 4);
        assert_eq!(word(&h, 20) as i32, -104);
        tokio::time::advance(Duration::from_millis(10)).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(1), client.read_exact(&mut h))
                .await
                .is_err()
        );
        cancel.cancel();
        run.await??;
        updates.changed().await?;
        assert!(!*updates.borrow());
        assert!(!engine.lock().unwrap().streaming());
        Ok(())
    }
    #[tokio::test(start_paused = true)]
    async fn alternate_stop_rejects_queued_old_stream_even_after_restart() -> Result<()> {
        let (engine, streaming) = fixture();
        let cancel = CancellationToken::new();
        let (server, mut client) = tokio::io::duplex(16384);
        let run = tokio::spawn(serve(server, engine, 0xffff0001, streaming, cancel.clone()));
        client.write_all(&submit(1, 1, 384, 4)).await?;
        for (seq, alt) in [(2, 0), (3, 1)] {
            let mut control = submit(seq, 0, 0, 0);
            control[12..16].fill(0);
            control[40..48].copy_from_slice(&[1, 11, alt, 0, 1, 0, 0, 0]);
            client.write_all(&control).await?;
        }
        let mut statuses = HashMap::new();
        for _ in 0..3 {
            let mut h = [0; 48];
            client.read_exact(&mut h).await?;
            let n = word(&h, 24) as usize + word(&h, 32) as usize * 16;
            let mut body = vec![0; n];
            client.read_exact(&mut body).await?;
            statuses.insert(word(&h, 4), word(&h, 20) as i32);
        }
        assert_eq!(statuses.get(&1), Some(&-108));
        assert_eq!(statuses.get(&2), Some(&0));
        assert_eq!(statuses.get(&3), Some(&0));
        cancel.cancel();
        run.await??;
        Ok(())
    }
    #[tokio::test(start_paused = true)]
    async fn same_alternate_reset_cannot_consume_new_pcm() -> Result<()> {
        let (engine, streaming) = fixture();
        let cancel = CancellationToken::new();
        let (server, mut client) = tokio::io::duplex(16384);
        let run = tokio::spawn(serve(
            server,
            engine.clone(),
            0xffff0001,
            streaming,
            cancel.clone(),
        ));
        client.write_all(&submit(1, 1, 96, 1)).await?;
        let mut control = submit(2, 0, 0, 0);
        control[12..16].fill(0);
        control[40..48].copy_from_slice(&[1, 11, 1, 0, 1, 0, 0, 0]);
        client.write_all(&control).await?;
        let mut h = [0; 48];
        client.read_exact(&mut h).await?;
        assert_eq!(word(&h, 4), 2);
        let pcm: Vec<u8> = (0..48).flat_map(|_| 0.5f32.to_le_bytes()).collect();
        engine.lock().unwrap().push_f32le(&pcm)?;
        client.write_all(&submit(3, 1, 96, 1)).await?;
        let mut statuses = HashMap::new();
        let mut new_pcm = vec![];
        for _ in 0..2 {
            client.read_exact(&mut h).await?;
            let size = word(&h, 24) as usize;
            let mut data = vec![0; size];
            client.read_exact(&mut data).await?;
            let mut descriptors = vec![0; word(&h, 32) as usize * 16];
            client.read_exact(&mut descriptors).await?;
            statuses.insert(word(&h, 4), word(&h, 20) as i32);
            if word(&h, 4) == 3 {
                new_pcm = data;
            }
        }
        assert_eq!(statuses.get(&1), Some(&-108));
        assert_eq!(statuses.get(&3), Some(&0));
        assert_eq!(new_pcm.len(), 96);
        assert!(new_pcm
            .chunks_exact(2)
            .all(|p| i16::from_le_bytes(p.try_into().unwrap()) > 16000));
        cancel.cancel();
        run.await??;
        Ok(())
    }
    #[tokio::test(start_paused = true)]
    async fn cancellation_preempts_a_blocked_reply() -> Result<()> {
        let (engine, streaming) = fixture();
        let cancel = CancellationToken::new();
        let (server, mut client) = tokio::io::duplex(1);
        let run = tokio::spawn(serve(
            server,
            engine.clone(),
            0xffff0001,
            streaming,
            cancel.clone(),
        ));
        let mut control = submit(2, 0, 18, 0);
        control[40..48].copy_from_slice(&[0x80, 6, 0, 1, 0, 0, 18, 0]);
        client.write_all(&control).await?;
        // Observe actual reply progress; a readonly EP0 request must not
        // notify capture demand merely to provide a test synchronization point.
        let mut first=[0;1];client.read_exact(&mut first).await?;
        let start = Instant::now();
        cancel.cancel();
        run.await??;
        assert_eq!(start.elapsed(), Duration::ZERO);
        assert!(!engine.lock().unwrap().streaming());
        Ok(())
    }
    #[tokio::test(start_paused = true)]
    async fn native_alsa_reused_frames_keep_receiver_clock_without_asap() -> Result<()> {
        let (engine, streaming) = fixture();
        let cancel = CancellationToken::new();
        let (server, mut client) = tokio::io::duplex(16384);
        let task = tokio::spawn(serve(server, engine, 0xffff0001, streaming, cancel.clone()));
        for (sequence, sender_frame) in [(1, 7u32), (2, 777u32)] {
            let mut request = submit(sequence, 1, 96, 1);
            request[20..24].copy_from_slice(&0x200u32.to_be_bytes());
            request[28..32].copy_from_slice(&sender_frame.to_be_bytes());
            let start = Instant::now();
            client.write_all(&request).await?;
            let mut header = [0; 48];
            client.read_exact(&mut header).await?;
            assert_eq!(word(&header, 20), 0);
            assert_eq!(word(&header, 24), 96);
            assert_ne!(word(&header, 28), sender_frame);
            assert!(word(&header, 28) < 10);
            assert!(
                start.elapsed() >= Duration::from_millis(1)
                    && start.elapsed() < Duration::from_millis(3)
            );
            let mut bytes = [1; 112];
            client.read_exact(&mut bytes).await?;
            assert!(bytes[..96].iter().all(|b| *b == 0));
        }
        cancel.cancel();
        task.await??;
        Ok(())
    }
    #[tokio::test(start_paused = true)]
    async fn overdue_iso_requests_keep_pcm_attached_to_their_frame_order() -> Result<()> {
        let (engine, streaming) = fixture();
        for group in 0..2 {
            let range = if group == 0 { 1..=20 } else { 21..=32 };
            let pcm: Vec<u8> = range
                .flat_map(|n| std::iter::repeat_n((n as f32 / 64.).to_le_bytes(), 48).flatten())
                .collect();
            engine.lock().unwrap().push_f32le(&pcm)?;
        }
        let cancel = CancellationToken::new();
        let (server, mut client) = tokio::io::duplex(16384);
        let task = tokio::spawn(serve(server, engine, 0xffff0001, streaming, cancel.clone()));
        for sequence in 1..=32 {
            client.write_all(&submit(sequence, 1, 96, 1)).await?;
        }
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        tokio::time::advance(Duration::from_millis(100)).await;
        for _ in 0..32 {
            let mut header = [0; 48];
            client.read_exact(&mut header).await?;
            let sequence = word(&header, 4);
            assert_eq!(word(&header, 20), 0);
            let mut bytes = [0; 112];
            client.read_exact(&mut bytes).await?;
            let actual = i16::from_le_bytes(bytes[..2].try_into().unwrap());
            let expected = (sequence as f32 / 64. * 32767.).round() as i16;
            assert!(
                (actual as i32 - expected as i32).abs() <= 1,
                "Frame{sequence} consumed another request's PCM:actual{actual} expected{expected}"
            );
        }
        cancel.cancel();
        task.await??;
        Ok(())
    }
    fn private_native_device(
    ) -> Result<(porthub_components::usb::Device, Vec<u8>, SharedMicrophone)> {
        let serial = format!(
            "PortHubPrivateUac{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        );
        let devnum = std::process::id() as u16;
        let devnum = devnum.max(1);
        let device = porthub_components::usb::Device {
            busid: format!("65535-{devnum}"),
            vendor: "1209".into(),
            product: "0001".into(),
            serial: serial.clone(),
            name: "PortHub private synthetic silence test".into(),
            busnum: 65535,
            devnum,
            speed: 2,
            blocked: None,
        };
        let mut wire = vec![0; 312];
        wire[..7].copy_from_slice(b"porthub");
        wire[256..256 + device.busid.len()].copy_from_slice(device.busid.as_bytes());
        for (offset, value) in [(288, 65535u32), (292, devnum as u32), (296, 2)] {
            wire[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        wire[300..302].copy_from_slice(&0x1209u16.to_be_bytes());
        wire[302..304].copy_from_slice(&1u16.to_be_bytes());
        wire[304..306].copy_from_slice(&0x100u16.to_be_bytes());
        wire[309] = 1;
        wire[310] = 1;
        wire[311] = 2;
        let engine = Arc::new(Mutex::new(Microphone::new(
            Identity {
                vendor: 0x1209,
                product: 1,
            },
            serial.clone(),
        )?));
        Ok((device, wire, engine))
    }
    /// Private PID1209:0001 is reserved for in-house testing only, not distribution.
    /// https://pid.codes/1209/0001/ -- this never opens a physical microphone.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "Requires explicitly authorized root VHCI/ALSA class-driver test"]
    async fn native_linux_receiver_class_driver_synthetic_silence() -> Result<()> {
        use anyhow::Context;
        use std::path::{Path, PathBuf};
        ensure!(
            std::env::var("PORTHUB_PRIVATE_UAC_CLASS_TEST").as_deref() == Ok("1"),
            "Explicit private UAC test authorization required"
        );
        ensure!(
            rustix::process::geteuid().is_root(),
            "Native receiver class test requires root"
        );
        let profile = PathBuf::from(std::env::var("PORTHUB_PRIVATE_UAC_PROFILE")?);
        ensure!(
            profile.is_absolute(),
            "Explicit absolute registration path required"
        );
        let (device, wire, engine) = private_native_device()?;
        let serial = device.serial.clone();
        let devnum = device.devnum;
        let (receiver, stream) = crate::usb::attach_virtual(&profile, &device, &wire).await?;
        let cancel = CancellationToken::new();
        let (streaming, _) = watch::channel(false);
        let worker_engine = engine.clone();
        let worker_cancel = cancel.clone();
        let task = AbortOnDropHandle::new(tokio::spawn(async move {
            let result = serve(
                stream,
                worker_engine,
                0xffff0000 | devnum as u32,
                streaming,
                worker_cancel,
            )
            .await;
            if let Err(error) = &result {
                eprintln!("PRIVATE_UAC_EXECUTOR_ERROR {error:#}");
            }
            result
        }));
        let (usb, card) = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                for entry in std::fs::read_dir("/sys/bus/usb/devices")?.flatten() {
                    let p = entry.path();
                    if std::fs::read_to_string(p.join("serial"))
                        .unwrap_or_default()
                        .trim()
                        != serial
                    {
                        continue;
                    }
                    let real = p.canonicalize()?;
                    ensure!(
                        real.to_string_lossy().contains("vhci_hcd"),
                        "Test microphone is not receiver-local VHCI"
                    );
                    ensure!(
                        std::fs::read_to_string(p.join("idVendor"))?.trim() == "1209"
                            && std::fs::read_to_string(p.join("idProduct"))?.trim() == "0001",
                        "Test descriptor identity changed"
                    );
                    for card in std::fs::read_dir("/sys/class/sound")?.flatten() {
                        let name = card.file_name().to_string_lossy().into_owned();
                        let Some(number) = name
                            .strip_prefix("card")
                            .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
                        else {
                            continue;
                        };
                        if card
                            .path()
                            .join("device")
                            .canonicalize()
                            .is_ok_and(|p| p.starts_with(&real))
                            && Path::new(&format!("/dev/snd/pcmC{number}D0c")).exists()
                        {
                            return Ok::<_, anyhow::Error>((p, number.to_owned()));
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .context("Virtual UAC1 driver did not enumerate an ALSA capture endpoint")??;
        ensure!(
            Path::new(&format!("/sys/class/sound/card{card}/device"))
                .canonicalize()?
                .starts_with(usb.canonicalize()?),
            "ALSA target identity changed before test"
        );
        println!(
            "PRIVATE_UAC_CLASS_ENDPOINT serial={serial} usb={} card={card}",
            usb.display()
        );
        let iso_errors_before = PRIVATE_ISO_ERRORS.load(std::sync::atomic::Ordering::Relaxed);
        let capture_started = Instant::now();
        let mut capture = tokio::process::Command::new("arecord")
            .args([
                "-q",
                "-D",
                &format!("hw:{card},0"),
                "-t",
                "raw",
                "-f",
                "S16_LE",
                "-r",
                "48000",
                "-c",
                "1",
                "-d",
                "3",
                "-",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let mut output = capture
            .stdout
            .take()
            .context("Explicit ALSA stdout unavailable")?;
        let mut bytes = Vec::new();
        let mut first_data = None;
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut first = [0u8; 4096];
            let count = output.read(&mut first).await?;
            if count > 0 {
                first_data = Some(capture_started.elapsed());
                bytes.extend_from_slice(&first[..count]);
            }
            output
                .take((288001 - bytes.len()) as u64)
                .read_to_end(&mut bytes)
                .await?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("Owned ALSA capture timed out")??;
        let status = capture.wait().await?;
        if !status.success() {
            let mut error = String::new();
            if let Some(stderr) = capture.stderr.take() {
                stderr.take(8192).read_to_string(&mut error).await?;
            }
            anyhow::bail!("Owned ALSA capture failed: {error}");
        }
        ensure!(
            bytes.len() == 288000 && bytes.iter().all(|b| *b == 0),
            "Native class capture did not deliver exactly3s48kHz monoS16 synthetic silence"
        );
        let iso_errors =
            PRIVATE_ISO_ERRORS.load(std::sync::atomic::Ordering::Relaxed) - iso_errors_before;
        ensure!(
            iso_errors == 0,
            "Native class capture encountered {iso_errors} rejected ISO submissions"
        );
        let wall = capture_started.elapsed();
        ensure!(
            wall >= Duration::from_millis(2500) && wall <= Duration::from_millis(4500),
            "Three-second native capture clock drifted: {wall:?}"
        );
        println!(
            "PRIVATE_UAC_CLASS_CLOCK wall_ms={} first_data_ms={} iso_rejected=0",
            wall.as_millis(),
            first_data.unwrap_or_default().as_millis()
        );
        let samples = engine.lock().unwrap().underrun_samples;
        ensure!(
            samples >= 144000,
            "Synthetic microphone clock did not produce the capture samples"
        );
        cancel.cancel();
        task.await??;
        drop(receiver);
        tokio::time::timeout(Duration::from_secs(5), async {
            while usb.exists() {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .context("Owned VHCI test endpoint did not detach")?;
        println!(
            "PRIVATE_UAC_CLASS_PASS bytes={} samples={} driver=snd-usb-audio detached=true",
            bytes.len(),
            bytes.len() / 2
        );
        Ok(())
    }
    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "Explicit Windows timer-only diagnostic; no USB, COM, audio or global timer changes"]
    async fn native_windows_timer_only_no_usb_or_audio() -> Result<()> {
        ensure!(std::env::var("PORTHUB_PRIVATE_TIMER_TEST").as_deref()==Ok("1"),"Explicit timer diagnostic required");
        for period_ms in [1u64,10] {
            let mut late=PrivateDistribution::default();let mut gaps=PrivateDistribution::default();
            let origin=Instant::now();let mut previous=origin;
            for index in 1..=100 {let due=origin+Duration::from_millis(period_ms*index);tokio::time::sleep_until(due).await;let now=Instant::now();late.add(now.saturating_duration_since(due).as_micros() as u64);gaps.add(now.saturating_duration_since(previous).as_micros() as u64);previous=now;}
            println!("PRIVATE_TIMER_ONLY {}",serde_json::json!({"clock":"tokio","period_ms":period_ms,"elapsed_us":origin.elapsed().as_micros(),"lateness":late.json(),"gap":gaps.json()}));
            let result=tokio::task::spawn_blocking(move || ->Result<serde_json::Value>{
                use windows_sys::Win32::{Foundation::{CloseHandle,WAIT_OBJECT_0},System::Threading::{CreateWaitableTimerExW,SetWaitableTimerEx,WaitForSingleObject,CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,TIMER_MODIFY_STATE,SYNCHRONIZATION_SYNCHRONIZE}};
                // Per-handle one-shot timer; no timeBeginPeriod/global power settings.
                // https://learn.microsoft.com/windows/win32/api/synchapi/nf-synchapi-createwaitabletimerexw
                // https://learn.microsoft.com/windows/win32/api/synchapi/nf-synchapi-setwaitabletimerex
                let handle=unsafe{CreateWaitableTimerExW(std::ptr::null(),std::ptr::null(),CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,TIMER_MODIFY_STATE|SYNCHRONIZATION_SYNCHRONIZE)};
                ensure!(!handle.is_null(),"Create high-resolution timer: {}",std::io::Error::last_os_error());
                struct Timer(windows_sys::Win32::Foundation::HANDLE);impl Drop for Timer{fn drop(&mut self){unsafe{CloseHandle(self.0);}}}
                let timer=Timer(handle);let origin=std::time::Instant::now();let mut previous=origin;let mut late=PrivateDistribution::default();let mut gaps=PrivateDistribution::default();
                for index in 1..=100 {let due=origin+Duration::from_millis(period_ms*index);let remaining=due.saturating_duration_since(std::time::Instant::now());
                    if !remaining.is_zero(){let ticks=-((remaining.as_nanos().div_ceil(100)).min(i64::MAX as u128) as i64).max(1);
                        ensure!(unsafe{SetWaitableTimerEx(timer.0,&ticks,0,None,std::ptr::null(),std::ptr::null(),0)}!=0,"Set private high-resolution timer: {}",std::io::Error::last_os_error());
                        ensure!(unsafe{WaitForSingleObject(timer.0,100)}==WAIT_OBJECT_0,"Private high-resolution timer timeout/failure");}
                    let now=std::time::Instant::now();late.add(now.saturating_duration_since(due).as_micros() as u64);gaps.add(now.saturating_duration_since(previous).as_micros() as u64);previous=now;
                }
                Ok(serde_json::json!({"clock":"private_high_resolution_waitable","period_ms":period_ms,"elapsed_us":origin.elapsed().as_micros(),"lateness":late.json(),"gap":gaps.json()}))
            }).await??;
            println!("PRIVATE_TIMER_ONLY {result}");
            let clock=Arc::new(native_clock::Clock::new()?);let origin=Instant::now();let mut previous=origin;
            let mut late=PrivateDistribution::default();let mut gaps=PrivateDistribution::default();
            for index in 1..=100 {let due=origin+Duration::from_millis(period_ms*index);clock.wait_until(due.into_std()).await?;let now=Instant::now();late.add(now.saturating_duration_since(due).as_micros() as u64);gaps.add(now.saturating_duration_since(previous).as_micros() as u64);previous=now;}
            println!("PRIVATE_TIMER_ONLY {}",serde_json::json!({"clock":"receiver_native_scheduler","period_ms":period_ms,"elapsed_us":origin.elapsed().as_micros(),"lateness":late.json(),"gap":gaps.json()}));
            drop(clock);

        }
        let clock=Arc::new(native_clock::Clock::new()?);let order=Arc::new(Mutex::new(Vec::new()));let origin=std::time::Instant::now();
        let first_clock=clock.clone();let first_order=order.clone();let (attempted,ready)=tokio::sync::oneshot::channel();let mut attempted=Some(attempted);let mut attempts=0;
        let first=tokio::spawn(async move{first_clock.run_at(origin,move||{attempts+=1;if let Some(attempted)=attempted.take(){let _=attempted.send(());}if attempts<3{return Ok(None)}first_order.lock().unwrap().push(1);Ok(Some(()))}).await});
        tokio::time::timeout(Duration::from_secs(1),ready).await??;
        let second_clock=clock.clone();let second_order=order.clone();
        let second=tokio::spawn(async move{second_clock.run_at(origin+Duration::from_millis(1),move||{second_order.lock().unwrap().push(2);Ok(Some(()))}).await});
        first.await??;second.await??;ensure!(*order.lock().unwrap()==vec![1,2],"Overdue native transfers reordered PCM assignment");drop(clock);
        let clock=Arc::new(native_clock::Clock::new()?);let mut queued=Vec::new();
        for _ in 0..MAX_PENDING {let borrowed=clock.clone();queued.push(tokio::spawn(async move{borrowed.wait_until(std::time::Instant::now()+Duration::from_secs(30)).await}));}
        let fill=std::time::Instant::now();while clock.available()!=0{ensure!(fill.elapsed()<Duration::from_secs(1),"Combined clock queue did not fill");tokio::task::yield_now().await;}
        ensure!(clock.wait_until(std::time::Instant::now()).await.is_err(),"Combined channel/pending bound exceeded");
        for task in &queued{task.abort();}for task in queued{let _=task.await;}
        let prune=std::time::Instant::now();while clock.available()!=MAX_PENDING{ensure!(prune.elapsed()<Duration::from_millis(500),"Cancellation did not wake and prune scheduler");tokio::time::sleep(Duration::from_millis(1)).await;}
        let prune_us=prune.elapsed().as_micros();drop(clock);
        let gate=Arc::new(Mutex::new(()));let held=gate.lock().unwrap();let borrowed_gate=gate.clone();
        let clock=Arc::new(native_clock::Clock::new()?);let borrowed=clock.clone();let (started,ready)=tokio::sync::oneshot::channel();let mut started=Some(started);
        let pending=tokio::spawn(async move{borrowed.run_at(std::time::Instant::now(),move||{if let Some(started)=started.take(){let _=started.send(());}match borrowed_gate.try_lock(){Ok(_)=>Ok(Some(())),Err(std::sync::TryLockError::WouldBlock)=>Ok(None),Err(_)=>anyhow::bail!("Poisoned fixture gate")}}).await});
        tokio::time::timeout(Duration::from_secs(1),ready).await??;pending.abort();let _=pending.await;
        let stopped=std::time::Instant::now();drop(clock);
        ensure!(stopped.elapsed()<Duration::from_millis(500),"Native clock blocked on contended callback during stop");
        let stop_us=stopped.elapsed().as_micros();drop(held);
        println!("PRIVATE_TIMER_STOP {}",serde_json::json!({"drop_us":stop_us,"prune_us":prune_us,"combined_bound":MAX_PENDING,"cancelled_without_clock_drop":true,"stop_while_mutex_held":true}));
        Ok(())
    }
    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "Requires explicitly authorized UDE synthetic receiver and exact-identity WASAPI consumer"]
    async fn native_windows_receiver_class_driver_synthetic_silence() -> Result<()> {
        use anyhow::Context;
        ensure!(
            std::env::var("PORTHUB_PRIVATE_UAC_CLASS_TEST").as_deref() == Ok("1"),
            "Explicit private UAC test authorization required"
        );
        crate::service::require_administrator()?;
        let profile = std::path::PathBuf::from(std::env::var("PORTHUB_PRIVATE_UAC_PROFILE")?);
        ensure!(profile.is_absolute(), "Explicit registration path required");
        let (device, wire, engine) = private_native_device()?;
        let (mut receiver, stream) = crate::usb::attach_virtual(&profile, &device, &wire).await?;
        let cancel = CancellationToken::new();
        let (streaming, _) = watch::channel(false);
        let worker_engine = engine.clone();
        let worker_cancel = cancel.clone();
        let devid = 0xffff0000 | device.devnum as u32;
        let task = AbortOnDropHandle::new(tokio::spawn(async move {
            let result = super::serve(stream, worker_engine, devid, streaming, worker_cancel).await;
            if let Err(error) = &result {
                eprintln!("PRIVATE_UAC_EXECUTOR_ERROR {error:#}");
            }
            result
        }));
        let folder = tempfile::Builder::new()
            .prefix("PortHubPrivateUacProof-")
            .tempdir()?;
        let result_file = folder.path().join("consumer-result.json");
        let before = PRIVATE_ISO_ERRORS.load(std::sync::atomic::Ordering::Relaxed);
        println!(
            "PRIVATE_WINDOWS_UAC_READY {}",
            serde_json::json!({"serial":device.serial,"vendor":"1209","product":"0001","result_file":result_file,"deadline_seconds":35})
        );
        let result = {
            let failure = receiver.failed();
            tokio::pin!(failure);
            tokio::time::timeout(Duration::from_secs(35),async {
                loop {
                    if result_file.exists(){
                        let metadata=std::fs::symlink_metadata(&result_file)?;
                        ensure!(metadata.is_file()&&!metadata.file_type().is_symlink()&&metadata.len()<=8192,"Invalid bounded consumer result file");
                        return Ok::<_,anyhow::Error>(serde_json::from_slice::<serde_json::Value>(&std::fs::read(&result_file)?)?);
                    }
                    tokio::select!{result=&mut failure=>{result?;anyhow::bail!("Owned UDE receiver failed")},_=tokio::time::sleep(Duration::from_millis(50))=>{}}
                }
            }).await.context("Exact-identity Windows consumer did not finish within35s")??
        };
        ensure!(
            result["serial"].as_str() == Some(device.serial.as_str())
                && result["identity_verified"] == true,
            "Consumer did not prove the exact owned virtual USB endpoint"
        );
        ensure!(
            result["default_unchanged"] == true,
            "Audio defaults changed during the owned fixture"
        );
        let samples = result["samples"]
            .as_u64()
            .context("Consumer sample count missing")?;
        ensure!(
            (144000..=145920).contains(&samples) && result["nonzero_samples"].as_u64() == Some(0),
            "Consumer did not capture three seconds of synthetic silence"
        );
        let elapsed = result["elapsed_ms"]
            .as_u64()
            .context("Consumer walltime missing")?;
        ensure!(
            (2500..=4500).contains(&elapsed),
            "Native Windows sample clock drifted"
        );
        ensure!(
            PRIVATE_ISO_ERRORS.load(std::sync::atomic::Ordering::Relaxed) == before,
            "Native UDE capture rejected ISO submissions"
        );
        ensure!(
            engine.lock().unwrap().underrun_samples >= samples,
            "Native USB class consumer did not pull the expected samples"
        );
        cancel.cancel();
        task.await??;
        drop(receiver);
        println!("PRIVATE_WINDOWS_UAC_PASS samples={samples} wall_ms={elapsed} iso_rejected=0 synthetic=true");
        Ok(())
    }
    #[tokio::test]
    async fn invalid_device_and_packet_bounds_fail_closed() -> Result<()> {
        for invalid in [0, 1] {
            let (mut tx, mut rx) = tokio::io::duplex(2048);
            let mut request = submit(1, 1, 96, 1);
            if invalid == 0 {
                request[8..12].copy_from_slice(&1u32.to_be_bytes());
            } else {
                request[52..56].copy_from_slice(&98u32.to_be_bytes());
            }
            tx.write_all(&request).await?;
            assert!(
                read(&mut rx, 0xffff0001, Arc::new(Semaphore::new(MAX_BYTES)))
                    .await
                    .is_err()
            );
        }
        Ok(())
    }
}
