//! Receiver-local, already-imported UVC bulk/control USB/IP executor.
//! No listener or source-camera access. The caller authenticates MediaReceive,
//! binds the explicit device identity, and owns the native attachment lifetime.
use super::usb_video::{BULK_ENDPOINT, Camera, STATUS_ENDPOINT};
use anyhow::{Result, ensure};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, watch},
};
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
const MAX_TRANSFER: usize = 65536;
const MAX_PENDING: usize = 32;
const MAX_BUFFERED: usize = 1024 * 1024;
pub type SharedCamera = Arc<Mutex<Camera>>;
/// A generation change requires a fresh source epoch even if watch delivery coalesces.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CaptureDemand {
    pub active: bool,
    pub generation: u64,
}
struct Request {
    sequence: u32,
    input: bool,
    endpoint: u32,
    length: usize,
    setup: [u8; 8],
    data: Vec<u8>,
    _bytes: OwnedSemaphorePermit,
    _slot: OwnedSemaphorePermit,
}
enum Command {
    Submit(Request),
    Unlink { sequence: u32, target: u32 },
}
fn word(b: &[u8], n: usize) -> u32 {
    u32::from_be_bytes(b[n..n + 4].try_into().unwrap())
}
async fn read<R: AsyncRead + Unpin>(
    r: &mut R,
    devid: u32,
    bytes: Arc<Semaphore>,
    slots: Arc<Semaphore>,
) -> Result<Command> {
    let mut h = [0; 48];
    r.read_exact(&mut h).await?;
    ensure!(
        word(&h, 8) == devid && word(&h, 12) <= 1 && word(&h, 16) <= 15,
        "Invalid video USB identity or endpoint"
    );
    if word(&h, 0) == 2 {
        ensure!(word(&h, 16) == 0, "Invalid video unlink endpoint");
        return Ok(Command::Unlink {
            sequence: word(&h, 4),
            target: word(&h, 20),
        });
    }
    ensure!(word(&h, 0) == 1, "Unsupported video USB command");
    let length = word(&h, 24) as usize;
    ensure!(
        length <= MAX_TRANSFER && [0, u32::MAX].contains(&word(&h, 32)),
        "Video USB transfer exceeds bounds or requests ISO"
    );
    let input = word(&h, 12) == 1;
    let endpoint = word(&h, 16);
    let setup = h[40..48].try_into().unwrap();
    if endpoint == 0 {
        ensure!(
            input == (h[40] & 0x80 != 0) && length == u16::from_le_bytes([h[46], h[47]]) as usize,
            "Video control direction/length mismatch"
        );
    } else {
        ensure!(h[40..48] == [0; 8], "Setup packet on video data endpoint");
    }
    let slot = slots.try_acquire_owned()?;
    let permit = bytes.try_acquire_many_owned(length.max(1) as u32)?;
    let mut data = if input { vec![] } else { vec![0; length] };
    r.read_exact(&mut data).await?;
    Ok(Command::Submit(Request {
        sequence: word(&h, 4),
        input,
        endpoint,
        length,
        setup,
        data,
        _bytes: permit,
        _slot: slot,
    }))
}
async fn reply<W: AsyncWrite + Unpin>(
    w: &mut W,
    command: u32,
    sequence: u32,
    status: i32,
    data: &[u8],
    actual: usize,
) -> Result<()> {
    ensure!(
        data.len() <= MAX_TRANSFER && actual <= MAX_TRANSFER,
        "Video completion exceeds bounds"
    );
    let mut h = [0; 48];
    h[..4].copy_from_slice(&command.to_be_bytes());
    h[4..8].copy_from_slice(&sequence.to_be_bytes());
    h[20..24].copy_from_slice(&status.to_be_bytes());
    if command == 3 {
        h[24..28].copy_from_slice(&(actual as u32).to_be_bytes());
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        w.write_all(&h).await?;
        w.write_all(data).await?;
        w.flush().await
    })
    .await??;
    Ok(())
}
struct Stop(SharedCamera, watch::Sender<CaptureDemand>);
impl Drop for Stop {
    fn drop(&mut self) {
        if let Ok(mut c) = self.0.lock() {
            c.stop();
        }
        self.1.send_modify(|d| d.active = false);
    }
}
/// `changed` must be notified after a source frame or epoch change. Empty queues
/// wait; they do not emit invented images or successful empty-frame completions.
/// Cancellation drops all queued requests and closes this receiver-local stream.
pub async fn serve<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    camera: SharedCamera,
    devid: u32,
    changed: Arc<Notify>,
    streaming: watch::Sender<CaptureDemand>,
    cancel: CancellationToken,
) -> Result<()> {
    ensure!(
        devid >> 16 == 65535 && devid & 65535 != 0,
        "Video device must use receiver-local namespace"
    );
    let _stop = Stop(camera.clone(), streaming.clone());
    tokio::select! {biased;_=cancel.cancelled()=>Ok(()),r=run(stream,camera,devid,changed,streaming)=>r}
}
async fn run<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    camera: SharedCamera,
    devid: u32,
    changed: Arc<Notify>,
    streaming: watch::Sender<CaptureDemand>,
) -> Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::channel(MAX_PENDING);
    let bytes = Arc::new(Semaphore::new(MAX_BUFFERED));
    let slots = Arc::new(Semaphore::new(MAX_PENDING));
    let _reader = AbortOnDropHandle::new(tokio::spawn(async move {
        loop {
            let command = read(&mut reader, devid, bytes.clone(), slots.clone()).await;
            let failed = command.is_err();
            if tx.send(command).await.is_err() || failed {
                break;
            }
        }
    }));
    let mut pending = VecDeque::<Request>::new();
    let mut generation = 0u64;
    let mut previous = false;
    let mut idle_deadline = None;
    let mut explicit_idle = false;
    loop {
        // Bulk requests execute in arrival order. No per-URB tasks can reorder
        // payload fragments, race an epoch transition, or outlive UNLINK.
        while let Some(at) = pending
            .iter()
            .position(|r| r.endpoint == (BULK_ENDPOINT & 15) as u32)
        {
            let result = camera
                .lock()
                .map_err(|_| anyhow::anyhow!("Video engine poisoned"))?
                .bulk_in(pending[at].length);
            let (status, data) = match result {
                Ok(Some(data)) => (0, data),
                Ok(None) => break,
                Err(status) => (status, vec![]),
            };
            let request = pending.remove(at).unwrap();
            reply(&mut writer, 3, request.sequence, status, &data, data.len()).await?;
        }
        if let Some(at) = pending
            .iter()
            .position(|r| r.endpoint == u32::from(STATUS_ENDPOINT & 15))
        {
            let status = camera
                .lock()
                .map_err(|_| anyhow::anyhow!("Video engine poisoned"))?
                .interrupt_status();
            if let Err(status) = status {
                let request = pending.remove(at).unwrap();
                reply(&mut writer, 3, request.sequence, status, &[], 0).await?;
                continue;
            }
        }
        let eligible = pending
            .iter()
            .any(|r| r.endpoint == u32::from(BULK_ENDPOINT & 15));
        let committed = camera
            .lock()
            .map_err(|_| anyhow::anyhow!("Video engine poisoned"))?
            .streaming();
        let demand = if eligible && committed {
            idle_deadline = None;
            true
        } else if previous && committed && !explicit_idle {
            let deadline = *idle_deadline
                .get_or_insert_with(|| tokio::time::Instant::now() + Duration::from_millis(100));
            tokio::time::Instant::now() < deadline
        } else {
            idle_deadline = None;
            false
        };
        explicit_idle = false;
        if previous && !demand {
            camera
                .lock()
                .map_err(|_| anyhow::anyhow!("Video engine poisoned"))?
                .end_epoch();
            idle_deadline = None;
        }
        if demand && !previous {
            generation = generation
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("Video demand generation exhausted"))?;
        }
        previous = demand;
        streaming.send_if_modified(|value| { let next=CaptureDemand{active:demand,generation}; if *value==next {false} else {*value=next;true} });
        tokio::select! {
            _=changed.notified()=>{},
            _=tokio::time::sleep_until(idle_deadline.unwrap_or_else(||tokio::time::Instant::now()+Duration::from_secs(3600))),if idle_deadline.is_some()=>{},
            command=rx.recv()=>{let Some(command)=command else{return Ok(());};match command?{
                Command::Unlink{sequence,target}=>{let status=if let Some(at)=pending.iter().position(|r|r.sequence==target){let removed=pending.remove(at).unwrap();if removed.endpoint==u32::from(BULK_ENDPOINT&15)&&!pending.iter().any(|r|r.endpoint==u32::from(BULK_ENDPOINT&15)){explicit_idle=true;}-104}else{0};reply(&mut writer,4,sequence,status,&[],0).await?;},
                Command::Submit(request)=>{
                    ensure!(!pending.iter().any(|r|r.sequence==request.sequence),"Duplicate pending video sequence");
                    if request.endpoint==0{
                        let(result,was_active,active)={let mut c=camera.lock().map_err(|_|anyhow::anyhow!("Video engine poisoned"))?;let was=c.streaming();let result=c.control(request.setup,&request.data);(result,was,c.streaming())};
                        let reset=result.is_ok()&&((request.setup[0]==0&&request.setup[1]==9)||(request.setup[0]==1&&request.setup[1]==11)||(request.setup[0]==0x21&&request.setup[1]==1&&request.setup[2..6]==[0,2,1,0]));
                        if (was_active&&!active)||reset{idle_deadline=None;previous=false;streaming.send_if_modified(|value|{let next=CaptureDemand{active:false,generation};if *value==next{false}else{*value=next;true}});while let Some(old)=pending.pop_front(){reply(&mut writer,3,old.sequence,-108,&[],0).await?;}}
                        let(status,data)=match result{Ok(data)=>(0,data),Err(status)=>(status,vec![])};ensure!(data.len()<=request.length,"Video control reply exceeds buffer");
                        let actual=if status!=0{0}else if request.input{data.len()}else{request.data.len()};reply(&mut writer,3,request.sequence,status,if request.input{&data}else{&[]},actual).await?;
                    }else if request.input&&[u32::from(BULK_ENDPOINT&15),u32::from(STATUS_ENDPOINT&15)].contains(&request.endpoint){ensure!(pending.len()<MAX_PENDING,"Video request queue full");pending.push_back(request);}
                    else{reply(&mut writer,3,request.sequence,-32,&[],0).await?;}
                }
            }}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::usb_video::Identity;
    use super::*;
    use porthub_components::media::{VideoEncoding, VideoFormat, VideoFrame};
    const DEVID: u32 = 0xffff0001;
    const E: &str = "11111111111111111111111111111111";
    fn header(command: u32, seq: u32, ep: u32, input: bool, n: usize) -> Vec<u8> {
        let mut h = vec![0; 48];
        for (i, v) in [
            (0, command),
            (4, seq),
            (8, DEVID),
            (12, u32::from(input)),
            (16, ep),
            (24, n as u32),
        ] {
            h[i..i + 4].copy_from_slice(&v.to_be_bytes());
        }
        h
    }
    fn frame() -> VideoFrame {
        VideoFrame {
            sequence: 1,
            source_monotonic_micros: 1,
            format: VideoFormat {
                encoding: VideoEncoding::Mjpeg,
                width: 640,
                height: 480,
                fps_num: 15,
                fps_den: 1,
            },
            jpeg: vec![
                255, 216, 255, 192, 0, 17, 8, 1, 224, 2, 128, 3, 1, 17, 0, 2, 17, 0, 3, 17, 0, 255,
                217,
            ],
        }
    }
    fn engine() -> SharedCamera {
        let mut c = Camera::new(
            Identity {
                vendor: 0x1209,
                product: 1,
            },
            "WireVideo01".into(),
        )
        .unwrap();
        c.control([0, 9, 1, 0, 0, 0, 0, 0], &[]).unwrap();
        let mut p = [0; 34];
        p[2] = 1;
        p[3] = 1;
        p[4..8].copy_from_slice(&666666u32.to_le_bytes());
        c.control([0x21, 1, 0, 2, 1, 0, 34, 0], &p).unwrap();
        c.begin_epoch(E).unwrap();
        Arc::new(Mutex::new(c))
    }
    async fn response(c: &mut tokio::io::DuplexStream) -> (u32, u32, i32, Vec<u8>) {
        let mut h = [0; 48];
        tokio::time::timeout(Duration::from_secs(1), c.read_exact(&mut h))
            .await
            .unwrap()
            .unwrap();
        let mut b = vec![0; word(&h, 24) as usize];
        c.read_exact(&mut b).await.unwrap();
        (word(&h, 0), word(&h, 4), word(&h, 20) as i32, b)
    }
    #[tokio::test]
    async fn windows_bulk_commit_then_alt_zero_starts_fresh_capture_generation()->Result<()> {
        let mut engine=Camera::new(Identity{vendor:0x1209,product:1},"WindowsBulkAlt0".into())?;engine.control([0,9,1,0,0,0,0,0],&[]).unwrap();
        let camera=Arc::new(Mutex::new(engine));let changed=Arc::new(Notify::new());let cancel=CancellationToken::new();let(s,mut c)=tokio::io::duplex(4096);let(demand,mut observed)=watch::channel(CaptureDemand::default());
        let task=tokio::spawn(serve(s,camera.clone(),DEVID,changed.clone(),demand,cancel.clone()));
        let mut commit=header(1,58,0,false,34);commit[40..48].copy_from_slice(&[0x21,1,0,2,1,0,34,0]);let mut parameters=[0;34];parameters[2]=1;parameters[3]=1;parameters[4..8].copy_from_slice(&666666u32.to_le_bytes());commit.extend(parameters);c.write_all(&commit).await?;let mut completion=[0;48];tokio::time::timeout(Duration::from_secs(1),c.read_exact(&mut completion)).await??;assert_eq!((word(&completion,4),word(&completion,20),word(&completion,24)),(58,0,34)); // OUT completion has no response body.
        let mut alt=header(1,60,0,false,0);alt[40..48].copy_from_slice(&[1,11,0,0,1,0,0,0]);c.write_all(&alt).await?;let r=response(&mut c).await;assert_eq!((r.1,r.2),(60,0));assert!(camera.lock().unwrap().streaming());assert!(!observed.borrow_and_update().active);
        c.write_all(&header(1,62,1,true,16384)).await?;tokio::time::timeout(Duration::from_secs(1),observed.changed()).await??;let first=*observed.borrow_and_update();assert!(first.active);
        camera.lock().unwrap().begin_epoch(E)?;camera.lock().unwrap().push(E,frame())?;changed.notify_one();let r=response(&mut c).await;assert_eq!((r.1,r.2,r.3.len()),(62,0,25));
        c.write_all(&header(1,64,1,true,16384)).await?;alt[4..8].copy_from_slice(&66u32.to_be_bytes());c.write_all(&alt).await?;let r=response(&mut c).await;assert_eq!((r.1,r.2),(64,-108));let r=response(&mut c).await;assert_eq!((r.1,r.2),(66,0));assert!(!camera.lock().unwrap().push(E,frame())?);assert!(camera.lock().unwrap().begin_epoch(E).is_err());
        observed.borrow_and_update();c.write_all(&header(1,68,1,true,16384)).await?;tokio::time::timeout(Duration::from_secs(1),observed.changed()).await??;let fresh=*observed.borrow_and_update();assert!(fresh.active&&fresh.generation>first.generation);
        let nonce="cccccccccccccccccccccccccccccccc";camera.lock().unwrap().begin_epoch(nonce)?;camera.lock().unwrap().push(nonce,frame())?;changed.notify_one();let r=response(&mut c).await;assert_eq!((r.1,r.2,r.3.len()),(68,0,25));cancel.cancel();task.await??;Ok(())
    }
    #[tokio::test]
    async fn readonly_precommit_controls_preserve_status_without_capture_demand()->Result<()> {
        let mut engine=Camera::new(Identity{vendor:0x1209,product:1},"PrecommitStatus".into())?;
        engine.control([0,9,1,0,0,0,0,0],&[]).unwrap();
        let camera=Arc::new(Mutex::new(engine));let cancel=CancellationToken::new();let(s,mut c)=tokio::io::duplex(4096);
        let(demand,mut observed)=watch::channel(CaptureDemand::default());let task=tokio::spawn(serve(s,camera,DEVID,Arc::new(Notify::new()),demand,cancel.clone()));
        c.write_all(&header(1,47,2,true,16)).await?;
        for (seq,setup) in [(49,[0xa1,0x81,0,1,1,0,34,0]),(50,[0xa1,0x85,0,1,1,0,2,0]),(51,[0xa1,0x86,0,1,1,0,1,0]),(52,[0x80,6,0,1,0,0,18,0])] {
            let mut query=header(1,seq,0,true,u16::from_le_bytes([setup[6],setup[7]]) as usize);query[40..48].copy_from_slice(&setup);c.write_all(&query).await?;
            let reply=response(&mut c).await;assert_eq!((reply.1,reply.2),(seq,0),"readonly control must not cancel status seq47");
            assert!(!observed.borrow_and_update().active);
        }
        assert!(tokio::time::timeout(Duration::from_millis(10),observed.changed()).await.is_err(),"readonly metadata must not restart source epochs");
        let mut unlink=header(2,53,0,false,0);unlink[20..24].copy_from_slice(&47u32.to_be_bytes());c.write_all(&unlink).await?;
        let reply=response(&mut c).await;assert_eq!((reply.0,reply.1,reply.2),(4,53,-104),"valid pending status remains unlinkable");
        c.write_all(&header(1,60,2,true,16)).await?;let mut reset=header(1,61,0,false,0);reset[40..48].copy_from_slice(&[0,9,0,0,0,0,0,0]);c.write_all(&reset).await?;
        let cancelled=response(&mut c).await;assert_eq!((cancelled.1,cancelled.2),(60,-108),"real deconfiguration still cancels pending status");let acknowledged=response(&mut c).await;assert_eq!((acknowledged.1,acknowledged.2),(61,0));
        cancel.cancel();task.await??;Ok(())
    }
    #[tokio::test]
    async fn queued_bulk_unlink_and_no_late_completion() -> Result<()> {
        let camera = engine();
        let changed = Arc::new(Notify::new());
        let cancel = CancellationToken::new();
        let (s, mut c) = tokio::io::duplex(4096);
        let task = tokio::spawn(serve(
            s,
            camera.clone(),
            DEVID,
            changed.clone(),
            watch::channel(CaptureDemand::default()).0,
            cancel.clone(),
        ));
        c.write_all(&header(1, 1, 1, true, 1024)).await?;
        let mut unlink = header(2, 2, 0, false, 0);
        unlink[20..24].copy_from_slice(&1u32.to_be_bytes());
        c.write_all(&unlink).await?;
        let r = response(&mut c).await;
        assert_eq!((r.0, r.1, r.2), (4, 2, -104));
        let next = "22222222222222222222222222222222";
        camera.lock().unwrap().begin_epoch(next)?;
        camera.lock().unwrap().push(next, frame())?;
        changed.notify_one();
        c.write_all(&header(1, 3, 1, true, 1024)).await?;
        let r = response(&mut c).await;
        assert_eq!((r.0, r.1, r.2), (3, 3, 0));
        assert_eq!(r.3.len(), 25);
        let mut unlink = header(2, 4, 0, false, 0);
        unlink[20..24].copy_from_slice(&3u32.to_be_bytes());
        c.write_all(&unlink).await?;
        let r = response(&mut c).await;
        assert_eq!((r.0, r.1, r.2), (4, 4, 0));
        cancel.cancel();
        task.await??;
        assert!(!camera.lock().unwrap().streaming());
        Ok(())
    }
    #[tokio::test]
    async fn control_remains_responsive_while_bulk_waits() -> Result<()> {
        let camera = engine();
        let cancel = CancellationToken::new();
        let (s, mut c) = tokio::io::duplex(4096);
        let task = tokio::spawn(serve(
            s,
            camera,
            DEVID,
            Arc::new(Notify::new()),
            watch::channel(CaptureDemand::default()).0,
            cancel.clone(),
        ));
        c.write_all(&header(1, 1, 1, true, 1024)).await?;
        let mut get = header(1, 2, 0, true, 1);
        get[40..48].copy_from_slice(&[0x80, 8, 0, 0, 0, 0, 1, 0]);
        c.write_all(&get).await?;
        let r = response(&mut c).await;
        assert_eq!((r.1, r.2, r.3), (2, 0, vec![1]));
        let mut reset = header(1, 3, 0, false, 0);
        reset[40..48].copy_from_slice(&[0, 9, 0, 0, 0, 0, 0, 0]);
        c.write_all(&reset).await?;
        let r = response(&mut c).await;
        assert_eq!((r.1, r.2), (1, -108));
        let r = response(&mut c).await;
        assert_eq!((r.1, r.2), (3, 0));
        cancel.cancel();
        task.await??;
        Ok(())
    }
    #[tokio::test]
    async fn capture_demand_requires_bulk_and_rotates_after_idle() -> Result<()> {
        let camera = engine();
        let cancel = CancellationToken::new();
        let (s, mut c) = tokio::io::duplex(4096);
        let (tx, mut demand) = watch::channel(CaptureDemand::default());
        let task = tokio::spawn(serve(
            s,
            camera,
            DEVID,
            Arc::new(Notify::new()),
            tx,
            cancel.clone(),
        ));
        assert!(!demand.borrow().active);
        c.write_all(&header(1, 1, 1, true, 1024)).await?;
        tokio::time::timeout(Duration::from_secs(1), demand.wait_for(|d| d.active)).await??;
        let first = demand.borrow().generation;
        let mut unlink = header(2, 2, 0, false, 0);
        unlink[20..24].copy_from_slice(&1u32.to_be_bytes());
        c.write_all(&unlink).await?;
        assert_eq!(response(&mut c).await.2, -104);
        tokio::time::timeout(Duration::from_secs(1), demand.wait_for(|d| !d.active)).await??;
        c.write_all(&header(1, 3, 1, true, 1024)).await?;
        tokio::time::timeout(
            Duration::from_secs(1),
            demand.wait_for(|d| d.active && d.generation > first),
        )
        .await??;
        cancel.cancel();
        task.await??;
        assert!(!demand.borrow().active);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn natural_refill_gap_keeps_epoch_but_true_idle_retires_it() -> Result<()> {
        let camera = engine();
        let changed = Arc::new(Notify::new());
        let cancel = CancellationToken::new();
        let (s, mut c) = tokio::io::duplex(4096);
        let (tx, mut demand) = watch::channel(CaptureDemand::default());
        let task = tokio::spawn(serve(
            s,
            camera.clone(),
            DEVID,
            changed.clone(),
            tx,
            cancel.clone(),
        ));
        c.write_all(&header(1, 1, 1, true, 1024)).await?;
        demand.wait_for(|d| d.active).await?;
        let generation = demand.borrow().generation;
        camera.lock().unwrap().push(E, frame())?;
        changed.notify_one();
        assert_eq!(response(&mut c).await.1, 1);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(50)).await;
        assert!(demand.borrow().active);
        c.write_all(&header(1, 2, 1, true, 1024)).await?;
        tokio::task::yield_now().await;
        assert_eq!(
            *demand.borrow(),
            CaptureDemand {
                active: true,
                generation
            }
        );
        assert!(camera.lock().unwrap().begin_epoch(E).is_ok());
        let mut unlink = header(2, 3, 0, false, 0);
        unlink[20..24].copy_from_slice(&2u32.to_be_bytes());
        c.write_all(&unlink).await?;
        assert_eq!(response(&mut c).await.2, -104);
        demand.wait_for(|d| !d.active).await?;
        assert!(!camera.lock().unwrap().push(E, frame())?);
        c.write_all(&header(1, 4, 1, true, 1024)).await?;
        demand
            .wait_for(|d| d.active && d.generation > generation)
            .await?;
        let epoch = "44444444444444444444444444444444";
        camera.lock().unwrap().begin_epoch(epoch)?;
        camera.lock().unwrap().push(epoch, frame())?;
        changed.notify_one();
        assert_eq!(response(&mut c).await.1, 4);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(101)).await;
        demand.wait_for(|d| !d.active).await?;
        assert!(!camera.lock().unwrap().push(epoch, frame())?);
        cancel.cancel();
        task.await??;
        Ok(())
    }
    #[tokio::test]
    async fn reject_foreign_identity_iso_and_oversize_before_body() {
        for kind in 0..4 {
            let (mut tx, mut rx) = tokio::io::duplex(128);
            let mut h = header(1, 1, 1, true, 1);
            match kind {
                0 => h[8..12].copy_from_slice(&1u32.to_be_bytes()),
                1 => h[32..36].copy_from_slice(&1u32.to_be_bytes()),
                2 => h[24..28].copy_from_slice(&65537u32.to_be_bytes()),
                _ => h[12..16].copy_from_slice(&2u32.to_be_bytes()),
            };
            tx.write_all(&h).await.unwrap();
            assert!(
                read(
                    &mut rx,
                    DEVID,
                    Arc::new(Semaphore::new(MAX_BUFFERED)),
                    Arc::new(Semaphore::new(MAX_PENDING))
                )
                .await
                .is_err()
            );
        }
    }
    #[tokio::test]
    async fn bounded_queue_closes_on_duplicate_or_exhaustion() {
        for duplicate in [true, false] {
            let cancel = CancellationToken::new();
            let (s, mut c) = tokio::io::duplex(65536);
            let task = tokio::spawn(serve(
                s,
                engine(),
                DEVID,
                Arc::new(Notify::new()),
                watch::channel(CaptureDemand::default()).0,
                cancel,
            ));
            for seq in 0..=MAX_PENDING {
                let seq = if duplicate { 1 } else { seq as u32 };
                if c.write_all(&header(1, seq, 1, true, 65536)).await.is_err() {
                    break;
                }
            }
            let result = tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap();
            assert!(result.is_err());
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "usbip_video_fixture.rs"]
mod native_fixture;
