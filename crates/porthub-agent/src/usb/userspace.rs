//! Bounded USB/IP transfer engine for native userspace USB adapters.
//! Transfers never appear in logs. Only the owner-authorized carrier reaches
//! this engine; the selected device identity is checked again on every URB.
use anyhow::{ensure, Result};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{mpsc, OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
};
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
const MAX_TRANSFER: usize = 1024 * 1024;
const MAX_BUFFERED: usize = 4 * 1024 * 1024;
const MAX_PENDING: usize = 32;
#[derive(Debug)]
pub(super) struct Transfer {
    pub sequence: u32,
    pub endpoint: u8,
    pub input: bool,
    pub flags: u32,
    pub length: usize,
    pub setup: [u8; 8],
    pub data: Vec<u8>,
}
pub(super) struct Completion {
    pub actual: usize,
    pub data: Vec<u8>,
}
pub(super) trait DeviceIo: Send + Sync + 'static {
    fn execute(
        &self,
        request: &Transfer,
        cancelled: &AtomicBool,
    ) -> std::result::Result<Completion, i32>;
}
struct Pending(HashMap<u32, Arc<AtomicBool>>);
impl Drop for Pending {
    fn drop(&mut self) {
        for flag in self.0.values() {
            flag.store(true, Ordering::Release);
        }
    }
}
struct Submit {
    request: Transfer,
    _budget: OwnedSemaphorePermit,
    unsupported_iso: bool,
}
enum Command {
    Submit(Submit),
    Unlink { sequence: u32, target: u32 },
}
fn word(h: &[u8; 48], offset: usize) -> u32 {
    u32::from_be_bytes(h[offset..offset + 4].try_into().unwrap())
}
async fn read<R: AsyncRead + Unpin>(
    reader: &mut R,
    devid: u32,
    budget: Arc<Semaphore>,
) -> Result<Command> {
    let mut h = [0; 48];
    reader.read_exact(&mut h).await?;
    let command = word(&h, 0);
    let sequence = word(&h, 4);
    let device = word(&h, 8);
    let direction = word(&h, 12);
    let endpoint = word(&h, 16);
    ensure!(device == devid, "USB transfer belongs to another device");
    ensure!(
        direction <= 1 && endpoint <= 15,
        "Invalid USB transfer endpoint"
    );
    if command == 2 {
        ensure!(endpoint == 0, "Invalid USB unlink endpoint");
        return Ok(Command::Unlink {
            sequence,
            target: word(&h, 20),
        });
    }
    ensure!(command == 1, "Unsupported USB transfer command");
    let length = word(&h, 24) as usize;
    let packets = word(&h, 32);
    ensure!(
        length <= MAX_TRANSFER,
        "USB transfer exceeds bounded buffer"
    );
    ensure!(
        packets == u32::MAX || packets <= 1024,
        "USB isochronous descriptor count exceeds limit"
    );
    let unsupported_iso = packets != 0 && packets != u32::MAX;
    let iso_bytes = if unsupported_iso {
        packets as usize * 16
    } else {
        0
    };
    let permit = budget
        .try_acquire_many_owned((length + iso_bytes).max(1) as u32)
        .map_err(|_| anyhow::anyhow!("USB transfer queue capacity exceeded"))?;
    let mut data = if direction == 0 {
        vec![0; length]
    } else {
        Vec::new()
    };
    if !data.is_empty() {
        reader.read_exact(&mut data).await?;
    }
    if iso_bytes != 0 {
        let mut descriptors = vec![0; iso_bytes];
        reader.read_exact(&mut descriptors).await?;
    }
    Ok(Command::Submit(Submit {
        request: Transfer {
            sequence,
            endpoint: endpoint as u8,
            input: direction == 1,
            flags: word(&h, 20),
            length,
            setup: h[40..48].try_into().unwrap(),
            data,
        },
        _budget: permit,
        unsupported_iso,
    }))
}
async fn response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    command: u32,
    sequence: u32,
    status: i32,
    actual: usize,
    data: &[u8],
) -> Result<()> {
    let mut h = [0; 48];
    h[..4].copy_from_slice(&command.to_be_bytes());
    h[4..8].copy_from_slice(&sequence.to_be_bytes());
    h[20..24].copy_from_slice(&status.to_be_bytes());
    h[24..28].copy_from_slice(&(actual as u32).to_be_bytes());
    writer.write_all(&h).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}
/// IO adapters use bounded blocking transfer deadlines; dropping this session
/// cancels pending USB/IP replies and lets their OS handles restore ownership.
pub(super) async fn serve<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    device: Arc<dyn DeviceIo>,
    devid: u32,
    cancel: CancellationToken,
) -> Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (tx, mut commands) = mpsc::channel(MAX_PENDING);
    let budget = Arc::new(Semaphore::new(MAX_BUFFERED));
    let _reader = AbortOnDropHandle::new(tokio::spawn(async move {
        loop {
            let command = read(&mut reader, devid, budget.clone()).await;
            let failed = command.is_err();
            if tx.send(command).await.is_err() || failed {
                break;
            }
        }
    }));
    let mut jobs = JoinSet::new();
    let mut pending = Pending(HashMap::new());
    loop {
        tokio::select! {
         _=cancel.cancelled()=>break,
         command=commands.recv()=>{
          let Some(command)=command else {break;};
          match command? {
           Command::Unlink{sequence,target}=>{
            let status=if pending.0.get(&target).is_some_and(|flag|!flag.swap(true,Ordering::AcqRel)){0}else{-2};
            response(&mut writer,4,sequence,status,0,&[]).await?;
           },
           Command::Submit(submit)=>{
            ensure!(jobs.len()<MAX_PENDING,"USB in-flight transfer limit exceeded");
            let sequence=submit.request.sequence;ensure!(!pending.0.contains_key(&sequence),"Duplicate in-flight USB sequence");
            let flag=Arc::new(AtomicBool::new(false));pending.0.insert(sequence,flag.clone());let io=device.clone();
            jobs.spawn_blocking(move || {
             let result=if submit.unsupported_iso {Err(-95)}else{io.execute(&submit.request,&flag)};
             (submit,result,flag)
            });
           }
          }
         },
         completed=jobs.join_next(),if !jobs.is_empty()=>{
          let (submit,result,flag)=completed.unwrap()?;let request=&submit.request;pending.0.remove(&request.sequence);
          if flag.load(Ordering::Acquire){continue;}
          let (mut status,actual,data)=match result {
           Ok(reply)=>{ensure!(reply.actual<=request.length&&(!request.input||reply.data.len()==reply.actual),"Invalid native USB transfer completion");(0,reply.actual,reply.data)},
           Err(error)=>(if error<0{error}else{-5},0,Vec::new())
          };
          if status==0&&request.input&&actual<request.length&&request.flags&1!=0 {status=-121;}
          response(&mut writer,3,request.sequence,status,actual,if request.input{&data}else{&[]}).await?;
         }
        }
    }
    for flag in pending.0.values() {
        flag.store(true, Ordering::Release);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Echo;
    impl DeviceIo for Echo {
        fn execute(&self, r: &Transfer, _: &AtomicBool) -> std::result::Result<Completion, i32> {
            Ok(Completion {
                actual: r.length,
                data: if r.input {
                    vec![0x5a; r.length]
                } else {
                    Vec::new()
                },
            })
        }
    }
    fn submit(sequence: u32, input: bool, length: u32) -> [u8; 48] {
        let mut h = [0; 48];
        for (offset, value) in [
            (0, 1u32),
            (4, sequence),
            (8, 0x10002),
            (12, u32::from(input)),
            (16, 1),
            (24, length),
        ] {
            h[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        h
    }
    #[tokio::test]
    async fn native_userspace_transfers_preserve_response_boundaries() -> Result<()> {
        let (server, mut peer) = tokio::io::duplex(128);
        let cancel = CancellationToken::new();
        let done = tokio::spawn(serve(server, Arc::new(Echo), 0x10002, cancel.clone()));
        peer.write_all(&submit(7, false, 4)).await?;
        peer.write_all(b"test").await?;
        let mut h = [0; 48];
        peer.read_exact(&mut h).await?;
        ensure!(
            word(&h, 0) == 3
                && word(&h, 4) == 7
                && word(&h, 8) == 0
                && word(&h, 12) == 0
                && word(&h, 16) == 0
                && word(&h, 24) == 4
        );
        peer.write_all(&submit(8, true, 6)).await?;
        peer.read_exact(&mut h).await?;
        let mut data = [0; 6];
        peer.read_exact(&mut data).await?;
        ensure!(data == [0x5a; 6] && word(&h, 4) == 8);
        cancel.cancel();
        done.await??;
        Ok(())
    }
    #[tokio::test]
    async fn invalid_lengths_and_device_ids_are_rejected_before_allocation() -> Result<()> {
        for mut h in [
            submit(1, true, (MAX_TRANSFER + 1) as u32),
            submit(1, true, 16),
        ] {
            if word(&h, 24) == 16 {
                h[8..12].copy_from_slice(&3u32.to_be_bytes());
            }
            let mut reader = h.as_slice();
            ensure!(
                read(&mut reader, 0x10002, Arc::new(Semaphore::new(MAX_BUFFERED)))
                    .await
                    .is_err()
            );
        }
        Ok(())
    }
    #[tokio::test]
    async fn isochronous_is_explicitly_unsupported_not_silently_misreported() -> Result<()> {
        let (server, mut peer) = tokio::io::duplex(128);
        let cancel = CancellationToken::new();
        let done = tokio::spawn(serve(server, Arc::new(Echo), 0x10002, cancel.clone()));
        let mut h = submit(1, true, 4);
        h[32..36].copy_from_slice(&1u32.to_be_bytes());
        peer.write_all(&h).await?;
        peer.write_all(&[0; 16]).await?;
        peer.read_exact(&mut h).await?;
        ensure!(i32::from_be_bytes(h[20..24].try_into()?) == -95 && word(&h, 24) == 0);
        cancel.cancel();
        done.await??;
        Ok(())
    }
    #[tokio::test]
    async fn unlink_does_not_emit_a_late_submission_reply() -> Result<()> {
        struct Slow;
        impl DeviceIo for Slow {
            fn execute(
                &self,
                _: &Transfer,
                _: &AtomicBool,
            ) -> std::result::Result<Completion, i32> {
                std::thread::sleep(std::time::Duration::from_millis(50));
                Err(-110)
            }
        }
        let (server, mut peer) = tokio::io::duplex(128);
        let cancel = CancellationToken::new();
        let done = tokio::spawn(serve(server, Arc::new(Slow), 0x10002, cancel.clone()));
        peer.write_all(&submit(11, true, 8)).await?;
        let mut unlink = submit(12, false, 0);
        unlink[..4].copy_from_slice(&2u32.to_be_bytes());
        unlink[16..20].fill(0);
        unlink[20..24].copy_from_slice(&11u32.to_be_bytes());
        peer.write_all(&unlink).await?;
        let mut h = [0; 48];
        peer.read_exact(&mut h).await?;
        ensure!(word(&h, 0) == 4 && word(&h, 4) == 12 && word(&h, 20) == 0);
        ensure!(
            tokio::time::timeout(std::time::Duration::from_millis(100), peer.read_u8())
                .await
                .is_err()
        );
        cancel.cancel();
        done.await??;
        Ok(())
    }
}
