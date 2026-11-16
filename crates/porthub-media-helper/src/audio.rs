//! Bounded inherited-pipe PCM bridge. No network credentials or ambient capture.
use anyhow::{ensure, Context, Result};
use pipewire::{self as pw, properties::properties, spa};
use porthub_components::media::{Operation, SessionRequest, MAX_PCM_FRAME, PCM_CHANNELS, PCM_RATE};
use std::{
    collections::VecDeque,
    io::{BufRead, Read, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
const QUEUE_BYTES: usize = PCM_RATE as usize * 4 / 10; // 100ms maximum, oldest samples discarded.
#[derive(Default)]
struct Queue(VecDeque<u8>);
impl Queue {
    fn push(&mut self, bytes: &[u8]) {
        if bytes.len() % 4 != 0 {
            return;
        }
        for bytes in bytes.chunks(4) {
            while self.0.len() + 4 > QUEUE_BYTES {
                for _ in 0..4 {
                    self.0.pop_front();
                }
            }
            self.0.extend(bytes);
        }
    }
    fn clear(&mut self) {
        for byte in &mut self.0 {
            *byte = 0;
        }
        self.0.clear();
    }
}
struct Data {
    queue: Arc<Mutex<Queue>>,
    cancel: Arc<AtomicBool>,
    capture: bool,
    format_ready: bool,
    negotiated: Arc<AtomicBool>,
}
fn read_frame(reader: &mut impl Read) -> Result<Option<Vec<u8>>> {
    let mut size = [0u8; 4];
    match reader.read(&mut size[..1])? {
        0 => return Ok(None),
        _ => reader.read_exact(&mut size[1..])?,
    }
    let size = u32::from_le_bytes(size) as usize;
    ensure!(
        size > 0 && size <= MAX_PCM_FRAME && size % 4 == 0,
        "Invalid PCM frame size"
    );
    let mut data = vec![0; size];
    reader.read_exact(&mut data)?;
    ensure!(
        data.chunks_exact(4)
            .all(|v| f32::from_le_bytes(v.try_into().unwrap()).is_finite()),
        "Invalid PCM sample"
    );
    Ok(Some(data))
}
pub fn serve() -> Result<()> {
    // Only an explicit parent-owned inherited pipe can request a media session.
    use std::os::unix::fs::FileTypeExt;
    ensure!(
        std::fs::metadata("/proc/self/fd/0")?.file_type().is_fifo(),
        "Media session requires an inherited control pipe"
    );
    let mut reader = std::io::BufReader::new(std::io::stdin());
    let mut header = Vec::new();
    std::io::Read::by_ref(&mut reader)
        .take(8193)
        .read_until(b'\n', &mut header)?;
    ensure!(
        header.len() <= 8192 && header.last() == Some(&b'\n'),
        "Invalid media session request"
    );
    let request: SessionRequest =
        serde_json::from_slice(&header).context("Invalid media session request")?;
    ensure!(request.valid(), "Invalid media session request");
    if request.operation == Operation::CaptureCamera {
        return crate::video_session::serve(
            &request.session,
            request
                .source_id
                .as_deref()
                .context("Missing camera identity")?,
            serde_json::from_value(
                request
                    .camera_identity
                    .context("Missing retained camera selection proof")?,
            )?,
            request
                .video_format
                .context("Missing exact camera format")?,
            reader,
        );
    }
    let capture = request.operation == Operation::CaptureMicrophone;
    pw::init();
    let loop_ = pw::main_loop::MainLoopRc::new(None)?;
    let context = pw::context::ContextRc::new(&loop_, None)?;
    let core = context.connect_rc(None)?;
    let target = if capture {
        Some(crate::linux::capture_target(
            &loop_,
            &core,
            request.source_id.as_deref().unwrap(),
        )?)
    } else {
        None
    };
    let queue = Arc::new(Mutex::new(Queue::default()));
    let cancel = Arc::new(AtomicBool::new(false));
    let (stop_sender, stop_receiver) = pw::channel::channel::<()>();
    let stop_flag = cancel.clone();
    let wake_loop = loop_.clone();
    let _stop_listener = stop_receiver.attach(loop_.loop_(), move |_| {
        stop_flag.store(true, Ordering::Release);
        wake_loop.quit();
    });
    let input_stop = stop_sender.clone();
    let ready_flag = Arc::new(AtomicBool::new(false));
    let initial_ready = ready_flag.clone();
    let timeout_cancel = cancel.clone();
    let timeout_loop = loop_.clone();
    let _initial_deadline = loop_.loop_().add_timer(move |_| {
        if !initial_ready.load(Ordering::Acquire) {
            timeout_cancel.store(true, Ordering::Release);
            timeout_loop.quit();
        }
    });
    _initial_deadline
        .update_timer(Some(Duration::from_secs(5)), None)
        .into_result()?;
    let input_failed = Arc::new(AtomicBool::new(false));
    let failed_input = input_failed.clone();
    let input_queue = queue.clone();
    let input_cancel = cancel.clone();
    std::thread::spawn(move || {
        if capture {
            let mut byte = [0u8; 1];
            let _ = reader.read(&mut byte);
        } else {
            loop {
                match read_frame(&mut reader) {
                    Ok(Some(frame)) => input_queue
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(&frame),
                    Ok(None) => break,
                    Err(_) => {
                        failed_input.store(true, Ordering::Release);
                        break;
                    }
                }
            }
        }
        input_queue
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        input_cancel.store(true, Ordering::Release);
        let _ = input_stop.send(());
    });
    let mut props = properties! {"media.type"=>"Audio","media.category"=>if capture{"Capture"}else{"Playback"},"media.role"=>"Communication","node.name"=>format!("porthub.{}",request.session),"node.description"=>format!("PortHub — {} — Microphone",request.name),"node.latency"=>"480/48000","node.pause-on-idle"=>"true"};
    if let Some(target) = target {
        props.insert("target.object", target);
        props.insert("node.dont-fallback", "true");
        props.insert("node.dont-reconnect", "true");
    } else {
        props.insert("media.class", "Audio/Source");
        props.insert("node.virtual", "true");
        props.insert("priority.session", "-1000000");
        props.insert("priority.driver", "1");
        props.insert("node.always-process", "false");
    }
    let stream = pw::stream::StreamBox::new(&core, "PortHub media", props)?;
    let negotiated = Arc::new(AtomicBool::new(false));
    let state_error = Arc::new(Mutex::new(None));
    let errors = state_error.clone();
    let fail = cancel.clone();
    let listener = stream
        .add_local_listener_with_user_data(Data {
            queue: queue.clone(),
            cancel: cancel.clone(),
            capture,
            format_ready: false,
            negotiated: negotiated.clone(),
        })
        .state_changed(move |_, _, _, state| {
            if matches!(
                state,
                pw::stream::StreamState::Error(_) | pw::stream::StreamState::Unconnected
            ) {
                *errors.lock().unwrap_or_else(|e| e.into_inner()) =
                    Some("Media endpoint disconnected");
                fail.store(true, Ordering::Release);
            }
        })
        .param_changed(|_, data, id, pod| {
            if id != spa::param::ParamType::Format.as_raw() {
                return;
            }
            let Some(pod) = pod else {
                data.format_ready = false;
                return;
            };
            let mut info = spa::param::audio::AudioInfoRaw::new();
            data.format_ready = info.parse(pod).is_ok()
                && info.format() == spa::param::audio::AudioFormat::F32LE
                && info.rate() == PCM_RATE
                && info.channels() == PCM_CHANNELS;
            data.negotiated.store(data.format_ready, Ordering::Release);
            if !data.format_ready {
                data.cancel.store(true, Ordering::Release);
            }
        })
        .process(|stream, data| {
            if !data.format_ready || data.cancel.load(Ordering::Acquire) {
                return;
            }
            let Some(mut buffer) = stream.dequeue_buffer() else {
                return;
            };
            let requested = buffer.requested() as usize;
            let Some(plane) = buffer.datas_mut().first_mut() else {
                return;
            };
            if data.capture {
                let size = plane.chunk().size() as usize;
                let offset = plane.chunk().offset() as usize;
                if size % 4 != 0 {
                    data.cancel.store(true, Ordering::Release);
                    return;
                }
                if let Some(bytes) = plane.data() {
                    if let Some(end) = offset.checked_add(size).filter(|end| *end <= bytes.len()) {
                        data.queue
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push(&bytes[offset..end]);
                    } else {
                        data.cancel.store(true, Ordering::Release);
                    }
                }
            } else {
                let mut used = 0;
                if let Some(bytes) = plane.data() {
                    used = bytes.len() / 4 * 4;
                    if requested > 0 {
                        used = used.min(requested.saturating_mul(4));
                    }
                    let mut queue = data.queue.lock().unwrap_or_else(|e| e.into_inner());
                    for byte in &mut bytes[..used] {
                        *byte = queue.0.pop_front().unwrap_or(0);
                    }
                }
                *plane.chunk_mut().offset_mut() = 0;
                *plane.chunk_mut().stride_mut() = 4;
                *plane.chunk_mut().size_mut() = used as u32;
            }
        })
        .register()?;
    let mut info = spa::param::audio::AudioInfoRaw::new();
    info.set_format(spa::param::audio::AudioFormat::F32LE);
    info.set_rate(PCM_RATE);
    info.set_channels(PCM_CHANNELS);
    let object = spa::pod::Object {
        type_: spa::utils::SpaTypes::ObjectParamFormat.as_raw(),
        id: spa::param::ParamType::EnumFormat.as_raw(),
        properties: info.into(),
    };
    let bytes = spa::pod::serialize::PodSerializer::serialize(
        std::io::Cursor::new(Vec::new()),
        &spa::pod::Value::Object(object),
    )
    .map_err(|_| anyhow::anyhow!("Unable to construct PCM format"))?
    .0
    .into_inner();
    let mut params = [spa::pod::Pod::from_bytes(&bytes).context("Invalid PCM format")?];
    let flags = pw::stream::StreamFlags::MAP_BUFFERS
        | if capture {
            pw::stream::StreamFlags::AUTOCONNECT
        } else {
            pw::stream::StreamFlags::empty()
        };
    stream.connect(
        if capture {
            spa::utils::Direction::Input
        } else {
            spa::utils::Direction::Output
        },
        None,
        flags,
        &mut params,
    )?;
    let started = Instant::now();
    let mut ready = false;
    while !cancel.load(Ordering::Acquire) {
        ensure!(
            ready || started.elapsed() < Duration::from_secs(5),
            "Media endpoint publication/capture timed out"
        );
        loop_.loop_().iterate(pw::loop_::Timeout::Infinite);
        let state = stream.state();
        if !ready
            && stream.node_id() != u32::MAX
            && if capture {
                matches!(state, pw::stream::StreamState::Streaming)
                    && negotiated.load(Ordering::Acquire)
            } else {
                matches!(
                    state,
                    pw::stream::StreamState::Paused | pw::stream::StreamState::Streaming
                )
            }
        {
            println!(
                "{}",
                serde_json::json!({"session":request.session,"state":if capture{"capturing"}else{"published"},"node_id":stream.node_id(),"rate":PCM_RATE,"channels":PCM_CHANNELS,"format":"f32le"})
            );
            std::io::stdout().flush()?;
            ready = true;
            ready_flag.store(true, Ordering::Release);
            if capture {
                let output_queue = queue.clone();
                let output_cancel = cancel.clone();
                let output_stop = stop_sender.clone();
                std::thread::spawn(move || {
                    let mut stdout = std::io::stdout().lock();
                    while !output_cancel.load(Ordering::Acquire) {
                        let frame = {
                            let mut q = output_queue.lock().unwrap_or_else(|e| e.into_inner());
                            let size = q.0.len().min(MAX_PCM_FRAME) / 4 * 4;
                            q.0.drain(..size).collect::<Vec<_>>()
                        };
                        if frame.is_empty() {
                            std::thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        if stdout
                            .write_all(&(frame.len() as u32).to_le_bytes())
                            .and_then(|_| stdout.write_all(&frame))
                            .and_then(|_| stdout.flush())
                            .is_err()
                        {
                            output_cancel.store(true, Ordering::Release);
                            let _ = output_stop.send(());
                            break;
                        }
                    }
                });
            }
        }
    }
    queue.lock().unwrap_or_else(|e| e.into_inner()).clear();
    drop((listener, stream));
    if let Some(reason) = *state_error.lock().unwrap_or_else(|e| e.into_inner()) {
        anyhow::bail!(reason);
    }
    ensure!(
        !input_failed.load(Ordering::Acquire),
        "Malformed media input; endpoint stopped"
    );
    ensure!(ready, "Media session stopped before endpoint became ready");
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pcm_input_rejects_truncation_overflow_and_non_finite_samples() {
        assert!(read_frame(&mut &[][..]).unwrap().is_none());
        for bytes in [
            vec![0],
            (MAX_PCM_FRAME as u32 + 4).to_le_bytes().to_vec(),
            [
                4u32.to_le_bytes().as_slice(),
                f32::NAN.to_le_bytes().as_slice(),
            ]
            .concat(),
        ] {
            assert!(read_frame(&mut bytes.as_slice()).is_err());
        }
    }
    #[test]
    fn backpressure_discards_oldest_complete_samples_and_stop_clears_queue() {
        let mut q = Queue::default();
        q.push(&vec![1; QUEUE_BYTES]);
        q.push(&[2, 2, 2, 2]);
        assert_eq!(q.0.len(), QUEUE_BYTES);
        assert_eq!(q.0.back(), Some(&2));
        q.clear();
        assert!(q.0.is_empty());
    }
}
