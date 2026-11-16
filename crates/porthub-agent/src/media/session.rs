//! Local user-session bridge. A system agent must authenticate a user broker,
//! never impersonate a desktop by guessing its UID or accepting a server path.
use crate::features::{self, Feature};
use anyhow::{ensure, Context, Result};
use porthub_components::{
    media::{Operation, SessionRequest, MAX_PCM_FRAME},
    media_store::{Manager, Manifest},
};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{ChildStdin, ChildStdout},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
#[derive(Clone, Copy)]
enum ReadyPlatform { PipeWire, Windows }
fn validate_native_ready(request:&SessionRequest,ready:&serde_json::Value,platform:ReadyPlatform)->Result<()> {
    ensure!(request.valid(), "Invalid explicit media readiness request");
    ensure!(ready["session"].as_str()==Some(request.session.as_str()) && ready["state"]==if request.operation==Operation::PublishMicrophone {"published"}else{"capturing"},"Media helper did not publish/capture the requested session");
    if request.operation==Operation::CaptureCamera {
        let backend=match platform {ReadyPlatform::PipeWire=>"v4l2",ReadyPlatform::Windows=>"windows-mf"};
        ensure!(ready["backend"]==backend && ready["source_id"].as_str()==request.source_id.as_deref() && serde_json::from_value::<porthub_components::media::VideoFormat>(ready["format"].clone()).ok()==request.video_format,"Camera helper negotiated a different source/format/backend");
    } else {
        match platform {
            ReadyPlatform::PipeWire=>ensure!(ready["node_id"].as_u64().is_some_and(|v|v<u32::MAX as u64),"Native PipeWire endpoint identity unavailable"),
            ReadyPlatform::Windows=>ensure!(request.operation==Operation::CaptureMicrophone && ready["backend"]=="wasapi" && ready["endpoint_id"].as_str().is_some_and(|v|!v.is_empty()&&v.len()<=512),"Native Windows capture endpoint unavailable"),
        }
        ensure!(ready["rate"]==48000&&ready["channels"]==1&&ready["format"]=="f32le","Media helper negotiated unsupported endpoint");
    }
    Ok(())
}
#[derive(Debug)]
pub struct CaptureDenied(pub porthub_components::media::Kind);
impl std::fmt::Display for CaptureDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0 == porthub_components::media::Kind::Camera {
            "Camera permission denied by the operating system"
        } else {
            "Microphone permission denied by the operating system"
        })
    }
}
impl std::error::Error for CaptureDenied {}
#[derive(Debug)]
pub struct CaptureUnsupported;
impl std::fmt::Display for CaptureUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Selected camera does not support the required MJPEG mode")
    }
}
impl std::error::Error for CaptureUnsupported {}
pub struct Session {
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    cancel: CancellationToken,
    _supervisor: JoinHandle<()>,
    pub ready: serde_json::Value,
    sequence: u64,
    sample_offset: u64,
    clock: std::time::Instant,
    incoming: Vec<u8>,
    expected: Option<usize>,
    operation: Operation,
    video_timestamp: Option<u64>,
}
impl Drop for Session {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.incoming.fill(0);
    }
}
fn feature(operation: Operation) -> Feature {
    match operation {
        Operation::CaptureMicrophone => Feature::MicrophoneShare,
        Operation::CaptureCamera => Feature::CameraShare,
        Operation::PublishMicrophone => Feature::MediaReceive,
    }
}
fn permitted(profile: &Path, operation: Operation) -> bool {
    features::load(profile).is_ok_and(|p| p.enabled(feature(operation)))
}
#[cfg(target_os = "linux")]
fn runtime() -> Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let uid = unsafe { libc::geteuid() };
    ensure!(
        uid != 0 && uid == unsafe { libc::getuid() },
        "Media adapter must run in its authenticated unprivileged user session"
    );
    let path = PathBuf::from(format!("/run/user/{uid}"));
    let meta = std::fs::symlink_metadata(&path)?;
    ensure!(
        meta.is_dir()
            && !meta.file_type().is_symlink()
            && meta.uid() == uid
            && meta.mode() & 0o077 == 0,
        "Unsafe media session runtime directory"
    );
    Ok(path)
}
#[cfg(target_os = "linux")]
struct CameraStop(std::os::fd::OwnedFd);
#[cfg(not(target_os = "linux"))]
struct CameraStop;
impl CameraStop {
    fn signal(&self) {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            for _ in 0..3 {
                let byte = 0u8;
                let result =
                    unsafe { libc::write(self.0.as_raw_fd(), (&byte as *const u8).cast(), 1) };
                if result == 1
                    || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
                {
                    break;
                }
            }
        }
    }
}
#[cfg(any(target_os = "linux", windows))]
fn camera_stop(input: &ChildStdin, operation: Operation) -> Result<Option<CameraStop>> {
    #[cfg(target_os = "linux")]
    if operation == Operation::CaptureCamera {
        use std::os::fd::{AsRawFd, FromRawFd};
        let descriptor = unsafe { libc::fcntl(input.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        ensure!(descriptor >= 0, "Camera stop control could not be retained");
        return Ok(Some(CameraStop(unsafe {
            std::os::fd::OwnedFd::from_raw_fd(descriptor)
        })));
    }
    let _ = (input, operation);
    Ok(None)
}
async fn supervise(
    mut child: tokio::process::Child,
    profile: PathBuf,
    operation: Operation,
    mut policy: tokio::sync::watch::Receiver<features::Policy>,
    stop: CancellationToken,
    camera_stop: Option<CameraStop>,
) {
    loop {
        tokio::select! {biased;_=stop.cancelled()=>break,r=child.wait()=>{let _=r;stop.cancel();return;},r=policy.changed()=>{if r.is_err()||!policy.borrow().enabled(feature(operation)){break;}},_=tokio::time::sleep(Duration::from_millis(50))=>{if !permitted(&profile,operation){break;}}}
    }
    stop.cancel();
    if let Some(camera_stop) = camera_stop {
        // Camera format/rate rollback lives in the helper's RAII guard. Give
        // its independently polled control pipe a bounded chance to unwind.
        camera_stop.signal();
        if matches!(tokio::time::timeout(Duration::from_millis(250), child.wait()).await,Ok(Ok(_))) {
            return;
        }
        tracing::warn!("Camera adapter exceeded graceful shutdown deadline; terminating it");
    }
    let _ = child.start_kill();
    let _ = child.wait().await;
}
impl Session {
    #[cfg(any(target_os = "linux", windows))]
    pub async fn spawn_local(
        profile: &Path,
        request: SessionRequest,
        manager: &Manager,
        manifest: &Manifest,
        parent: &CancellationToken,
    ) -> Result<Self> {
        ensure!(request.valid(), "Invalid explicit media session");
        ensure!(
            permitted(profile, request.operation),
            "Media capability disabled by local client policy"
        );
        #[cfg(target_os = "linux")]
        let runtime = runtime()?;
        #[cfg(windows)]
        let _desktop = super::windows_host::current()?;
        let cancel = parent.child_token();
        let binary = tokio::select! {biased;_=cancel.cancelled()=>anyhow::bail!("Media session cancelled"),r=manager.ensure(manifest,&cancel)=>r?};
        ensure!(
            permitted(profile, request.operation),
            "Media capability disabled before helper launch"
        );
        let mut command = tokio::process::Command::new(binary);
        command
            .arg("serve")
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        #[cfg(target_os = "linux")]
        command.env("XDG_RUNTIME_DIR", runtime);
        #[cfg(windows)]
        super::windows_host::configure_command(&mut command)?;
        #[cfg(target_os = "linux")]
        if let Some(home) = directories::BaseDirs::new() {
            command.env("HOME", home.home_dir());
        }
        let startup_context = if cfg!(windows) {
            "Verified Windows media helper cannot start; Windows audio and Media Foundation components are required"
        } else {
            "Verified media helper cannot start; compatible GNU libraries and PipeWire session are required"
        };
        let mut child = command.spawn().context(startup_context)?;
        let mut input = child
            .stdin
            .take()
            .context("Media helper input unavailable")?;
        let mut output = BufReader::new(
            child
                .stdout
                .take()
                .context("Media helper output unavailable")?,
        );
        let policy = features::subscribe(profile);
        let watch_profile = profile.to_owned();
        let operation = request.operation;
        let stop = cancel.clone();
        let camera_control = camera_stop(&input, operation)?;
        let supervisor = tokio::spawn(supervise(
            child,
            watch_profile,
            operation,
            policy,
            stop,
            camera_control,
        ));
        let mut header = serde_json::to_vec(&request)?;
        header.push(b'\n');
        input.write_all(&header).await?;
        input.flush().await?;
        let result = tokio::time::timeout(Duration::from_secs(6), async {
            let mut line = Vec::new();
            while line.len() < 4096 {
                let byte = output.read_u8().await?;
                line.push(byte);
                if byte == b'\n' {
                    break;
                }
            }
            ensure!(
                line.last() == Some(&b'\n'),
                "Media helper readiness exceeds bound"
            );
            let ready: serde_json::Value = serde_json::from_slice(&line)?;
            if request.operation == Operation::CaptureCamera
                && ready["session"].as_str() == Some(request.session.as_str())
                && ready["state"] == "unsupported"
            {
                return Err(CaptureUnsupported.into());
            }
            if ready["session"].as_str() == Some(request.session.as_str())
                && ready["state"] == "denied"
            {
                return Err(
                    CaptureDenied(if request.operation == Operation::CaptureCamera {
                        porthub_components::media::Kind::Camera
                    } else {
                        porthub_components::media::Kind::Microphone
                    })
                    .into(),
                );
            }
            #[cfg(target_os="linux")]
            validate_native_ready(&request,&ready,ReadyPlatform::PipeWire)?;
            #[cfg(windows)]
            validate_native_ready(&request,&ready,ReadyPlatform::Windows)?;
            Ok::<_, anyhow::Error>(ready)
        })
        .await;
        let ready = match result {
            Ok(Ok(v)) => v,
            other => {
                cancel.cancel();
                supervisor.await.ok();
                return Err(match other {
                    Ok(Err(e)) => e,
                    Err(_) => anyhow::anyhow!("Media helper readiness timed out"),
                    _ => unreachable!(),
                });
            }
        };
        ensure!(
            permitted(profile, request.operation),
            "Media capability disabled during helper launch"
        );
        Ok(Self {
            input,
            output,
            cancel,
            _supervisor: supervisor,
            ready,
            sequence: 0,
            sample_offset: 0,
            clock: std::time::Instant::now(),
            incoming: Vec::new(),
            expected: None,
            operation: request.operation,
            video_timestamp: None,
        })
    }
    pub async fn read_network_frame(&mut self) -> Result<porthub_components::media::PcmFrame> {
        let pcm = self.read_pcm().await?;
        let frame = porthub_components::media::PcmFrame {
            sequence: self.sequence,
            sample_offset: self.sample_offset,
            source_monotonic_micros: self.clock.elapsed().as_micros().min(u64::MAX as u128) as u64,
            pcm,
        };
        self.sequence = self
            .sequence
            .checked_add(1)
            .context("Media sequence overflow")?;
        self.sample_offset = self
            .sample_offset
            .checked_add((frame.pcm.len() / 4) as u64)
            .context("Media sample clock overflow")?;
        Ok(frame)
    }
    pub async fn read_pcm(&mut self) -> Result<Vec<u8>> {
        ensure!(
            self.operation != Operation::CaptureCamera,
            "Camera session cannot provide PCM"
        );
        // fill_buf never consumes bytes on cancellation; partial headers/payloads
        // remain in self so policy/control events cannot corrupt PCM framing.
        loop {
            if self.expected.is_none() && self.incoming.len() == 4 {
                let length = u32::from_le_bytes(self.incoming[..4].try_into().unwrap()) as usize;
                ensure!(
                    length > 0 && length <= MAX_PCM_FRAME && length % 4 == 0,
                    "Invalid media PCM frame"
                );
                self.expected = Some(length);
            }
            if self
                .expected
                .is_some_and(|length| self.incoming.len() == length + 4)
            {
                let frame = self.incoming.split_off(4);
                self.incoming.clear();
                self.expected = None;
                validate_pcm(&frame)?;
                return Ok(frame);
            }
            let needed = self.expected.map(|n| n + 4).unwrap_or(4) - self.incoming.len();
            let bytes = self.output.fill_buf().await?;
            ensure!(!bytes.is_empty(), "Media adapter closed its PCM stream");
            let count = bytes.len().min(needed);
            self.incoming.extend_from_slice(&bytes[..count]);
            self.output.consume(count);
        }
    }
    pub async fn read_video_frame(&mut self) -> Result<porthub_components::media::VideoFrame> {
        use porthub_components::media::{VideoFormat, VideoFrame, MAX_VIDEO_NETWORK_FRAME};
        ensure!(
            self.operation == Operation::CaptureCamera,
            "Microphone session cannot provide camera frames"
        );
        loop {
            if self.expected.is_none() && self.incoming.len() == 4 {
                let length = u32::from_le_bytes(self.incoming[..4].try_into().unwrap()) as usize;
                ensure!(
                    length >= 40 && length <= MAX_VIDEO_NETWORK_FRAME,
                    "Invalid camera frame size"
                );
                self.expected = Some(length);
            }
            if self.expected.is_some_and(|n| self.incoming.len() == n + 4) {
                let frame = VideoFrame::decode(&self.incoming[4..])
                    .context("Invalid native camera frame")?;
                self.incoming.fill(0);
                self.incoming.clear();
                self.expected = None;
                ensure!(
                    frame.format == VideoFormat::baseline_mjpeg()
                        && frame.sequence >= self.sequence
                        && self
                            .video_timestamp
                            .is_none_or(|at| frame.source_monotonic_micros >= at),
                    "Camera frame identity or continuity changed"
                );
                self.sequence = frame
                    .sequence
                    .checked_add(1)
                    .context("Camera sequence overflow")?;
                self.video_timestamp = Some(frame.source_monotonic_micros);
                return Ok(frame);
            }
            let need = self.expected.map(|n| n + 4).unwrap_or(4) - self.incoming.len();
            let bytes = self.output.fill_buf().await?;
            ensure!(!bytes.is_empty(), "Camera adapter closed");
            let count = need.min(bytes.len());
            self.incoming.extend_from_slice(&bytes[..count]);
            self.output.consume(count);
        }
    }
    pub async fn write_pcm(&mut self, frame: &[u8]) -> Result<()> {
        validate_pcm(frame)?;
        self.input.write_u32_le(frame.len() as u32).await?;
        self.input.write_all(frame).await?;
        self.input.flush().await?;
        Ok(())
    }
    pub fn stop(&self) {
        self.cancel.cancel();
    }
}
fn validate_pcm(frame: &[u8]) -> Result<()> {
    ensure!(
        !frame.is_empty() && frame.len() <= MAX_PCM_FRAME && frame.len() % 4 == 0,
        "Invalid media PCM frame"
    );
    ensure!(
        frame
            .chunks_exact(4)
            .all(|b| f32::from_le_bytes(b.try_into().unwrap()).is_finite()),
        "Invalid media PCM samples"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_ready_platform_and_operation_matrix()->Result<()> {
        use serde_json::json;
        let source=format!("media:{}","a".repeat(64));
        let mut request=SessionRequest{operation:Operation::CaptureCamera,session:"b".repeat(32),name:"Exact camera".into(),source_id:Some(source.clone()),video_format:Some(porthub_components::media::VideoFormat::baseline_mjpeg()),camera_identity:Some(json!({"local":"proof"}))};
        let mut ready=json!({"session":request.session,"state":"capturing","backend":"windows-mf","source_id":source,"format":request.video_format});
        assert!(validate_native_ready(&request,&ready,ReadyPlatform::Windows).is_ok());
        assert!(validate_native_ready(&request,&ready,ReadyPlatform::PipeWire).is_err());
        ready["backend"]="v4l2".into();assert!(validate_native_ready(&request,&ready,ReadyPlatform::PipeWire).is_ok());assert!(validate_native_ready(&request,&ready,ReadyPlatform::Windows).is_err());
        ready["source_id"]="media:wrong".into();assert!(validate_native_ready(&request,&ready,ReadyPlatform::PipeWire).is_err());ready["source_id"]=request.source_id.clone().unwrap().into();
        ready["format"]["width"]=320.into();assert!(validate_native_ready(&request,&ready,ReadyPlatform::PipeWire).is_err());ready["format"]=serde_json::to_value(request.video_format)?;
        ready["session"]="c".repeat(32).into();assert!(validate_native_ready(&request,&ready,ReadyPlatform::PipeWire).is_err());
        request.operation=Operation::CaptureMicrophone;request.video_format=None;request.camera_identity=None;
        ready=json!({"session":request.session,"state":"capturing","backend":"wasapi","endpoint_id":"exact-endpoint","rate":48000,"channels":1,"format":"f32le"});
        assert!(validate_native_ready(&request,&ready,ReadyPlatform::Windows).is_ok());assert!(validate_native_ready(&request,&ready,ReadyPlatform::PipeWire).is_err());
        ready["endpoint_id"]="".into();assert!(validate_native_ready(&request,&ready,ReadyPlatform::Windows).is_err());ready["endpoint_id"]="exact-endpoint".into();
        ready["backend"]="windows-mf".into();assert!(validate_native_ready(&request,&ready,ReadyPlatform::Windows).is_err());ready["backend"]="wasapi".into();ready["rate"]=44100.into();assert!(validate_native_ready(&request,&ready,ReadyPlatform::Windows).is_err());
        ready["rate"]=48000.into();ready["node_id"]=7.into();assert!(validate_native_ready(&request,&ready,ReadyPlatform::PipeWire).is_ok());
        request.operation=Operation::PublishMicrophone;request.source_id=None;ready["state"]="published".into();assert!(validate_native_ready(&request,&ready,ReadyPlatform::PipeWire).is_ok());assert!(validate_native_ready(&request,&ready,ReadyPlatform::Windows).is_err());
        Ok(())
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn local_policy_and_parent_cancellation_reap_the_adapter_process() -> Result<()> {
        let temp = tempfile::tempdir()?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))?;
        for operation in [Operation::CaptureMicrophone, Operation::PublishMicrophone] {
            for via_policy in [true, false] {
                let child = tokio::process::Command::new("/bin/sleep")
                    .arg("30")
                    .kill_on_drop(true)
                    .spawn()?;
                let pid = child.id().unwrap();
                let (sender, policy) = tokio::sync::watch::channel(features::Policy::default());
                let stop = CancellationToken::new();
                let task = tokio::spawn(supervise(
                    child,
                    temp.path().join("profile.json"),
                    operation,
                    policy,
                    stop.clone(),
                    None,
                ));
                sender.send_modify(|p| {
                    p.disabled.insert(Feature::Keyboard, true);
                });
                ensure!(
                    tokio::time::timeout(Duration::from_millis(70), stop.cancelled())
                        .await
                        .is_err(),
                    "Disabling keyboard must not revoke independent media permission"
                );
                if via_policy {
                    sender.send_modify(|p| {
                        p.disabled.insert(feature(operation), true);
                    });
                } else {
                    stop.cancel();
                }
                tokio::time::timeout(Duration::from_secs(1), task).await??;
                ensure!(stop.is_cancelled());
                ensure!(
                    unsafe { libc::kill(pid as i32, 0) } == -1
                        && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH),
                    "Media adapter was not reaped"
                );
            }
        }
        Ok(())
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn interleaved_policy_events_cannot_consume_partial_pcm_headers() -> Result<()> {
        let temp = tempfile::tempdir()?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))?;
        let mut child = tokio::process::Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        let stop = CancellationToken::new();
        let (_policy, receiver) = tokio::sync::watch::channel(features::Policy::default());
        let task = tokio::spawn(supervise(
            child,
            temp.path().join("policy"),
            Operation::PublishMicrophone,
            receiver,
            stop.clone(),
            None,
        ));
        let mut session = Session {
            input,
            output,
            cancel: stop,
            _supervisor: task,
            ready: serde_json::Value::Null,
            sequence: 0,
            sample_offset: 0,
            clock: std::time::Instant::now(),
            incoming: vec![],
            expected: None,
            operation: Operation::CaptureMicrophone,
            video_timestamp: None,
        };
        session.input.write_all(&[8, 0, 0]).await?;
        ensure!(
            tokio::time::timeout(Duration::from_millis(20), session.read_pcm())
                .await
                .is_err()
        );
        session.input.write_all(&[0, 0, 0, 0]).await?;
        ensure!(
            tokio::time::timeout(Duration::from_millis(20), session.read_pcm())
                .await
                .is_err()
        );
        session.input.write_all(&[0, 0, 0, 0, 0]).await?;
        let frame = tokio::time::timeout(Duration::from_secs(1), session.read_pcm()).await??;
        ensure!(frame == vec![0; 8]);
        session.stop();
        tokio::time::timeout(Duration::from_secs(1), &mut session._supervisor).await??;
        Ok(())
    }
    #[test]
    fn invalid_or_unbounded_pcm_never_reaches_helper() {
        for frame in [
            vec![],
            vec![0; MAX_PCM_FRAME + 4],
            vec![0; 3],
            f32::NAN.to_le_bytes().to_vec(),
        ] {
            assert!(validate_pcm(&frame).is_err());
        }
        assert!(validate_pcm(&[0; 4]).is_ok());
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn camera_shutdown_allows_restore_but_bounds_an_unresponsive_helper() -> Result<()> {
        let root = tempfile::tempdir()?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
        for responds in [true, false] {
            let marker = root
                .path()
                .join(if responds { "restored" } else { "stalled" });
            let script = if responds {
                "import pathlib,sys;print('ready',flush=True);sys.stdin.buffer.read(1);pathlib.Path(sys.argv[1]).write_text('restored')"
            } else {
                "import time;print('ready',flush=True);time.sleep(30)"
            };
            let mut child = tokio::process::Command::new("python3")
                .arg("-c")
                .arg(script)
                .arg(&marker)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .kill_on_drop(true)
                .spawn()?;
            let pid = child.id().unwrap();
            let input = child.stdin.take().unwrap();
            let control = camera_stop(&input, Operation::CaptureCamera)?;
            let mut ready = BufReader::new(child.stdout.take().unwrap());
            let mut line = String::new();
            tokio::time::timeout(Duration::from_secs(2), ready.read_line(&mut line)).await??;
            assert_eq!(line, "ready\n");
            let (_policy, receiver) = tokio::sync::watch::channel(features::Policy::default());
            let stop = CancellationToken::new();
            let start = std::time::Instant::now();
            let task = tokio::spawn(supervise(
                child,
                root.path().join("policy"),
                Operation::CaptureCamera,
                receiver,
                stop.clone(),
                control,
            ));
            stop.cancel();
            tokio::time::timeout(Duration::from_secs(2), task).await??;
            assert_eq!(
                marker.exists(),
                responds,
                "Only an acknowledged camera shutdown can report rollback"
            );
            assert!(!PathBuf::from(format!("/proc/{pid}")).exists());
            if !responds {
                assert!(start.elapsed() >= Duration::from_millis(200));
            }
            assert!(start.elapsed() < Duration::from_secs(1));
            drop(input);
        }
        Ok(())
    }
}
