//! Reuse USB's authenticated path negotiation for an explicitly typed native-media
//! session. Transport does not interpret PCM/JPEG; purpose-specific local hooks
//! validate receiver descriptors before attaching the existing OS controller.
use super::*;
use futures_util::StreamExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;
async fn open_media(control: &Control, id: &str, side: &str) -> Result<Socket> {
    use tokio_tungstenite::tungstenite::{client::IntoClientRequest, protocol::WebSocketConfig};
    ensure!(
        id.len() == 32
            && id.bytes().all(|b| b.is_ascii_hexdigit())
            && matches!(side, "source" | "destination"),
        "Invalid media route"
    );
    for base in control.authorities() {
        let mut url = url::Url::parse(&format!("{base}/api/media/stream/{id}/{side}"))?;
        let scheme = match url.scheme() {
            "https" => "wss",
            "http" if control.profile().allow_insecure_http_for_tests => "ws",
            _ => continue,
        };
        url.set_scheme(scheme)
            .map_err(|_| anyhow::anyhow!("Invalid media gateway"))?;
        let attempt = tokio::time::timeout(Duration::from_secs(12), async {
            let sources = control.stream_sources(&base).await?;
            ensure!(!sources.is_empty(), "No approved media path");
            let stream = porthub_mesh::underlay::connect(&url, &sources).await?;
            porthub_mesh::configure_tcp(&stream);
            stream.set_nodelay(true)?;
            let mut request = url.as_str().into_client_request()?;
            request.headers_mut().insert(
                "x-porthub-machine-id",
                control.profile().machine_id.parse()?,
            );
            request.headers_mut().insert(
                "authorization",
                format!("Bearer {}", control.profile().token).parse()?,
            );
            let (socket, _) = tokio_tungstenite::client_async_tls_with_config(
                request,
                stream,
                Some(
                    WebSocketConfig::default()
                        .max_message_size(Some(262144))
                        .max_frame_size(Some(262144)),
                ),
                None,
            )
            .await?;
            Ok::<_, anyhow::Error>(socket)
        })
        .await;
        if let Ok(Ok(socket)) = attempt {
            control.prefer_proxy_authority(base);
            return Ok(socket);
        }
    }
    anyhow::bail!("Authenticated media gateway unavailable")
}
/// Caller independently enforces source/receiver media policy for the complete
/// lifetime, including before native attachment. USB/direct policies are also
/// retained by the existing transport pumps.
pub(crate) async fn transfer<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    path: &Path,
    control: Arc<Control>,
    id: &str,
    source: bool,
    cancel: CancellationToken,
    ready: tokio::sync::oneshot::Sender<()>,
) -> Result<()> {
    transfer_for(
        stream,
        path,
        control,
        id,
        source,
        cancel,
        ready,
        Feature::MicrophoneShare,
    )
    .await
}
/// Camera plans use the same authenticated path policy, with an independent
/// local source permission. No raw USB feature is required for native media.
pub(crate) async fn transfer_camera<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    path: &Path,
    control: Arc<Control>,
    id: &str,
    source: bool,
    cancel: CancellationToken,
    ready: tokio::sync::oneshot::Sender<()>,
) -> Result<()> {
    transfer_for(
        stream,
        path,
        control,
        id,
        source,
        cancel,
        ready,
        Feature::CameraShare,
    )
    .await
}
async fn transfer_for<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    path: &Path,
    control: Arc<Control>,
    id: &str,
    source: bool,
    cancel: CancellationToken,
    ready: tokio::sync::oneshot::Sender<()>,
    source_feature: Feature,
) -> Result<()> {
    ensure!(
        matches!(
            source_feature,
            Feature::MicrophoneShare | Feature::CameraShare
        ),
        "Invalid media source purpose"
    );
    let diagnostic = |stage| {
        #[cfg(all(test,windows))]
        crate::media::windows_e2e_fixture::diagnostic(path,stage,usize::from(source));
        #[cfg(not(all(test,windows)))]
        let _=stage;
    };
    let work = async {
        diagnostic("websocket-start");
        let mut socket =
            open_media(&control, id, if source { "source" } else { "destination" }).await?;
        diagnostic("websocket-open");
        let peer_ready = tokio::time::timeout(Duration::from_secs(35), socket.next())
            .await?
            .context("Media peer disconnected")??;
        ensure!(
            matches!(peer_ready,tokio_tungstenite::tungstenite::Message::Text(ref text) if text.as_str()=="ready"),
            "Media peer unavailable"
        );
        diagnostic("peer-ready");
        let allowed = crate::terminal_policy::direct_allowed(path, control.profile());
        diagnostic("negotiate-start");
        let carrier = negotiate(&mut socket, source, allowed, &control).await?;
        diagnostic("negotiate-ok");
        #[cfg(all(test, target_os = "linux"))]
        crate::media::e2e_fixture::verify_carrier(carrier.tcp.as_ref(), control.profile())?;
        #[cfg(all(test, target_os = "linux"))]
        crate::media::windows_receiver_fixture::verify_carrier(carrier.tcp.as_ref(), control.profile())?;
        #[cfg(all(test, target_os = "linux"))]
        if source_feature == Feature::CameraShare {
            crate::media::video_e2e_fixture::verify_carrier(
                carrier.tcp.as_ref(),
                control.profile(),
            )?;
        }
        #[cfg(all(test,windows))]
        crate::media::windows_e2e_fixture::verify_carrier(carrier.tcp.as_ref(),control.profile())?;
        #[cfg(all(test,windows))]
        crate::media::windows_video_destination_fixture::verify_carrier(carrier.tcp.as_ref(),control.profile(),id)?;
        let _ = ready.send(());
        if let Some(bulk) = carrier.tcp {
            bridge_bulk_with_policy(
                stream,
                socket,
                bulk,
                features::subscribe(path),
                None,
                carrier.restart,
                if source {
                    source_feature
                } else {
                    Feature::MediaReceive
                },
            )
            .await
        } else {
            bridge_with_policy(
                stream,
                socket,
                carrier.sctp,
                features::subscribe(path),
                None,
                carrier.restart,
                if source {
                    source_feature
                } else {
                    Feature::MediaReceive
                },
            )
            .await
        }
    };
    tokio::select! {biased;_=cancel.cancelled()=>Ok(()),result=work=>result}
}
pub(crate) fn receiver_available() -> bool {
    super::capabilities()[1]
}

#[cfg(any(target_os = "linux", windows))]
fn authorize_audio(
    profile: &Path,
    device: &porthub_components::usb::Device,
    wire: &[u8],
) -> Result<()> {
    ensure!(
        features::enabled(profile, Feature::MediaReceive),
        "Native media receiving disabled by client policy"
    );
    ensure!(
        device.busnum == 65535
            && device.busid == format!("65535-{}", device.devnum)
            && device.speed == 2
            && device.serial.len() == 32
            && device.serial.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid receiver-local audio identity"
    );
    protocol::validate(wire, device)?;
    ensure!(
        wire[306..309] == [0, 0, 0] && wire[309..312] == [1, 1, 2],
        "Only the fixed receiver-local USB Audio Class descriptor is permitted"
    );
    Ok(())
}
#[cfg(any(target_os = "linux", windows))]
pub(crate) async fn attach_audio(
    profile: &Path,
    device: &porthub_components::usb::Device,
    wire: &[u8],
) -> Result<(super::VirtualReceiver, tokio::net::TcpStream)> {
    authorize_audio(profile, device, wire)?;
    #[cfg(target_os = "linux")]
    {
        linux::module(false).await?;
        let (guard, stream) = linux::handoff(profile, device, false)?;
        Ok((
            VirtualReceiver {
                _guard: Handoff::Linux(guard),
            },
            stream,
        ))
    }
    #[cfg(windows)]
    {
        windows::module(false).await?;
        let (guard, stream) = windows::destination(device, wire).await?;
        Ok((
            VirtualReceiver {
                _guard: Handoff::Windows(guard),
            },
            stream,
        ))
    }
}

#[cfg(any(target_os = "linux", windows))]
fn authorize_video(
    profile: &Path,
    device: &porthub_components::usb::Device,
    wire: &[u8],
) -> Result<()> {
    ensure!(
        features::enabled(profile, Feature::MediaReceive),
        "Native camera receiving disabled by client policy"
    );
    ensure!(
        device.busnum == 65535
            && device.busid == format!("65535-{}", device.devnum)
            && device.speed == 3
            && device.serial.len() == 32
            && device.serial.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid receiver-local video identity"
    );
    protocol::validate(wire, device)?;
    ensure!(
        wire[306..309] == [0xef, 2, 1] && wire[309..312] == [1, 1, 2],
        "Only the fixed high-speed USB Video Class descriptor is permitted"
    );
    Ok(())
}
#[cfg(any(target_os = "linux", windows))]
pub(crate) async fn attach_video(
    profile: &Path,
    device: &porthub_components::usb::Device,
    wire: &[u8],
) -> Result<(super::VirtualReceiver, tokio::net::TcpStream)> {
    authorize_video(profile, device, wire)?;
    #[cfg(target_os = "linux")]
    {
        linux::module(false).await?;
        let (guard, stream) = linux::handoff(profile, device, false)?;
        Ok((
            VirtualReceiver {
                _guard: Handoff::Linux(guard),
            },
            stream,
        ))
    }
    #[cfg(windows)]
    {
        windows::module(false).await?;
        let (guard, stream) = windows::destination(device, wire).await?;
        Ok((
            VirtualReceiver {
                _guard: Handoff::Windows(guard),
            },
            stream,
        ))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    #[tokio::test]
    async fn camera_receiving_is_independent_and_rejects_audio_or_wrong_speed() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir()?;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
        let profile = root.path().join("fixture.json");
        for feature in ["usb", "microphone-share", "camera-share"] {
            let (control, _reply) = tokio::io::duplex(4096);
            features::serve(
                tokio::io::BufReader::new(control),
                &profile,
                json!({"operation":"client_features","feature":feature,"enabled":false}),
            )
            .await?;
        }
        let mut device = porthub_components::usb::Device {
            busid: "65535-1".into(),
            vendor: "1209".into(),
            product: "0001".into(),
            serial: "a".repeat(32),
            name: "Private camera fixture".into(),
            busnum: 65535,
            devnum: 1,
            speed: 3,
            blocked: None,
        };
        let mut wire = protocol::legacy_device(&device)?;
        wire[306..309].copy_from_slice(&[0xef, 2, 1]);
        wire[309..312].copy_from_slice(&[1, 1, 2]);
        authorize_video(&profile, &device, &wire)?;
        wire[306..309].fill(0);
        assert!(authorize_video(&profile, &device, &wire).is_err());
        wire[306..309].copy_from_slice(&[0xef, 2, 1]);
        device.speed = 2;
        assert!(authorize_video(&profile, &device, &wire).is_err());
        device.speed = 3;
        let (control, _reply) = tokio::io::duplex(4096);
        features::serve(
            tokio::io::BufReader::new(control),
            &profile,
            json!({"operation":"client_features","feature":"media-receive","enabled":false}),
        )
        .await?;
        assert!(authorize_video(&profile, &device, &wire).is_err());
        Ok(())
    }
    #[tokio::test]
    async fn media_receive_and_raw_usb_permissions_are_independent() -> Result<()> {
        let root = tempfile::tempdir()?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
        let profile = root.path().join("fixture.json");
        let device = porthub_components::usb::Device {
            busid: "65535-1".into(),
            vendor: "1209".into(),
            product: "0001".into(),
            serial: "a".repeat(32),
            name: "Private fixture".into(),
            busnum: 65535,
            devnum: 1,
            speed: 2,
            blocked: None,
        };
        let mut wire = protocol::legacy_device(&device)?;
        wire[306..309].copy_from_slice(&[0, 0, 0]);
        wire[309..312].copy_from_slice(&[1, 1, 2]);
        let (control, _reply) = tokio::io::duplex(4096);
        features::serve(
            tokio::io::BufReader::new(control),
            &profile,
            json!({"operation":"client_features","feature":"usb","enabled":false}),
        )
        .await?;
        authorize_audio(&profile, &device, &wire)?;
        let error = super::super::attach_virtual(&profile, &device, &wire)
            .await
            .err()
            .context("Raw USB must remain disabled")?;
        assert!(error.to_string().contains("disabled"));
        let mut unknown = wire.clone();
        unknown[306] = 8;
        assert!(
            authorize_audio(&profile, &device, &unknown).is_err(),
            "Storage cannot use the audio-only policy boundary"
        );
        let (control, _reply) = tokio::io::duplex(4096);
        features::serve(
            tokio::io::BufReader::new(control),
            &profile,
            json!({"operation":"client_features","feature":"usb","enabled":true}),
        )
        .await?;
        let (control, _reply) = tokio::io::duplex(4096);
        features::serve(
            tokio::io::BufReader::new(control),
            &profile,
            json!({"operation":"client_features","feature":"media-receive","enabled":false}),
        )
        .await?;
        assert!(features::enabled(&profile, Feature::Usb));
        assert!(authorize_audio(&profile, &device, &wire).is_err());
        Ok(())
    }
}
