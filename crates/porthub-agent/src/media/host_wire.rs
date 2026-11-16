//! Cancellation-safe framing on the already OS-authenticated local user broker.
use anyhow::{ensure, Result};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
const MAX: usize = 128 * 1024;
pub struct Reader<R> {
    reader: BufReader<R>,
    pending: Vec<u8>,
    expected: Option<usize>,
    limit: usize,
}
impl<R: AsyncRead + Unpin> Reader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader: BufReader::new(reader),
            pending: vec![],
            expected: None,
            limit: MAX,
        }
    }
    /// Only an authenticated camera session may opt into the larger frame bound.
    /// The ordinary constructor and all PHM1 callers retain 128 KiB.
    pub fn camera(reader: R) -> Self {
        let mut value = Self::new(reader);
        value.limit = porthub_components::media::MAX_VIDEO_NETWORK_FRAME + 33;
        value
    }
    pub async fn next(&mut self) -> Result<Vec<u8>> {
        loop {
            if self.expected.is_none() && self.pending.len() == 4 {
                let length = u32::from_le_bytes(self.pending[..4].try_into().unwrap()) as usize;
                ensure!(
                    length > 0 && length <= self.limit,
                    "Media broker frame exceeds bound"
                );
                self.expected = Some(length);
            }
            if self
                .expected
                .is_some_and(|length| self.pending.len() == length + 4)
            {
                let frame = self.pending.split_off(4);
                self.pending.clear();
                self.expected = None;
                return Ok(frame);
            }
            let need = self.expected.map(|n| n + 4).unwrap_or(4) - self.pending.len();
            let bytes = self.reader.fill_buf().await?;
            ensure!(!bytes.is_empty(), "Media user broker closed");
            let count = need.min(bytes.len());
            self.pending.extend_from_slice(&bytes[..count]);
            self.reader.consume(count);
        }
    }
}
impl<R> Drop for Reader<R> {
    fn drop(&mut self) {
        self.pending.fill(0);
    }
}
/// Separate camera writer: the existing microphone/control writer stays strict.
pub async fn write_camera<W: AsyncWrite + Unpin>(writer: &mut W, frame: &[u8]) -> Result<()> {
    ensure!(
        !frame.is_empty() && frame.len() <= porthub_components::media::MAX_VIDEO_NETWORK_FRAME + 33,
        "Invalid camera broker frame"
    );
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        writer.write_u32_le(frame.len() as u32).await?;
        writer.write_all(frame).await?;
        writer.flush().await
    })
    .await??;
    Ok(())
}
pub fn video(session: &str, frame: &porthub_components::media::VideoFrame) -> Option<Vec<u8>> {
    if session.len() != 32 || !session.bytes().all(|v| v.is_ascii_hexdigit()) {
        return None;
    }
    let encoded = frame.encode()?;
    let mut bytes = Vec::with_capacity(33 + encoded.len());
    bytes.push(1);
    bytes.extend(session.as_bytes());
    bytes.extend(encoded);
    Some(bytes)
}
pub fn parse_video(bytes: &[u8], session: &str) -> Option<porthub_components::media::VideoFrame> {
    if session.len() != 32
        || !session.bytes().all(|v| v.is_ascii_hexdigit())
        || bytes.len() < 33
        || bytes.len() > porthub_components::media::MAX_VIDEO_NETWORK_FRAME + 33
        || bytes[0] != 1
        || &bytes[1..33] != session.as_bytes()
    {
        return None;
    }
    porthub_components::media::VideoFrame::decode(&bytes[33..])
}
pub async fn write<W: AsyncWrite + Unpin>(writer: &mut W, frame: &[u8]) -> Result<()> {
    ensure!(
        !frame.is_empty() && frame.len() <= MAX,
        "Invalid media broker frame"
    );
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        writer.write_u32_le(frame.len() as u32).await?;
        writer.write_all(frame).await?;
        writer.flush().await
    })
    .await??;
    Ok(())
}
pub async fn json<W: AsyncWrite + Unpin>(writer: &mut W, value: &serde_json::Value) -> Result<()> {
    write(writer, &serde_json::to_vec(value)?).await
}
pub fn pcm(session: &str, frame: &porthub_components::media::PcmFrame) -> Option<Vec<u8>> {
    if session.len() != 32 || !session.bytes().all(|v| v.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = Vec::with_capacity(1 + 32 + porthub_components::media::MAX_NETWORK_FRAME);
    bytes.push(0);
    bytes.extend(session.as_bytes());
    bytes.extend(frame.encode()?);
    Some(bytes)
}
pub fn parse_pcm(bytes: &[u8], session: &str) -> Option<porthub_components::media::PcmFrame> {
    if bytes.len() < 33 || bytes[0] != 0 || &bytes[1..33] != session.as_bytes() {
        return None;
    }
    porthub_components::media::PcmFrame::decode(&bytes[33..])
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn local_frames_survive_control_interruption_and_reject_size_before_allocation(
    ) -> Result<()> {
        let (mut send, read) = tokio::io::duplex(32);
        let mut reader = Reader::new(read);
        send.write_all(&[3, 0]).await?;
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), reader.next())
                .await
                .is_err()
        );
        send.write_all(&[0, 0, b'a']).await?;
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), reader.next())
                .await
                .is_err()
        );
        send.write_all(b"bc").await?;
        assert_eq!(reader.next().await?, b"abc");
        send.write_all(&u32::MAX.to_le_bytes()).await?;
        assert!(reader.next().await.is_err());
        Ok(())
    }
    #[tokio::test]
    async fn camera_limit_is_opt_in_and_headers_remain_cancellation_safe() -> Result<()> {
        use tokio::io::AsyncWriteExt;
        let size = MAX + 1;
        let (mut send, read) = tokio::io::duplex(64);
        let mut ordinary = Reader::new(read);
        send.write_u32_le(size as u32).await?;
        assert!(ordinary.next().await.is_err());
        let (mut send, read) = tokio::io::duplex(64);
        let mut camera = Reader::camera(read);
        let task = tokio::spawn(async move {
            send.write_u32_le(size as u32).await?;
            send.write_all(&vec![7; size]).await?;
            Ok::<_, std::io::Error>(())
        });
        assert_eq!(camera.next().await?, vec![7; size]);
        task.await??;
        let (mut send, read) = tokio::io::duplex(64);
        let mut camera = Reader::camera(read);
        send.write_all(&[3, 0]).await?;
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(5), camera.next())
                .await
                .is_err()
        );
        send.write_all(&[0, 0, 1, 2, 3]).await?;
        assert_eq!(camera.next().await?, vec![1, 2, 3]);
        send.write_u32_le((porthub_components::media::MAX_VIDEO_NETWORK_FRAME + 34) as u32)
            .await?;
        assert!(camera.next().await.is_err());
        Ok(())
    }
    #[test]
    fn camera_frames_are_nonce_and_type_bound() {
        use porthub_components::media::{VideoEncoding, VideoFormat, VideoFrame};
        let frame = VideoFrame {
            sequence: 0,
            source_monotonic_micros: 0,
            format: VideoFormat {
                encoding: VideoEncoding::Mjpeg,
                width: 640,
                height: 480,
                fps_num: 15,
                fps_den: 1,
            },
            jpeg: include_bytes!("../../tests/data/private_uvc_colorbars_640x480.jpg").to_vec(),
        };
        let epoch = "a".repeat(32);
        let mut bytes = video(&epoch, &frame).unwrap();
        assert_eq!(parse_video(&bytes, &epoch), Some(frame));
        assert!(parse_video(&bytes, &"b".repeat(32)).is_none());
        bytes[0] = 0;
        assert!(parse_video(&bytes, &epoch).is_none());
        assert!(video(
            "invalid",
            &porthub_components::media::VideoFrame {
                sequence: 0,
                source_monotonic_micros: 0,
                format: porthub_components::media::VideoFormat {
                    encoding: porthub_components::media::VideoEncoding::Mjpeg,
                    width: 1,
                    height: 1,
                    fps_num: 1,
                    fps_den: 1
                },
                jpeg: vec![]
            }
        )
        .is_none());
    }
    #[test]
    fn pcm_is_bound_to_exact_local_session_not_just_message_type() {
        let f = porthub_components::media::PcmFrame {
            sequence: 0,
            sample_offset: 0,
            source_monotonic_micros: 0,
            pcm: vec![0; 4],
        };
        let session = "a".repeat(32);
        let bytes = pcm(&session, &f).unwrap();
        assert_eq!(parse_pcm(&bytes, &session), Some(f));
        assert!(parse_pcm(&bytes, &"b".repeat(32)).is_none());
    }
}
