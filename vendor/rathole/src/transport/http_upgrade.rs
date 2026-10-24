//! HTTP/1.1 Upgrade on the shared PortHub URL. Buffered bytes after the header
//! are retained for the framed tunnel, including pipelined handshake bytes.
use super::framed::SUBPROTOCOL;
use anyhow::{bail, Result};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

const MAX_HEADER: usize = 16 * 1024;
async fn header<S: AsyncRead + Unpin>(stream: &mut BufReader<S>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    loop {
        let room = MAX_HEADER.saturating_sub(bytes.len());
        let n = (&mut *stream)
            .take((room + 1) as u64)
            .read_until(b'\n', &mut bytes)
            .await?;
        if n == 0 {
            bail!("truncated HTTP upgrade header");
        }
        if bytes.len() > MAX_HEADER {
            bail!("HTTP upgrade header too large");
        }
        if bytes.ends_with(b"\r\n\r\n") {
            return Ok(bytes);
        }
    }
}
fn contains(headers: &[httparse::Header<'_>], name: &str, value: &str) -> bool {
    headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case(name))
        .any(|h| {
            std::str::from_utf8(h.value)
                .ok()
                .is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(value)))
        })
}

pub async fn client<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    host: &str,
    path: &str,
) -> Result<BufReader<S>> {
    if host
        .bytes()
        .chain(path.bytes())
        .any(|b| b.is_ascii_control() || b == b' ')
    {
        bail!("invalid HTTP upgrade target");
    }
    let mut stream = BufReader::new(stream);
    stream.write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: {SUBPROTOCOL}\r\n\r\n").as_bytes()).await?;
    stream.flush().await?;
    let bytes = header(&mut stream).await?;
    let mut slots = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut slots);
    if !response.parse(&bytes)?.is_complete()
        || response.version != Some(1)
        || response.code != Some(101)
        || !contains(response.headers, "connection", "upgrade")
        || !contains(response.headers, "upgrade", SUBPROTOCOL)
    {
        bail!("server refused PortHub HTTP upgrade");
    }
    Ok(stream)
}

pub async fn server<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    path: &str,
) -> Result<BufReader<S>> {
    let mut stream = BufReader::new(stream);
    let bytes = header(&mut stream).await?;
    let mut slots = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut slots);
    if !request.parse(&bytes)?.is_complete()
        || request.version != Some(1)
        || request.method != Some("GET")
        || request.path != Some(path)
        || !contains(request.headers, "connection", "upgrade")
        || !contains(request.headers, "upgrade", SUBPROTOCOL)
    {
        bail!("invalid PortHub HTTP upgrade request");
    }
    stream.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: {SUBPROTOCOL}\r\n\r\n").as_bytes()).await?;
    stream.flush().await?;
    Ok(stream)
}
