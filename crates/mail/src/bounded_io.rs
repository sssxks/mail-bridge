//! Guard IMAP literals before the mature parser sees an advertised length.
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Maximum accepted full message size: 2 MiB.
pub const MAX_MAIL: usize = 2 * 1024 * 1024;
/// Maximum advertised literal size, allowing bounded header overhead.
const MAX_LITERAL: usize = MAX_MAIL + 8192;
/// Maximum retained IMAP protocol line: 64 KiB.
const MAX_LINE: usize = 64 * 1024;
/// Maximum bytes observed on one guarded IMAP connection: 4 MiB.
const MAX_TRANSFER: usize = 4 * 1024 * 1024;

/// Parse and bound a protocol literal length before the IMAP parser allocates it.
fn literal_length(line: &[u8]) -> io::Result<Option<usize>> {
    if !line.ends_with(b"}\r\n") {
        return Ok(None);
    }
    let Some(start) = line.iter().rposition(|&byte| byte == b'{') else {
        return Ok(None);
    };
    let raw = &line[start + 1..line.len() - 3];
    let raw = raw.strip_suffix(b"+").unwrap_or(raw);
    let length = std::str::from_utf8(raw)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .ok_or_else(|| io::Error::other("Invalid literal"))?;
    if length > MAX_LITERAL {
        return Err(io::Error::other("IMAP literal limit"));
    }
    Ok(Some(length))
}

/// Bounded protocol wrapper `Inner × TransferBytes × PartialLine × RemainingLiteral`.
/// Private counters/buffers inspect each received byte before the upstream IMAP parser sees it.
#[derive(Debug)]
pub struct GuardIo<T> {
    /// Owned underlying connection or IO object.
    pub inner: T,
    /// Bytes observed across this guarded IMAP connection.
    total: usize,
    /// Reusable partial protocol-line buffer, bounded by MAX_LINE.
    line: Vec<u8>,
    /// Number of literal bytes remaining; these bytes bypass protocol-line parsing.
    literal: usize,
}
impl<T> GuardIo<T> {
    /// Construct this component from its explicit dependencies.
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            total: 0,
            line: Vec::with_capacity(128),
            literal: 0,
        }
    }
    /// Account received bytes and enforce line, literal and transfer limits.
    fn inspect(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.total = self.total.saturating_add(bytes.len());
        if self.total > MAX_TRANSFER {
            return Err(io::Error::other("IMAP transfer limit"));
        }
        for &byte in bytes {
            if self.literal > 0 {
                self.literal -= 1;
                continue;
            }
            self.line.push(byte);
            if self.line.len() > MAX_LINE {
                return Err(io::Error::other("IMAP response line limit"));
            }
            if byte == b'\n' {
                self.literal = literal_length(&self.line)?.unwrap_or_default();
                self.line.clear();
            }
        }
        Ok(())
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for GuardIo<T> {
    /// Read into a bounded scratch buffer and inspect bytes before exposing them upstream.
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut data = [0u8; 8192];
        let length = buf.remaining().min(data.len());
        let mut read = ReadBuf::new(&mut data[..length]);
        match Pin::new(&mut self.inner).poll_read(cx, &mut read) {
            Poll::Ready(Ok(())) => {
                let bytes = read.filled();
                if let Err(e) = self.inspect(bytes) {
                    return Poll::Ready(Err(e));
                }
                buf.put_slice(bytes);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for GuardIo<T> {
    /// Delegate writing to the owned underlying IO object.
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    /// Flush the owned underlying IO object.
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    /// Shut down the owned underlying IO object.
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_literal_lengths_and_rejects_invalid_values() {
        assert_eq!(
            literal_length(b"* 1 FETCH (BODY[] {42}\r\n").unwrap(),
            Some(42)
        );
        assert_eq!(
            literal_length(b"* 1 FETCH (BODY[] {42+}\r\n").unwrap(),
            Some(42)
        );
        assert_eq!(literal_length(b"* OK ready\r\n").unwrap(), None);
        assert!(literal_length(b"* 1 FETCH (BODY[] {oops}\r\n").is_err());
        assert!(
            literal_length(format!("* 1 FETCH (BODY[] {{{}}}\r\n", MAX_LITERAL + 1).as_bytes())
                .is_err()
        );
    }

    #[test]
    fn tracks_fragmented_headers_without_parsing_literal_contents_as_lines() {
        let mut guard = GuardIo::new(());
        guard.inspect(b"* 1 FETCH (BODY[] {1").unwrap();
        guard.inspect(b"2}\r\nline one\nli").unwrap();
        assert_eq!(guard.literal, 1);
        assert!(guard.line.is_empty());

        guard.inspect(b"n").unwrap();
        assert_eq!(guard.literal, 0);
        assert!(guard.line.is_empty());

        guard.inspect(b")\r\n").unwrap();
        assert!(guard.line.is_empty());
    }

    #[test]
    fn enforces_line_and_transfer_limits() {
        let mut line_guard = GuardIo::new(());
        assert!(line_guard.inspect(&vec![b'x'; MAX_LINE + 1]).is_err());

        let mut transfer_guard = GuardIo::new(());
        transfer_guard.total = MAX_TRANSFER;
        assert!(transfer_guard.inspect(b"x").is_err());
    }
}
