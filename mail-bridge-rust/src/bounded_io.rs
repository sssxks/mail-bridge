//! Guard IMAP literals before the mature parser sees an advertised length.
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
pub const MAX_MAIL: usize = 2 * 1024 * 1024;
#[derive(Debug)]
pub struct GuardIo<T> {
    pub inner: T,
    total: usize,
    line: Vec<u8>,
    literal: usize,
}
impl<T> GuardIo<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            total: 0,
            line: Vec::with_capacity(128),
            literal: 0,
        }
    }
    fn inspect(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.total += bytes.len();
        if self.total > 4 * 1024 * 1024 {
            return Err(io::Error::other("IMAP transfer limit"));
        }
        for &byte in bytes {
            if self.literal > 0 {
                self.literal -= 1;
                continue;
            }
            self.line.push(byte);
            if self.line.len() > 65536 {
                return Err(io::Error::other("IMAP response line limit"));
            }
            if byte == b'\n' {
                if self.line.ends_with(b"}\r\n")
                    && let Some(start) = self.line.iter().rposition(|&b| b == b'{')
                {
                    let raw = &self.line[start + 1..self.line.len() - 3];
                    let raw = raw.strip_suffix(b"+").unwrap_or(raw);
                    let number = std::str::from_utf8(raw)
                        .ok()
                        .and_then(|s| s.parse::<usize>().ok())
                        .ok_or_else(|| io::Error::other("Invalid literal"))?;
                    if number > MAX_MAIL + 8192 {
                        return Err(io::Error::other("IMAP literal limit"));
                    }
                    self.literal = number;
                }
                self.line.clear();
            }
        }
        Ok(())
    }
}
impl<T: AsyncRead + Unpin> AsyncRead for GuardIo<T> {
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
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
