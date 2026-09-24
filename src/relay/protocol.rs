//! The wire format of a relay session, version 2.
//!
//! The client writes the header line, then frames: a byte for the kind, a
//! big-endian `u32` length and the payload. A data frame carries up to
//! [`MAX_DATA`] bytes of the file; a control frame carries a JSON object
//! of up to [`MAX_CONTROL`] bytes, a password answer for one. The relay
//! keeps answering in JSON lines, as in version 1, with two more kinds:
//! `{"credit": n}` and `{"need": …}`.
//!
//! Credit keeps a control frame from waiting behind megabytes of data
//! that the relay has no room for yet: the client may have
//! [`INITIAL_CREDIT`] bytes of data in flight, and every `credit` line
//! allows that many more. Control frames need no credit and go first.

use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};
use tokio::sync::{Notify, mpsc};

use crate::{Error, Result};

/// A frame of file bytes.
pub const DATA: u8 = 1;
/// A frame with one JSON object.
pub const CONTROL: u8 = 2;
/// The most a data frame carries.
pub const MAX_DATA: usize = 1 << 20;
/// The most a control frame carries.
pub const MAX_CONTROL: usize = 64 << 10;
/// Data bytes the client may send before the first `credit` line.
pub const INITIAL_CREDIT: u64 = 4 << 20;
/// The relay grants more credit in steps of this size.
pub const CREDIT_STEP: u64 = 1 << 20;
/// What the client's feeder puts into one data frame.
pub const CHUNK: usize = 64 << 10;

/// One frame, decoded.
#[derive(Debug)]
pub enum Frame {
    Data(Vec<u8>),
    Control(Value),
}

/// The next frame, or `None` when the input ended between frames.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Frame>> {
    let mut head = [0u8; 5];
    match reader.read_exact(&mut head).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let kind = head[0];
    let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
    let limit = match kind {
        DATA => MAX_DATA,
        CONTROL => MAX_CONTROL,
        other => return Err(bad(format!("unknown frame kind {other}"))),
    };
    if len > limit {
        return Err(bad(format!(
            "frame of {len} bytes is longer than {limit} bytes"
        )));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            bad("the input ended inside a frame".to_string())
        } else {
            e.into()
        }
    })?;
    Ok(Some(match kind {
        DATA => Frame::Data(payload),
        _ => Frame::Control(
            serde_json::from_slice(&payload).map_err(|e| bad(format!("control frame: {e}")))?,
        ),
    }))
}

/// A frame of `kind` around `payload`, ready to write.
pub fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 5);
    out.push(kind);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// A control frame with `value`.
pub fn control(value: &Value) -> Vec<u8> {
    frame(CONTROL, value.to_string().as_bytes())
}

fn bad(what: String) -> Error {
    Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, what))
}

/// The relay's side of the credit: data frames arrive on a channel, and
/// whatever the copy takes out of it is reported on `consumed`, so the
/// relay can grant that much more.
pub struct ChannelReader {
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    pending: Vec<u8>,
    offset: usize,
    consumed: mpsc::UnboundedSender<u64>,
}

impl ChannelReader {
    pub fn new(
        rx: mpsc::UnboundedReceiver<Vec<u8>>,
        consumed: mpsc::UnboundedSender<u64>,
    ) -> ChannelReader {
        ChannelReader {
            rx,
            pending: Vec::new(),
            offset: 0,
            consumed,
        }
    }
}

impl AsyncRead for ChannelReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // An empty chunk is skipped: 0 bytes read would mean the end.
        while self.offset >= self.pending.len() {
            match self.rx.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(chunk)) => {
                    self.pending = chunk;
                    self.offset = 0;
                }
            }
        }
        let n = buf.remaining().min(self.pending.len() - self.offset);
        buf.put_slice(&self.pending[self.offset..self.offset + n]);
        self.offset += n;
        if self.offset >= self.pending.len() {
            // The chunk is out of memory: room for that much more.
            let _ = self.consumed.send(self.pending.len() as u64);
            self.pending = Vec::new();
            self.offset = 0;
        }
        Poll::Ready(Ok(()))
    }
}

/// The client's side of the credit: how many data bytes may still be
/// sent, topped up by every `credit` line.
pub struct Credit {
    left: Mutex<u64>,
    more: Notify,
}

impl Credit {
    pub fn new(initial: u64) -> Credit {
        Credit {
            left: Mutex::new(initial),
            more: Notify::new(),
        }
    }

    pub fn grant(&self, n: u64) {
        *self.left.lock().unwrap_or_else(|e| e.into_inner()) += n;
        self.more.notify_one();
    }

    /// Wait until `n` bytes may be sent, and take them.
    pub async fn take(&self, n: u64) {
        loop {
            {
                let mut left = self.left.lock().unwrap_or_else(|e| e.into_inner());
                if *left >= n {
                    *left -= n;
                    return;
                }
            }
            self.more.notified().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn frames_round_trip() {
        let mut bytes = frame(DATA, b"hello");
        bytes.extend(control(&json!({ "password": { "id": 1 } })));
        let mut cursor = std::io::Cursor::new(bytes);
        match read_frame(&mut cursor).await.unwrap().unwrap() {
            Frame::Data(d) => assert_eq!(d, b"hello"),
            other => panic!("{other:?}"),
        }
        match read_frame(&mut cursor).await.unwrap().unwrap() {
            Frame::Control(v) => assert_eq!(v["password"]["id"], 1),
            other => panic!("{other:?}"),
        }
        assert!(read_frame(&mut cursor).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn bad_frames_are_errors() {
        for (bytes, what) in [
            (vec![9, 0, 0, 0, 0], "unknown frame kind"),
            (frame(DATA, b"abc")[..6].to_vec(), "ended inside"),
            (vec![DATA, 0xff, 0, 0, 0], "longer than"),
            (frame(CONTROL, b"nope"), "control frame"),
        ] {
            let mut cursor = std::io::Cursor::new(bytes);
            let err = read_frame(&mut cursor).await.unwrap_err().to_string();
            assert!(err.contains(what), "{err}");
        }
    }

    #[tokio::test]
    async fn the_reader_reports_what_it_consumed() {
        let (tx, rx) = mpsc::unbounded_channel();
        let (ctx, mut crx) = mpsc::unbounded_channel();
        let mut reader = ChannelReader::new(rx, ctx);
        tx.send(vec![1; 10]).unwrap();
        tx.send(Vec::new()).unwrap();
        tx.send(vec![2; 5]).unwrap();
        drop(tx);
        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.unwrap();
        assert_eq!(out.len(), 15);
        assert_eq!(crx.recv().await, Some(10));
        assert_eq!(crx.recv().await, Some(5));
    }

    #[tokio::test]
    async fn credit_blocks_until_granted() {
        let credit = std::sync::Arc::new(Credit::new(3));
        credit.take(3).await;
        let waiting = {
            let credit = credit.clone();
            tokio::spawn(async move { credit.take(2).await })
        };
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        credit.grant(2);
        waiting.await.unwrap();
    }
}
