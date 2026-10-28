//! Wire format of the clipboard channel.
//!
//! Clipboard contents can be several megabytes (e.g. screenshots), so they
//! are not sent over the DTLS input-event channel but over a separate
//! TLS 1.3 stream (TCP, same port number as the UDP listener).
//! Every TCP connection carries exactly one request and one response:
//!
//! ```text
//! request:  "LMCB" | version: u8 | op: u8 | known_hash: [u8; 32] | [content if op == Push]
//! response: status: u8 | [content if status == Content]
//! content:  secret: u8 | mime_len: u8 | mime | data_len: u32 | data
//! ```
//!
//! `known_hash` is the hash of the content last exchanged with the peer, so
//! a [`Op::Pull`] can be answered with [`Status::Unchanged`] instead of
//! transferring the same data again.

use num_enum::{IntoPrimitive, TryFromPrimitive};
use sha2::{Digest, Sha256};
use std::io;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAGIC: &[u8; 4] = b"LMCB";
const VERSION: u8 = 1;

/// maximum size of clipboard data accepted from or sent to a peer
pub(crate) const MAX_CLIPBOARD_SIZE: usize = 32 * 1024 * 1024;

pub(crate) type ContentHash = [u8; 32];

#[derive(Debug, Error)]
pub(crate) enum ProtoError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("not a lan-mouse clipboard stream")]
    BadMagic,
    #[error("unsupported clipboard protocol version {0}")]
    Version(u8),
    #[error("invalid opcode {0}")]
    Op(u8),
    #[error("invalid status {0}")]
    Status(u8),
    #[error("clipboard content too large ({0} bytes)")]
    TooLarge(usize),
    #[error("invalid mime type")]
    Mime,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub(crate) enum Op {
    /// the sender transfers its clipboard to the receiver
    Push = 1,
    /// the sender requests the clipboard of the receiver
    Pull = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub(crate) enum Status {
    /// push accepted
    Ok = 0,
    /// pull answered with content
    Content = 1,
    /// pull: content matches `known_hash`
    Unchanged = 2,
    /// pull: the clipboard is empty or holds no supported type
    Empty = 3,
    /// clipboard sharing is disabled or the content is a secret
    Refused = 4,
    /// the receiver failed to access its clipboard
    Error = 5,
}

/// clipboard content in a single representation
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ClipboardContent {
    /// mime type of `data`, e.g. `text/plain;charset=utf-8` or `image/png`
    pub(crate) mime: String,
    pub(crate) data: Vec<u8>,
    /// marked as sensitive by a password manager (`x-kde-passwordManagerHint`)
    pub(crate) secret: bool,
}

impl std::fmt::Debug for ClipboardContent {
    // never log clipboard data
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClipboardContent")
            .field("mime", &self.mime)
            .field("len", &self.data.len())
            .field("secret", &self.secret)
            .finish()
    }
}

impl ClipboardContent {
    /// hash identifying the content (the secret flag is not part of it)
    pub(crate) fn hash(&self) -> ContentHash {
        let mut hash = Sha256::new();
        hash.update(self.mime.as_bytes());
        hash.update([0]);
        hash.update(&self.data);
        hash.finalize().into()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Request {
    pub(crate) op: Op,
    pub(crate) known_hash: ContentHash,
    /// `Some` iff `op == Op::Push`
    pub(crate) content: Option<ClipboardContent>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Response {
    pub(crate) status: Status,
    /// `Some` iff `status == Status::Content`
    pub(crate) content: Option<ClipboardContent>,
}

impl Response {
    pub(crate) fn status(status: Status) -> Self {
        Self {
            status,
            content: None,
        }
    }
}

pub(crate) async fn write_request<W: AsyncWrite + Unpin>(
    w: &mut W,
    req: &Request,
) -> Result<(), ProtoError> {
    w.write_all(MAGIC).await?;
    w.write_u8(VERSION).await?;
    w.write_u8(req.op.into()).await?;
    w.write_all(&req.known_hash).await?;
    if let Some(content) = &req.content {
        write_content(w, content).await?;
    }
    w.flush().await?;
    Ok(())
}

pub(crate) async fn read_request<R: AsyncRead + Unpin>(r: &mut R) -> Result<Request, ProtoError> {
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic).await?;
    if &magic != MAGIC {
        return Err(ProtoError::BadMagic);
    }
    let version = r.read_u8().await?;
    if version != VERSION {
        return Err(ProtoError::Version(version));
    }
    let op = r.read_u8().await?;
    let op = Op::try_from(op).map_err(|_| ProtoError::Op(op))?;
    let mut known_hash = [0u8; 32];
    r.read_exact(&mut known_hash).await?;
    let content = match op {
        Op::Push => Some(read_content(r).await?),
        Op::Pull => None,
    };
    Ok(Request {
        op,
        known_hash,
        content,
    })
}

pub(crate) async fn write_response<W: AsyncWrite + Unpin>(
    w: &mut W,
    res: &Response,
) -> Result<(), ProtoError> {
    w.write_u8(res.status.into()).await?;
    if let Some(content) = &res.content {
        write_content(w, content).await?;
    }
    w.flush().await?;
    Ok(())
}

pub(crate) async fn read_response<R: AsyncRead + Unpin>(r: &mut R) -> Result<Response, ProtoError> {
    let status = r.read_u8().await?;
    let status = Status::try_from(status).map_err(|_| ProtoError::Status(status))?;
    let content = match status {
        Status::Content => Some(read_content(r).await?),
        _ => None,
    };
    Ok(Response { status, content })
}

async fn write_content<W: AsyncWrite + Unpin>(
    w: &mut W,
    content: &ClipboardContent,
) -> Result<(), ProtoError> {
    let mime_len = u8::try_from(content.mime.len()).map_err(|_| ProtoError::Mime)?;
    if content.data.len() > MAX_CLIPBOARD_SIZE {
        return Err(ProtoError::TooLarge(content.data.len()));
    }
    w.write_u8(content.secret as u8).await?;
    w.write_u8(mime_len).await?;
    w.write_all(content.mime.as_bytes()).await?;
    w.write_u32(content.data.len() as u32).await?;
    w.write_all(&content.data).await?;
    Ok(())
}

async fn read_content<R: AsyncRead + Unpin>(r: &mut R) -> Result<ClipboardContent, ProtoError> {
    let secret = r.read_u8().await? != 0;
    let mime_len = r.read_u8().await? as usize;
    let mut mime = vec![0u8; mime_len];
    r.read_exact(&mut mime).await?;
    let mime = String::from_utf8(mime).map_err(|_| ProtoError::Mime)?;
    if mime.is_empty() || mime.chars().any(|c| c.is_control()) {
        return Err(ProtoError::Mime);
    }
    let len = r.read_u32().await? as usize;
    if len > MAX_CLIPBOARD_SIZE {
        return Err(ProtoError::TooLarge(len));
    }
    let mut data = vec![0u8; len];
    r.read_exact(&mut data).await?;
    Ok(ClipboardContent { mime, data, secret })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(s: &str) -> ClipboardContent {
        ClipboardContent {
            mime: "text/plain;charset=utf-8".into(),
            data: s.as_bytes().to_vec(),
            secret: false,
        }
    }

    #[tokio::test]
    async fn request_roundtrip() {
        for req in [
            Request {
                op: Op::Push,
                known_hash: [7; 32],
                content: Some(text("hola ñandú")),
            },
            Request {
                op: Op::Pull,
                known_hash: [1; 32],
                content: None,
            },
        ] {
            let mut buf = Vec::new();
            write_request(&mut buf, &req).await.unwrap();
            let decoded = read_request(&mut buf.as_slice()).await.unwrap();
            assert_eq!(decoded, req);
        }
    }

    #[tokio::test]
    async fn response_roundtrip() {
        let mut content = text("secret");
        content.secret = true;
        for res in [
            Response {
                status: Status::Content,
                content: Some(content),
            },
            Response::status(Status::Unchanged),
            Response::status(Status::Refused),
        ] {
            let mut buf = Vec::new();
            write_response(&mut buf, &res).await.unwrap();
            let decoded = read_response(&mut buf.as_slice()).await.unwrap();
            assert_eq!(decoded, res);
        }
    }

    #[tokio::test]
    async fn rejects_oversized_content() {
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&[VERSION, Op::Push.into()]);
        buf.extend_from_slice(&[0; 32]);
        buf.extend_from_slice(&[0, 9]);
        buf.extend_from_slice(b"image/png");
        buf.extend_from_slice(&(MAX_CLIPBOARD_SIZE as u32 + 1).to_be_bytes());
        assert!(matches!(
            read_request(&mut buf.as_slice()).await,
            Err(ProtoError::TooLarge(_))
        ));
    }

    #[tokio::test]
    async fn rejects_bad_magic_and_version() {
        let buf = b"XXXX\x01\x02".to_vec();
        assert!(matches!(
            read_request(&mut buf.as_slice()).await,
            Err(ProtoError::BadMagic)
        ));
        let mut buf = MAGIC.to_vec();
        buf.push(VERSION + 1);
        assert!(matches!(
            read_request(&mut buf.as_slice()).await,
            Err(ProtoError::Version(_))
        ));
    }

    #[test]
    fn hash_ignores_secret_flag() {
        let a = text("x");
        let mut b = a.clone();
        b.secret = true;
        assert_eq!(a.hash(), b.hash());
        assert_ne!(a.hash(), text("y").hash());
    }
}
