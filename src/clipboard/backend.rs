//! Access to the local clipboard.
//!
//! The clipboard is only read when the cursor moves to another device or a
//! peer asks for it - there is no polling or monitoring.

use thiserror::Error;

use super::proto::ClipboardContent;

#[derive(Debug, Error)]
pub(crate) enum BackendError {
    #[error("clipboard access is not supported on this platform")]
    Unsupported,
    #[error("clipboard content too large")]
    TooLarge,
    #[error("{0}")]
    Other(String),
}

/// Blocking clipboard access; called from `spawn_blocking`.
pub(crate) trait ClipboardBackend: Send + Sync {
    /// read the clipboard, `None` if it is empty or holds no supported type
    fn read(&self) -> Result<Option<ClipboardContent>, BackendError>;
    /// replace the clipboard with the given content
    fn write(&self, content: ClipboardContent) -> Result<(), BackendError>;
}

pub(crate) fn create() -> Box<dyn ClipboardBackend> {
    #[cfg(wayland_clipboard)]
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        log::info!("using wayland clipboard backend (data-control protocol)");
        return Box::new(wayland::WaylandClipboard);
    }
    log::warn!("no clipboard backend available, clipboard sharing is inactive");
    Box::new(Unsupported)
}

struct Unsupported;

impl ClipboardBackend for Unsupported {
    fn read(&self) -> Result<Option<ClipboardContent>, BackendError> {
        Err(BackendError::Unsupported)
    }

    fn write(&self, _content: ClipboardContent) -> Result<(), BackendError> {
        Err(BackendError::Unsupported)
    }
}

/// pick the representation to transfer: text first, then images (png preferred)
pub(crate) fn select_mime<'a>(mut offered: impl Iterator<Item = &'a str> + Clone) -> Option<Mime> {
    if offered.clone().any(is_text) {
        return Some(Mime::Text);
    }
    if offered.clone().any(|m| m == "image/png") {
        return Some(Mime::Image("image/png".into()));
    }
    offered
        .find(|m| m.starts_with("image/"))
        .map(|m| Mime::Image(m.to_owned()))
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Mime {
    Text,
    Image(String),
}

pub(crate) const TEXT_MIME: &str = "text/plain;charset=utf-8";

fn is_text(mime: &str) -> bool {
    matches!(mime, "TEXT" | "STRING" | "UTF8_STRING")
        || mime == "text/plain"
        || mime.starts_with("text/plain;")
}

#[cfg(wayland_clipboard)]
mod wayland {
    use std::io::Read;

    use wl_clipboard_rs::{
        copy::{self, Options, Source},
        paste::{self, ClipboardType, Seat},
        utils::PASSWORD_MANAGER_HINT_MIME_TYPE,
    };

    use super::{BackendError, ClipboardBackend, Mime, TEXT_MIME, select_mime};
    use crate::clipboard::proto::{ClipboardContent, MAX_CLIPBOARD_SIZE};

    pub(super) struct WaylandClipboard;

    fn read_mime(mime: paste::MimeType<'_>, limit: usize) -> Result<Vec<u8>, BackendError> {
        let (pipe, _) = paste::get_contents(ClipboardType::Regular, Seat::Unspecified, mime)
            .map_err(|e| BackendError::Other(e.to_string()))?;
        let mut data = Vec::new();
        pipe.take(limit as u64 + 1)
            .read_to_end(&mut data)
            .map_err(|e| BackendError::Other(e.to_string()))?;
        if data.len() > limit {
            return Err(BackendError::TooLarge);
        }
        Ok(data)
    }

    impl ClipboardBackend for WaylandClipboard {
        fn read(&self) -> Result<Option<ClipboardContent>, BackendError> {
            let offered = match paste::get_mime_types(ClipboardType::Regular, Seat::Unspecified) {
                Ok(m) => m,
                Err(paste::Error::ClipboardEmpty | paste::Error::NoSeats) => return Ok(None),
                Err(e) => return Err(BackendError::Other(e.to_string())),
            };

            // KeePassXC & co. mark passwords with `x-kde-passwordManagerHint: secret`.
            // If the hint is offered but cannot be read, assume a secret.
            let secret = offered.contains(PASSWORD_MANAGER_HINT_MIME_TYPE)
                && read_mime(
                    paste::MimeType::Specific(PASSWORD_MANAGER_HINT_MIME_TYPE),
                    64,
                )
                .map(|v| v.trim_ascii() == b"secret")
                .unwrap_or(true);

            let Some(mime) = select_mime(offered.iter().map(String::as_str)) else {
                return Ok(None);
            };
            let (mime, data) = match mime {
                Mime::Text => (
                    TEXT_MIME.to_owned(),
                    read_mime(paste::MimeType::Text, MAX_CLIPBOARD_SIZE)?,
                ),
                Mime::Image(m) => {
                    let data = read_mime(paste::MimeType::Specific(&m), MAX_CLIPBOARD_SIZE)?;
                    (m, data)
                }
            };
            Ok(Some(ClipboardContent { mime, data, secret }))
        }

        fn write(&self, content: ClipboardContent) -> Result<(), BackendError> {
            let mime = if content.mime == TEXT_MIME {
                copy::MimeType::Text
            } else {
                copy::MimeType::Specific(content.mime)
            };
            let mut opts = Options::new();
            // keep secrets out of clipboard managers' history on this device, too
            opts.sensitive(content.secret);
            // served from a background thread until the clipboard is replaced
            opts.copy(Source::Bytes(content.data.into_boxed_slice()), mime)
                .map_err(|e| BackendError::Other(e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_text_then_png() {
        let sel = |m: &[&str]| select_mime(m.iter().copied());
        assert_eq!(sel(&["image/png", "UTF8_STRING"]), Some(Mime::Text));
        assert_eq!(
            sel(&["image/jpeg", "image/png", "x-kde-passwordManagerHint"]),
            Some(Mime::Image("image/png".into()))
        );
        assert_eq!(sel(&["image/jpeg"]), Some(Mime::Image("image/jpeg".into())));
        assert_eq!(sel(&["text/html", "application/x-foo"]), None);
        assert_eq!(sel(&[]), None);
    }

    /// exercises the real clipboard of the running session (overwrites it):
    /// `cargo test -p lan-mouse wayland_roundtrip -- --ignored`
    #[cfg(wayland_clipboard)]
    #[test]
    #[ignore]
    fn wayland_roundtrip() {
        let backend = create();
        for (mime, data, secret) in [
            (TEXT_MIME, "lan-mouse ñ 🦊".as_bytes().to_vec(), false),
            (TEXT_MIME, b"hunter2".to_vec(), true),
            ("image/png", vec![0x89, b'P', b'N', b'G', 0, 1, 2], false),
        ] {
            let content = ClipboardContent {
                mime: mime.into(),
                data,
                secret,
            };
            backend.write(content.clone()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(200));
            assert_eq!(backend.read().unwrap(), Some(content));
        }
    }
}
