//! Clipboard sharing.
//!
//! The clipboard follows the cursor: when the cursor moves to a remote
//! device, the local clipboard is pushed to it, and when the cursor comes
//! back, the clipboard of the remote device is pulled. Both requests are
//! always initiated by the device capturing the input, so only the
//! listening side needs to accept clipboard connections (TCP, same port
//! number as the DTLS listener).
//!
//! Content marked as secret by a password manager is only sent if
//! explicitly allowed via [`ClipboardSettings::allow_secrets`].

mod backend;
mod proto;
mod tls;

use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    future::Future,
    io,
    net::SocketAddr,
    rc::Rc,
    sync::{Arc, RwLock},
    time::Duration,
};

use lan_mouse_ipc::ClientHandle;
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::{JoinHandle, spawn_blocking, spawn_local},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use webrtc_dtls::crypto::Certificate;

use crate::{client::ClientManager, crypto};
use backend::{BackendError, ClipboardBackend};
use proto::{ClipboardContent, ContentHash, Op, ProtoError, Request, Response, Status};

/// time to wait for the connection to a client to be established
/// (the cursor can enter a client before it is connected)
const PEER_WAIT: Duration = Duration::from_secs(3);
/// timeout for local clipboard access
const BACKEND_TIMEOUT: Duration = Duration::from_secs(3);
/// timeout for a complete clipboard transfer
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ClipboardSettings {
    /// share the clipboard with other devices
    pub(crate) enabled: bool,
    /// also send content marked as secret by a password manager
    pub(crate) allow_secrets: bool,
}

#[derive(Debug, Error)]
pub(crate) enum ClipboardError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Tls(#[from] rustls::Error),
    #[error(transparent)]
    Proto(#[from] ProtoError),
    #[error(transparent)]
    Backend(#[from] BackendError),
    #[error("timeout")]
    Timeout,
}

struct Shared {
    cert: Certificate,
    acceptor: TlsAcceptor,
    backend: Arc<dyn ClipboardBackend>,
    client_manager: ClientManager,
    settings: Cell<ClipboardSettings>,
    /// hash of the content last exchanged with a peer (by certificate fingerprint)
    last_exchanged: RefCell<HashMap<String, ContentHash>>,
}

pub(crate) struct Clipboard {
    shared: Rc<Shared>,
    port: u16,
    listen_task: Option<JoinHandle<()>>,
}

impl Clipboard {
    pub(crate) fn new(
        cert: Certificate,
        authorized_keys: Arc<RwLock<HashMap<String, String>>>,
        client_manager: ClientManager,
        settings: ClipboardSettings,
        port: u16,
    ) -> Result<Self, rustls::Error> {
        let acceptor = TlsAcceptor::from(tls::server_config(&cert, authorized_keys)?);
        let shared = Rc::new(Shared {
            cert,
            acceptor,
            backend: Arc::from(backend::create()),
            client_manager,
            settings: Cell::new(ClipboardSettings::default()),
            last_exchanged: Default::default(),
        });
        let mut clipboard = Self {
            shared,
            port,
            listen_task: None,
        };
        clipboard.set_settings(settings);
        Ok(clipboard)
    }

    pub(crate) fn settings(&self) -> ClipboardSettings {
        self.shared.settings.get()
    }

    pub(crate) fn set_settings(&mut self, settings: ClipboardSettings) {
        log::info!(
            "clipboard sharing: {}, sending secrets: {}",
            if settings.enabled { "on" } else { "off" },
            if settings.allow_secrets { "on" } else { "off" },
        );
        self.shared.settings.set(settings);
        match (settings.enabled, &self.listen_task) {
            (true, None) => self.start_listener(),
            (false, Some(_)) => self.stop_listener(),
            _ => {}
        }
    }

    pub(crate) fn change_port(&mut self, port: u16) {
        self.port = port;
        if self.listen_task.is_some() {
            self.stop_listener();
            self.start_listener();
        }
    }

    pub(crate) fn terminate(&mut self) {
        self.stop_listener();
    }

    fn start_listener(&mut self) {
        let task = spawn_local(listen(self.port, self.shared.clone()));
        self.listen_task = Some(task);
    }

    fn stop_listener(&mut self) {
        if let Some(task) = self.listen_task.take() {
            task.abort();
        }
    }

    /// the cursor entered the given client: send it our clipboard
    pub(crate) fn push(&self, handle: ClientHandle) {
        if !self.settings().enabled {
            return;
        }
        let shared = self.shared.clone();
        spawn_local(async move {
            if let Err(e) = push(&shared, handle).await {
                log::warn!("clipboard: push to client {handle} failed: {e}");
            }
        });
    }

    /// the cursor left the given client: fetch its clipboard
    pub(crate) fn pull(&self, handle: ClientHandle) {
        if !self.settings().enabled {
            return;
        }
        let shared = self.shared.clone();
        spawn_local(async move {
            if let Err(e) = pull(&shared, handle).await {
                log::warn!("clipboard: pull from client {handle} failed: {e}");
            }
        });
    }
}

impl Drop for Clipboard {
    fn drop(&mut self) {
        self.stop_listener();
    }
}

async fn with_timeout<T, E>(
    duration: Duration,
    f: impl Future<Output = Result<T, E>>,
) -> Result<T, ClipboardError>
where
    ClipboardError: From<E>,
{
    match tokio::time::timeout(duration, f).await {
        Ok(r) => Ok(r?),
        Err(_) => Err(ClipboardError::Timeout),
    }
}

async fn read_local(shared: &Shared) -> Result<Option<ClipboardContent>, ClipboardError> {
    let backend = shared.backend.clone();
    let task = async move {
        spawn_blocking(move || backend.read())
            .await
            .map_err(io::Error::other)
    };
    Ok(with_timeout(BACKEND_TIMEOUT, task).await??)
}

async fn write_local(shared: &Shared, content: ClipboardContent) -> Result<(), ClipboardError> {
    let backend = shared.backend.clone();
    let task = async move {
        spawn_blocking(move || backend.write(content))
            .await
            .map_err(io::Error::other)
    };
    Ok(with_timeout(BACKEND_TIMEOUT, task).await??)
}

/// address and certificate fingerprint of a connected client
async fn connected_peer(shared: &Shared, handle: ClientHandle) -> Option<(SocketAddr, String)> {
    let deadline = tokio::time::Instant::now() + PEER_WAIT;
    loop {
        let cm = &shared.client_manager;
        if let (Some(addr), Some(fp)) = (cm.active_addr(handle), cm.peer_fingerprint(handle)) {
            return Some((addr, fp));
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn push(shared: &Shared, handle: ClientHandle) -> Result<(), ClipboardError> {
    let Some((addr, fingerprint)) = connected_peer(shared, handle).await else {
        log::debug!("clipboard: client {handle} not connected, not sending clipboard");
        return Ok(());
    };
    let Some(content) = read_local(shared).await? else {
        return Ok(());
    };
    if content.secret && !shared.settings.get().allow_secrets {
        log::info!("clipboard: not sending a secret to {addr} (sending secrets is disabled)");
        return Ok(());
    }
    let hash = content.hash();
    let known_hash = shared.last_exchanged.borrow().get(&fingerprint).copied();
    if known_hash == Some(hash) {
        log::debug!("clipboard: {addr} already has our clipboard");
        return Ok(());
    }
    log::info!("clipboard: sending {content:?} to {addr}");
    let request = Request {
        op: Op::Push,
        known_hash: known_hash.unwrap_or_default(),
        content: Some(content),
    };
    let response = request_peer(&shared.cert, addr, &fingerprint, request).await?;
    match response.status {
        Status::Ok => {
            shared.last_exchanged.borrow_mut().insert(fingerprint, hash);
        }
        s => log::info!("clipboard: {addr} did not accept the clipboard: {s:?}"),
    }
    Ok(())
}

async fn pull(shared: &Shared, handle: ClientHandle) -> Result<(), ClipboardError> {
    let Some((addr, fingerprint)) = connected_peer(shared, handle).await else {
        log::debug!("clipboard: client {handle} not connected, not fetching clipboard");
        return Ok(());
    };
    let known_hash = shared.last_exchanged.borrow().get(&fingerprint).copied();
    let request = Request {
        op: Op::Pull,
        known_hash: known_hash.unwrap_or_default(),
        content: None,
    };
    let response = request_peer(&shared.cert, addr, &fingerprint, request).await?;
    match (response.status, response.content) {
        (Status::Content, Some(content)) => {
            log::info!("clipboard: received {content:?} from {addr}");
            let hash = content.hash();
            write_local(shared, content).await?;
            shared.last_exchanged.borrow_mut().insert(fingerprint, hash);
        }
        (s, _) => log::debug!("clipboard: nothing received from {addr}: {s:?}"),
    }
    Ok(())
}

async fn request_peer(
    cert: &Certificate,
    addr: SocketAddr,
    fingerprint: &str,
    request: Request,
) -> Result<Response, ClipboardError> {
    let connector = TlsConnector::from(tls::client_config(cert, fingerprint.to_owned())?);
    let transfer = async {
        let tcp = TcpStream::connect(addr).await?;
        let mut stream = connector.connect(tls::server_name(), tcp).await?;
        proto::write_request(&mut stream, &request).await?;
        let response = proto::read_response(&mut stream).await?;
        let _ = stream.shutdown().await;
        Ok::<_, ClipboardError>(response)
    };
    with_timeout(TRANSFER_TIMEOUT, transfer).await
}

async fn listen(port: u16, shared: Rc<Shared>) {
    let listener = match TcpListener::bind(("0.0.0.0", port)).await {
        Ok(l) => l,
        Err(e) => {
            log::warn!("clipboard: could not listen on tcp port {port}: {e}");
            return;
        }
    };
    log::info!("clipboard: listening on tcp port {port}");
    accept_loop(listener, shared).await
}

async fn accept_loop(listener: TcpListener, shared: Rc<Shared>) {
    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                log::warn!("clipboard: accept: {e}");
                continue;
            }
        };
        let shared = shared.clone();
        spawn_local(async move {
            let serve = async {
                let mut stream = shared.acceptor.accept(stream).await?;
                let fingerprint = stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|c| c.first())
                    .map(|c| crypto::generate_fingerprint(c))
                    .expect("client certificate verified");
                serve(&shared, &mut stream, addr, fingerprint).await
            };
            if let Err(e) = with_timeout(TRANSFER_TIMEOUT, serve).await {
                log::warn!("clipboard: request from {addr} failed: {e}");
            }
        });
    }
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    shared: &Shared,
    stream: &mut S,
    addr: SocketAddr,
    fingerprint: String,
) -> Result<(), ClipboardError> {
    let request = proto::read_request(stream).await?;
    let settings = shared.settings.get();
    let response = if !settings.enabled {
        Response::status(Status::Refused)
    } else {
        match request.op {
            Op::Push => {
                let content = request.content.expect("push carries content");
                log::info!("clipboard: received {content:?} from {addr}");
                let hash = content.hash();
                match write_local(shared, content).await {
                    Ok(()) => {
                        shared.last_exchanged.borrow_mut().insert(fingerprint, hash);
                        Response::status(Status::Ok)
                    }
                    Err(e) => {
                        log::warn!("clipboard: could not set clipboard: {e}");
                        Response::status(Status::Error)
                    }
                }
            }
            Op::Pull => match read_local(shared).await {
                Ok(None) => Response::status(Status::Empty),
                Ok(Some(c)) if c.secret && !settings.allow_secrets => {
                    log::info!(
                        "clipboard: not sending a secret to {addr} (sending secrets is disabled)"
                    );
                    Response::status(Status::Refused)
                }
                Ok(Some(c)) => {
                    let hash = c.hash();
                    if hash == request.known_hash {
                        Response::status(Status::Unchanged)
                    } else {
                        log::info!("clipboard: sending {c:?} to {addr}");
                        shared.last_exchanged.borrow_mut().insert(fingerprint, hash);
                        Response {
                            status: Status::Content,
                            content: Some(c),
                        }
                    }
                }
                Err(e) => {
                    log::warn!("clipboard: could not read clipboard: {e}");
                    Response::status(Status::Error)
                }
            },
        }
    };
    proto::write_response(stream, &response).await?;
    let _ = stream.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use tokio::task::LocalSet;

    use super::*;

    /// in-memory clipboard
    #[derive(Default)]
    struct Memory(Mutex<Option<ClipboardContent>>);

    impl ClipboardBackend for Memory {
        fn read(&self) -> Result<Option<ClipboardContent>, BackendError> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn write(&self, content: ClipboardContent) -> Result<(), BackendError> {
            *self.0.lock().unwrap() = Some(content);
            Ok(())
        }
    }

    struct Peer {
        fingerprint: String,
        memory: Arc<Memory>,
        shared: Rc<Shared>,
    }

    fn peer(authorized: &[&str], settings: ClipboardSettings) -> Peer {
        let cert = Certificate::generate_self_signed(["ignored".to_owned()]).unwrap();
        let fingerprint = crypto::certificate_fingerprint(&cert);
        let keys = authorized
            .iter()
            .map(|fp| (fp.to_string(), "peer".to_string()))
            .collect();
        let memory = Arc::new(Memory::default());
        let config = tls::server_config(&cert, Arc::new(RwLock::new(keys))).unwrap();
        let shared = Rc::new(Shared {
            cert: cert.clone(),
            acceptor: TlsAcceptor::from(config),
            backend: memory.clone(),
            client_manager: ClientManager::default(),
            settings: Cell::new(settings),
            last_exchanged: Default::default(),
        });
        Peer {
            fingerprint,
            memory,
            shared,
        }
    }

    async fn serve_peer(peer: &Peer) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        spawn_local(accept_loop(listener, peer.shared.clone()));
        addr
    }

    fn text(s: &str, secret: bool) -> ClipboardContent {
        ClipboardContent {
            mime: backend::TEXT_MIME.into(),
            data: s.as_bytes().to_vec(),
            secret,
        }
    }

    fn pull_request(known_hash: ContentHash) -> Request {
        Request {
            op: Op::Pull,
            known_hash,
            content: None,
        }
    }

    const ON: ClipboardSettings = ClipboardSettings {
        enabled: true,
        allow_secrets: false,
    };

    /// throwaway certificate fingerprint of a client, generated up front so
    /// the server can authorize it
    fn client() -> (Certificate, String) {
        let cert = Certificate::generate_self_signed(["ignored".to_owned()]).unwrap();
        let fp = crypto::certificate_fingerprint(&cert);
        (cert, fp)
    }

    #[tokio::test]
    async fn push_and_pull() {
        LocalSet::new()
            .run_until(async {
                let (a, a_fp) = client();
                let b = peer(&[&a_fp], ON);
                let addr = serve_peer(&b).await;

                // push
                let content = text("hola desde A 🦊", false);
                let push = Request {
                    op: Op::Push,
                    known_hash: [0; 32],
                    content: Some(content.clone()),
                };
                let res = request_peer(&a, addr, &b.fingerprint, push).await.unwrap();
                assert_eq!(res.status, Status::Ok);
                assert_eq!(b.memory.0.lock().unwrap().clone(), Some(content.clone()));

                // pulling what we pushed transfers nothing
                let res = request_peer(&a, addr, &b.fingerprint, pull_request(content.hash()))
                    .await
                    .unwrap();
                assert_eq!(res.status, Status::Unchanged);

                // B copies an image, A pulls it
                let image = ClipboardContent {
                    mime: "image/png".into(),
                    data: vec![0x89, b'P', b'N', b'G', 1, 2, 3],
                    secret: false,
                };
                *b.memory.0.lock().unwrap() = Some(image.clone());
                let res = request_peer(&a, addr, &b.fingerprint, pull_request(content.hash()))
                    .await
                    .unwrap();
                assert_eq!(res.status, Status::Content);
                assert_eq!(res.content, Some(image));
            })
            .await;
    }

    #[tokio::test]
    async fn secrets_need_permission() {
        LocalSet::new()
            .run_until(async {
                let (a, a_fp) = client();
                let b = peer(&[&a_fp], ON);
                let addr = serve_peer(&b).await;
                let password = text("hunter2", true);
                *b.memory.0.lock().unwrap() = Some(password.clone());

                let res = request_peer(&a, addr, &b.fingerprint, pull_request([0; 32]))
                    .await
                    .unwrap();
                assert_eq!(res.status, Status::Refused);
                assert_eq!(res.content, None);

                b.shared.settings.set(ClipboardSettings {
                    enabled: true,
                    allow_secrets: true,
                });
                let res = request_peer(&a, addr, &b.fingerprint, pull_request([0; 32]))
                    .await
                    .unwrap();
                assert_eq!(res.status, Status::Content);
                assert_eq!(res.content, Some(password));
            })
            .await;
    }

    #[tokio::test]
    async fn disabled_refuses() {
        LocalSet::new()
            .run_until(async {
                let (a, a_fp) = client();
                let b = peer(&[&a_fp], ClipboardSettings::default());
                let addr = serve_peer(&b).await;
                *b.memory.0.lock().unwrap() = Some(text("x", false));
                let res = request_peer(&a, addr, &b.fingerprint, pull_request([0; 32]))
                    .await
                    .unwrap();
                assert_eq!(res.status, Status::Refused);
            })
            .await;
    }

    #[tokio::test]
    async fn rejects_unauthorized_client() {
        LocalSet::new()
            .run_until(async {
                let (a, _) = client();
                let b = peer(&[], ON);
                let addr = serve_peer(&b).await;
                *b.memory.0.lock().unwrap() = Some(text("x", false));
                let res = request_peer(&a, addr, &b.fingerprint, pull_request([0; 32])).await;
                assert!(res.is_err(), "unauthorized client got {res:?}");
            })
            .await;
    }

    #[tokio::test]
    async fn rejects_unexpected_server() {
        LocalSet::new()
            .run_until(async {
                let (a, a_fp) = client();
                let b = peer(&[&a_fp], ON);
                let addr = serve_peer(&b).await;
                let push = Request {
                    op: Op::Push,
                    known_hash: [0; 32],
                    content: Some(text("for someone else", false)),
                };
                let (_, other_fp) = client();
                let res = request_peer(&a, addr, &other_fp, push).await;
                assert!(res.is_err(), "impostor server accepted: {res:?}");
                assert_eq!(b.memory.0.lock().unwrap().clone(), None);
            })
            .await;
    }
}
