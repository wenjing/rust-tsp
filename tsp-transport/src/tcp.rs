use std::{collections::HashMap, env, error::Error, io, net::SocketAddr, sync::Arc};

use futures::SinkExt;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, Mutex},
};
use tokio_stream::StreamExt;
use tokio_util::{
    bytes::BytesMut,
    codec::{BytesCodec, Framed},
    sync::CancellationToken,
};
use tracing_subscriber::EnvFilter;

pub async fn broadcast_server(token: CancellationToken) -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let state = Arc::new(Mutex::new(Shared::new()));

    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:1337".to_string());

    let listener = TcpListener::bind(&addr).await?;

    tracing::info!("server running on {}", addr);

    loop {
        tokio::select! {
            Ok((stream, addr)) = listener.accept() => {
                let state = Arc::clone(&state);

                tokio::spawn(async move {
                    tracing::debug!("accepted connection");
                    if let Err(e) = process(state, stream, addr).await {
                        tracing::info!("an error occurred; error = {:?}", e);
                    }
                });
            }
            _ = token.cancelled() => {
                tracing::info!("stopping server");
                return Ok(());
            }
        }
    }
}

type Tx = mpsc::UnboundedSender<BytesMut>;
type Rx = mpsc::UnboundedReceiver<BytesMut>;

struct Shared {
    peers: HashMap<SocketAddr, Tx>,
}

struct Peer {
    messages: Framed<TcpStream, BytesCodec>,
    rx: Rx,
}

impl Shared {
    fn new() -> Self {
        Shared {
            peers: HashMap::new(),
        }
    }
    async fn broadcast(&mut self, sender: SocketAddr, message: BytesMut) {
        for peer in self.peers.iter_mut() {
            if *peer.0 != sender {
                let _ = peer.1.send(message.clone());
            }
        }
    }
}

impl Peer {
    async fn new(
        state: Arc<Mutex<Shared>>,
        messages: Framed<TcpStream, BytesCodec>,
    ) -> io::Result<Peer> {
        let addr = messages.get_ref().peer_addr()?;
        let (tx, rx) = mpsc::unbounded_channel();

        state.lock().await.peers.insert(addr, tx);

        Ok(Peer { messages, rx })
    }
}

async fn process(
    state: Arc<Mutex<Shared>>,
    stream: TcpStream,
    addr: SocketAddr,
) -> Result<(), Box<dyn Error>> {
    let peer_id = addr.to_string();

    tracing::info!("{} connected", peer_id);

    let messages = Framed::new(stream, BytesCodec::new());
    let mut peer = Peer::new(state.clone(), messages).await?;

    loop {
        tokio::select! {
            Some(msg) = peer.rx.recv() => {
                tracing::info!("{} send a message ({} bytes)", peer_id, msg.len());
                peer.messages.send(msg).await?;
            }
            result = peer.messages.next() => match result {
                Some(Ok(msg)) => {
                    tracing::info!("{} broadcasting message ({} bytes)", peer_id, msg.len());
                    let mut state = state.lock().await;
                    state.broadcast(addr, msg).await;
                }
                Some(Err(e)) => {
                    tracing::error!(
                        "an error occurred while processing messages for {}; error = {:?}",
                        peer_id,
                        e
                    );
                }
                None => break,
            },
        }
    }

    {
        let mut state = state.lock().await;
        state.peers.remove(&addr);

        tracing::info!("{} has disconnected", peer_id);
    }

    Ok(())
}
