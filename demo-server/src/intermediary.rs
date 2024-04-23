use axum::{
    body::Bytes,
    extract::{ws::Message, Path, State, WebSocketUpgrade},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};
use futures::{sink::SinkExt, stream::StreamExt};
use std::{error::Error, sync::Arc};
use tokio::sync::broadcast;
use tsp::AsyncStore;

struct IntermediaryState {
    domain: String,
    db: AsyncStore,
    tx: broadcast::Sender<(String, Vec<u8>)>,
}

pub(crate) async fn start_intermediary(
    domain: &str,
    port: u16,
    db: AsyncStore,
) -> Result<(), Box<dyn Error>> {
    let state = Arc::new(IntermediaryState {
        domain: domain.to_owned(),
        db,
        tx: broadcast::channel(100).0,
    });

    // Compose the routes
    let app = Router::new()
        .route("/", get(index))
        .route("/transport/:name", post(new_message).get(websocket_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::debug!("intermediary listening on port {port}");

    axum::serve(listener, app).await?;

    Ok(())
}

async fn index(State(state): State<Arc<IntermediaryState>>) -> Html<String> {
    Html(format!("<h1>{}</h1>", state.domain))
}

async fn new_message(
    State(state): State<Arc<IntermediaryState>>,
    Path(_name): Path<String>,
    body: Bytes,
) -> Response {
    let message: Vec<u8> = body.to_vec();

    let Ok((sender, Some(receiver))) = tsp::cesr::get_sender_receiver(&message) else {
        return (StatusCode::BAD_REQUEST, "invalid message, receiver missing").into_response();
    };

    let Ok(sender) = std::str::from_utf8(sender) else {
        return (StatusCode::BAD_REQUEST, "invalid sender").into_response();
    };

    let Ok(receiver) = std::str::from_utf8(receiver) else {
        return (StatusCode::BAD_REQUEST, "invalid receiver").into_response();
    };

    let mut message: Vec<u8> = body.to_vec();

    if let Ok(true) = state.db.has_private_vid(receiver) {
        let Ok(()) = state.db.route_message(sender, receiver, &mut message).await else {
            return (StatusCode::BAD_REQUEST, "error routing message").into_response();
        };
    } else {
        // insert message in queue
        let _ = state.tx.send((receiver.to_owned(), message));
    }

    StatusCode::OK.into_response()
}

/// Handle incoming websocket connections
async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<IntermediaryState>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let mut messages_rx = state.tx.subscribe();
    let vid = format!("did:web:did.tsp-test.org:user:{name}");

    ws.on_upgrade(|socket| {
        let (mut ws_send, _) = socket.split();

        async move {
            while let Ok((receiver, message)) = messages_rx.recv().await {
                if receiver == vid {
                    let _ = ws_send.send(Message::Binary(message)).await;
                }
            }
        }
    })
}
