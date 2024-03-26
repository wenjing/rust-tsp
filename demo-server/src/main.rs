use axum::{
    extract::{
        ws::{Message, WebSocket},
        Path, State, WebSocketUpgrade,
    },
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Form, Json, Router,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use futures::{sink::SinkExt, stream::StreamExt};
use serde::Deserialize;
use serde_json::json;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{broadcast, RwLock};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tsp_definitions::{Payload, VerifiedVid};
use tsp_vid::{PrivateVid, Vid};

const DOMAIN: &str = "tsp-test.org";

/// Identity struct, used to store the DID document and VID of a user
struct Identity {
    did_doc: serde_json::Value,
    vid: Vid,
}

/// Application state, used to store the identities and the broadcast channel
struct AppState {
    db: RwLock<HashMap<String, Identity>>,
    tx: broadcast::Sender<(String, String, Vec<u8>)>,
}

/// Define the routes and start a server
#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "demo_server=trace".into()),
        )
        .init();

    let state = Arc::new(AppState {
        db: Default::default(),
        tx: broadcast::channel(100).0,
    });

    // Compose the routes
    let app = Router::new()
        .route("/", get(index))
        .route("/script.js", get(script))
        .route("/create-identity", post(create_identity))
        .route("/resolve-vid", post(resolve_vid))
        .route("/user/:name/did.json", get(get_did_doc))
        .route("/send-message", post(send_message))
        .route("/receive-messages", get(websocket_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

#[cfg(debug_assertions)]
async fn index() -> Html<String> {
    Html(std::fs::read_to_string("demo-server/index.html").unwrap())
}

#[cfg(not(debug_assertions))]
async fn index() -> Html<String> {
    Html(std::include_str!("../index.html").to_string())
}

#[cfg(debug_assertions)]
async fn script() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript")],
        std::fs::read_to_string("demo-server/script.js").unwrap(),
    )
}

#[cfg(not(debug_assertions))]
async fn script() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript")],
        std::include_str!("../script.js").to_string(),
    )
}

#[derive(Deserialize, Debug)]
struct CreateIdentityInput {
    name: String,
}

/// Create a new identity (private VID)
async fn create_identity(
    State(state): State<Arc<AppState>>,
    Form(form): Form<CreateIdentityInput>,
) -> impl IntoResponse {
    let (did_doc, _, private_vid) =
        tsp_vid::create_did_web(&form.name, DOMAIN, "tcp://127.0.0.1:1337");

    let key = private_vid.identifier();

    state.db.write().await.insert(
        key.to_string(),
        Identity {
            did_doc: did_doc.clone(),
            vid: private_vid.vid().clone(),
        },
    );

    Json(private_vid)
}

#[derive(Deserialize, Debug)]
struct ResolveVidInput {
    vid: String,
}

/// Resolve a VID to JSON encoded key material
async fn resolve_vid(
    State(state): State<Arc<AppState>>,
    Form(form): Form<ResolveVidInput>,
) -> Response {
    // local state lookup
    if let Some(identity) = state.db.read().await.get(&form.vid) {
        return Json(&identity.vid).into_response();
    }

    // remote lookup
    let vid = tsp_vid::resolve_vid(&form.vid).await.ok();

    match vid {
        Some(vid) => Json(&vid).into_response(),
        None => (StatusCode::BAD_REQUEST, "invalid vid").into_response(),
    }
}

/// Get the DID document of a user
async fn get_did_doc(State(state): State<Arc<AppState>>, Path(name): Path<String>) -> Response {
    let key = format!("did:web:{DOMAIN}:{name}");

    match state.db.read().await.get(&key) {
        Some(identity) => Json(identity.did_doc.clone()).into_response(),
        None => (StatusCode::NOT_FOUND, "no user found").into_response(),
    }
}

/// Format CESR encoded message parts to descriptive JSON
fn format_part(title: &str, part: &tsp_cesr::Part, plain: Option<&[u8]>) -> serde_json::Value {
    let full = [&part.prefix[..], &part.data[..]].concat();

    json!({
        "title": title,
        "prefix": part.prefix.iter().map(|b| format!("{:#04x}", b)).collect::<Vec<String>>().join(" "),
        "data": Base64UrlUnpadded::encode_string(&full),
        "plain": plain
            .and_then(|b| std::str::from_utf8(b).ok())
            .or(std::str::from_utf8(&part.data).ok()),
    })
}

/// Decode a CESR encoded message into descriptive JSON
fn decode_message(message: &[u8], payload: &[u8]) -> Option<serde_json::Value> {
    let parts = tsp_cesr::decode_message_into_parts(message).ok()?;

    Some(json!({
        "prefix": format_part("Prefix", &parts.prefix, None),
        "sender": format_part("Sender", &parts.sender, None),
        "receiver": parts.receiver.map(|v| format_part("Receiver", &v, None)),
        "nonconfidentialData": parts.nonconfidential_data.map(|v| format_part("Non-confidential data", &v, None)),
        "ciphertext": parts.ciphertext.map(|v| format_part("Ciphertext", &v, Some(payload))),
        "signature": format_part("Signature", &parts.signature, None),
    }))
}

/// Form to send a TSP message
#[derive(Deserialize, Debug)]
struct SendMessageForm {
    message: String,
    nonconfidential_data: Option<String>,
    sender: PrivateVid,
    receiver: Vid,
}

/// Send a TSP message using a HTML form
async fn send_message(
    State(state): State<Arc<AppState>>,
    Json(form): Json<SendMessageForm>,
) -> Response {
    let result = tsp_crypto::seal(
        &form.sender,
        &form.receiver,
        form.nonconfidential_data.as_deref().and_then(|d| {
            if d.is_empty() {
                None
            } else {
                Some(d.as_bytes())
            }
        }),
        Payload::Content(form.message.as_bytes()),
    );

    match result {
        Ok(message) => {
            // insert message in queue
            state
                .tx
                .send((
                    form.sender.identifier().to_owned(),
                    form.receiver.identifier().to_owned(),
                    message.clone(),
                ))
                .unwrap();

            let decoded = decode_message(&message, form.message.as_bytes()).unwrap();

            Json(decoded).into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "error creating message").into_response(),
    }
}

/// Handle incoming websocket connections
async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| websocket(socket, state))
}

/// Handle the websocket connection
/// Keep track of the verified VID's, private VID's and forward messages 
async fn websocket(stream: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = stream.split();
    let mut rx = state.tx.subscribe();
    let senders = Arc::new(RwLock::new(HashMap::<String, Vid>::new()));
    let receivers = Arc::new(RwLock::new(HashMap::<String, PrivateVid>::new()));

    // Forward messages from the broadcast channel to the websocket
    let incoming_senders = senders.clone();
    let incoming_receivers = receivers.clone();
    let mut send_task = tokio::spawn(async move {
        while let Ok((sender_id, receiver_id, message)) = rx.recv().await {
            let incoming_senders_read = incoming_senders.read().await;
            let Some(sender_vid) = incoming_senders_read.get(&sender_id) else {
                continue;
            };

            let incoming_receivers_read = incoming_receivers.read().await;
            let Some(receiver_vid) = incoming_receivers_read.get(&receiver_id) else {
                continue;
            };

            tracing::debug!("forwarding message {sender_id} {receiver_id}");

            let mut encrypted_message = message.clone();
            let Ok((_, payload, _)) =
                tsp_crypto::open(receiver_vid, sender_vid, &mut encrypted_message)
            else {
                continue;
            };

            let Some(decoded) = decode_message(&message, payload.as_bytes()) else {
                continue;
            };

            if sender
                .send(Message::Text(decoded.to_string()))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    // Receive encoded VID's from the websocket and store them in the local state
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(Message::Text(identity))) = receiver.next().await {
            if let Ok(identity) = serde_json::from_str::<PrivateVid>(&identity) {
                receivers
                    .write()
                    .await
                    .insert(identity.identifier().to_string(), identity);
            }

            if let Ok(identity) = serde_json::from_str::<Vid>(&identity) {
                senders
                    .write()
                    .await
                    .insert(identity.identifier().to_string(), identity);
            }
        }
    });

    // Abort the tasks when one of them finishes
    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    };
}
