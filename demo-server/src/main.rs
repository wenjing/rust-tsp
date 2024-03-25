use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Form, Json, Router,
};
use base64ct::{Base64Url, Encoding};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tsp_cesr::CipherView;
use tsp_definitions::{Payload, VerifiedVid};
use tsp_vid::{PrivateVid, Vid};

const DOMAIN: &str = "tsp-test.org";

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .init();

    let db = Db::default();

    // Compose the routes
    let app = Router::new()
        .route("/", get(index))
        .route("/create-identity", post(create_identity))
        .route("/resolve-vid", post(resolve_vid))
        .route("/user/:name/did.json", get(get_did_doc))
        .route("/send-message", post(send_message))
        .route("/receive-messages", post(recieve_messages))
        .with_state(db);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

#[cfg(debug_assertions)]
async fn index() -> Html<String> {
    let body = std::fs::read_to_string("demo-server/index.html").unwrap();

    Html(body)
}

#[cfg(not(debug_assertions))]
async fn index() -> Html<String> {
    Html(std::include_str!("../index.html").to_string())
}

#[derive(Deserialize, Debug)]
struct CreateIdentityInput {
    name: String,
}

async fn create_identity(
    State(db): State<Db>,
    Form(form): Form<CreateIdentityInput>,
) -> impl IntoResponse {
    let (did_doc, _, private_vid) =
        tsp_vid::create_did_web(&form.name, DOMAIN, "tcp://127.0.0.1:1337");

    let key = private_vid.identifier();

    db.write().unwrap().insert(
        key.to_string(),
        Identity {
            did_doc: did_doc.clone(),
            vid: private_vid.vid().clone(),
            messages: vec![],
        },
    );

    Json(private_vid)
}

#[derive(Deserialize, Debug)]
struct ResolveVidInput {
    vid: String,
}

async fn resolve_vid(State(db): State<Db>, Form(form): Form<ResolveVidInput>) -> Response {
    // local state lookup
    if let Some(identity) = db.read().unwrap().get(&form.vid) {
        return Json(&identity.vid).into_response();
    }

    // remote lookup
    let vid = tsp_vid::resolve_vid(&form.vid).await.ok();

    match vid {
        Some(vid) => Json(&vid).into_response(),
        None => (StatusCode::BAD_REQUEST, "invalid vid").into_response(),
    }
}

async fn get_did_doc(Path(name): Path<String>, State(db): State<Db>) -> Response {
    let key = format!("did:web:{DOMAIN}:{name}");

    match db.read().unwrap().get(&key) {
        Some(identity) => Json(identity.did_doc.clone()).into_response(),
        None => (StatusCode::NOT_FOUND, "no user found").into_response(),
    }
}

fn view_to_range_json(view: CipherView) -> serde_json::Value {
    json!({
        "sender": (view.sender.start, view.sender.end),
        "receiver": view.receiver.map(|r| (r.start, r.end)),
        "nonconfidential_data": view.nonconfidential_data.map(|r| (r.start, r.end)),
        "signed_data": (view.signed_data.start,view.signed_data.end),
        "ciphertext": view.ciphertext.map(|r| (r.start, r.end)),
    })
}

async fn recieve_messages(State(db): State<Db>, Json(receiver): Json<PrivateVid>) -> Response {
    // local state lookup
    let read_db = db.read().unwrap();
    let Some(identity) = read_db.get(receiver.vid().identifier()) else {
        return Json::<&[u8]>(&[]).into_response();
    };

    let messages: Vec<serde_json::Value> = identity
        .messages
        .iter()
        .filter_map(|(vid, message)| {
            let mut message = message.to_vec();
            let view = tsp_cesr::decode_envelope_mut(&mut message).ok()?;
            let mut json = view_to_range_json(view);
            json["message"] = Base64Url::encode_string(&message).into();

            let payload = tsp_crypto::open(&receiver, vid, &mut message).ok()?;
            json["payload"] = String::from_utf8_lossy(payload.1.as_bytes()).into();

            Some(json)
        })
        .collect();

    Json(messages).into_response()
}

#[derive(Deserialize, Debug)]
struct SendMessageForm {
    message: String,
    nonconfidential_data: Option<String>,
    sender: PrivateVid,
    receiver: Vid,
}

async fn send_message(State(db): State<Db>, Json(form): Json<SendMessageForm>) -> Response {
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
        Ok(mut message) => {
            let key = form.receiver.identifier();

            // insert message in database
            if let Some(entry) = db.write().unwrap().get_mut(key) {
                entry
                    .messages
                    .push((form.sender.vid().clone(), message.clone()));
            }

            let message_encoded = Base64Url::encode_string(&message);
            let view = tsp_cesr::decode_envelope_mut(&mut message).unwrap();
            let mut json = view_to_range_json(view);
            json["message"] = message_encoded.into();
            json["payload"] = form.message.into();

            Json(json).into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "error creating message").into_response(),
    }
}

struct Identity {
    did_doc: serde_json::Value,
    vid: Vid,
    messages: Vec<(Vid, Vec<u8>)>,
}

type Db = Arc<RwLock<HashMap<String, Identity>>>;
