use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Form, Json, Router,
};
use base64ct::{Base64, Encoding};
use serde::Deserialize;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tsp_definitions::{Payload, VerifiedVid};
use tsp_vid::{PrivateVid, Vid};

const DOMAIN: &str = "tsp-test.org";

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "demo-server=debug,tower_http=debug".into()),
        )
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
        .with_state(db);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

async fn index() -> Html<String> {
    // Html(std::include_str!("../index.html"))
    let body = std::fs::read_to_string("demo-server/index.html").unwrap();

    Html(body)
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

#[derive(Deserialize, Debug)]
struct SendMessageForm {
    message: String,
    sender: PrivateVid,
    receiver: Vid,
}

async fn send_message(Json(form): Json<SendMessageForm>) -> Response {
    let result = tsp_crypto::seal(
        &form.sender,
        &form.receiver,
        None,
        Payload::Content(form.message.as_bytes()),
    );

    match result {
        Ok(message) => Json(Base64::encode_string(&message)).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "error creating message").into_response(),
    }
}

struct Identity {
    did_doc: serde_json::Value,
    vid: Vid,
}

type Db = Arc<RwLock<HashMap<String, Identity>>>;
