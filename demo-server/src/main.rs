use axum::{
    response::{Html, IntoResponse},
    routing::{get, post},
    Form, Json, Router,
};
use serde::Deserialize;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tsp_vid::Vid;

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
#[allow(dead_code)]
struct CreateIdentityInput {
    name: String,
}

async fn create_identity(Form(form): Form<CreateIdentityInput>) -> impl IntoResponse {
    let (_did_doc, private_doc) =
        tsp_vid::create_did_web(&form.name, "did.tsp-test.org", "tcp://127.0.0.1:1337");

    Json(private_doc)
}

type Db = Arc<RwLock<HashMap<String, Vid>>>;
