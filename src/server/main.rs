use axum::{routing::get, Router};
use tinap::server::{ws_authenticate, ws_delete, ws_registration, Server};

#[tokio::main]
async fn main() {
    let state = Server::initialize();

    let app = Router::new()
        .route("/registration", get(ws_registration))
        .route("/authenticate", get(ws_authenticate))
        .route("/delete", get(ws_delete))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:6969")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap()
}
