use axum::{routing::get, Router};
use axum_signed_urls::SignedUrl;
use std::env;

async fn handler(_: SignedUrl) -> String {
    "Hello, secret!".to_string()
}

#[tokio::main]
async fn main() {
    env::set_var("AXUM_SECRET", "hunter2");

    let app = Router::new().route("/", get(handler));

    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap()
}
