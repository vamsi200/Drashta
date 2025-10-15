#![allow(unused_imports)]

use crate::events::{drain_older_logs, drain_upto_n_entries, receive_data};
use crate::parser::{Entry, EventData};
use axum::{Router, extract::Query, routing::get};
use http::header;
use tower_http::cors::{Any, CorsLayer};

pub async fn render_app(tx: tokio::sync::broadcast::Sender<EventData>) {
    let addr = "0.0.0.0:3200";
    println!("Started Listening at - {addr}");

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let live_app = Router::new()
        .route("/live", get(receive_data))
        .layer(cors.clone())
        .with_state(tx.clone());

    let drain_app = Router::new()
        .route("/drain", get(drain_upto_n_entries))
        .layer(cors.clone());

    let drain_older_logs_app = Router::new()
        .route("/older", get(drain_older_logs))
        .layer(cors);

    let app = Router::new()
        .merge(live_app)
        .merge(drain_app)
        .merge(drain_older_logs_app);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3200")
        .await
        .expect("err");

    axum::serve(listener, app.into_make_service())
        .await
        .inspect_err(|e| eprint!("{e}"))
        .unwrap();
}
