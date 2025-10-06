#![allow(unused_imports)]

use crate::events::{drain_backlog, drain_data_upto_n, receive_data};
use crate::parser::{Entry, EventData};
use axum::{Router, extract::Query, routing::get};
use http::header;
use tower_http::cors::{Any, CorsLayer};
// pub fn generate_tempate(data: Sse<impl futures::Stream<Item = Result<Event, Infallible>>>) {
//     todo!()
// }

pub async fn render_app(tx: tokio::sync::broadcast::Sender<EventData>) {
    let addr = "0.0.0.0:3200";
    println!("Started Listening at - {}", addr);

    // let app = Router::new()
    //     // .route("/events", get(receive_data))
    //     .route("/drain_upto", get(drain_data_upto_n))
    //     .with_state(tx);

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/drain", get(drain_backlog))
        .route("/live", get(receive_data))
        .layer(cors)
        .with_state(tx);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3200")
        .await
        .expect("err");

    axum::serve(listener, app.into_make_service())
        .await
        .inspect_err(|e| eprint!("{e}"))
        .unwrap();
}
