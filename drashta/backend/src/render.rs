use crate::{events::drain_backlog, parser::SshdEvent};
// use crate::parser::Entry;
use axum::{Router, routing::get};
// pub fn generate_tempate(data: Sse<impl futures::Stream<Item = Result<Event, Infallible>>>) {
//     todo!()
// }

pub async fn render_app<'a>(tx: tokio::sync::broadcast::Sender<SshdEvent>) {
    let addr = "0.0.0.0:3200";
    println!("Started Listening at - {}", addr);

    let app = Router::new()
        // .route("/events", get(receive_data))
        .route("/drain", get(drain_backlog))
        // .route("/drain_upto", get(drain_data_upto_n))
        .with_state(tx);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3200")
        .await
        .expect("err");

    axum::serve(listener, app.into_make_service())
        .await
        .inspect_err(|e| eprint!("{e}"))
        .unwrap();
}
