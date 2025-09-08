use crate::events::receive_data;
use crate::parser::Entry;
// use crate::parser::{flush_previous_data, read_journal_logs};
use axum::{Router, routing::get};

// pub fn generate_tempate(data: Sse<impl futures::Stream<Item = Result<Event, Infallible>>>) {
//     todo!()
// }

pub async fn render_app(tx: tokio::sync::broadcast::Sender<Entry>) {
    let addr = "0.0.0.0:3200";
    println!("Started Listening at - {}", addr);
    let tx_clone = tx.clone();

    let app = Router::new()
        .route("/events", get(receive_data))
        .with_state(tx_clone.clone());
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3200")
        .await
        .expect("err");

    axum::serve(listener, app.into_make_service())
        .await
        .inspect_err(|e| eprint!("{e}"))
        .unwrap();
}
