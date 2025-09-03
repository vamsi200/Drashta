use crate::parser::Entry;
use askama::Template;
use axum::{Router, routing::get};
use drashta::events::receive_data;
use drashta::parser::{flush_previous_data, read_journal_logs};
#[derive(Template)]
#[template(path = "test.html")]

pub struct HelloTemplate<'a> {
    name: &'a str,
}

pub async fn render_app(tx: tokio::sync::broadcast::Sender<Entry>) {
    let addr = "0.0.0.0:3200";
    println!("Started Listening at - {}", addr);

    let journal_units = vec!["NetworkManager.service", "sshd.service"];

    let tx_clone = tx.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let app = Router::new()
                .route("/", get(receive_data))
                .with_state(tx_clone);

            let listener = tokio::net::TcpListener::bind("0.0.0.0:3200")
                .await
                .expect("err");
            axum::serve(listener, app).await.unwrap();
        });
    });
    flush_previous_data(tx.clone(), journal_units.clone())
        .await
        .unwrap();
    read_journal_logs(tx, journal_units).await.unwrap();
}
