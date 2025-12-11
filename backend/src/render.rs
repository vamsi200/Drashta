use crate::events::{drain_older_logs, drain_previous_logs, drain_upto_n_entries, receive_data};
use crate::parser::EventData;
use axum::Json;
use axum::extract::State;
use axum::{Router, routing::get};
use serde::Serialize;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;

#[derive(Serialize)]
struct ConfigResponse {
    port: u16,
}

async fn get_config(State(port): State<u16>) -> Json<ConfigResponse> {
    Json(ConfigResponse { port })
}

const CYAN: &str = "\x1b[36m";
const RESET: &str = "\x1b[0m";

pub async fn render_app(tx: tokio::sync::broadcast::Sender<EventData>, port: u16) {
    let addr = format!("0.0.0.0:{port}");

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
        .layer(cors.clone());

    let drain_previous_logs_app = Router::new()
        .route("/previous", get(drain_previous_logs))
        .layer(cors.clone());

    let config = Router::new()
        .route("/config.json", get(get_config))
        .with_state(port);

    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static");
    let frontend = Router::new().nest_service("/app/", ServeDir::new(path));

    let app = Router::new()
        .merge(config)
        .merge(frontend)
        .merge(live_app)
        .merge(drain_app)
        .merge(drain_older_logs_app)
        .merge(drain_previous_logs_app);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect(&format!("Failed to start the listener"));

    println!("{CYAN}[INFO] {RESET}Started Listening at - {}", &addr);
    println!(
        "{CYAN}[INFO] {RESET}UI is started at - {}",
        format!("http://{}/app/", &addr)
    );
    axum::serve(listener, app.into_make_service())
        .await
        .inspect_err(|e| eprintln!("{e}"))
        .unwrap();
}
