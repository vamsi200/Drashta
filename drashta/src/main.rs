#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_imports)]

use anyhow::{Ok, Result};
use drashta::parser::{self, Entry};
mod web;
use crate::{
    parser::{flush_previous_data, read_journal_logs},
    web::render,
};
use web::render::render_app;

#[tokio::main]
async fn main() -> Result<()> {
    let (tx, _) = tokio::sync::broadcast::channel::<Entry>(1024);

    // tokio::spawn(receive_data(tx.clone())).await?;

    render_app(tx.clone()).await;
    // read_journal_logs(tx.clone(), Some("NetworkManager.service"))
    //     .await
    //     .unwrap();
    // render_app(tx.clone()).await;

    // flush_previous_data(tx, d).await?;
    Ok(())
}
