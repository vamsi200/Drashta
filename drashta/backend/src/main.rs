#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_imports)]

use crate::parser::{flush_previous_data, read_journal_logs};
use anyhow::{Ok, Result};
use drashta::parser::{self, Entry};
use drashta::render::render_app;

#[tokio::main]
pub async fn main() -> Result<()> {
    let (tx, _) = tokio::sync::broadcast::channel::<Entry>(1);

    // tokio::spawn(receive_data(tx.clone())).await?;
    let tx_clone = tx.clone();
    let journal_units = vec!["sshd.service"];
    let _ = render_app(tx).await;

    // read_journal_logs(tx.clone(), Some("NetworkManager.service"))
    //     .await
    //     .unwrap();
    // render_app(tx.clone()).await;

    // flush_previous_data(tx, d).await?;
    Ok(())
}
