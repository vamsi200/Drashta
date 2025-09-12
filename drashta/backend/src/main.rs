#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_imports)]

use std::vec;

use crate::parser::{flush_previous_data, read_journal_logs};
use anyhow::{Ok, Result};
use drashta::parser::{self, Entry, SshdEvent};
use drashta::render::render_app;
use std::borrow::Cow;
#[tokio::main]
pub async fn main() -> Result<()> {
    let (tx, _) = tokio::sync::broadcast::channel::<SshdEvent>(1);

    // tokio::spawn(receive_data(tx.clone())).await?;
    // let _ = render_app(tx).await;
    let unit = vec!["sshd.service"];

    let _ = flush_previous_data(tx, unit);

    // read_journal_logs(tx.clone(), Some("NetworkManager.service"))
    //     .await
    //     .unwrap();
    // render_app(tx.clone()).await;

    // flush_previous_data(tx, d).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_sshd() {
        let unit = vec!["sshd.service"];
        let (tx, _) = tokio::sync::broadcast::channel::<Entry>(1);
        // let _ = flush_previous_data(tx, unit);
    }
}
