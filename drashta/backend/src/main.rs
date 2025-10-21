#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_imports)]

use crate::parser::read_journal_logs;
use anyhow::{Ok, Result};
use drashta::events::receive_data;
use drashta::parser::{
    self, Cursor, Entry, EventData, process_manual_events_previous, process_manual_events_upto_n,
};
use drashta::render::render_app;
use log::info;
use std::borrow::Cow;
use std::vec;

#[tokio::main]
pub async fn main() -> Result<()> {
    env_logger::init();
    let (tx, _) = tokio::sync::broadcast::channel::<EventData>(1024);
    // let new_cursor: Cursor = Cursor {
    //     timestamp: "2025-06-10T13:45:56+0530".to_string(),
    //     data: "[2025-06-10T13:45:56+0530] [ALPM] upgraded pacman-mirrorlist (20250101-1 -> 20250522-1)".to_owned(),
    //     offset: 40000,
    // };
    let _ = render_app(tx).await;
    // let cursor = manual_parse(tx, "pkgmanager.events", 100)?;
    // info!("Cursor : {:?}", cursor);
    // process_manual_events_previous(tx, "pkgmanager.events", new_cursor, 30000)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_sshd() {
        let unit = vec!["sshd.service"];
        let (tx, _) = tokio::sync::broadcast::channel::<Entry>(1024);
    }
}
