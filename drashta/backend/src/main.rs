#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_imports)]

use crate::parser::read_journal_logs;
use anyhow::{Ok, Result};
use drashta::events::receive_data;
use drashta::parser::{
    self, Cursor, Entry, EventData, process_manual_events_next, process_manual_events_previous,
    process_manual_events_upto_n,
};
use drashta::render::render_app;
use log::info;
use std::borrow::Cow;
use std::vec;

#[tokio::main]
pub async fn main() -> Result<()> {
    env_logger::init();
    let (tx, _) = tokio::sync::broadcast::channel::<EventData>(1024);
    // let (tx, _) = tokio::sync::mpsc::channel::<EventData>(1024);
    let _ = render_app(tx).await;
    // let cursor = manual_parse(tx, "pkgmanager.events", 100)?;
    // info!("Cursor : {:?}", cursor);
    //
    // process_manual_events_next(tx, "pkgmanager.events", cursor, 30000)?;

    // process_manual_events_previous(tx, "pkgmanager.events", cursor, 10)?;

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
