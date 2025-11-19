#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_imports)]

use crate::parser::read_journal_logs;
use ahash::AHashMap;
use anyhow::{Ok, Result};
use drashta::events::receive_data;
use drashta::parser::{
    self, Cursor, Entry, EventData, EventType, RawMsgType, process_manual_events_previous,
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
    let _ = render_app(tx).await;
    Ok(())
}
