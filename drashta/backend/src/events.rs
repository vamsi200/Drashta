#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_imports)]

use crate::parser::{
    Entry, EventData, flush_previous_data, flush_upto_n_entries, read_journal_logs,
};
use crate::redis::insert_into_db;
use anyhow::Result;
use axum::extract::{Query, State};
use axum::{
    Router,
    response::sse::{Event, KeepAlive, Sse},
    routing::get,
};
use futures::StreamExt;
use futures::{Stream, stream};
use log::{Level, debug, error, info, log_enabled};
use serde::Deserialize;
use serde_json::{json, to_string};
use std::borrow::Cow;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::io::Write;
use std::mem::size_of_val;
use std::process::exit;
use std::sync::{Arc, Mutex};
use std::thread::{sleep, spawn};
use std::time::Duration;
use std::{collections::BTreeMap, io::BufWriter};
use tokio::sync::broadcast::Sender;
use tokio::sync::mpsc::{self, Receiver};
use tokio::task::{spawn_blocking, yield_now};
use tokio_stream::wrappers::{BroadcastStream, ReceiverStream};

pub struct Journalunits {
    journal_units: Vec<String>,
}
impl Journalunits {
    pub fn new() -> Vec<String> {
        vec![]
    }
}

#[derive(Deserialize)]
pub struct ChunkSize {
    size: usize,
}

#[derive(Deserialize, Debug)]
pub struct FilterEvent {
    event_name: Option<String>,
}

fn format_thing(map: BTreeMap<String, String>) -> String {
    match map.get("MESSAGE") {
        Some(r) => r.to_owned(),
        None => "".to_string(),
    }
}

pub async fn drain_data_upto_n(
    State(tx): State<tokio::sync::broadcast::Sender<Entry>>,
    chunk_size: Query<ChunkSize>,
) -> Sse<impl futures::Stream<Item = Result<Event, Infallible>>> {
    let rx = tx.clone().subscribe();
    let journal_units = Journalunits::new();
    let n = chunk_size.0.size;

    assert!(!rx.is_closed());
    tokio::task::spawn_blocking(move || {
        println!("Flushing Events upto - {n}");
        if let Err(e) = flush_upto_n_entries(tx, journal_units, n) {
            eprintln!("Error: {:?}", e);
        }
    });

    let stream = BroadcastStream::new(rx).filter_map(|res| async move {
        res.ok()
            .map(|msg| Ok(Event::default().data(format!("{:?}", msg))))
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

pub async fn drain_backlog(
    filter_event: Query<FilterEvent>,
) -> Sse<impl futures::Stream<Item = Result<Event, Infallible>>> {
    let (tx, mut rx) = mpsc::channel::<EventData>(1024);
    let mut journal_units = Journalunits::new();

    match filter_event.0.event_name {
        Some(event) => journal_units.push(event),
        None => journal_units.clear(),
    }

    tokio::task::spawn_blocking(move || {
        flush_previous_data(tx, Some(journal_units)).unwrap();
    });
    let stream = async_stream::stream! {
        while let Some(msg) = rx.recv().await {
            let json = to_string(&msg).unwrap_or_else(|_| "{}".to_string());
            yield Ok(Event::default().data(json));
        }
    };

    Sse::new(stream).keep_alive(KeepAlive::default())
}

pub async fn receive_data(
    State(tx): State<tokio::sync::broadcast::Sender<EventData>>,
    filter_event: Query<FilterEvent>,
) -> Sse<impl futures::Stream<Item = Result<Event, Infallible>>> {
    let rx = tx.clone().subscribe();
    let mut journal_units = Journalunits::new();

    match filter_event.0.event_name {
        Some(event) => journal_units.push(event),
        None => journal_units.clear(),
    }

    std::thread::spawn(move || {
        println!("Getting Live Events");

        if let Err(e) = read_journal_logs(tx, Some(journal_units)) {
            eprintln!("Error: {:?}", e);
        }
    });

    let stream = BroadcastStream::new(rx).filter_map(|res| async move {
        match res {
            Ok(msg) => {
                let json = to_string(&msg).unwrap_or_else(|_| "{}".to_string());
                Some(Ok(Event::default().data(json)))
            }
            Err(_) => None,
        }
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}
