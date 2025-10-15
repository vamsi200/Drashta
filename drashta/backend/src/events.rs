#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_imports)]

use crate::parser::{Entry, EventData, handle_service_event, read_journal_logs};
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
    cursor: Option<String>,
    limit: i32,
}

fn format_thing(map: BTreeMap<String, String>) -> String {
    match map.get("MESSAGE") {
        Some(r) => r.to_owned(),
        None => "".to_string(),
    }
}

pub async fn drain_older_logs(
    filter_event: Query<FilterEvent>,
) -> Sse<impl futures::Stream<Item = Result<Event, Infallible>>> {
    let (tx, mut rx) = mpsc::channel::<EventData>(1024);
    let mut journal_units = Journalunits::new();

    match filter_event.0.event_name {
        Some(event) => journal_units.push(event),
        None => journal_units.clear(),
    }
    let cursor = filter_event.0.cursor.unwrap();
    let limit = filter_event.0.limit;
    let handle = tokio::task::spawn_blocking(move || {
        let tx = tx;
        let mut last_cursor = String::new();

        for ev in journal_units {
            info!("Draining {ev} upto {limit} entries");
            if let Ok(cursor) = handle_service_event(&ev, tx.clone(), None, limit) {
                last_cursor = cursor;
            }
        }

        last_cursor
    });

    let new_cursor: String = handle.await.unwrap();

    let stream = async_stream::stream! {
        let cursor_json = json!({ "cursor": cursor }).to_string();
        yield Ok(Event::default().event("cursor").data(cursor_json));
        while let Some(msg) = rx.recv().await {
            let json = to_string(&msg).unwrap_or_else(|_| "{}".to_string());
            yield Ok(Event::default().event("log").data(json));

        }
    };

    Sse::new(stream).keep_alive(KeepAlive::default())
}

pub async fn drain_upto_n_entries(
    filter_event: Query<FilterEvent>,
) -> Sse<impl futures::Stream<Item = Result<Event, Infallible>>> {
    let (tx, mut rx) = mpsc::channel::<EventData>(1024);
    let mut journal_units = Journalunits::new();

    match filter_event.0.event_name {
        Some(event) => journal_units.push(event),
        None => journal_units.clear(),
    }
    let limit = filter_event.0.limit;

    let handle = tokio::task::spawn_blocking(move || {
        let tx = tx;
        let mut last_cursor = String::new();

        for ev in journal_units {
            info!("Draining {ev} upto {limit} entries");
            if let Ok(cursor) = handle_service_event(&ev, tx.clone(), None, limit) {
                last_cursor = cursor;
            }
        }

        last_cursor
    });

    let cursor: String = handle.await.unwrap();

    let stream = async_stream::stream! {
        let cursor_json = json!({ "cursor": cursor }).to_string();
        yield Ok(Event::default().event("cursor").data(cursor_json));

        while let Some(msg) = rx.recv().await {
            let json = to_string(&msg).unwrap_or_else(|_| "{}".to_string());
            yield Ok(Event::default().event("log").data(json));
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
    let local = tokio::task::LocalSet::new();

    println!("Getting Live Events");
    std::thread::spawn(move || {
        if let Err(e) = read_journal_logs(tx, Some(journal_units)) {
            eprintln!("Error: {e}");
        }
    });

    let stream = BroadcastStream::new(rx).filter_map(|res| async move {
        match res {
            Ok(msg) => {
                let json = to_string(&msg).unwrap_or_else(|_| "{}".to_string());
                Some(Ok(Event::default().data(json)))
            }
            Err(e) => {
                info!("Event Dropped!");
                Some(Ok(Event::default()))
            } // Err(_) => None,
        }
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}
