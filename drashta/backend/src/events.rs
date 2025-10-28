#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_imports)]

use crate::parser::{
    Cursor, CursorType, Entry, EventData, EventType, ParserFuncArgs, ProcessLogType,
    deserialize_cursor, get_service_configs, handle_service_event, read_journal_logs,
};
use anyhow::Result;
use axum::extract::State;
use axum::{
    Router,
    response::sse::{Event, KeepAlive, Sse},
    routing::get,
};
use axum_extra::extract::Query;
use futures::StreamExt;
use futures::{Stream, stream};
use log::{Level, debug, error, info, log_enabled};
use serde::{Deserialize, Deserializer};
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

#[derive(Deserialize, Debug, Clone)]
pub struct FilterEvent {
    event_name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_cursor")]
    cursor: Option<CursorType>,
    limit: Option<i32>,
    query: Option<String>,
    event_type: Option<Vec<String>>,
    timestamp_from: Option<String>,
    timestamp_to: Option<String>,
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
    let limit = filter_event.0.limit.unwrap();
    let filter_keyword = filter_event.0.query;

    let cursor_type = filter_event.0.cursor.unwrap();

    let handle = tokio::task::spawn_blocking(move || {
        let tx = tx;
        let mut new_cursor_type: Option<CursorType> = None;
        let ref_event_type = filter_event
            .0
            .event_type
            .as_ref()
            .map(|v| v.iter().map(|s| s.as_str()).collect::<Vec<_>>());

        for ev in journal_units {
            info!(
                "Draining {ev} from {:?} upto {:?} entries (next)",
                cursor_type, limit
            );

            let opts = ParserFuncArgs::new(
                ev.as_str(),
                tx.clone(),
                limit,
                ProcessLogType::ProcessOlderLogs,
                filter_keyword.clone(),
                ref_event_type.clone(),
                Some(cursor_type.clone()),
            );
            if let Ok(cursor_type) = handle_service_event(opts) {
                new_cursor_type = cursor_type
            }
        }

        new_cursor_type
    });

    let new_cursor = handle.await.unwrap();

    let stream = async_stream::stream! {
        let cursor_json = json!({ "cursor": new_cursor }).to_string();
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

    match &filter_event.0.event_name {
        Some(event) => journal_units.push(event.clone()),
        None => journal_units.clear(),
    }

    let limit = filter_event.0.limit.unwrap();
    let journal_units_clone = journal_units.clone();
    let tx_clone = tx.clone();
    let filter_keyword = filter_event.0.query;
    let handle = tokio::task::spawn_blocking(move || {
        let ref_event_type: Option<Vec<&str>> = filter_event
            .0
            .event_type
            .as_ref()
            .map(|s| s.iter().map(|s| s.as_str()).collect());

        let mut last_cursor: Option<CursorType> = None;

        info!("Invoked initial drain!");
        for ev in journal_units_clone {
            let opts = ParserFuncArgs::new(
                ev.as_str(),
                tx.clone(),
                limit,
                ProcessLogType::ProcessInitialLogs,
                filter_keyword.clone(),
                ref_event_type.clone(),
                None,
            );

            if let Ok(cursor) = handle_service_event(opts) {
                if let Some(cursor_type) = cursor {
                    last_cursor = Some(cursor_type);
                    info!("Cursor - {:?}", last_cursor);
                }
            }
        }

        last_cursor
    });

    let cursor = handle.await.unwrap();
    let stream = async_stream::stream! {
        if let Some(cursor) = cursor {
            let cursor_json = json!({ "cursor": cursor }).to_string();
            yield Ok(Event::default().event("cursor").data(cursor_json));
        }

        while let Some(msg) = rx.recv().await {
            let json = to_string(&msg).unwrap_or_else(|_| "{}".to_string());
            yield Ok(Event::default().event("log").data(json));
        }
    };

    Sse::new(stream).keep_alive(KeepAlive::default())
}

pub async fn drain_previous_logs(
    filter_event: Query<FilterEvent>,
) -> Sse<impl futures::Stream<Item = Result<Event, Infallible>>> {
    let (tx, mut rx) = mpsc::channel::<EventData>(1024);
    let mut journal_units = Journalunits::new();

    match filter_event.0.event_name {
        Some(event) => journal_units.push(event),
        None => journal_units.clear(),
    }
    let limit = filter_event.0.limit.unwrap();

    let cursor_type = filter_event.0.cursor.unwrap();
    let filter_keyword = filter_event.0.query;

    let handle = tokio::task::spawn_blocking(move || {
        let mut new_cursor_type = None;

        let ref_event_type: Option<Vec<&str>> = filter_event
            .0
            .event_type
            .as_ref()
            .map(|s| s.iter().map(|s| s.as_str()).collect());

        for ev in journal_units {
            info!(
                "Draining {ev} from {:?} upto {limit:?} entries (previous)",
                cursor_type
            );

            let opts = ParserFuncArgs::new(
                ev.as_str(),
                tx.clone(),
                limit,
                ProcessLogType::ProcessPreviousLogs,
                filter_keyword.clone(),
                ref_event_type.clone(),
                Some(cursor_type.clone()),
            );

            let result = handle_service_event(opts);

            if let Ok(cursor_type) = result {
                new_cursor_type = cursor_type;
            }
        }

        new_cursor_type
    });

    let new_cursor = handle.await.unwrap();

    let stream = async_stream::stream! {
        let cursor_json = json!({ "cursor": new_cursor }).to_string();
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
    let filter_keyword = filter_event.0.query;

    std::thread::spawn(move || {
        let ref_event_type = filter_event
            .0
            .event_type
            .as_ref()
            .map(|v| v.iter().map(|s| s.as_str()).collect::<Vec<_>>());

        for val in journal_units {
            info!("Trying to get Live Events from `{}`", val);
            if let Err(e) = read_journal_logs(
                &val,
                filter_keyword.clone(),
                ref_event_type.clone(),
                tx.clone(),
            ) {
                eprintln!("Error: {e}");
            }
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
