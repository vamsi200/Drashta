use anyhow::Result;
use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use axum_extra::extract::Query;
use futures::StreamExt;
use log::info;
use rayon::iter::IntoParallelRefIterator;
use rayon::prelude::*;
use serde::Deserialize;
use serde_json::{json, to_string};
use std::{collections::VecDeque, convert::Infallible, time::Duration};
use tokio::sync::mpsc::{self};
use tokio_stream::wrappers::BroadcastStream;

use crate::parser::*;

#[derive(Deserialize, Debug, Clone)]
pub struct FilterEvent {
    event_name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_cursor")]
    cursor: Option<CursorType>,
    limit: Option<i32>,
    query: Option<String>,
    event_type: Option<Vec<String>>,
}

pub async fn drain_older_logs(
    filter_event: Query<FilterEvent>,
) -> Sse<impl futures::Stream<Item = Result<Event, Infallible>>> {
    let (tx, mut rx) = mpsc::channel::<EventData>(102400);

    let journal_units = filter_event.0.event_name.unwrap_or_default();

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

        info!("Draining {journal_units} from {cursor_type:?} upto {limit} entries (next)",);

        let opts = ParserFuncArgs::new(
            &journal_units,
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

        new_cursor_type
    });

    let new_cursor = handle.await.unwrap();
    let mut batch = VecDeque::with_capacity(100);
    let parallel_required_bro = limit >= 1000;
    let stream = async_stream::stream! {
        let cursor_json = json!({ "cursor": new_cursor }).to_string();
        yield Ok(Event::default().event("cursor").data(cursor_json));

        while let Some(msg) = rx.recv().await {
            batch.push_back(msg);

            if batch.len() >= 100 {
                if parallel_required_bro {
                    let logs: Vec<_> = batch
                        .par_iter()
                        .map(|x| {
                            let json = serde_json::to_string(x).unwrap_or("{}".to_string());
                            Event::default().event("log").data(json)
                        })
                        .collect();

                    batch.clear();

                    for event in logs {
                        yield Ok(event);
                    }

                } else {
                    for x in batch.drain(..) {
                        let json = serde_json::to_string(&x).unwrap_or("{}".to_string());
                        yield Ok(Event::default().event("log").data(json));
                    }
                }
            }
        }
    };

    Sse::new(stream).keep_alive(KeepAlive::default())
}

pub async fn drain_upto_n_entries(
    filter_event: Query<FilterEvent>,
) -> Sse<impl futures::Stream<Item = Result<Event, Infallible>>> {
    let (tx, mut rx) = mpsc::channel::<EventData>(102400);
    let journal_units = filter_event.0.event_name.unwrap_or_default();

    let limit = filter_event.0.limit.unwrap();
    let journal_units_clone = journal_units.clone();
    let filter_keyword = filter_event.0.query;
    let handle = std::thread::spawn(move || {
        let ref_event_type: Option<Vec<&str>> = filter_event
            .0
            .event_type
            .as_ref()
            .map(|s| s.iter().map(|s| s.as_str()).collect());

        let mut last_cursor: Option<CursorType> = None;

        info!("Invoked initial drain for service: {journal_units}");
        let opts = ParserFuncArgs::new(
            &journal_units_clone,
            tx.clone(),
            limit,
            ProcessLogType::ProcessInitialLogs,
            filter_keyword.clone(),
            ref_event_type.clone(),
            None,
        );

        if let Ok(Some(cursor_type)) = handle_service_event(opts) {
            last_cursor = Some(cursor_type);
            info!("Cursor - {last_cursor:?}");
        }

        last_cursor
    });

    let cursor = handle.join().unwrap();
    let mut batch = VecDeque::with_capacity(100);
    let parallel_required_bro = limit >= 1000;

    let stream = async_stream::stream! {
        if let Some(cursor) = cursor {
            let cursor_json = json!({ "cursor": cursor }).to_string();
            yield Ok(Event::default().event("cursor").data(cursor_json));
        }

        while let Some(msg) = rx.recv().await {
            batch.push_back(msg);

            if parallel_required_bro{
                let logs: Vec<_> = batch.par_iter().map(|x|{
                    let json = serde_json::to_string(x).unwrap_or("{}".to_string());
                    Event::default().event("log").data(json)
                }).collect();

                batch.clear();
                for event in logs{
                    yield Ok(event);
                }

            } else {
                for x in batch.drain(..){
                    let json = serde_json::to_string(&x).unwrap_or("{}".to_string());
                    yield Ok(Event::default().event("log").data(json));

                }
            }
        }
    };

    Sse::new(stream).keep_alive(KeepAlive::default())
}

pub async fn drain_previous_logs(
    filter_event: Query<FilterEvent>,
) -> Sse<impl futures::Stream<Item = Result<Event, Infallible>>> {
    let (tx, mut rx) = mpsc::channel::<EventData>(102400);
    let journal_units = filter_event.0.event_name.unwrap_or_default();

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

        info!("Draining {journal_units} from {cursor_type:?} upto {limit:?} entries (previous)",);

        let opts = ParserFuncArgs::new(
            &journal_units,
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

        new_cursor_type
    });

    let new_cursor = handle.await.unwrap();
    let mut batch = VecDeque::with_capacity(100);
    let parallel_required_bro = limit >= 1000;

    let stream = async_stream::stream! {
        let cursor_json = json!({ "cursor": new_cursor }).to_string();
        yield Ok(Event::default().event("cursor").data(cursor_json));
        while let Some(msg) = rx.recv().await {
            batch.push_back(msg);
            if parallel_required_bro{
                let logs: Vec<_> = batch.par_iter().map(|x|{
                    let json = serde_json::to_string(x).unwrap_or("{}".to_string());
                    Event::default().event("log").data(json)
                }).collect();

                batch.clear();
                for event in logs{
                    yield Ok(event);
                }

            } else {
                for event in batch.drain(..){
                    let json = to_string(&event).unwrap_or_else(|_| "{}".to_string());
                    yield Ok(Event::default().event("log").data(json));
                }
            }

        }
    };

    Sse::new(stream).keep_alive(KeepAlive::default())
}

pub async fn receive_data(
    State(tx): State<tokio::sync::broadcast::Sender<EventData>>,
    filter_event: Query<FilterEvent>,
) -> Sse<impl futures::Stream<Item = Result<Event, Infallible>>> {
    let rx = tx.clone().subscribe();
    let journal_units = filter_event.0.event_name.unwrap_or_default();

    let filter_keyword = filter_event.0.query;

    std::thread::spawn(move || {
        let ref_event_type = filter_event
            .0
            .event_type
            .as_ref()
            .map(|v| v.iter().map(|s| s.as_str()).collect::<Vec<_>>());

        info!("Trying to get Live Events from `{journal_units}`");

        let is_manual_event = MANUAL_PARSE_EVENTS.iter().any(|&x| x == journal_units);
        if is_manual_event {
            if let Err(e) = read_journal_logs_manual(
                &journal_units,
                filter_keyword.clone(),
                ref_event_type.clone(),
                tx.clone(),
            ) {
                eprintln!("Error: {e}");
            }
        } else if let Err(e) = read_journal_logs(
            &journal_units,
            filter_keyword.clone(),
            ref_event_type.clone(),
            tx.clone(),
        ) {
            eprintln!("Error: {e}");
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
    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keepalive"),
    )
}
