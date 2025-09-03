#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_imports)]

use crate::parser::Entry;
use anyhow::Result;
use axum::{
    Router,
    response::sse::{Event, KeepAlive, Sse},
    routing::get,
};

use axum::extract::State;
use futures::StreamExt;
use futures::{Stream, stream};
use std::convert::Infallible;
use std::io::Write;
use std::sync::Arc;
use std::{collections::BTreeMap, io::BufWriter};
use tokio::sync::broadcast;
use tokio::sync::broadcast::Sender;
use tokio::task::{spawn_blocking, yield_now};
use tokio_stream::wrappers::BroadcastStream;

pub async fn receive_data(
    State(tx): State<tokio::sync::broadcast::Sender<Entry>>,
) -> Sse<impl futures::Stream<Item = Result<Event, Infallible>>> {
    let rx = tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|res| async move {
        res.ok()
            .map(|msg| Ok(Event::default().data(format!("{:?}", msg))))
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}
