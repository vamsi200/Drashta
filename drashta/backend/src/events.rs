#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_imports)]

use crate::parser::{Entry, flush_previous_data, flush_upto_n_entries, read_journal_logs};
use anyhow::Result;
use axum::extract::{Query, State};
use axum::{
    Router,
    response::sse::{Event, KeepAlive, Sse},
    routing::get,
};
use futures::StreamExt;
use futures::{Stream, stream};
use serde::Deserialize;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::io::Write;
use std::mem::size_of_val;
use std::process::exit;
use std::thread::sleep;
use std::time::Duration;
use std::{collections::BTreeMap, io::BufWriter};
use tokio::sync::broadcast::Sender;
use tokio::sync::mpsc::Receiver;
use tokio::task::{spawn_blocking, yield_now};
use tokio_stream::wrappers::{BroadcastStream, ReceiverStream};

pub struct Journalunits {
    journal_units: Vec<&'static str>,
}

#[derive(Deserialize)]
pub struct ChunkSize {
    size: usize,
}

impl Journalunits {
    pub fn new() -> Vec<&'static str> {
        // just for testing
        vec![
            "sshd.service",
            "systemd-journald.service",
            "systemd-logind.service",
            "cron.service",
            "rsyslog.service",
            "NetworkManager.service",
            "dhcpcd.service",
            "nginx.service",
            "apache2.service",
            "docker.service",
            "firewalld.service",
            "polkit.service",
            "udisks2.service",
            "bluetooth.service",
            "systemd-udevd.service",
            "postgresql.service",
            "mysql.service",
            "cups.service",
        ]
    }
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
            .map(|msg| Ok(Event::default().event("test").data(format!("{:?}", msg))))
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

pub async fn drain_backlog(
    State(tx): State<tokio::sync::broadcast::Sender<Entry>>,
) -> Sse<impl futures::Stream<Item = Result<Event, Infallible>>> {
    let rx = tx.clone().subscribe();
    let journal_units = Journalunits::new();

    assert!(!rx.is_closed());
    tokio::task::spawn_blocking(move || {
        println!("Flushing Events");
        if let Err(e) = flush_previous_data(tx, journal_units) {
            eprintln!("Error: {:?}", e);
        }
    });

    let stream = BroadcastStream::new(rx).filter_map(|res| async move {
        res.ok()
            .map(|msg| Ok(Event::default().event("test").data(format!("{:?}", msg))))
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

pub async fn receive_data(
    State(tx): State<tokio::sync::broadcast::Sender<Entry>>,
) -> Sse<impl futures::Stream<Item = Result<Event, Infallible>>> {
    let rx = tx.clone().subscribe();
    let journal_units = Journalunits::new();

    std::thread::spawn(move || {
        println!("Getting Live Events");

        if let Err(e) = read_journal_logs(tx, journal_units) {
            eprintln!("Error: {:?}", e);
        }
    });

    let stream = BroadcastStream::new(rx).filter_map(|res| async move {
        res.ok()
            .map(|msg| Ok(Event::default().event("test").data(format!("{:?}", msg))))
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}
