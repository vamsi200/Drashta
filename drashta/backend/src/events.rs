#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_imports)]

use crate::parser::{Entry, flush_previous_data, read_journal_logs};
use anyhow::Result;
use axum::extract::State;
use axum::{
    Router,
    response::sse::{Event, KeepAlive, Sse},
    routing::get,
};
use futures::StreamExt;
use futures::{Stream, stream};
use std::convert::Infallible;
use std::io::Write;
use std::mem::size_of_val;
use std::sync::Arc;
use std::{collections::BTreeMap, io::BufWriter};
use tokio::sync::broadcast;
use tokio::sync::broadcast::Sender;
use tokio::task::{spawn_blocking, yield_now};
use tokio_stream::wrappers::BroadcastStream;

fn format_thing(map: BTreeMap<String, String>) -> String {
    match map.get("MESSAGE") {
        Some(r) => r.to_owned(),
        None => "".to_string(),
    }
}
pub async fn receive_data(
    State(tx): State<tokio::sync::broadcast::Sender<Entry>>,
) -> Sse<impl futures::Stream<Item = Result<Event, Infallible>>> {
    let rx = tx.clone().subscribe();

    // just for testing
    let journal_units = vec![
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
    ];

    if !rx.is_closed() {
        println!("Draining Logs..");
        flush_previous_data(tx.clone(), journal_units.clone()).unwrap();
        std::thread::spawn(move || {
            println!("Live Logs..");
            if let Err(e) = read_journal_logs(tx, journal_units) {
                eprintln!("Error: {:?}", e);
            }
        });
    }
    let stream = BroadcastStream::new(rx).filter_map(|res| async move {
        res.ok()
            .map(|msg| Ok(Event::default().event("test").data(format_thing(msg))))
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}
