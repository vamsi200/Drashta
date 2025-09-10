#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_imports)]

use crate::events;
use crate::events::receive_data;
use anyhow::{Ok, Result};
use axum::extract::State;
use std::{
    collections::{BTreeMap, VecDeque},
    fmt::Debug,
    os::fd::{AsRawFd, BorrowedFd},
    thread::sleep,
    time::Duration,
};
use systemd::{journal::JournalRef, *};
use tokio::sync::broadcast;
pub type Entry = BTreeMap<String, String>;

const MESSAGE_QUEUE_SIZE: usize = 1000;

pub fn flush_previous_data(
    tx: tokio::sync::broadcast::Sender<Entry>,
    unit: Vec<&str>,
) -> Result<()> {
    let mut s: Journal = journal::OpenOptions::default()
        .all_namespaces(true)
        .open()?;

    let unit_str: Vec<String> = unit.iter().map(|x| x.to_string()).collect();

    for unit in unit_str.clone() {
        s.match_add("_SYSTEMD_UNIT", unit)?;
    }
    s.seek_head()?;

    while let Some(data) = s.next_entry()? {
        if let Err(e) = tx.send(data) {
            println!("Dropped event: {:?}", e);
        }
    }

    Ok(())
}

pub fn flush_upto_n_entries(
    tx: tokio::sync::broadcast::Sender<Entry>,
    unit: Vec<&str>,
    n: usize,
) -> Result<()> {
    let mut s: Journal = journal::OpenOptions::default()
        .all_namespaces(true)
        .open()?;

    let unit_str: Vec<String> = unit.iter().map(|x| x.to_string()).collect();

    for unit in unit_str.clone() {
        s.match_add("_SYSTEMD_UNIT", unit)?;
    }
    s.seek_tail()?;
    s.previous()?;

    let mut count = 0;
    while let Some(data) = s.previous_entry()? {
        count += 1;
        if let Err(e) = tx.send(data) {
            println!("Dropped event: {:?}", e);
        }
        if count == n {
            break;
        }
    }

    Ok(())
}

pub fn read_journal_logs(tx: tokio::sync::broadcast::Sender<Entry>, unit: Vec<&str>) -> Result<()> {
    let mut s: Journal = journal::OpenOptions::default()
        .all_namespaces(true)
        .open()
        .unwrap();

    let unit_str: Vec<String> = unit.iter().map(|x| x.to_string()).collect();
    for unit in unit_str.clone() {
        s.match_add("_SYSTEMD_UNIT", unit)?;
    }
    loop {
        while let Some(data) = s.await_next_entry(None)? {
            if let Err(e) = tx.send(data) {
                println!("Dropped event: {:?}", e);
            } else {
                continue;
            }
        }
        sleep(Duration::from_secs(1));
    }
}
