#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_imports)]

use crate::events;
use crate::events::receive_data;
use anyhow::{Ok, Result};
use axum::extract::State;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt::Debug,
    os::fd::{AsRawFd, BorrowedFd},
    thread::sleep,
    time::Duration,
};
use systemd::{journal::JournalRef, *};
use tokio::sync::broadcast;
pub type Entry = BTreeMap<String, String>;

pub async fn flush_previous_data(
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
        let _ = tx.send(data);
    }
    Ok(())
}

pub async fn read_journal_logs(
    tx: tokio::sync::broadcast::Sender<Entry>,
    unit: Vec<&str>,
) -> Result<()> {
    let mut s: Journal = journal::OpenOptions::default()
        .all_namespaces(true)
        .open()
        .unwrap();

    let unit_str: Vec<String> = unit.iter().map(|x| x.to_string()).collect();
    for unit in unit_str.clone() {
        s.match_add("_SYSTEMD_UNIT", unit)?;
    }

    loop {
        match s.await_next_entry(None)? {
            Some(d) => {
                let _ = tx.send(d);
            }
            None => {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        }
    }
    // loop {
    //     while let some(data) = s.next_entry()? {
    //         println!("{:?}", data);
    //         let _ = tx.send(data);
    //     }
    //     s.wait(Some(Duration::from_secs(1))).unwrap();
    // }

    // let fd = s.as_raw_fd();
    // let bfd = unsafe { BorrowedFd::borrow_raw(fd) };
    // let mut fds = [PollFd::new(bfd, PollFlags::POLLIN)];

    // loop {
    //     s.wait(Some(std::time::Duration::from_secs(1)))?;
    //     match poll(&mut fds, PollTimeout::NONE) {
    //         Ok(n) if n > 0 => {
    //             if let Some(ev) = fds[0].revents() {
    //                 if ev.contains(PollFlags::POLLIN) {
    //                     while let Some(et) = s.next_entry()? {
    //                         if let Some(sys_unit) = et.get("_SYSTEMD_UNIT") {
    //                             if sys_unit == "sshd.service" {
    //                                 println!("{:?}", et.get("MESSAGE").unwrap());
    //                             }
    //                         }
    //                     }
    //                 }
    //             }
    //         }
    //         Ok(_) => continue,
    //         Err(e) => {
    //             eprint!("{e}");
    //             break;
    //         }
    //     }
    // }
}
