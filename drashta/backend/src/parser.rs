#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_imports)]

use crate::events;
use crate::events::receive_data;
use aho_corasick::AhoCorasick;
use anyhow::{Ok, Result};
use axum::extract::State;
use once_cell::sync::Lazy;
use regex::Regex;
use std::borrow::Cow;
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

#[derive(Debug, Clone)]
pub enum SshdEvent<'a> {
    AuthSuccess {
        timestamp: Cow<'a, str>,
        user: Cow<'a, str>,
        ip: Cow<'a, str>,
        port: Cow<'a, str>,
        method: Cow<'a, str>,
    },

    AuthFailure {
        timestamp: Cow<'a, str>,
        user: Cow<'a, str>,
        ip: Cow<'a, str>,
        port: Cow<'a, str>,
        method: Cow<'a, str>,
    },

    SessionOpened {
        timestamp: Cow<'a, str>,
        user: Cow<'a, str>,
        uid: Cow<'a, str>,
    },

    SessionClosed {
        timestamp: Cow<'a, str>,
        user: Cow<'a, str>,
    },

    ConnectionClosed {
        timestamp: Cow<'a, str>,
        ip: Cow<'a, str>,
        port: Cow<'a, str>,
        user: Cow<'a, str>,
        msg: Cow<'a, str>,
    },

    ProtocolMismatch {
        timestamp: Cow<'a, str>,
        ip: Cow<'a, str>,
        details: Cow<'a, str>,
    },

    Warning {
        timestamp: Cow<'a, str>,
        msg: Cow<'a, str>,
    },

    Unknown {
        timestamp: Cow<'a, str>,
        msg: Cow<'a, str>,
    },
}

pub fn parse_sshd_logs(map: Entry) -> Option<SshdEvent<'static>> {
    static AUTH_SUCCESS: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^Accepted (\w+) for (\w+) from ([0-9a-fA-F:.]+) port (\d+) ssh2$").unwrap()
    });

    static AUTH_FAILURE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"^Failed (\w+) for (?:invalid user )?(\w+) from ([0-9a-fA-F:.]+) port (\d+) ssh2$",
        )
        .unwrap()
    });

    static SESSION_OPENED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"^pam_unix\(sshd:session\): session opened(?: for user (\w+)\(uid=(\d+)\) by (\w+)\(uid=(\d+)\))?$",
        )
        .unwrap()
    });

    static SESSION_CLOSED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^pam_unix\(sshd:session\): session closed(?: for user (\w+))?").unwrap()
    });

    static CONNECTION_CLOSED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^Connection closed by authenticating user (\w+) ([0-9a-fA-F:.]+) port (\d+) \[(\w+)\]")
            .unwrap()
    });

    if let Some(s) = map.get("MESSAGE") {
        let test = String::new();

        if let Some(msg) = AUTH_SUCCESS.captures(s) {
            let timestamp = map.get("SYSLOG_TIMESTAMP").unwrap().clone();
            let method = msg.get(1).unwrap().as_str().to_string();
            let user = msg.get(2).unwrap().as_str().to_string();
            let ip = msg.get(3).unwrap().as_str().to_string();
            let port = msg.get(4).unwrap().as_str().to_string();

            return Some(SshdEvent::AuthSuccess {
                timestamp: Cow::Owned(timestamp),
                user: Cow::Owned(user),
                ip: Cow::Owned(ip),
                port: Cow::Owned(port),
                method: Cow::Owned(method),
            });
        }
        if let Some(msg) = AUTH_FAILURE.captures(s) {
            let timestamp = map.get("SYSLOG_TIMESTAMP").unwrap().clone();
            let method = msg.get(1).unwrap().as_str().to_string();
            let user = msg.get(2).unwrap().as_str().to_string();
            let ip = msg.get(3).unwrap().as_str().to_string();
            let port = msg.get(4).unwrap().as_str().to_string();

            return Some(SshdEvent::AuthSuccess {
                timestamp: Cow::Owned(timestamp),
                user: Cow::Owned(user),
                ip: Cow::Owned(ip),
                port: Cow::Owned(port),
                method: Cow::Owned(method),
            });
        }

        if let Some(msg) = SESSION_OPENED.captures(s) {
            let timestamp = map.get("SYSLOG_TIMESTAMP").unwrap().clone();
            let user = msg.get(1).unwrap().as_str().to_string();
            let uid = msg.get(2).unwrap().as_str().to_string();

            return Some(SshdEvent::SessionOpened {
                timestamp: Cow::Owned(timestamp.clone().to_owned()),
                user: Cow::Owned(user),
                uid: Cow::Owned(uid),
            });
        }

        if let Some(msg) = SESSION_CLOSED.captures(s) {
            let timestamp = map.get("SYSLOG_TIMESTAMP").unwrap().clone();
            let user = msg.get(1).unwrap().as_str().to_string();

            return Some(SshdEvent::SessionClosed {
                timestamp: Cow::Owned(timestamp.clone().to_owned()),
                user: Cow::Owned(user),
            });
        }

        if let Some(msg) = CONNECTION_CLOSED.captures(s) {
            let timestamp = map.get("SYSLOG_TIMESTAMP").unwrap().clone();
            let user = msg.get(1).unwrap().as_str().to_string();
            let ip = msg.get(2).unwrap().as_str().to_string();
            let port = msg.get(3).unwrap().as_str().to_string();
            let msg = msg.get(4).unwrap().as_str().to_string();

            return Some(SshdEvent::ConnectionClosed {
                timestamp: Cow::Owned(timestamp.clone().to_owned()),
                ip: Cow::Owned(ip),
                port: Cow::Owned(port),
                user: Cow::Owned(user),
                msg: Cow::Owned(msg),
            });
        }
    }
    None
}

pub fn flush_previous_data<'a>(
    tx: tokio::sync::broadcast::Sender<SshdEvent>,
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
        // if let Err(e) = tx.send(data) {
        //     println!("Dropped event: {:?}", e);
        // }
        //

        let data_clone = data.clone();
        if let Some(s) = parse_sshd_logs(data) {
            if let Err(e) = tx.send(s) {
                println!("Dropped");
            }
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
