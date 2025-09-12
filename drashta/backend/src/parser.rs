#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_imports)]

use crate::events;
use crate::events::receive_data;
use aho_corasick::AhoCorasick;
use anyhow::{Ok, Result};
use axum::extract::State;
use libc::iw_pmkid_cand;
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
pub enum SshdEvent {
    AuthSuccess {
        timestamp: String,
        user: String,
        ip: String,
        port: String,
        method: String,
        raw_msg: String,
    },

    AuthFailure {
        timestamp: String,
        user: String,
        ip: String,
        port: String,
        method: String,
        raw_msg: String,
    },

    SessionOpened {
        timestamp: String,
        user: String,
        uid: String,
        raw_msg: String,
    },

    SessionClosed {
        timestamp: String,
        user: String,
        raw_msg: String,
    },

    ConnectionClosed {
        timestamp: String,
        ip: String,
        port: String,
        user: Option<String>,
        msg: String,
        raw_msg: String,
    },

    ProtocolMismatch {
        timestamp: String,
        ip: String,
        port: String,
        raw_msg: String,
    },

    Warning {
        timestamp: String,
        msg: String,
        raw_msg: String,
    },

    Unknown {
        timestamp: String,
        msg: String,
        raw_msg: String,
    },

    ReceivedDisconnect {
        timestamp: String,
        ip: String,
        port: String,
        code: Option<String>,
        msg: String,
        raw_msg: String,
    },

    NegotiationFailure {
        timestamp: String,
        ip: String,
        port: Option<String>,
        details: String,
        raw_msg: String,
    },

    TooManyAuthFailures {
        timestamp: String,
        user: Option<String>,
        ip: Option<String>,
        port: Option<String>,
        raw_msg: String,
    },
}

pub fn parse_sshd_logs(map: Entry) -> Option<SshdEvent> {
    static AUTH_SUCCESS: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?x)^Accepted\s+(\w+)\s+for\s+(\S+)\s+from\s+([0-9A-Fa-f:.]+)\s+port\s+(\d+)(?:\s+ssh\d*)?\s*$").unwrap()
    });

    static AUTH_FAILURE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?x)^Failed\s+(\w+)\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+([0-9A-Fa-f:.]+)\s+port\s+(\d+)(?:\s+ssh\d*)?\s*$").unwrap()
    });

    static SESSION_OPENED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?x)^pam_unix\(sshd:session\):\s+session\s+opened(?:\s+for\s+user\s+(\S+))?")
            .unwrap()
    });

    static SESSION_CLOSED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?x)^pam_unix\(sshd:session\):\s+session\s+closed(?:\s+for\s+user\s+(\S+))?")
            .unwrap()
    });

    static CONNECTION_CLOSED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?x)^Connection\s+(?:closed|reset)(?:\s+by(?:\s+authenticating\s+user)?\s+(\S+))?\s+([0-9A-Fa-f:.]+)\s+port\s+(\d+)(?:\s+\[([^\]]+)\])?\s*$").unwrap()
    });

    static PROTOCOL_MISMATCH: Lazy<Vec<Regex>> = Lazy::new(|| {
        vec![
        Regex::new(r"(?x)^kex_exchange_identification:\s*(?:read:\s*)?(Client sent invalid protocol identifier|Connection (?:closed by remote host|reset by peer))\s*$").unwrap(),
        Regex::new(r"(?x)^Bad\s+protocol\s+version\s+identification\s+'(.+?)'(?:\s+from\s+([0-9A-Fa-f:.]+))?(?:\s+port\s+(\d+))?\s*$").unwrap(),
        Regex::new(r"(?x)^Protocol\s+major\s+versions\s+differ\s+for\s+([0-9A-Fa-f:.]+)\s+port\s+(\d+):\s*(\d+)\s*vs\.\s*(\d+)\s*$").unwrap(),
        Regex::new(r"(?x)^(?:banner\s+exchange|ssh_dispatch_run_fatal):\s+Connection\s+from\s+([0-9A-Fa-f:.]+)\s+port\s+(\d+):\s*(invalid format|message authentication code incorrect|Connection corrupted)(?:\s+\[preauth\])?\s*$").unwrap(),
        Regex::new(r"(?x)^Read\s+from\s+socket\s+failed:\s+Connection\s+(?:reset|closed)\s+by\s+peer\s*$").unwrap(),
    ]
    });

    static RECEIVED_DISCONNECT: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?x)^Received\s+disconnect\s+from\s+([0-9A-Fa-f:.]+)(?:\s+port\s+(\d+))?:\s*(\d+):\s*(.+?)(?:\s+\[preauth\])?\s*$")
        .unwrap()
    });

    static NEGOTIATION_FAILURE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?x)^Unable\s+to\s+negotiate(?:\s+with)?\s+([0-9A-Fa-f:.]+)(?:\s+port\s+(\d+))?:\s*(?:no\s+matching|no\s+matching\s+.*\s+found|no matching .* found).*$")
            .unwrap()
    });

    static TOO_MANY_AUTH: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?x)^(?:Disconnecting:|Disconnected:)?\s*Too\s+many\s+authentication\s+failures(?:\s+for\s+(?:invalid\s+user\s+)?(\S+))?\s*(?:\[preauth\])?\s*$")
            .unwrap()
    });

    static WARNING: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?x)^(?:warning:|WARNING:|error:|fatal:)?\s*(.+\S)\s*$").unwrap()
    });

    static UNKNOWN: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?s)^(.*\S.*)$").unwrap());

    if let Some(s) = map.get("MESSAGE") {
        let mut timestamp = String::new();
        if let Some(tp) = map.get("SYSLOG_TIMESTAMP") {
            timestamp = tp.to_owned();
        }

        if let Some(msg) = AUTH_SUCCESS.captures(s) {
            let Some(method) = msg.get(1) else {
                return None;
            };
            let Some(user) = msg.get(2) else {
                return None;
            };
            let Some(ip) = msg.get(3) else {
                return None;
            };
            let Some(port) = msg.get(4) else {
                return None;
            };

            return Some(SshdEvent::AuthSuccess {
                timestamp: timestamp,
                user: user.as_str().to_string(),
                ip: ip.as_str().to_string(),
                port: port.as_str().to_string(),
                method: method.as_str().to_string(),
                raw_msg: s.clone(),
            });
        }

        if let Some(msg) = AUTH_FAILURE.captures(s) {
            let Some(method) = msg.get(1) else {
                return None;
            };
            let Some(user) = msg.get(2) else {
                return None;
            };
            let Some(ip) = msg.get(3) else {
                return None;
            };
            let Some(port) = msg.get(4) else {
                return None;
            };

            return Some(SshdEvent::AuthFailure {
                timestamp: timestamp,
                user: user.as_str().to_string(),
                ip: ip.as_str().to_string(),
                port: port.as_str().to_string(),
                method: method.as_str().to_string(),
                raw_msg: s.clone(),
            });
        }

        if let Some(msg) = SESSION_OPENED.captures(s) {
            let Some(user) = msg.get(1) else {
                return None;
            };
            let Some(uid) = msg.get(2) else {
                return None;
            };

            return Some(SshdEvent::SessionOpened {
                timestamp: timestamp.clone(),
                user: user.as_str().to_string(),
                uid: uid.as_str().to_string(),
                raw_msg: s.clone(),
            });
        }

        if let Some(msg) = SESSION_CLOSED.captures(s) {
            let Some(user) = msg.get(1) else {
                return None;
            };

            return Some(SshdEvent::SessionClosed {
                timestamp: timestamp.clone(),
                user: user.as_str().to_string(),
                raw_msg: s.clone(),
            });
        }

        if let Some(msg) = CONNECTION_CLOSED.captures(s) {
            let Some(user) = msg.get(1) else {
                return None;
            };
            let Some(ip) = msg.get(2) else {
                return None;
            };
            let Some(port) = msg.get(3) else {
                return None;
            };
            let Some(message) = msg.get(4) else {
                return None;
            };

            return Some(SshdEvent::ConnectionClosed {
                timestamp: timestamp.clone(),
                ip: ip.as_str().to_string(),
                port: port.as_str().to_string(),
                user: Some(user.as_str().to_string()),
                msg: message.as_str().to_string(),
                raw_msg: s.clone(),
            });
        }

        for rgx in PROTOCOL_MISMATCH.iter() {
            if let Some(msg) = rgx.captures(s) {
                let Some(ip) = msg.get(1) else {
                    return None;
                };
                let Some(port) = msg.get(2) else {
                    return None;
                };

                return Some(SshdEvent::ProtocolMismatch {
                    timestamp: timestamp.clone(),
                    ip: ip.as_str().to_string(),
                    port: port.as_str().to_string(),
                    raw_msg: s.clone(),
                });
            }
        }

        if let Some(msg) = WARNING.captures(s) {
            let Some(message) = msg.get(1) else {
                return None;
            };

            return Some(SshdEvent::Warning {
                timestamp: timestamp.clone(),
                msg: message.as_str().to_string(),
                raw_msg: s.clone(),
            });
        }

        if let Some(msg) = UNKNOWN.captures(s) {
            let Some(message) = msg.get(1) else {
                return None;
            };

            return Some(SshdEvent::Unknown {
                timestamp: timestamp.clone(),
                msg: message.as_str().to_string(),
                raw_msg: s.clone(),
            });
        }

        if let Some(msg) = RECEIVED_DISCONNECT.captures(s) {
            let Some(ip) = msg.get(1) else {
                return None;
            };
            let Some(port) = msg.get(2) else {
                return None;
            };
            let code = msg.get(3).map(|m| m.as_str().to_string());
            let Some(message) = msg.get(4) else {
                return None;
            };

            return Some(SshdEvent::ReceivedDisconnect {
                timestamp: timestamp.clone(),
                ip: ip.as_str().to_string(),
                port: port.as_str().to_string(),
                code,
                msg: message.as_str().to_string(),
                raw_msg: s.clone(),
            });
        }

        if let Some(msg) = NEGOTIATION_FAILURE.captures(s) {
            let Some(ip) = msg.get(1) else {
                return None;
            };
            let port = msg.get(2).map(|m| m.as_str().to_string());
            let Some(details) = msg.get(3) else {
                return None;
            };

            return Some(SshdEvent::NegotiationFailure {
                timestamp: timestamp.clone(),
                ip: ip.as_str().to_string(),
                port,
                details: details.as_str().to_string(),
                raw_msg: s.clone(),
            });
        }

        if let Some(msg) = TOO_MANY_AUTH.captures(s) {
            let user = msg.get(1).map(|m| m.as_str().to_string());
            let ip = msg.get(2).map(|m| m.as_str().to_string());
            let port = msg.get(3).map(|m| m.as_str().to_string());

            return Some(SshdEvent::TooManyAuthFailures {
                timestamp: timestamp.clone(),
                user,
                ip,
                port,
                raw_msg: s.clone(),
            });
        }
    }
    None
}

use std::mem::drop;

pub fn flush_previous_data(
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

    while let Some(data) = s.next_entry()? {
        if let Some(s) = parse_sshd_logs(data) {
            println!("{:?}", s);
            // if let Err(e) = tx.send(s) {
            //     println!("Dropped");
            // }
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
