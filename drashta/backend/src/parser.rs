#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_imports)]

use crate::events;
use crate::events::receive_data;
use ahash::AHashMap;
use aho_corasick::AhoCorasick;
use anyhow::Result;
use axum::extract::State;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::result::Result::Ok;
use std::sync::Arc;
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
pub struct EventData {
    pub timestamp: String,
    pub service: Service,
    pub data: AHashMap<String, String>,
    pub event_type: EventType,
    pub raw_msg: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Service {
    Sshd,
    Sudo,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum EventType {
    Success,
    Failure,
    SessionOpened,
    SessionClosed,
    ConnectionClosed,
    TooManyAuthFailures,
    Warning,
    Info,
    Other,
    IncorrectPassword,
    AuthError,
}

pub fn rg_capture(msg: &regex::Captures, i: usize) -> Option<String> {
    msg.get(i).map(|m| m.as_str().to_string())
}

macro_rules! insert_fields {
    ($map:expr, $msg:expr, { $($key:expr => $idx:expr),+ $(,)? }) => {
        $(
            $map.insert($key.to_string(), rg_capture(&$msg, $idx)?);
        )+
    };
}

pub fn parse_sshd_logs(map: Entry) -> Option<EventData> {
    static SSHD_REGEX: Lazy<Vec<(&str, Regex)>> = Lazy::new(|| {
        vec![
            ("AUTH_SUCCESS", Regex::new(r"(?x)^Accepted\s+(\w+)\s+for\s+(\S+)\s+from\s+([0-9A-Fa-f:.]+)\s+port\s+(\d+)(?:\s+ssh\d*)?\s*$").unwrap()),
            ("AUTH_FAILURE", Regex::new(r"(?x)^Failed\s+(\w+)\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+([0-9A-Fa-f:.]+)\s+port\s+(\d+)(?:\s+ssh\d*)?\s*$").unwrap()),
            ("SESSION_OPENED", Regex::new(r"(?x)^pam_unix\(sshd:session\):\s+session\s+opened(?:\s+for\s+user\s+(\S+))?").unwrap()),
            ("SESSION_CLOSED", Regex::new(r"(?x)^pam_unix\(sshd:session\):\s+session\s+closed(?:\s+for\s+user\s+(\S+))?").unwrap()),
            ("CONNECTION_CLOSED", Regex::new(r"(?x)^Connection\s+(?:closed|reset)(?:\s+by(?:\s+authenticating\s+user)?\s+(\S+))?\s+([0-9A-Fa-f:.]+)\s+port\s+(\d+)(?:\s+\[([^\]]+)\])?\s*$").unwrap()),
            ("RECEIVED_DISCONNECT", Regex::new(r"(?x)^Received\s+disconnect\s+from\s+([0-9A-Fa-f:.]+)(?:\s+port\s+(\d+))?:\s*(\d+):\s*(.+?)(?:\s+\[preauth\])?\s*$").unwrap()),
            ("NEGOTIATION_FAILURE", Regex::new(r"(?x)^Unable\s+to\s+negotiate(?:\s+with)?\s+([0-9A-Fa-f:.]+)(?:\s+port\s+(\d+))?:\s*(?:no\s+matching|no\s+matching\s+.*\s+found|no matching .* found).*$").unwrap()),
            ("TOO_MANY_AUTH", Regex::new(r"(?x)^(?:Disconnecting:|Disconnected:)?\s*Too\s+many\s+authentication\s+failures(?:\s+for\s+(?:invalid\s+user\s+)?(\S+))?\s*(?:\[preauth\])?\s*$").unwrap()),
            ("WARNING", Regex::new(r"(?x)^(?:warning:|WARNING:|error:|fatal:)?\s*(.+\S)\s*$").unwrap()),
            ("UNKNOWN", Regex::new(r"(?s)^(.*\S.*)$").unwrap()),
        ]
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

    if let Some(s) = map.get("MESSAGE") {
        let mut timestamp = String::new();
        if let Some(tp) = map.get("SYSLOG_TIMESTAMP") {
            timestamp = tp.to_owned();
        }
        let mut map = AHashMap::new();

        for (name, regex) in SSHD_REGEX.iter() {
            if let Some(msg) = regex.captures(s) {
                match *name {
                    "AUTH_SUCCESS" => {
                        insert_fields!(map, msg,{
                            "user" => 2,
                            "ip" => 3,
                            "port" => 4,
                            "method" => 1,
                        });

                        let ev = EventData {
                            timestamp: timestamp,
                            service: Service::Sshd,
                            data: map,
                            event_type: EventType::Success,
                            raw_msg: s.clone(),
                        };
                        return Some(ev);
                    }
                    "AUTH_FAILURE" => {
                        insert_fields!(map, msg,{
                            "user" => 2,
                            "ip" => 3,
                            "port" => 4,
                            "method" => 1,
                        });

                        let ev = EventData {
                            timestamp: timestamp,
                            service: Service::Sshd,
                            data: map,
                            event_type: EventType::Failure,
                            raw_msg: s.clone(),
                        };

                        return Some(ev);
                    }
                    "SESSION_OPENED" => {
                        insert_fields!(map, msg, {
                            "user" => 1,
                            "uid" => 2,
                        });

                        let ev = EventData {
                            timestamp: timestamp,
                            service: Service::Sshd,
                            data: map,
                            event_type: EventType::SessionOpened,
                            raw_msg: s.clone(),
                        };

                        return Some(ev);
                    }
                    "SESSION_CLOSED" => {
                        insert_fields!(map, msg, {
                            "user" => 1,
                        });
                        let ev = EventData {
                            timestamp: timestamp,
                            service: Service::Sshd,
                            data: map,
                            event_type: EventType::SessionClosed,
                            raw_msg: s.clone(),
                        };

                        return Some(ev);
                    }
                    "CONNECTION_CLOSED" => {
                        insert_fields!(map, msg, {
                            "user" => 1,
                            "ip" => 2,
                            "port" => 3,
                            "msg" => 4,
                        });

                        let ev = EventData {
                            timestamp: timestamp,
                            service: Service::Sshd,
                            data: map,
                            event_type: EventType::ConnectionClosed,
                            raw_msg: s.clone(),
                        };

                        return Some(ev);
                    }
                    "WARNING" => {
                        insert_fields!(map, msg, {
                            "msg" => 1,
                        });

                        let ev = EventData {
                            timestamp: timestamp,
                            service: Service::Sshd,
                            data: map,
                            event_type: EventType::Warning,
                            raw_msg: s.clone(),
                        };

                        return Some(ev);
                    }
                    "UNKNOWN" => {
                        insert_fields!(map, msg, {
                            "msg" => 1,
                        });

                        let ev = EventData {
                            timestamp: timestamp,
                            service: Service::Sshd,
                            data: map,
                            event_type: EventType::Other,
                            raw_msg: s.clone(),
                        };

                        return Some(ev);
                    }
                    "RECEIVED_DISCONNECT" => {
                        insert_fields!(map, msg, {
                            "ip" => 1,
                            "port" => 2,
                            "code" => 3,
                            "msg" => 4,
                        });

                        let ev = EventData {
                            timestamp: timestamp,
                            service: Service::Sshd,
                            data: map,
                            event_type: EventType::Other,
                            raw_msg: s.clone(),
                        };

                        return Some(ev);
                    }
                    "NEGOTIATION_FAILURE" => {
                        insert_fields!(map, msg, {
                            "ip" => 1,
                            "port" => 2,
                            "details" => 3,
                        });

                        let ev = EventData {
                            timestamp: timestamp,
                            service: Service::Sshd,
                            data: map,
                            event_type: EventType::Other,
                            raw_msg: s.clone(),
                        };

                        return Some(ev);
                    }
                    "TOO_MANY_AUTH" => {
                        insert_fields!(map, msg, {
                            "user" => 1,
                            "ip" => 2,
                            "port" => 3,
                        });

                        let ev = EventData {
                            timestamp: timestamp,
                            service: Service::Sshd,
                            data: map,
                            event_type: EventType::TooManyAuthFailures,
                            raw_msg: s.clone(),
                        };

                        return Some(ev);
                    }
                    _ => {}
                }
            }
        }

        for rgx in PROTOCOL_MISMATCH.iter() {
            if let Some(msg) = rgx.captures(s) {
                insert_fields!(map, msg, {
                    "ip" => 2,
                    "port" => 3,
                });

                let ev = EventData {
                    timestamp: timestamp,
                    service: Service::Sshd,
                    data: map,
                    event_type: EventType::Other,
                    raw_msg: s.clone(),
                };

                return Some(ev);
            }
        }
    }
    None
}

pub fn parse_sudo_login_attempts(map: Entry) -> Option<EventData> {
    static SUDO_REGEX: Lazy<Vec<(&str, Regex)>> = Lazy::new(|| {
        vec![
            ("COMMAND_RUN", Regex::new(r"(?x)^(\w+)\s+:\s+TTY=(\S+)\s+;\s+PWD=(\S+)\s+;\s+USER=(\S+)\s+;\s+COMMAND=(/usr/bin/su.*)$").unwrap()),
            ("SESSION_OPENED_SUDO", Regex::new(r"^pam_unix\(sudo:session\): session opened for user (\w+)\(uid=(\d+)\) by (\w+)\(uid=(\d+)\)$").unwrap()),
            ("SESSION_OPENED_SU", Regex::new(r"^pam_unix\(su:session\): session opened for user (\w+)\(uid=(\d+)\) by (\w+)\(uid=(\d+)\)$").unwrap()),
            ("SESSION_CLOSED", Regex::new(r"^pam_unix\(sudo:session\):\s+session closed for user (\S+)$").unwrap()),
            ("AUTH_FAILURE", Regex::new(r"^pam_unix\(sudo:auth\): authentication failure; logname=(\S+) uid=(\d+) euid=(\d+) tty=(\S+) ruser=(\S+) rhost=(\S*)\s+user=(\S+)$").unwrap()),
            ("INCORRECT_PASSWORD", Regex::new(r"^(\S+)\s+:\s+(\d+)\s+incorrect password attempt ; TTY=(\S+) ; PWD=(\S+) ; USER=(\S+) ; COMMAND=(\S+)$").unwrap()),
            ("NOT_IN_SUDOERS", Regex::new(r"(?x)^\s*(?P<user>\S+)\s+is\s+not\s+in\s+the\s+sudoers\s+file").unwrap()),
            ("AUTH_ERROR", Regex::new(r"(?x)pam_unix\(sudo:auth\):\s+(?P<msg>.+?)(?:\s+\[ (?P<user>\w+) \])?\s*$").unwrap()),
            ("SUDO_WARNING", Regex::new(r"(?x)^sudo:\s+(?P<msg>.+)$").unwrap()),
        ]
    });

    if let Some(s) = map.get("MESSAGE") {
        let mut timestamp = String::new();
        if let Some(tp) = map.get("SYSLOG_TIMESTAMP") {
            timestamp = tp.to_owned();
        }
        let mut map = AHashMap::new();
        let trim_msg = s.trim_start();

        for (name, regex) in SUDO_REGEX.iter() {
            if let Some(msg) = regex.captures(trim_msg) {
                match *name {
                    "COMMAND_RUN" => {
                        insert_fields!(map, msg, {
                            "invoking_user" => 1,
                            "tty" => 2,
                            "pwd" => 3,
                            "target_user" => 4,
                            "command" => 5,
                        });

                        let ev = EventData {
                            timestamp,
                            service: Service::Sudo,
                            data: map,
                            event_type: EventType::Info,
                            raw_msg: s.clone(),
                        };

                        return Some(ev);
                    }
                    _ => {}
                }
            }
            if let Some(msg) = regex.captures(s) {
                match *name {
                    "SESSION_OPENED_SU" => {
                        insert_fields!(map, msg, {
                            "target_user" => 1,
                            "uid" => 2,
                            "invoking_user" => 3,
                            "invoking_uid" => 4,
                        });

                        let ev = EventData {
                            timestamp,
                            service: Service::Sudo,
                            data: map,
                            event_type: EventType::SessionOpened,
                            raw_msg: s.clone(),
                        };

                        return Some(ev);
                    }
                    "SESSION_OPENED_SUDO" => {
                        insert_fields!(map, msg, {
                            "target_user" => 1,
                            "uid" => 2,
                            "invoking_user" => 3,
                            "invoking_uid" => 4,
                        });

                        let ev = EventData {
                            timestamp,
                            service: Service::Sudo,
                            data: map,
                            event_type: EventType::SessionOpened,
                            raw_msg: s.clone(),
                        };

                        return Some(ev);
                    }
                    "SESSION_CLOSED" => {
                        insert_fields!(map, msg, {
                            "target_user" => 1,
                        });

                        let ev = EventData {
                            timestamp,
                            service: Service::Sudo,
                            data: map,
                            event_type: EventType::SessionClosed,
                            raw_msg: s.clone(),
                        };

                        return Some(ev);
                    }
                    "AUTH_FAILURE" => {
                        insert_fields!(map, msg, {
                            "logname" => 1,
                            "uid" => 2,
                            "euid" => 3,
                            "tty" => 4,
                            "ruser" => 5,
                            "rhost" => 6,
                            "target_user" => 7,
                        });

                        let ev = EventData {
                            timestamp,
                            service: Service::Sudo,
                            data: map,
                            event_type: EventType::Failure,
                            raw_msg: s.clone(),
                        };

                        return Some(ev);
                    }
                    "INCORRECT_PASSWORD" => {
                        insert_fields!(map, msg, {
                            "invoking_user" => 1,
                            "attempts" => 2,
                            "tty" => 3,
                            "pwd" => 4,
                            "target_user" => 5,
                            "command" => 6,
                        });

                        let ev = EventData {
                            timestamp,
                            service: Service::Sudo,
                            data: map,
                            event_type: EventType::IncorrectPassword,
                            raw_msg: s.clone(),
                        };

                        return Some(ev);
                    }
                    "NOT_IN_SUDOERS" => {
                        insert_fields!(map, msg, {
                            "user" => 1,
                        });

                        let ev = EventData {
                            timestamp,
                            service: Service::Sudo,
                            data: map,
                            event_type: EventType::Info,
                            raw_msg: s.clone(),
                        };

                        return Some(ev);
                    }
                    "AUTH_ERROR" => {
                        insert_fields!(map, msg, {
                            "msg" => 1,
                        });

                        if let Some(user) = rg_capture(&msg, 2) {
                            map.insert("user".to_string(), user);
                        }

                        let ev = EventData {
                            timestamp,
                            service: Service::Sudo,
                            data: map,
                            event_type: EventType::AuthError,
                            raw_msg: s.clone(),
                        };

                        return Some(ev);
                    }
                    "SUDO_WARNING" => {
                        insert_fields!(map, msg, {
                            "msg" => 1,
                        });

                        let ev = EventData {
                            timestamp,
                            service: Service::Sudo,
                            data: map,
                            event_type: EventType::Warning,
                            raw_msg: s.clone(),
                        };

                        return Some(ev);
                    }
                    _ => {}
                }
            }
        }
    }

    None
}

// fn parse_kernel_events()

//TODO: Need to check the name's of the services beacuse there are different on different distros
pub fn flush_previous_data(
    tx: tokio::sync::broadcast::Sender<EventData>,
    unit: Option<Vec<String>>,
) -> Result<()> {
    let mut s: Journal = journal::OpenOptions::default()
        .all_namespaces(true)
        .open()?;

    if let Some(unit) = unit {
        for val in unit {
            match val.as_str() {
                "sshd.events" => {
                    s.match_add("_SYSTEMD_UNIT", "sshd.service")?;
                    while let Some(data) = s.next_entry()? {
                        if let Some(ev) = parse_sshd_logs(data) {
                            if let Err(e) = tx.send(ev) {
                                println!("Dropped");
                            }
                        }
                    }
                }

                "sudo.events" => {
                    s.match_add("_COMM", "su")?;
                    s.match_add("_COMM", "sudo")?;
                    while let Some(data) = s.next_entry()? {
                        if let Some(ev) = parse_sudo_login_attempts(data) {
                            match ev.event_type {
                                EventType::Info => {
                                    println!("{:?}", ev);
                                }
                                _ => {}
                            }
                        }
                    }
                }

                "login.events" => {
                    s.match_add("_COMM", "login")?;
                    s.match_add("_SYSTEMD_UNIT", "systemd-logind.service")?;
                    while let Some(data) = s.next_entry()? {
                        println!("{:?}", data);
                    }
                }

                "pkg.events" => {
                    // Not working!!
                    s.match_add("_EXE", "/usr/bin/yay")?;
                    s.match_add("_EXE", "/usr/bin/pacman")?;
                    while let Some(data) = s.next_entry()? {
                        println!("{:?}", data);
                    }
                }

                "firewall.events" => {
                    s.match_add("_SYSTEMD_UNIT", "firewalld.service")?;
                    while let Some(data) = s.next_entry()? {
                        println!("{:?}", data);
                    }
                }

                "network.events" => {
                    s.match_add("_SYSTEMD_UNIT", "NetworkManger.service")?;
                    while let Some(data) = s.next_entry()? {
                        println!("{:?}", data);
                    }
                }

                "kernel.events" => {
                    s.match_add("_TRANSPORT", "kernel")?;
                    while let Some(data) = s.next_entry()? {
                        println!("{:?}", data);
                    }
                }

                "userchange.events" => {
                    s.match_add("_COMM", "useradd")?;
                    s.match_add("_COMM", "groupadd")?;
                    s.match_add("_COMM", "passwd")?;
                    while let Some(data) = s.next_entry()? {
                        println!("{:?}", data);
                    }
                }

                "config.events" => {
                    s.match_add("_COMM", "sshd-keygen")?;
                    s.match_add("_COMM", "scp")?; // need to add others maybe?
                    s.match_add("_SYSTEMD_UNIT", "cronie.service")?;
                    // s.match_add("_SYSTEMD_UNIT", "cron.service")?;

                    while let Some(data) = s.next_entry()? {
                        println!("{:?}", data);
                    }
                }

                "all.events" => {
                    todo!()
                }
                _ => {}
            }
        }
    } else {
        // while let Some(data) = s.next_entry()? {
        //     parse_login_attempts(data);
        //     // if let Err(e) = tx.send(s) {
        //     //     println!("Dropped");
        //     // }
        // }
    }

    Ok(())
}

pub fn flush_upto_n_entries(
    tx: tokio::sync::broadcast::Sender<Entry>,
    unit: Vec<String>,
    n: usize,
) -> Result<()> {
    let mut s: Journal = journal::OpenOptions::default()
        .all_namespaces(true)
        .open()?;

    for u in unit {
        s.match_add("_SYSTEMD_UNIT", u)?;
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

pub fn read_journal_logs(
    tx: tokio::sync::broadcast::Sender<Entry>,
    unit: Vec<String>,
) -> Result<()> {
    let mut s: Journal = journal::OpenOptions::default()
        .all_namespaces(true)
        .open()
        .unwrap();

    for u in unit {
        s.match_add("_SYSTEMD_UNIT", u)?;
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
