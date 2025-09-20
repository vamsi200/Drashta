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
    pub event_type: EventType,
    pub data: AHashMap<String, String>,
    pub raw_msg: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Service {
    Sshd,
    Sudo,
    Login,
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
    AuthFailure,
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

pub fn parse_sshd_logs(entry_map: Entry) -> Option<EventData> {
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

    let mut map = AHashMap::new();
    if let Some(s) = entry_map.get("MESSAGE") {
        let mut timestamp = String::new();
        if let Some(tp) = entry_map.get("SYSLOG_TIMESTAMP") {
            timestamp = tp.to_owned();
        }

        for (name, regex) in SSHD_REGEX.iter() {
            if let Some(msg) = regex.captures(s) {
                let (data, event_type): (Option<&[(&str, usize)]>, EventType) = match *name {
                    "AUTH_SUCCESS" => (
                        Some(&[("user", 2), ("ip", 3), ("port", 4), ("method", 1)]),
                        EventType::Success,
                    ),
                    "AUTH_FAILURE" => (
                        Some(&[("method", 1), ("user", 2), ("ip", 3), ("port", 4)]),
                        EventType::Failure,
                    ),

                    "SESSION_OPENED" => {
                        (Some(&[("user", 1), ("uid", 2)]), EventType::SessionOpened)
                    }

                    "SESSION_CLOSED" => (Some(&[("user", 1)]), EventType::SessionClosed),

                    "CONNECTION_CLOSED" => (
                        Some(&[("user", 1), ("ip", 2), ("port", 3), ("msg", 4)]),
                        EventType::ConnectionClosed,
                    ),

                    "WARNING" => (Some(&[("msg", 1)]), EventType::Warning),
                    "UNKNOWN" => (Some(&[("msg", 1)]), EventType::Other),

                    "RECEIVED_DISCONNECT" => (
                        Some(&[("ip", 1), ("port", 2), ("code", 3), ("msg", 4)]),
                        EventType::Other,
                    ),

                    "NEGOTIATION_FAILURE" => (
                        Some(&[("ip", 1), ("port", 2), ("details", 3)]),
                        EventType::Other,
                    ),

                    "TOO_MANY_AUTH" => (
                        Some(&[("user", 1), ("ip", 2), ("port", 3)]),
                        EventType::TooManyAuthFailures,
                    ),

                    _ => (None, EventType::Other),
                };

                if let Some(fields) = data {
                    for &(name, idx) in fields {
                        if let Some(m) = msg.get(idx) {
                            map.insert(name.to_string(), m.as_str().to_string());
                        }
                    }
                }

                return Some(EventData {
                    timestamp,
                    service: Service::Sshd,
                    data: map,
                    event_type,
                    raw_msg: s.clone(),
                });
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
                    event_type: EventType::Info,
                    raw_msg: s.clone(),
                };

                return Some(ev);
            }
        }
    }
    None
}

pub fn parse_sudo_login_attempts(entry_map: Entry) -> Option<EventData> {
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

    let mut map = AHashMap::new();
    if let Some(s) = entry_map.get("MESSAGE") {
        let mut timestamp = String::new();
        if let Some(tp) = entry_map.get("SYSLOG_TIMESTAMP") {
            timestamp = tp.to_owned();
        }
        let trim_msg = s.trim_start();

        for (name, regex) in SUDO_REGEX.iter() {
            if let Some(msg) = regex.captures(trim_msg) {
                let (data, event_type): (Option<&[(&str, usize)]>, EventType) = match *name {
                    "COMMAND_RUN" => (
                        Some(&[
                            ("invoking_user", 1),
                            ("tty", 2),
                            ("pwd", 3),
                            ("target_user", 4),
                            ("command", 5),
                        ]),
                        EventType::Info,
                    ),
                    _ => (None, EventType::Other),
                };
                if let Some(fields) = data {
                    for &(name, idx) in fields {
                        if let Some(m) = msg.get(idx) {
                            map.insert(name.to_string(), m.as_str().to_string());
                        }
                    }
                }
                return Some(EventData {
                    timestamp,
                    service: Service::Sudo,
                    data: map,
                    event_type,
                    raw_msg: s.clone(),
                });
            }
            if let Some(msg) = regex.captures(s) {
                let (data, event_type): (Option<&[(&str, usize)]>, EventType) = match *name {
                    "SESSION_OPENED_SU" => (
                        Some(&[
                            ("target_user", 1),
                            ("uid", 2),
                            ("invoking_user", 3),
                            ("invoking_uid", 4),
                        ]),
                        EventType::SessionOpened,
                    ),

                    "SESSION_OPENED_SUDO" => (
                        Some(&[
                            ("target_user", 1),
                            ("uid", 2),
                            ("invoking_user", 3),
                            ("invoking_uid", 4),
                        ]),
                        EventType::SessionOpened,
                    ),

                    "SESSION_CLOSED" => (Some(&[("target_user", 1)]), EventType::SessionClosed),

                    "AUTH_FAILURE" => (
                        Some(&[
                            ("logname", 1),
                            ("uid", 2),
                            ("euid", 3),
                            ("tty", 4),
                            ("ruser", 5),
                            ("rhost", 6),
                            ("target_user", 7),
                        ]),
                        EventType::Failure,
                    ),
                    "INCORRECT_PASSWORD" => (
                        Some(&[
                            ("invoking_user", 1),
                            ("attempts", 2),
                            ("tty", 3),
                            ("pwd", 4),
                            ("target_user", 5),
                            ("command", 6),
                        ]),
                        EventType::IncorrectPassword,
                    ),

                    "NOT_IN_SUDOERS" => (Some(&[("user", 1)]), EventType::Info),

                    "AUTH_ERROR" => (Some(&[("msg", 1)]), EventType::AuthError),

                    "SUDO_WARNING" => (Some(&[("msg", 1)]), EventType::Warning),

                    _ => (None, EventType::Other),
                };

                if let Some(fields) = data {
                    for &(name, idx) in fields {
                        if let Some(m) = msg.get(idx) {
                            map.insert(name.to_string(), m.as_str().to_string());
                        }
                    }
                }
                if *name == "AUTH_ERROR" {
                    if let Some(user) = msg.get(2) {
                        map.insert("user".to_string(), user.as_str().to_string());
                    }
                }

                return Some(EventData {
                    timestamp,
                    service: Service::Sudo,
                    data: map,
                    event_type,
                    raw_msg: s.clone(),
                });
            }
        }
    }

    None
}

pub fn parse_login_attempts(entry_map: Entry) -> Option<EventData> {
    static LOGIN_REGEXES: Lazy<Vec<(&str, Regex)>> = Lazy::new(|| {
        vec![
        ("AUTH_FAILURE", Regex::new(r"^pam_unix\(login:auth\): authentication failure; logname=(\S+) uid=(\d+) euid=(\d+) tty=(\S+) ruser=(\S*) rhost=(\S*)$").unwrap()),
        ("AUTH_CHECK_PASS", Regex::new(r"^pam_unix\(login:auth\): check pass; user unknown$").unwrap()),
        ("AUTH_USER_UNKNOWN", Regex::new(r"^pam_unix\(login:auth\): user (\S+) unknown$").unwrap()),
        ("FAILL0CK_USER_UNKNOWN", Regex::new(r"^pam_faillock\(login:auth\): User unknown$").unwrap()),
        ("NOLOGIN_REFUSED", Regex::new(r"^pam_nologin\(login:auth\): Refused user (\S+)").unwrap()),
        ("ACCOUNT_EXPIRED", Regex::new(r"^pam_unix\(login:account\): account (\S+) has expired.*$").unwrap()),
        ("SESSION_OPENED", Regex::new(r"^pam_unix\(login:session\): session opened for user (\S+)\(uid=(\d+)\) by LOGIN\(uid=(\d+)\)$").unwrap()),
        ("SESSION_CLOSED", Regex::new(r"^pam_unix\(login:session\): session closed for user (\S+)$").unwrap()),
        ("LOGIN_SUCCESS", Regex::new(r"^LOGIN ON (\S+) BY (\S+)$").unwrap()),
        ("FAILED_LOGIN", Regex::new(r"^FAILED LOGIN \d+ (?:FROM (\S+) )?FOR (\S+), (.+)$").unwrap()),
        ("FAILED_LOGIN_TTY", Regex::new(r"^FAILED LOGIN \d+ ON (\S+) FOR (\S+), (.+)$").unwrap()),
        ("TOO_MANY_TRIES", Regex::new(r"^TOO MANY LOGIN TRIES \(\d+\) ON (\S+) FOR (\S+)$").unwrap()),
    ]
    });

    let mut map = AHashMap::new();

    for (name, regex) in LOGIN_REGEXES.iter() {
        let mut timestamp = String::new();
        if let Some(tp) = entry_map.get("SYSLOG_TIMESTAMP") {
            timestamp = tp.to_owned();
        }

        if let Some(s) = entry_map.get("MESSAGE") {
            if let Some(msg) = regex.captures(s) {
                let (data, event_type): (Option<&[(&str, usize)]>, EventType) = match *name {
                    "AUTH_FAILURE" => (
                        Some(&[
                            ("logname", 1),
                            ("uid", 2),
                            ("euid", 3),
                            ("tty", 4),
                            ("ruser", 5),
                            ("rhost", 6),
                        ]),
                        EventType::AuthFailure,
                    ),

                    "AUTH_CHECK_PASS" | "AUTH_USER_UNKNOWN" | "FAILL0CK_USER_UNKNOWN" => {
                        (None, EventType::Info)
                    }

                    "NOLOGIN_REFUSED" | "ACCOUNT_EXPIRED" => {
                        (Some(&[("user", 1)]), EventType::Info)
                    }

                    "SESSION_OPENED" => (
                        Some(&[("user", 1), ("uid", 2), ("LoginId", 3)]),
                        EventType::SessionOpened,
                    ),

                    "SESSION_CLOSED" => (Some(&[("user", 1)]), EventType::SessionClosed),

                    "LOGIN_SUCCESS" => (Some(&[("tty", 1), ("user", 2)]), EventType::Success),

                    "FAILED_LOGIN" | "FAILED_LOGIN_TTY" => (
                        Some(&[("tries", 2), ("tty", 1), ("user", 3)]),
                        EventType::Failure,
                    ),

                    "TOO_MANY_TRIES" => (
                        Some(&[("tries", 1), ("tty", 2), ("user", 3)]),
                        EventType::TooManyAuthFailures,
                    ),

                    _ => (None, EventType::Other),
                };

                if let Some(fields) = data {
                    for &(name, idx) in fields {
                        if let Some(m) = msg.get(idx) {
                            map.insert(name.to_string(), m.as_str().to_string());
                        }
                    }
                }
                return Some(EventData {
                    timestamp,
                    service: Service::Login,
                    data: map,
                    event_type,
                    raw_msg: s.clone(),
                });
            }
        }
    }
    None
}
pub fn parse_kernel_events(map: Entry) -> Option<EventData> {
    todo!()
}
pub fn parse_user_change_events(map: Entry) -> Option<EventData> {
    todo!()
}

pub fn parse_pkg_events(map: Entry) -> Option<EventData> {
    todo!()
}

pub fn parse_config_change_events(map: Entry) -> Option<EventData> {
    todo!()
}
pub fn parse_network_events(map: Entry) -> Option<EventData> {
    todo!()
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
                                EventType::AuthError => {
                                    println!("{:?}", ev);
                                }
                                _ => {}
                            }
                        }
                    }
                }

                "login.events" => {
                    s.match_add("_COMM", "login")?;
                    while let Some(data) = s.next_entry()? {
                        if let Some(ev) = parse_login_attempts(data) {
                            println!("{:?}", ev);
                        }
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
