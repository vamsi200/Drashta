#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_imports)]

use crate::events;
use crate::events::receive_data;
use ahash::AHashMap;
use aho_corasick::AhoCorasick;
use anyhow::Result;
use axum::extract::State;
use log::info;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::borrow::Cow;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::result::Result::Ok;
use std::sync::Arc;
use std::time::UNIX_EPOCH;
use std::{
    collections::{BTreeMap, VecDeque},
    fmt::Debug,
    os::fd::{AsRawFd, BorrowedFd},
    thread::sleep,
    time::Duration,
};
use systemd::{journal::JournalRef, *};
use tokio::io::unix::AsyncFd;
use tokio::sync::{broadcast, mpsc};

pub type Entry = BTreeMap<String, String>;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type", content = "value")]
pub enum RawMsgType {
    Structured(BTreeMap<String, String>),
    Plain(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct EventData {
    pub timestamp: String,
    pub service: Service,
    pub event_type: EventType,
    pub data: AHashMap<String, String>,
    pub raw_msg: RawMsgType,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum Service {
    Sshd,
    Sudo,
    Login,
    UserChange,
    PkgManager,
    ConfigChange,
    NetworkManager,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
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
    NewUser,
    NewGroup,
    DeleteGroup,
    DeleteUser,
    ModifyUser,
    ModifyGroup,
    PasswdChange,
    PkgInstalled,
    PkgRemoved,
    PkgUpgraded,
    PkgReinstalled,
    PkgDowndraded,
    CmdRun,
    CronReload,
    NewConnection,
}

type ParserFn = fn(entry_map: Entry) -> Option<EventData>;

pub struct ServiceConfig {
    matches: Vec<(&'static str, &'static str)>,
    parser: ParserFn,
}

macro_rules! insert_fields {
    ($map:expr, $msg:expr, { $($key:expr => $idx:expr),+ $(,)? }) => {
        $(
            $map.insert($key.to_string(), rg_capture(&$msg, $idx)?);
        )+
    };
}

macro_rules! handle_services {
    ($service_name:expr, $tx:expr, $cursor:expr, $limit:expr, $($service:expr),* $(,)?) => {{
        let result: Result<String, anyhow::Error> = if let Some(cursor_val) = $cursor.clone() {
            match $service_name {
                $(
                    $service => process_service_logs($service, $tx.clone(), Some(cursor_val.clone()), $limit),
                )*
                _ => Ok(String::new()),
            }
        } else {
            match $service_name {
                $(
                    $service => process_service_logs($service, $tx.clone(), None, $limit),
                )*
                _ => Ok(String::new()),
            }
        };
        result
    }};
}

pub fn rg_capture(msg: &regex::Captures, i: usize) -> Option<String> {
    msg.get(i).map(|m| m.as_str().to_string())
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
                    raw_msg: RawMsgType::Structured(entry_map),
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
                    timestamp,
                    service: Service::Sshd,
                    data: map,
                    event_type: EventType::Info,
                    raw_msg: RawMsgType::Structured(entry_map),
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
        let trim_msg = s.trim();

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
            }
            if let Some(msg) = regex.captures(trim_msg) {
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
                    raw_msg: RawMsgType::Structured(entry_map),
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
                    raw_msg: RawMsgType::Structured(entry_map),
                });
            }
        }
    }
    None
}
pub fn parse_kernel_events(map: Entry) -> Option<EventData> {
    todo!()
}
pub fn parse_user_change_events(entry_map: Entry) -> Option<EventData> {
    static USER_CREATION_REGEX: Lazy<Vec<(&str, Regex)>> = Lazy::new(|| {
        vec![
            ("NEW_USER", Regex::new(r"^new user: name=(\S+), UID=(\d+), GID=(\d+), home=(\S+), shell=(\S+), from=(\S+)$").unwrap()),
            ("NEW_GROUP", Regex::new(r"^new group: name=(\S+), GID=(\d+)$").unwrap()),
            ("GROUP_ADDED_ETC_GROUP", Regex::new(r"^group added to /etc/group: name=(\S+), GID=(\d+)$").unwrap()),
            ("GROUP_ADDED_ETC_GSHADOW", Regex::new(r"^group added to /etc/gshadow: name=(\S+)$").unwrap()),
        ]
    });

    static USER_DELETION_REGEX: Lazy<Vec<(&str, Regex)>> = Lazy::new(|| {
        vec![
            (
                "DELETE_USER",
                Regex::new(
                    r"^delete user: name=(\S+), UID=(\d+), GID=(\d+), home=(\S+), shell=(\S+)$",
                )
                .unwrap(),
            ),
            (
                "DELETE_USER_HOME",
                Regex::new(r"^delete home directory: (.+)$").unwrap(),
            ),
            (
                "DELETE_USER_MAIL",
                Regex::new(r"^delete mail spool: (.+)$").unwrap(),
            ),
            (
                "DELETE_GROUP",
                Regex::new(r"^delete group: name=(\S+), GID=(\d+)$").unwrap(),
            ),
        ]
    });

    static USER_MODIFICATION_REGEX: Lazy<Vec<(&str, Regex)>> = Lazy::new(|| {
        vec![
            (
                "MODIFY_USER",
                Regex::new(r"^usermod: name=(\S+),.*$").unwrap(),
            ),
            (
                "MODIFY_GROUP",
                Regex::new(r"^groupmod: name=(\S+),.*$").unwrap(),
            ),
            (
                "USER_PASSWD_CHANGE",
                Regex::new(r"^passwd\[(\d+)\]: password changed for (\S+)$").unwrap(),
            ),
            (
                "USER_SHADOW_UPDATED",
                Regex::new(r"^shadow file updated for user (\S+)$").unwrap(),
            ),
        ]
    });

    let mut map = AHashMap::new();
    let mut timestamp = String::new();
    if let Some(tp) = entry_map.get("SYSLOG_TIMESTAMP") {
        timestamp = tp.to_owned();
    }

    if let Some(msg) = entry_map.get("MESSAGE") {
        for (name, regex) in USER_CREATION_REGEX.iter() {
            if let Some(s) = regex.captures(msg) {
                let (data, event_type): (Option<&[(&str, usize)]>, EventType) = match *name {
                    "NEW_USER" => (
                        Some(&[
                            ("name", 1),
                            ("uid", 2),
                            ("gid", 3),
                            ("home", 4),
                            ("shell", 5),
                            ("pts", 6),
                        ]),
                        EventType::NewUser,
                    ),
                    "NEW_GROUP" => (Some(&[("name", 1), ("gid", 2)]), EventType::NewGroup),
                    "GROUP_ADDED_ETC_GROUP" => (Some(&[("name", 1), ("gid", 2)]), EventType::Info),
                    "GROUP_ADDED_ETC_GSHADOW" => (Some(&[("name", 1)]), EventType::Info),
                    _ => (None, EventType::Other),
                };
                if let Some(fields) = data {
                    for &(name, idx) in fields {
                        if let Some(m) = s.get(idx) {
                            map.insert(name.to_string(), m.as_str().to_string());
                        }
                    }
                }
                return Some(EventData {
                    timestamp,
                    service: Service::UserChange,
                    event_type,
                    data: map,
                    raw_msg: RawMsgType::Structured(entry_map),
                });
            }
            for (name, regex) in USER_DELETION_REGEX.iter() {
                if let Some(s) = regex.captures(msg) {
                    let (data, event_type): (Option<&[(&str, usize)]>, EventType) = match *name {
                        "DELETE_USER" => (
                            Some(&[
                                ("name", 1),
                                ("uid", 2),
                                ("gid", 3),
                                ("home", 4),
                                ("shell", 5),
                            ]),
                            EventType::DeleteUser,
                        ),
                        "DELETE_USER_HOME" => (Some(&[("name", 1)]), EventType::DeleteGroup),
                        "DELETE_USER_MAIL" => (Some(&[("name", 1)]), EventType::Info),
                        "DELETE_GROUP" => {
                            (Some(&[("name", 1), ("gid", 2)]), EventType::DeleteGroup)
                        }
                        _ => (None, EventType::Other),
                    };
                    if let Some(fields) = data {
                        for &(name, idx) in fields {
                            if let Some(m) = s.get(idx) {
                                map.insert(name.to_string(), m.as_str().to_string());
                            }
                        }
                    }
                    return Some(EventData {
                        timestamp,
                        service: Service::UserChange,
                        event_type,
                        data: map,
                        raw_msg: RawMsgType::Structured(entry_map),
                    });
                }
            }

            for (name, regex) in USER_MODIFICATION_REGEX.iter() {
                if let Some(s) = regex.captures(msg) {
                    let (data, event_type): (Option<&[(&str, usize)]>, EventType) = match *name {
                        "MODIFY_USER" => (Some(&[("name", 1)]), EventType::ModifyUser),
                        "MODIFY_GROUP" => (Some(&[("name", 1)]), EventType::DeleteGroup),
                        "USER_PASSWD_CHANGE" => {
                            (Some(&[("processid", 1), ("user", 2)]), EventType::Info)
                        }
                        "USER_SHADOW_UPDATED" => (Some(&[("name", 1)]), EventType::DeleteGroup),
                        _ => (None, EventType::Other),
                    };
                    if let Some(fields) = data {
                        for &(name, idx) in fields {
                            if let Some(m) = s.get(idx) {
                                map.insert(name.to_string(), m.as_str().to_string());
                            }
                        }
                    }
                    return Some(EventData {
                        timestamp,
                        service: Service::UserChange,
                        event_type,
                        data: map,
                        raw_msg: RawMsgType::Structured(entry_map),
                    });
                }
            }
        }
    }
    None
}
pub fn parse_pkg_events(content: String) -> Option<EventData> {
    static PKG_EVENTS_REGEX: Lazy<Vec<(&str, Regex)>> = Lazy::new(|| {
        vec![
            (
                "INSTALLED",
                Regex::new(r"^\[(.+?)\] \[ALPM\] installed (\S+) \(([^)]+)\)$").unwrap(),
            ),
            (
                "REMOVED",
                Regex::new(r"^\[(.+?)\] \[ALPM\] removed (\S+) \(([^)]+)\)$").unwrap(),
            ),
            (
                "UPGRADED",
                Regex::new(r"^\[(.+?)\] \[ALPM\] upgraded (\S+) \(([^)]+) -> ([^)]+)\)$").unwrap(),
            ),
            (
                "DOWNGRADED",
                Regex::new(r"^\[(.+?)\] \[ALPM\] downgraded (\S+) \(([^)]+) -> ([^)]+)\)$")
                    .unwrap(),
            ),
            (
                "REINSTALLED",
                Regex::new(r"^\[(.+?)\] \[ALPM\] reinstalled (\S+) \(([^)]+)\)$").unwrap(),
            ),
        ]
    });
    let mut map = AHashMap::new();

    for (name, regex) in PKG_EVENTS_REGEX.iter() {
        if let Some(s) = regex.captures(&content) {
            let timestamp = s.get(1).unwrap().as_str().to_string();
            let (data, event_type): (Option<&[(&str, usize)]>, EventType) = match *name {
                "INSTALLED" => (Some(&[("pkg_name", 2)]), EventType::PkgInstalled),
                "REMOVED" => (Some(&[("pkg_name", 2)]), EventType::PkgRemoved),
                "UPGRADED" => (
                    Some(&[("pkg_name", 2), ("version_from", 3), ("version_to", 4)]),
                    EventType::PkgUpgraded,
                ),
                "DOWNGRADED" => (
                    Some(&[("pkg_name", 2), ("version_from", 3), ("version_to", 4)]),
                    EventType::PkgDowndraded,
                ),
                "REINSTALLED" => (
                    Some(&[("pkg_name", 2), ("version", 3)]),
                    EventType::PkgReinstalled,
                ),
                _ => (None, EventType::Other),
            };

            if let Some(fields) = data {
                for &(name, idx) in fields {
                    if let Some(m) = s.get(idx) {
                        map.insert(name.to_string(), m.as_str().to_string());
                    }
                }
            }
            return Some(EventData {
                timestamp,
                service: Service::PkgManager,
                event_type,
                data: map,
                raw_msg: RawMsgType::Plain(content),
            });
        }
    }
    None
}

pub fn parse_config_change_events(entry_map: Entry) -> Option<EventData> {
    static CRON_REGEX: Lazy<Vec<(&str, Regex)>> = Lazy::new(|| {
        vec![
            (
                "CRON_CMD",
                Regex::new(r"^\((\S+)\)\s+CMD\s+\((.+)\)$").unwrap(),
            ),
            (
                "CRON_RELOAD",
                Regex::new(r"^\((\S+)\)\s+RELOAD\s+\(crontabs/(\S+)\)$").unwrap(),
            ),
            (
                "CRON_ERROR_BAD_COMMAND",
                Regex::new(r"^\((\S+)\)\s+ERROR\s+\(bad command\)$").unwrap(),
            ),
            (
                "CRON_ERROR_BAD_MINUTE",
                Regex::new(r"^\((\S+)\)\s+ERROR\s+\(bad minute\)$").unwrap(),
            ),
            (
                "CRON_ERROR_OTHER",
                Regex::new(r"^\((\S+)\)\s+ERROR\s+\((.+)\)$").unwrap(),
            ),
            (
                "CRON_DENIED",
                Regex::new(r"^\((\S+)\)\s+AUTH\s+\(crontab denied\)$").unwrap(),
            ),
            (
                "CRON_SESSION_OPEN",
                Regex::new(
                    r"^pam_unix\(cron:session\): session opened for user (\S+) by \(uid=(\d+)\)$",
                )
                .unwrap(),
            ),
            (
                "CRON_SESSION_CLOSE",
                Regex::new(r"^pam_unix\(cron:session\): session closed for user (\S+)$").unwrap(),
            ),
        ]
    });
    let mut map = AHashMap::new();
    let mut timestamp = String::new();
    if let Some(tp) = entry_map.get("SYSLOG_TIMESTAMP") {
        timestamp = tp.trim().to_owned();
    }

    for (name, regex) in CRON_REGEX.iter() {
        if let Some(s) = entry_map.get("MESSAGE") {
            let trimmed_msg = s.trim();
            if let Some(msg) = regex.captures(trimmed_msg) {
                let (fields, event_type): (Option<&[(&str, usize)]>, EventType) = match *name {
                    "CRON_CMD" => (Some(&[("user", 1), ("cron_cmd", 2)]), EventType::CmdRun),
                    "CRON_RELOAD" => (
                        Some(&[("user", 1), ("cron_reload", 2)]),
                        EventType::CronReload,
                    ),
                    "CRON_ERROR_BAD_COMMAND" => (Some(&[("user", 1)]), EventType::Info),
                    "CRON_ERROR_BAD_MINUTE" => (Some(&[("user", 1)]), EventType::Info),
                    "CRON_ERROR_OTHER" => (Some(&[("user", 1)]), EventType::Info),

                    "CRON_DENIED" => (Some(&[("user", 1)]), EventType::Failure),
                    "CRON_SESSION_OPEN" => {
                        (Some(&[("user", 1), ("uid", 2)]), EventType::SessionOpened)
                    }
                    "CRON_SESSION_CLOSE" => (Some(&[("user", 1)]), EventType::SessionClosed),

                    _ => (None, EventType::Other),
                };

                if let Some(data) = fields {
                    for &(fields, idx) in data {
                        map.insert(
                            fields.to_string(),
                            msg.get(idx).unwrap().as_str().to_string(),
                        );
                    }
                }

                return Some(EventData {
                    timestamp,
                    service: Service::ConfigChange,
                    event_type,
                    data: map,
                    raw_msg: RawMsgType::Structured(entry_map),
                });
            }
        }
    }
    None
}
pub fn parse_network_events(entry_map: Entry) -> Option<EventData> {
    todo!()
}
pub fn parse_firewalld_events(map: Entry) -> Option<EventData> {
    todo!()
}

pub fn get_service_configs() -> AHashMap<&'static str, ServiceConfig> {
    let mut map = AHashMap::new();

    map.insert(
        "sshd.events",
        ServiceConfig {
            matches: vec![
                ("_COMM", "sshd"),
                ("_EXE", "/usr/sbin/sshd"),
                ("_SYSTEMD_UNIT", "sshd.service"),
            ],
            parser: parse_sshd_logs,
        },
    );

    map.insert(
        "sudo.events",
        ServiceConfig {
            matches: vec![("_COMM", "su"), ("_COMM", "sudo")],
            parser: parse_sudo_login_attempts,
        },
    );

    map.insert(
        "login.events",
        ServiceConfig {
            matches: vec![("_COMM", "login")],
            parser: parse_login_attempts,
        },
    );

    map.insert(
        "firewall.events",
        ServiceConfig {
            matches: vec![("_SYSTEMD_UNIT", "firewalld.service")],
            parser: |_d| None, // TODO
        },
    );

    map.insert(
        "network.events",
        ServiceConfig {
            matches: vec![("_SYSTEMD_UNIT", "NetworkManager.service")],
            parser: parse_network_events,
        },
    );

    map.insert(
        "kernel.events",
        ServiceConfig {
            matches: vec![("_TRANSPORT", "kernel")],
            parser: parse_kernel_events,
        },
    );

    map.insert(
        "userchange.events",
        ServiceConfig {
            matches: vec![
                ("_COMM", "useradd"),
                ("_COMM", "groupadd"),
                ("_COMM", "passwd"),
            ],
            parser: parse_user_change_events,
        },
    );

    map.insert(
        "configchange.events",
        ServiceConfig {
            matches: vec![("_SYSTEMD_UNIT", "cronie.service")],
            parser: parse_config_change_events,
        },
    );

    map
}

pub fn process_upto_n_entries(
    mut journal: Journal,
    tx: tokio::sync::mpsc::Sender<EventData>,
    limit: i32,
    config: &ServiceConfig,
) -> Result<String> {
    for (field, value) in &config.matches {
        journal.match_add(field, value.to_string())?;
        journal.match_or()?;
    }

    journal.seek_head()?;
    let mut count = 0;
    while count < limit {
        if let Some(data) = journal.next_entry()? {
            if let Some(ev) = (config.parser)(data) {
                if tx.blocking_send(ev).is_err() {
                    info!("Event Dropped!");
                }
                count += 1;
            }
        } else {
            break;
        }
    }

    let cursor = journal.cursor()?;
    Ok(cursor)
}
pub fn process_older_logs(
    mut journal: Journal,
    tx: tokio::sync::mpsc::Sender<EventData>,
    limit: i32,
    config: &ServiceConfig,
    cursor: String,
) -> Result<String> {
    for (field, value) in &config.matches {
        journal.match_add(field, value.to_string())?;
        journal.match_or()?;
    }
    journal.seek_cursor(&cursor)?;

    journal.next_entry()?;

    let mut count = 0;
    let mut last_cursor = cursor.clone();

    while count < limit {
        match journal.next_entry()? {
            Some(data) => {
                if let Some(ev) = (config.parser)(data) {
                    if tx.blocking_send(ev).is_err() {
                        info!("Event Dropped!");
                    }
                    count += 1;
                }
                last_cursor = journal.cursor()?;
            }
            None => break,
        }
    }

    Ok(last_cursor)
}

//TODO: Include the live part here as well
//Add the PkgManager impl
pub fn process_service_logs(
    service_name: &str,
    tx: tokio::sync::mpsc::Sender<EventData>,
    cursor: Option<String>,
    limit: i32,
) -> Result<String> {
    let configs = get_service_configs();

    let Some(config) = configs.get(service_name) else {
        anyhow::bail!("Unknown service: {}", service_name);
    };

    let s: Journal = journal::OpenOptions::default()
        .all_namespaces(true)
        .open()?;

    let new_cursor = match cursor {
        Some(cursor) => process_older_logs(s, tx, limit, config, cursor)?,
        None => process_upto_n_entries(s, tx, limit, config)?,
    };

    Ok(new_cursor)
}

// Should also think to capture command failures
//TODO: Need to check the name's of the services beacuse there are different on different distros
pub fn handle_service_event(
    service_name: &str,
    tx: tokio::sync::mpsc::Sender<EventData>,
    cursor: Option<String>,
    limit: i32,
) -> Result<String> {
    let new_cursor = handle_services!(
        service_name,
        tx,
        cursor,
        limit,
        "sshd.events",
        "sudo.events",
        "login.events",
        "firewall.events",
        "network.events",
        "kernel.events",
        "userchange.events",
        "configchange.events",
        "pkgmanager.events",
    )?;

    Ok(new_cursor)
}

pub fn read_journal_logs(
    tx: tokio::sync::broadcast::Sender<EventData>,
    unit: Option<Vec<String>>,
) -> Result<()> {
    let mut s: Journal = journal::OpenOptions::default()
        .all_namespaces(true)
        .open()
        .unwrap();

    if let Some(ref unit) = unit {
        for val in unit {
            if val == "sshd.events" {
                s.match_add("_COMM", "sshd-session")?;
                s.match_or()?;
                s.match_add("_COMM", "sshd")?;
                s.match_or()?;
                s.match_add("_EXE", "/usr/sbin/sshd")?;
                s.match_or()?;
                s.match_add("_SYSTEMD_UNIT", "sshd@.service")?;

                info!("Watching sshd live events...");

                let now = std::time::SystemTime::now()
                    .duration_since(UNIX_EPOCH)?
                    .as_micros() as u64;

                s.seek_realtime_usec(now)?;
                loop {
                    while let Some(data) = s.next_entry()? {
                        if let Some(ev) = parse_sshd_logs(data) {
                            let _ = tx.send(ev);
                        }
                    }
                    sleep(Duration::from_secs(1));
                }
            }
        }
    }

    Ok(())
}
