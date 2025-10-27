#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_imports)]

use crate::events;
use crate::events::receive_data;
use ahash::AHashMap;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use aho_corasick::{Input, Match, automaton::Automaton, dfa::DFA};
use anyhow::Result;
use axum::extract::State;
use futures::future::Either;
use log::{error, info};
use memchr::memmem;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::borrow::Cow;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek};
use std::path::PathBuf;
use std::result::Result::Ok;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::Mutex;
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
    Structured(Entry),
    Plain(String),
}

impl RawMsgType {
    fn contains_bytes(&self, pat: &str) -> bool {
        let ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(&[pat])
            .unwrap();

        match self {
            RawMsgType::Structured(map) => map.values().any(|v| ac.is_match(v)),
            RawMsgType::Plain(s) => ac.is_match(s),
        }
    }
}
#[derive(PartialEq, Deserialize, Serialize, Debug, Clone)]
pub struct Cursor {
    pub timestamp: String,
    pub data: String,
    pub offset: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ProcessLogType {
    ProcessInitialLogs,
    ProcessOlderLogs,
    ProcessPreviousLogs,
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

type ParserFn = fn(entry_map: Entry, ev_type: Option<Vec<&str>>) -> Option<EventData>;

pub struct ServiceConfig {
    matches: Vec<(&'static str, &'static str)>,
    parser: ParserFn,
}

#[derive(Clone)]
pub struct ParserFuncArgs<'a> {
    service_name: &'a str,
    tx: tokio::sync::mpsc::Sender<EventData>,
    limit: i32,
    processlogtype: ProcessLogType,
    filter: Option<String>,
    ev_type: Option<Vec<&'a str>>,
    journal: Arc<Mutex<Journal>>,
    cursor: Option<CursorType>,
}

impl<'a> ParserFuncArgs<'a> {
    pub fn new(
        service_name: &'a str,
        tx: tokio::sync::mpsc::Sender<EventData>,
        limit: i32,
        processlogtype: ProcessLogType,
        filter: Option<String>,
        ev_type: Option<Vec<&'a str>>,
        cursor: Option<CursorType>,
    ) -> Self {
        let journal: Journal = journal::OpenOptions::default()
            .all_namespaces(true)
            .open()
            .expect("Couldn't create new Journal");
        Self {
            cursor,
            service_name,
            tx,
            limit,
            processlogtype,
            filter,
            ev_type,
            journal: Arc::new(Mutex::new(journal)),
        }
    }
}

pub static MANUAL_PARSE_EVENTS: Lazy<Vec<&'static str>> = Lazy::new(|| vec!["pkgmanager.events"]);

// TODO: Work on using Structs for function arguments.. I can't do this all day lil bro..
macro_rules! handle_services {
    (
        $opts:expr,
        $cursor:expr,
        $($service:expr),* $(,)?
    ) => {{
        let opts = $opts.clone();
        let service_name = opts.service_name;
        let cursor: Option<String> = $cursor;
        let result: Result<String, anyhow::Error> = match service_name {
            $(
                $service => process_service_logs(
                    $opts,
                    $cursor
                ),
            )*
            _ => Ok(String::new()),
        };

        result
    }};
}

pub fn rg_capture(msg: &regex::Captures, i: usize) -> Option<String> {
    msg.get(i).map(|m| m.as_str().to_string())
}

pub fn str_to_regex_names(ev: &str) -> &'static [&'static str] {
    match ev {
        // SSHD
        "Success" => &["AUTH_SUCCESS"],
        "Failure" => &["AUTH_FAILURE"],
        "SessionOpened" => &["SESSION_OPENED"],
        "SessionClosed" => &["SESSION_CLOSED"],
        "ConnectionClosed" => &["CONNECTION_CLOSED"],
        "TooManyAuthFailures" => &["TOO_MANY_AUTH"],
        "Warning" => &["WARNING"],
        "Info" => &["RECEIVED_DISCONNECT", "NEGOTIATION_FAILURE"],
        "Other" => &["UNKNOWN"],
        // SUDO
        "IncorrectPassword" => &["INCORRECT_PASSWORD"],
        "AuthError" => &["AUTH_ERROR"],
        "AuthFailure" => &["AUTH_FAILURE"],
        "CmdRun" => &["COMMAND_RUN"],
        "SessionOpenedSudo" => &["SESSION_OPENED_SUDO", "SESSION_OPENED_SU"],
        "SudoWarning" => &["SUDO_WARNING"],
        "NotInSudoers" => &["NOT_IN_SUDOERS"],
        // LOGIN
        "LoginSuccess" => &["LOGIN_SUCCESS"],
        "FailedLogin" => &["FAILED_LOGIN", "FAILED_LOGIN_TTY"],
        "TooManyTries" => &["TOO_MANY_TRIES"],
        "AuthCheckPass" => &["AUTH_CHECK_PASS"],
        "AuthUserUnknown" => &["AUTH_USER_UNKNOWN"],
        "FaillockUserUnknown" => &["FAILL0CK_USER_UNKNOWN"],
        "NoLoginRefused" => &["NOLOGIN_REFUSED"],
        "AccountExpired" => &["ACCOUNT_EXPIRED"],
        "SessionOpenedLogin" => &["SESSION_OPENED"],
        "SessionClosedLogin" => &["SESSION_CLOSED"],
        // USER CREATION
        "NewUser" => &["NEW_USER"],
        "NewGroup" => &["NEW_GROUP"],
        "GroupAddedEtcGroup" => &["GROUP_ADDED_ETC_GROUP"],
        "GroupAddedEtcGshadow" => &["GROUP_ADDED_ETC_GSHADOW"],
        // USER DELETION
        "DeleteUser" => &["DELETE_USER"],
        "DeleteUserHome" => &["DELETE_USER_HOME"],
        "DeleteUserMail" => &["DELETE_USER_MAIL"],
        "DeleteGroup" => &["DELETE_GROUP"],
        // USER MODIFICATION
        "ModifyUser" => &["MODIFY_USER"],
        "ModifyGroup" => &["MODIFY_GROUP"],
        "PasswdChange" => &["USER_PASSWD_CHANGE"],
        "ShadowUpdated" => &["USER_SHADOW_UPDATED"],
        // PKG EVENTS
        "PkgInstalled" => &["INSTALLED"],
        "PkgRemoved" => &["REMOVED"],
        "PkgUpgraded" => &["UPGRADED"],
        "PkgDowndraded" => &["DOWNGRADED"],
        "PkgReinstalled" => &["REINSTALLED"],
        // CRON
        "CronCmd" => &["CRON_CMD"],
        "CronReload" => &["CRON_RELOAD"],
        "CronErrorBadCommand" => &["CRON_ERROR_BAD_COMMAND"],
        "CronErrorBadMinute" => &["CRON_ERROR_BAD_MINUTE"],
        "CronErrorOther" => &["CRON_ERROR_OTHER"],
        "CronDenied" => &["CRON_DENIED"],
        "CronSessionOpen" => &["CRON_SESSION_OPEN"],
        "CronSessionClose" => &["CRON_SESSION_CLOSE"],
        "NewConnection" => &["CONNECTION_CLOSED"],

        _ => &[],
    }
}

pub fn parse_sshd_logs(entry_map: Entry, ev_type: Option<Vec<&str>>) -> Option<EventData> {
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

    let msg = entry_map.get("MESSAGE")?;
    let timestamp = entry_map
        .get("SYSLOG_TIMESTAMP")
        .cloned()
        .unwrap_or_default();

    let filtered_regexes: Vec<_> = if let Some(ev_types) = ev_type {
        let names: Vec<&str> = ev_types
            .iter()
            .flat_map(|&s| str_to_regex_names(s).to_owned())
            .collect();

        SSHD_REGEX
            .iter()
            .filter(|(name, _)| names.contains(name))
            .collect()
    } else {
        SSHD_REGEX.iter().collect()
    };

    let mut map = AHashMap::new();
    let s = entry_map.get("MESSAGE")?;
    let timestamp = entry_map
        .get("SYSLOG_TIMESTAMP")
        .cloned()
        .unwrap_or_default();

    for (name, regex) in filtered_regexes {
        if let Some(caps) = regex.captures(s) {
            let (data, event_type): (Option<&[(&str, usize)]>, EventType) = match *name {
                "AUTH_SUCCESS" => (
                    Some(&[("user", 2), ("ip", 3), ("port", 4), ("method", 1)]),
                    EventType::Success,
                ),
                "AUTH_FAILURE" => (
                    Some(&[("method", 1), ("user", 2), ("ip", 3), ("port", 4)]),
                    EventType::Failure,
                ),
                "SESSION_OPENED" => (Some(&[("user", 1)]), EventType::SessionOpened),
                "SESSION_CLOSED" => (Some(&[("user", 1)]), EventType::SessionClosed),
                "CONNECTION_CLOSED" => (
                    Some(&[("user", 1), ("ip", 2), ("port", 3)]),
                    EventType::ConnectionClosed,
                ),
                "WARNING" => (Some(&[("msg", 1)]), EventType::Warning),
                "TOO_MANY_AUTH" => (Some(&[("user", 1)]), EventType::TooManyAuthFailures),
                _ => (Some(&[("msg", 1)]), EventType::Other),
            };

            if let Some(fields) = data {
                for &(fname, idx) in fields {
                    if let Some(m) = caps.get(idx) {
                        map.insert(fname.to_string(), m.as_str().to_string());
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
    None
}

pub fn parse_sudo_login_attempts(
    entry_map: Entry,
    ev_type: Option<Vec<&str>>,
) -> Option<EventData> {
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

    let filtered_regexes: Vec<_> = if let Some(ev_types) = ev_type {
        let names: Vec<&str> = ev_types
            .iter()
            .flat_map(|&s| str_to_regex_names(s).to_owned())
            .collect();

        SUDO_REGEX
            .iter()
            .filter(|(name, _)| names.contains(name))
            .collect()
    } else {
        SUDO_REGEX.iter().collect()
    };

    let mut map = AHashMap::new();
    if let Some(s) = entry_map.get("MESSAGE") {
        let mut timestamp = String::new();
        if let Some(tp) = entry_map.get("SYSLOG_TIMESTAMP") {
            timestamp = tp.to_owned();
        }
        let trim_msg = s.trim();

        for (name, regex) in filtered_regexes.iter() {
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

pub fn parse_login_attempts(entry_map: Entry, ev_type: Option<Vec<&str>>) -> Option<EventData> {
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

    let filtered_regexes: Vec<_> = if let Some(ev_types) = ev_type {
        let names: Vec<&str> = ev_types
            .iter()
            .flat_map(|&s| str_to_regex_names(s).to_owned())
            .collect();

        LOGIN_REGEXES
            .iter()
            .filter(|(name, _)| names.contains(name))
            .collect()
    } else {
        LOGIN_REGEXES.iter().collect()
    };

    for (name, regex) in filtered_regexes.iter() {
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

pub fn parse_kernel_events(map: Entry, ev_type: Option<Vec<&str>>) -> Option<EventData> {
    todo!()
}

pub fn parse_user_change_events(entry_map: Entry, ev_type: Option<Vec<&str>>) -> Option<EventData> {
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

    let filtered_regexes: Vec<_> = if let Some(ev_types) = ev_type {
        let names: Vec<&str> = ev_types
            .iter()
            .flat_map(|&s| str_to_regex_names(s).to_owned())
            .collect();

        let filtered: Vec<_> = USER_CREATION_REGEX
            .iter()
            .chain(USER_DELETION_REGEX.iter())
            .chain(USER_MODIFICATION_REGEX.iter())
            .filter(|(name, _)| names.contains(name))
            .collect();
        filtered
    } else {
        let filtered: Vec<_> = USER_CREATION_REGEX
            .iter()
            .chain(USER_DELETION_REGEX.iter())
            .chain(USER_MODIFICATION_REGEX.iter())
            .collect();
        filtered
    };

    let mut map = AHashMap::new();
    let mut timestamp = String::new();
    if let Some(tp) = entry_map.get("SYSLOG_TIMESTAMP") {
        timestamp = tp.to_owned();
    }

    if let Some(msg) = entry_map.get("MESSAGE") {
        for (name, regex) in filtered_regexes.iter() {
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
            for (name, regex) in filtered_regexes.iter() {
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

            for (name, regex) in filtered_regexes.iter() {
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

pub fn parse_pkg_events(content: String, ev_type: Option<Vec<&str>>) -> Option<EventData> {
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

    let filtered_regexes: Vec<_> = if let Some(ev_types) = ev_type {
        let names: Vec<&str> = ev_types
            .iter()
            .flat_map(|&s| str_to_regex_names(s).to_owned())
            .collect();

        PKG_EVENTS_REGEX
            .iter()
            .filter(|(name, _)| names.contains(name))
            .collect()
    } else {
        PKG_EVENTS_REGEX.iter().collect()
    };

    for (name, regex) in filtered_regexes.iter() {
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

pub fn parse_config_change_events(
    entry_map: Entry,
    ev_type: Option<Vec<&str>>,
) -> Option<EventData> {
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

    let filtered_regexes: Vec<_> = if let Some(ev_types) = ev_type {
        let names: Vec<&str> = ev_types
            .iter()
            .flat_map(|&s| str_to_regex_names(s).to_owned())
            .collect();

        CRON_REGEX
            .iter()
            .filter(|(name, _)| names.contains(name))
            .collect()
    } else {
        CRON_REGEX.iter().collect()
    };

    let mut map = AHashMap::new();
    let mut timestamp = String::new();
    if let Some(tp) = entry_map.get("SYSLOG_TIMESTAMP") {
        timestamp = tp.trim().to_owned();
    }

    for (name, regex) in filtered_regexes.iter() {
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
pub fn parse_network_events(entry_map: Entry, ev_type: Option<Vec<&str>>) -> Option<EventData> {
    todo!()
}
pub fn parse_firewalld_events(map: Entry, ev_type: Option<Vec<&str>>) -> Option<EventData> {
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
            parser: |_d, _s| None, // TODO
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

pub fn process_upto_n_entries(opts: ParserFuncArgs, config: &ServiceConfig) -> Result<String> {
    let filter = opts.filter;
    let limit = opts.limit;
    let tx = opts.tx;
    let mut journal = opts.journal.lock().unwrap();
    let event_type = opts.ev_type;

    let mut keyword = String::new();
    if let Some(filter) = filter {
        keyword = filter;
    }

    for (field, value) in &config.matches {
        journal.match_add(field, value.to_string())?;
        journal.match_or()?;
    }

    journal.seek_head()?;
    let mut count = 0;
    while count < limit {
        if let Some(data) = journal.next_entry()? {
            if let Some(ev) = (config.parser)(data, event_type.clone()) {
                if !ev.raw_msg.contains_bytes(keyword.as_str()) {
                    continue;
                }
                if tx.blocking_send(ev).is_err() {
                    error!("Event Dropped!");
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
    opts: ParserFuncArgs,
    ev_type: Option<Vec<&str>>,
    config: &ServiceConfig,
    cursor: String,
) -> Result<String> {
    let filter = opts.filter;
    let limit = opts.limit;
    let tx = opts.tx;
    let mut journal = opts.journal.lock().unwrap();
    let event_type = opts.ev_type;

    let mut keyword = String::new();
    if let Some(filter) = filter {
        keyword = filter;
    }

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
                if let Some(ev) = (config.parser)(data, ev_type.clone()) {
                    if !ev.raw_msg.contains_bytes(keyword.as_str()) {
                        continue;
                    }
                    if tx.blocking_send(ev).is_err() {
                        error!("Event Dropped!");
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

pub fn process_previous_logs(
    opts: ParserFuncArgs,
    config: &ServiceConfig,
    cursor: String,
) -> Result<String> {
    let filter = opts.filter;
    let limit = opts.limit;
    let tx = opts.tx;
    let event_type = opts.ev_type;
    let mut journal = opts.journal.lock().unwrap();

    let mut keyword = String::new();
    if let Some(filter) = filter {
        keyword = filter;
    }
    for (i, (field, value)) in config.matches.iter().enumerate() {
        journal.match_add(field, value.to_string())?;
        if i < config.matches.len() - 1 {
            journal.match_or()?;
        }
    }

    journal.seek_cursor(&cursor)?;

    let mut count = 0;
    let mut last_cursor = cursor.clone();
    while count < limit {
        match journal.previous_entry()? {
            Some(data) => {
                if let Some(ev) = (config.parser)(data, event_type.clone()) {
                    if !ev.raw_msg.contains_bytes(keyword.as_str()) {
                        continue;
                    }
                    if tx.blocking_send(ev).is_err() {
                        error!("Event Dropped!");
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
    opts: ParserFuncArgs,
    cursor: Option<String>,
) -> Result<String, anyhow::Error> {
    let configs = get_service_configs();
    let event_type = opts.ev_type.clone();
    let service_name = opts.service_name;
    let processlogtype = opts.processlogtype.clone();
    let Some(config) = configs.get(service_name) else {
        ::anyhow::bail!("Unknown Service: {}", service_name);
    };

    let s: Journal = journal::OpenOptions::default()
        .all_namespaces(true)
        .open()?;

    let new_cursor = match (cursor, processlogtype) {
        (Some(cursor), ProcessLogType::ProcessOlderLogs) => {
            process_older_logs(opts, event_type, config, cursor)?
        }
        (Some(cursor), ProcessLogType::ProcessPreviousLogs) => {
            process_previous_logs(opts, config, cursor)?
        }
        (None, ProcessLogType::ProcessInitialLogs) => process_upto_n_entries(opts, config)?,
        _ => String::new(),
    };

    Ok(new_cursor)
}

pub fn process_manual_events_upto_n(opts: ParserFuncArgs) -> Result<Option<Cursor>> {
    let service_name = opts.service_name;
    let filter = opts.filter.clone();
    let ev_type = opts.ev_type.clone();
    let cursor = opts.cursor.clone();
    let limit = opts.limit;
    let tx = opts.tx.clone();

    let mut keyword = String::new();
    if let Some(filter) = filter {
        keyword = filter;
    }

    let mut cursor: Option<Cursor> = None;

    if service_name == "pkgmanager.events" {
        let file_name = PathBuf::from("/var/log/pacman.log");
        let file = File::open(file_name).unwrap();
        let mut reader = BufReader::with_capacity(128 * 1024, file);
        info!("Called pkgmanager.events");
        let mut count = 0;
        let mut buf = String::new();
        let mut line_count = 0;
        while reader.read_line(&mut buf).unwrap() > 0 && count < limit {
            let offset = reader.stream_position()?;
            line_count += 1;
            if let Some(ev) = parse_pkg_events(buf.trim_end().to_string(), ev_type.clone()) {
                if !ev.raw_msg.contains_bytes(keyword.as_str()) {
                    continue;
                }
                if tx.blocking_send(ev.clone()).is_err() {
                    error!("Event Dropped!");
                }
                count += 1;
                if cursor.is_none() {
                    let timestamp = ev.timestamp.clone();
                    let mut data = String::new();
                    match ev.raw_msg.clone() {
                        RawMsgType::Plain(s) => {
                            data = s;
                        }
                        _ => {}
                    }
                    cursor = Some(Cursor {
                        timestamp,
                        data,
                        offset,
                    })
                }
            }
            buf.clear();
        }
    }
    Ok(cursor)
}

pub fn process_manual_events_next(opts: ParserFuncArgs, cursor: Cursor) -> Result<Option<Cursor>> {
    let service_name = opts.service_name;
    let filter = opts.filter.clone();
    let ev_type = opts.ev_type.clone();
    let limit = opts.limit;
    let tx = opts.tx.clone();

    let mut keyword = String::new();
    if let Some(filter) = filter {
        keyword = filter;
    }
    let mut new_cursor: Option<Cursor> = None;
    let mut count = 0;

    if service_name == "pkgmanager.events" {
        let patterns = [cursor.timestamp.as_bytes()];

        let file = File::open("/var/log/pacman.log")?;
        let mut reader = BufReader::new(&file);

        let mut line = String::new();

        reader.seek(std::io::SeekFrom::Start(cursor.offset))?;
        info!("Seeking from {}", cursor.offset);

        let mut line_count = 0;

        while reader.read_line(&mut line)? > 0 {
            line_count += 1;
            let offset = reader.stream_position()? - line.len() as u64;

            if line_count == 1 {
                if patterns
                    .iter()
                    .all(|pat| memmem::find(line.as_bytes(), pat).is_none())
                {
                    error!("Line Mismatch!");
                    break;
                }
                line.clear();
                continue;
            }

            if let Some(ev) = parse_pkg_events(line.trim_end().to_string(), ev_type.clone()) {
                if !ev.raw_msg.contains_bytes(keyword.as_str()) {
                    continue;
                }
                if tx.blocking_send(ev.clone()).is_err() {
                    error!("Event Dropped!");
                    break;
                }

                count += 1;

                let timestamp = ev.timestamp.clone();
                let data = match ev.raw_msg.clone() {
                    RawMsgType::Plain(s) => s,
                    _ => String::new(),
                };
                new_cursor = Some(Cursor {
                    timestamp,
                    data,
                    offset,
                });

                if count >= limit {
                    break;
                }
            }

            line.clear();
        }
    }
    Ok(new_cursor)
}

pub fn process_manual_events_previous(
    opts: ParserFuncArgs,
    cursor: Cursor,
) -> Result<Option<Cursor>> {
    let service_name = opts.service_name;
    let filter = opts.filter.clone();
    let ev_type = opts.ev_type.clone();
    let limit = opts.limit;
    let tx = opts.tx.clone();
    let mut new_cursor: Option<Cursor> = None;
    let mut keyword = String::new();
    if let Some(filter) = filter {
        keyword = filter;
    }
    let chunk_size = 8192;
    if service_name == "pkgmanager.events" {
        let patterns = [cursor.timestamp.as_bytes(), cursor.data.as_bytes()];
        let offset = cursor.offset;
        let lines = read_file_backward("/var/log/pacman.log", offset)?;
        let mut count = 0;
        if patterns
            .iter()
            .all(|pat| memmem::find(lines.iter().nth(0).unwrap().as_bytes(), pat).is_some())
        {
            for line in lines {
                if count >= limit {
                    break;
                }
                if let Some(ev) = parse_pkg_events(line.trim_end().to_string(), ev_type.clone()) {
                    if !ev.raw_msg.contains_bytes(keyword.as_str()) {
                        continue;
                    }
                    if tx.blocking_send(ev.clone()).is_err() {
                        continue;
                    } else {
                        count += 1;
                    }

                    if new_cursor.is_none() {
                        let timestamp = ev.timestamp.clone();
                        let data = match ev.raw_msg.clone() {
                            RawMsgType::Plain(s) => s,
                            _ => String::new(),
                        };
                        new_cursor = Some(Cursor {
                            timestamp,
                            data,
                            offset,
                        });
                    }
                }
            }
        } else {
            error!("Line Mismatch!");
        }
    }
    Ok(new_cursor)
}

pub fn read_file_backward(path: &str, offset: u64) -> Result<Vec<String>> {
    let mut file = File::open(path)?;
    let chunk_size = 8192;
    let mut out = Vec::new();
    let mut partial_line = String::new();
    let mut current_pos = offset;

    file.seek(std::io::SeekFrom::Start(offset))?;
    let mut reader = BufReader::new(&file);
    let mut line_at_offset = String::new();
    reader.read_line(&mut line_at_offset)?;

    if !line_at_offset.is_empty() {
        out.push(line_at_offset.trim_end_matches('\n').to_string());
    }

    file = File::open(path)?;

    while current_pos > 0 {
        let read_size = chunk_size.min(current_pos as usize);
        current_pos -= read_size as u64;

        let mut buf = vec![0u8; read_size];
        file.seek(std::io::SeekFrom::Start(current_pos))?;
        file.read_exact(&mut buf)?;

        let chunk = String::from_utf8_lossy(&buf).to_string();

        let full_chunk = format!("{}{}", chunk, partial_line);
        let split: Vec<&str> = full_chunk.split('\n').collect();

        partial_line = split[0].to_string();

        for line in split.iter().skip(1).rev() {
            if !line.is_empty() {
                out.push(line.to_string());
            }
        }
    }

    if current_pos == 0 && !partial_line.is_empty() {
        out.push(partial_line);
    }

    Ok(out)
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum CursorType {
    Journal(String),
    Manual(Cursor),
}

impl FromStr for CursorType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with("Journal:") {
            Ok(CursorType::Journal(s["Journal:".len()..].to_string()))
        } else if s.starts_with("Manual:") {
            let json_str = &s["Manual:".len()..];
            serde_json::from_str::<Cursor>(json_str)
                .map(CursorType::Manual)
                .map_err(|e| format!("Failed to parse Manual cursor: {}", e))
        } else {
            Err(format!("Unknown cursor variant: {}", s))
        }
    }
}

pub fn deserialize_cursor<'de, D>(deserializer: D) -> Result<Option<CursorType>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;
    match s {
        Some(s) if !s.is_empty() => serde_json::from_str::<CursorType>(&s)
            .map(Some)
            .map_err(serde::de::Error::custom),
        _ => Ok(None),
    }
}

// Should also think to capture command failures
//TODO: Need to check the name's of the services beacuse there are different on different distros
pub fn handle_service_event(opts: ParserFuncArgs) -> Result<Option<CursorType>> {
    let mut cursor_type: Option<CursorType> = None;
    let service_name = opts.service_name;
    let filter = opts.filter.clone();
    let ev_type = opts.ev_type.clone();
    let cursor = opts.cursor.clone();
    let processlogtype = opts.processlogtype.clone();
    let limit = opts.limit;
    let tx = opts.tx.clone();
    let is_manual_service = MANUAL_PARSE_EVENTS.iter().any(|&ev| ev == service_name);
    let configs = get_service_configs();

    if is_manual_service {
        match processlogtype {
            ProcessLogType::ProcessInitialLogs => {
                if let Some(c) = process_manual_events_upto_n(opts)? {
                    cursor_type = Some(CursorType::Manual(c));
                }
            }
            ProcessLogType::ProcessOlderLogs => {
                if let Some(CursorType::Manual(c)) = cursor {
                    if let Some(next_c) = process_manual_events_next(opts, c)? {
                        cursor_type = Some(CursorType::Manual(next_c));
                    }
                }
            }
            ProcessLogType::ProcessPreviousLogs => {
                if let Some(CursorType::Manual(c)) = cursor {
                    if let Some(prev_c) = process_manual_events_previous(opts, c)? {
                        cursor_type = Some(CursorType::Manual(prev_c));
                    }
                }
            }
        }
    } else {
        match cursor {
            Some(CursorType::Journal(c)) => {
                if let Ok(new_c) = handle_services!(
                    opts.clone(),
                    Some(c.clone()),
                    "sshd.events",
                    "sudo.events",
                    "login.events",
                    "firewall.events",
                    "network.events",
                    "kernel.events",
                    "userchange.events",
                    "configchange.events",
                    "pkgmanager.events",
                ) {
                    cursor_type = Some(CursorType::Journal(new_c));
                }
            }
            None => {
                info!("Invoked initial drain!");
                if let Ok(new_c) = handle_services!(
                    opts,
                    None,
                    "sshd.events",
                    "sudo.events",
                    "login.events",
                    "firewall.events",
                    "network.events",
                    "kernel.events",
                    "userchange.events",
                    "configchange.events",
                    "pkgmanager.events",
                ) {
                    cursor_type = Some(CursorType::Journal(new_c));
                }
            }
            _ => {}
        }
    }
    Ok(cursor_type)
}

pub fn search_logs(input: EventData, search_query: &str) -> Result<()> {
    let patterns = &[search_query];
    let ac = AhoCorasick::new(patterns).unwrap();
    let data = input.raw_msg;
    match data {
        RawMsgType::Plain(ref map) => {
            for mat in ac.find_iter(map.as_str()) {
                info!("Found in line - {:?}", map);
            }
        }
        _ => {}
    }
    Ok(())
}
pub fn read_journal_logs(
    tx: tokio::sync::broadcast::Sender<EventData>,
    unit: Option<Vec<String>>,
    ev_type: Option<Vec<&str>>,
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
                        if let Some(ev) = parse_sshd_logs(data, ev_type.clone()) {
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
