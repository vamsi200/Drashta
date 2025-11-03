#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_imports)]

use std::{
    borrow::Cow,
    collections::{BTreeMap, VecDeque},
    fmt::Debug,
    fs::File,
    io::{BufRead, BufReader, Read, Seek},
    os::fd::{AsRawFd, BorrowedFd},
    path::PathBuf,
    rc::Rc,
    result::Result::Ok,
    str::FromStr,
    sync::{Arc, Mutex},
    thread::sleep,
    time::{Duration, UNIX_EPOCH},
};

use ahash::AHashMap;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, Input, Match, automaton::Automaton, dfa::DFA};
use anyhow::Result;
use axum::extract::State;
use chrono::{DateTime, Local, TimeZone};
use futures::future::Either;
use log::{error, info, warn};
use memchr::memmem;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{
    Deserialize, Serialize,
    de::{self, Deserializer},
};
use serde_json::json;
use systemd::{journal::JournalRef, *};
use tokio::{
    io::unix::AsyncFd,
    sync::{broadcast, mpsc},
};

use crate::events::{self, receive_data};
use crate::regex::*;
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
            .build([pat])
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
    ConnectionActivated,
    ConnectionDeactivated,
    DhcpLease,
    IpConfig,
    DeviceAdded,
    DeviceRemoved,
    WifiAssociationSuccess,
    WifiAuthFailure,
    StateChange,
    ConnectionAttempt,
    PolicyChange,
    WifiScan,
    DnsConfig,
    VpnEvent,
    FirewallEvent,
    AgentRequest,
    ConnectivityCheck,
    DispatcherEvent,
    LinkEvent,
    AuditEvent,
    VirtualDeviceEvent,
    SystemdEvent,
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
    journal: Rc<Mutex<Journal>>,
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
            journal: Rc::new(Mutex::new(journal)),
        }
    }
}

pub static MANUAL_PARSE_EVENTS: Lazy<Vec<&'static str>> = Lazy::new(|| vec!["pkgmanager.events"]);

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
        // NETWORK MANAGER
        "NetworkConnectionActivated" => &["CONNECTION_ACTIVATED"],
        "NetworkConnectionDeactivated" => &["CONNECTION_DEACTIVATED"],
        "NetworkDhcpLease" => &["DHCP_LEASE"],
        "NetworkIpConfig" => &["IP_CONFIG"],
        "NetworkDeviceAdded" => &["DEVICE_ADDED"],
        "NetworkDeviceRemoved" => &["DEVICE_REMOVED"],
        "NetworkWifiAssociationSuccess" => &["WIFI_ASSOC_SUCCESS"],
        "NetworkWifiAuthFailure" => &["WIFI_AUTH_FAILURE"],
        "NetworkStateChange" => &["STATE_CHANGE"],
        "NetworkConnectionAttempt" => &["CONNECTION_ATTEMPT"],
        "NetworkWarning" => &["WARNING"],
        "NetworkUnknown" => &["UNKNOWN"],
        _ => &[],
    }
}

pub fn parse_sshd_logs(entry_map: Entry, ev_type: Option<Vec<&str>>) -> Option<EventData> {
    static PROTOCOL_MISMATCH: Lazy<Vec<(&str, Regex)>> = Lazy::new(|| {
        vec![
            (
                "INVALID_PROTOCOL_ID",
                Regex::new(
                    r"(?x)
                ^kex_exchange_identification:\s*
                (?:read:\s*)?
                (Client\s+sent\s+invalid\s+protocol\s+identifier|
                 Connection\s+(?:closed\s+by\s+remote\s+host|reset\s+by\s+peer))
                \s*$
            ",
                )
                .unwrap(),
            ),
            (
                "BAD_PROTOCOL_VERSION",
                Regex::new(
                    r"(?x)
                ^Bad\s+protocol\s+version\s+identification\s+
                '(.+?)'
                (?:\s+from\s+([0-9A-Fa-f:.]+))?
                (?:\s+port\s+(\d+))?
                \s*$
            ",
                )
                .unwrap(),
            ),
            (
                "MAJOR_VERSION_DIFF",
                Regex::new(
                    r"(?x)
                ^Protocol\s+major\s+versions\s+differ\s+
                for\s+([0-9A-Fa-f:.]+)\s+port\s+(\d+):\s*
                (\d+)\s*vs\.\s*(\d+)
                \s*$
            ",
                )
                .unwrap(),
            ),
            (
                "BANNER_OR_DISPATCH_ERROR",
                Regex::new(
                    r"(?x)
                ^(?:banner\s+exchange|ssh_dispatch_run_fatal):\s+
                Connection\s+from\s+([0-9A-Fa-f:.]+)\s+port\s+(\d+):\s*
                (invalid\s+format|
                 message\s+authentication\s+code\s+incorrect|
                 Connection\s+corrupted)
                (?:\s+\[preauth\])?
                \s*$
            ",
                )
                .unwrap(),
            ),
            (
                "SOCKET_READ_FAILURE",
                Regex::new(
                    r"(?x)
                ^Read\s+from\s+socket\s+failed:\s+
                Connection\s+(?:reset|closed)\s+by\s+peer
                \s*$
            ",
                )
                .unwrap(),
            ),
            ("UNKNOWN", Regex::new(r"(?s)^(.*\S.*)$").unwrap()),
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
            .chain(PROTOCOL_MISMATCH.iter())
            .filter(|(name, _)| names.contains(name))
            .collect()
    } else {
        SSHD_REGEX.iter().chain(PROTOCOL_MISMATCH.iter()).collect()
    };

    let mut map = AHashMap::new();
    let s = entry_map.get("MESSAGE")?;

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

fn format_syslog_timestamp(ts_microseconds: &str) -> String {
    if let Ok(micros) = ts_microseconds.parse::<i64>() {
        let dt: DateTime<Local> = Local.timestamp_micros(micros).unwrap();
        dt.format("%b %e %H:%M:%S").to_string()
    } else {
        "invalid".into()
    }
}

pub fn parse_network_events(entry_map: Entry, ev_type: Option<Vec<&str>>) -> Option<EventData> {
    let msg = entry_map.get("MESSAGE")?;

    let filtered_regexes: Vec<_> = if let Some(ev_types) = ev_type {
        let names: Vec<&str> = ev_types
            .iter()
            .flat_map(|&s| str_to_regex_names(s).to_owned())
            .collect();
        NETWORK_REGEX
            .iter()
            .filter(|(name, _)| names.contains(name))
            .collect()
    } else {
        NETWORK_REGEX.iter().collect()
    };

    let mut map = AHashMap::new();
    let s = entry_map.get("MESSAGE")?;

    let journal_timestamp = entry_map
        .get("_SOURCE_REALTIME_TIMESTAMP")
        .cloned()
        .unwrap_or_default();
    let timestamp = format_syslog_timestamp(&journal_timestamp);
    for (name, regex) in filtered_regexes {
        if let Some(caps) = regex.captures(s) {
            let (data, event_type): (Option<&[(&str, usize)]>, EventType) = match *name {
                "DEVICE_ACTIVATION" => (
                    Some(&[("device", 1), ("result", 2), ("details", 3)]),
                    EventType::ConnectionActivated,
                ),
                "DEVICE_STATE_CHANGE" => (
                    Some(&[("device", 1), ("from", 2), ("to", 3), ("reason", 4)]),
                    EventType::StateChange,
                ),
                "MANAGER_STATE" => (
                    Some(&[("state", 1), ("version", 2), ("action", 3)]),
                    EventType::StateChange,
                ),
                "DHCP_EVENT" => (
                    Some(&[
                        ("iface", 1),
                        ("version", 2),
                        ("from", 3),
                        ("to", 4),
                        ("option", 5),
                        ("value", 6),
                    ]),
                    EventType::DhcpLease,
                ),
                "DHCP_INIT" => (Some(&[("client", 1)]), EventType::DhcpLease),
                "POLICY_SET" => (
                    Some(&[("connection", 1), ("iface", 2), ("purpose", 3)]),
                    EventType::PolicyChange,
                ),
                "SUPPLICANT_STATE" => (
                    Some(&[("device", 1), ("from", 2), ("to", 3)]),
                    EventType::WifiAssociationSuccess,
                ),
                "WIFI_SCAN" => (Some(&[("device", 1)]), EventType::WifiScan),
                "PLATFORM_ERROR" => (
                    Some(&[("operation", 1), ("details", 2), ("errno", 3), ("error", 4)]),
                    EventType::Warning,
                ),
                "SETTINGS_CONNECTION" => (Some(&[("msg", 1)]), EventType::ConnectionAttempt),
                "DNS_CONFIG" => (Some(&[("msg", 1)]), EventType::DnsConfig),
                "VPN_EVENT" => (Some(&[("msg", 1)]), EventType::VpnEvent),
                "FIREWALL_EVENT" => (Some(&[("msg", 1)]), EventType::FirewallEvent),
                "AGENT_REQUEST" => (Some(&[("msg", 1)]), EventType::AgentRequest),
                "CONNECTIVITY_CHECK" => (Some(&[("msg", 1)]), EventType::ConnectivityCheck),
                "DISPATCHER" => (Some(&[("msg", 1)]), EventType::DispatcherEvent),
                "LINK_EVENT" => (
                    Some(&[("device", 1), ("state", 2), ("carrier", 3)]),
                    EventType::LinkEvent,
                ),
                "VIRTUAL_DEVICE" => (Some(&[("msg", 1)]), EventType::VirtualDeviceEvent),
                "AUDIT" => (Some(&[("msg", 1)]), EventType::AuditEvent),
                "SYSTEMD" => (Some(&[("msg", 1)]), EventType::SystemdEvent),
                "GENERIC" => (Some(&[("component", 1), ("msg", 2)]), EventType::Other),

                "CONNECTION_ACTIVATED" => (
                    Some(&[("device", 1), ("type", 2)]),
                    EventType::ConnectionActivated,
                ),
                "CONNECTION_DEACTIVATED" => (
                    Some(&[("device", 1), ("type", 2)]),
                    EventType::ConnectionDeactivated,
                ),
                "DHCP_LEASE" => (Some(&[("device", 1), ("ip", 2)]), EventType::DhcpLease),
                "IP_CONFIG" => (
                    Some(&[("timestamp", 1), ("device", 2)]),
                    EventType::IpConfig,
                ),
                "DEVICE_ADDED" => (
                    Some(&[("timestamp", 1), ("device_info", 2)]),
                    EventType::DeviceAdded,
                ),
                "DEVICE_REMOVED" => (
                    Some(&[("timestamp", 1), ("device_info", 2)]),
                    EventType::DeviceRemoved,
                ),
                "WIFI_ASSOC_SUCCESS" => {
                    (Some(&[("timestamp", 1)]), EventType::WifiAssociationSuccess)
                }
                "WIFI_AUTH_FAILURE" => (
                    Some(&[("timestamp", 1), ("reason", 2)]),
                    EventType::WifiAuthFailure,
                ),
                "STATE_CHANGE" => (
                    Some(&[("timestamp", 1), ("state", 2)]),
                    EventType::StateChange,
                ),
                "CONNECTION_ATTEMPT" => (
                    Some(&[("timestamp", 1), ("connection", 2)]),
                    EventType::ConnectionAttempt,
                ),
                "WARNING" => (Some(&[("msg", 1)]), EventType::Warning),
                "UNKNOWN" => (Some(&[("msg", 1)]), EventType::Other),
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
                service: Service::NetworkManager,
                data: map,
                event_type,
                raw_msg: RawMsgType::Structured(entry_map),
            });
        }
    }
    None
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
        "networkmanager.events",
        ServiceConfig {
            matches: vec![
                ("_SYSTEMD_UNIT", "NetworkManager.service"),
                ("_EXE", "/usr/bin/NetworkManager"),
            ],
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
    let filter = opts.filter.unwrap_or_default();
    let limit = opts.limit;
    let tx = opts.tx;
    let mut journal = opts.journal.lock().unwrap();
    let event_type = opts.ev_type;

    for (field, value) in &config.matches {
        journal.match_add(field, value.to_string())?;
        journal.match_or()?;
    }

    journal.seek_head()?;
    let mut sent = 0;
    let mut scanned = 0;
    let max_scan = limit * 10;
    while sent < limit {
        if let Some(data) = journal.next_entry()? {
            scanned += 1;

            if let Some(ev) = (config.parser)(data, event_type.clone()) {
                if !ev.raw_msg.contains_bytes(&filter) {
                    continue;
                }

                if tx.try_send(ev).is_err() {
                    continue;
                } else {
                    sent += 1;
                }
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
                    if let RawMsgType::Plain(s) = ev.raw_msg.clone() {
                        data = s;
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
            .all(|pat| memmem::find(lines.first().unwrap().as_bytes(), pat).is_some())
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

        let full_chunk = format!("{chunk}{partial_line}");
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
        if let Some(val) = s.strip_prefix("Journal:") {
            Ok(CursorType::Journal(val.to_string()))
        } else if let Some(val) = s.strip_prefix("Manual:") {
            let json_str = val;
            serde_json::from_str::<Cursor>(json_str)
                .map(CursorType::Manual)
                .map_err(|e| format!("Failed to parse Manual cursor: {e}"))
        } else {
            Err(format!("Unknown cursor variant: {s}"))
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
    let is_manual_service = MANUAL_PARSE_EVENTS.contains(&service_name);
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
                    "networkmanager.events",
                    "kernel.events",
                    "userchange.events",
                    "configchange.events",
                    "pkgmanager.events",
                ) {
                    cursor_type = Some(CursorType::Journal(new_c));
                }
            }
            None => {
                if let Ok(new_c) = handle_services!(
                    opts,
                    None,
                    "sshd.events",
                    "sudo.events",
                    "login.events",
                    "firewall.events",
                    "networkmanager.events",
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

const MAX_FAILED_EVENTS: usize = 5_000;

pub fn read_journal_logs(
    service_name: &str,
    filter: Option<String>,
    ev_type: Option<Vec<&str>>,
    tx: tokio::sync::broadcast::Sender<EventData>,
) -> anyhow::Result<()> {
    use std::{collections::VecDeque, thread::sleep, time::Duration};

    let configs = get_service_configs();
    let mut failed_ev_buf = VecDeque::new();

    let Some(config) = configs.get(service_name) else {
        anyhow::bail!("Unknown Service: {}", service_name);
    };

    let mut journal: Journal = journal::OpenOptions::default()
        .all_namespaces(true)
        .open()?;
    for (field, val) in &config.matches {
        journal.match_add(field, val.to_string())?;
        journal.match_or()?;
    }

    let keyword = filter.unwrap_or_default();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_micros() as u64;

    journal.seek_realtime_usec(now)?;

    loop {
        while let Some(data) = journal.next_entry()? {
            if let Some(ev) = (config.parser)(data, ev_type.clone()) {
                if !ev.raw_msg.contains_bytes(&keyword) {
                    continue;
                }

                if let Err(_) = tx.send(ev.clone()) {
                    info!("No active receiver, buffering event...");
                    if failed_ev_buf.len() >= MAX_FAILED_EVENTS {
                        warn!(
                            "Buffer full with - {} events, dropping oldest to prevent memory increase",
                            failed_ev_buf.len()
                        );
                        failed_ev_buf.pop_front();
                    }
                    failed_ev_buf.push_back(ev);
                }
            }
        }

        if tx.receiver_count() > 0 && !failed_ev_buf.is_empty() {
            info!("Receiver reconnected, flushing buffered events...");

            let mut still_failed = VecDeque::new();
            while let Some(ev) = failed_ev_buf.pop_front() {
                if tx.send(ev.clone()).is_err() {
                    still_failed.push_back(ev);
                    break;
                }
            }

            failed_ev_buf = still_failed;
        }

        sleep(Duration::from_millis(500));
    }
}
