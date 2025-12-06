use std::{
    collections::{BTreeMap, VecDeque},
    fmt::Debug,
    fs::File,
    io::{BufRead, BufReader, Read, Seek, SeekFrom},
    path::PathBuf,
    rc::Rc,
    result::Result::Ok,
    str::FromStr,
    sync::Mutex,
    thread::sleep,
    time::Duration,
};

use ahash::AHashMap;
use anyhow::Result;
use anyhow::anyhow;
use chrono::{DateTime, Local, TimeZone};
use inotify::{Inotify, WatchMask};
use log::{error, info, warn};
use memchr::memmem;
use once_cell::sync::Lazy;

use rayon::prelude::*;
use serde::{Deserialize, Serialize, de::Deserializer};
use systemd::*;

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
        let pat_lower = pat.to_lowercase();

        match self {
            RawMsgType::Structured(map) => {
                map.values().any(|v| v.to_lowercase().contains(&pat_lower))
            }
            RawMsgType::Plain(s) => s.to_lowercase().contains(&pat_lower),
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
    Firewalld,
    Kernel,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum AuthEvent {
    Success,
    Failure,
    SessionOpened,
    SessionClosed,
    ConnectionClosed,
    TooManyAuthFailures,
    IncorrectPassword,
    AuthError,
    AuthFailure,
    NotInSudoers,
    AccountExpired,
    NologinRefused,
    Warning,
    Info,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum UserEvent {
    NewUser,
    NewGroup,
    DeleteGroup,
    DeleteUser,
    ModifyUser,
    ModifyGroup,
    PasswdChange,
    Info,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum PkgEvent {
    Installed,
    Removed,
    Upgraded,
    Reinstalled,
    Downgraded,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum ConfigEvent {
    CmdRun,
    CronReload,
    SessionOpened,
    SessionClosed,
    Failure,
    Info,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum NetworkEvent {
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
    Warning,
    Other,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum FirewallEvent {
    ServiceStarted,
    ServiceStopped,
    ConfigReloaded,
    ZoneChanged,
    ServiceModified,
    PortModified,
    RuleApplied,
    IptablesCommand,
    InterfaceBinding,
    CommandFailed,
    OperationStatus,
    ModuleMessage,
    DBusMessage,
    Warning,
    Error,
    Info,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum KernelEvent {
    Panic,
    OomKill,
    Segfault,
    UsbError,
    UsbDescriptorError,
    UsbDeviceEvent,
    DiskError,
    FsMount,
    FsError,
    CpuError,
    MemoryError,
    DeviceDetected,
    DriverEvent,
    NetInterface,
    PciDevice,
    AcpiEvent,
    ThermalEvent,
    DmaError,
    AuditEvent,
    KernelTaint,
    FirmwareLoad,
    IrqEvent,
    TaskKilled,
    RcuStall,
    Watchdog,
    BootEvent,
    Emergency,
    Alert,
    Critical,
    Error,
    Warning,
    Notice,
    Info,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum SystemEvent {
    Info,
    Warning,
    Error,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum EventType {
    Auth(AuthEvent),
    User(UserEvent),
    Package(PkgEvent),
    Network(NetworkEvent),
    Firewall(FirewallEvent),
    Kernel(KernelEvent),
    Config(ConfigEvent),
    System(SystemEvent),
}

pub type ParserFn = fn(entry_map: Entry, ev_type: Option<Vec<&str>>) -> Option<EventData>;
pub type ParserFnForManual = fn(entry_map: String, ev_type: Option<Vec<&str>>) -> Option<EventData>;

pub enum ParserFunctionType {
    ParserFn(ParserFn),
    ParserFnForManual(ParserFnForManual),
}

pub struct ServiceConfig {
    matches: Option<Vec<(&'static str, &'static str)>>,
    parser: ParserFunctionType,
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

pub fn parse_sshd_logs(entry_map: Entry, ev_type: Option<Vec<&str>>) -> Option<EventData> {
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
                    EventType::Auth(AuthEvent::Success),
                ),
                "AUTH_FAILURE" => (
                    Some(&[("method", 1), ("user", 2), ("ip", 3), ("port", 4)]),
                    EventType::Auth(AuthEvent::Failure),
                ),
                "SESSION_OPENED" => (
                    Some(&[("user", 1)]),
                    EventType::Auth(AuthEvent::SessionOpened),
                ),
                "SESSION_CLOSED" => (
                    Some(&[("user", 1)]),
                    EventType::Auth(AuthEvent::SessionClosed),
                ),
                "CONNECTION_CLOSED" => (
                    Some(&[("user", 1), ("ip", 2), ("port", 3)]),
                    EventType::Auth(AuthEvent::ConnectionClosed),
                ),
                "WARNING" => (Some(&[("msg", 1)]), EventType::Auth(AuthEvent::Warning)),
                "TOO_MANY_AUTH" => (
                    Some(&[("user", 1)]),
                    EventType::Auth(AuthEvent::TooManyAuthFailures),
                ),
                _ => (Some(&[("msg", 1)]), EventType::Auth(AuthEvent::Other)),
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
                let (data, _): (Option<&[(&str, usize)]>, EventType) = match *name {
                    "COMMAND_RUN" => (
                        Some(&[
                            ("invoking_user", 1),
                            ("tty", 2),
                            ("pwd", 3),
                            ("target_user", 4),
                            ("command", 5),
                        ]),
                        EventType::Auth(AuthEvent::Info),
                    ),
                    _ => (None, EventType::Auth(AuthEvent::Other)),
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
                        EventType::Auth(AuthEvent::SessionOpened),
                    ),

                    "SESSION_OPENED_SUDO" => (
                        Some(&[
                            ("target_user", 1),
                            ("uid", 2),
                            ("invoking_user", 3),
                            ("invoking_uid", 4),
                        ]),
                        EventType::Auth(AuthEvent::SessionOpened),
                    ),

                    "SESSION_CLOSED" => (
                        Some(&[("target_user", 1)]),
                        EventType::Auth(AuthEvent::SessionClosed),
                    ),

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
                        EventType::Auth(AuthEvent::Failure),
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
                        EventType::Auth(AuthEvent::IncorrectPassword),
                    ),

                    "NOT_IN_SUDOERS" => (
                        Some(&[("user", 1)]),
                        EventType::Auth(AuthEvent::NotInSudoers),
                    ),

                    "AUTH_ERROR" => (Some(&[("msg", 1)]), EventType::Auth(AuthEvent::AuthError)),

                    "SUDO_WARNING" => (Some(&[("msg", 1)]), EventType::Auth(AuthEvent::Warning)),

                    _ => (None, EventType::Auth(AuthEvent::Other)),
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
        let journal_timestamp = entry_map
            .get("_SOURCE_REALTIME_TIMESTAMP")
            .cloned()
            .unwrap_or_default();
        let timestamp = format_syslog_timestamp(&journal_timestamp);

        if let Some(s) = entry_map.get("MESSAGE") {
            if let Some(msg) = regex.captures(s) {
                let (data, event_type): (Option<&[(&str, usize)]>, EventType) = match *name {
                    "AUTH_FAILURE" => (None, EventType::Auth(AuthEvent::Failure)),

                    "AUTH_USER_UNKNOWN" | "FAILL0CK" | "ACCOUNT_EXPIRED" => {
                        (None, EventType::Auth(AuthEvent::Info))
                    }

                    "NOLOGIN_REFUSED" => (Some(&[("user", 1)]), EventType::Auth(AuthEvent::Info)),

                    "SESSION_OPENED" => (
                        Some(&[("user", 1)]),
                        EventType::Auth(AuthEvent::SessionOpened),
                    ),
                    "SESSION_CLOSED" => (
                        Some(&[("user", 1)]),
                        EventType::Auth(AuthEvent::SessionClosed),
                    ),
                    "SYSTEMD_NEW_SESSION" => (
                        Some(&[("user", 1)]),
                        EventType::Auth(AuthEvent::SessionOpened),
                    ),
                    "SYSTEMD_SESSION_CLOSED" => (None, EventType::Auth(AuthEvent::SessionClosed)),

                    "SYSTEMD_SESSION_OPENED_UID" => (
                        Some(&[("user", 1)]),
                        EventType::Auth(AuthEvent::SessionOpened),
                    ),
                    "SYSTEMD_SESSION_CLOSED_UID" => (
                        Some(&[("user", 1)]),
                        EventType::Auth(AuthEvent::SessionClosed),
                    ),

                    "LOGIN_SUCCESS" => (
                        Some(&[("tty", 1), ("user", 2)]),
                        EventType::Auth(AuthEvent::Success),
                    ),

                    "FAILED_LOGIN" => (None, EventType::Auth(AuthEvent::Failure)),
                    "FAILED_LOGIN_TTY" => (
                        Some(&[("tty", 1), ("user", 2)]),
                        EventType::Auth(AuthEvent::Failure),
                    ),

                    "SDDM_LOGIN_SUCCESS" => {
                        (Some(&[("user", 1)]), EventType::Auth(AuthEvent::Success))
                    }
                    "SDDM_LOGIN_FAILURE" => {
                        (Some(&[("user", 1)]), EventType::Auth(AuthEvent::Failure))
                    }

                    "FAILED_PASSWORD_SSH" => {
                        (Some(&[("user", 1)]), EventType::Auth(AuthEvent::Failure))
                    }
                    "INVALID_USER_ATTEMPT" => {
                        (Some(&[("user", 1)]), EventType::Auth(AuthEvent::Failure))
                    }
                    "ACCOUNT_LOCKED" => (Some(&[("user", 1)]), EventType::Auth(AuthEvent::Failure)),
                    "PASSWORD_CHANGED" => (Some(&[("user", 1)]), EventType::Auth(AuthEvent::Info)),

                    _ => (None, EventType::Auth(AuthEvent::Other)),
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

pub fn parse_kernel_events(entry_map: Entry, ev_type: Option<Vec<&str>>) -> Option<EventData> {
    let journal_timestamp = entry_map
        .get("_SOURCE_BOOTTIME_TIMESTAMP")
        .cloned()
        .unwrap_or_default();
    let timestamp = format_syslog_timestamp(&journal_timestamp);

    let filtered_regexes: Vec<_> = if let Some(ev_types) = ev_type {
        let names: Vec<&str> = ev_types
            .iter()
            .flat_map(|&s| str_to_regex_names(s).to_owned())
            .collect();

        KERNEL_REGEX
            .iter()
            .filter(|(name, _)| names.contains(name))
            .collect()
    } else {
        KERNEL_REGEX.iter().collect()
    };

    let mut map = AHashMap::new();
    let s = entry_map.get("MESSAGE")?;

    for (name, regex) in filtered_regexes {
        if let Some(caps) = regex.captures(s) {
            let (data, event_type): (Option<&[(&str, usize)]>, EventType) = match *name {
                "KERNEL_PANIC" => (
                    Some(&[("msg", 1), ("cpu", 2)]),
                    EventType::Kernel(KernelEvent::Panic),
                ),
                "OOM_KILL" => (
                    Some(&[("pid", 1), ("process", 2), ("score", 3)]),
                    EventType::Kernel(KernelEvent::OomKill),
                ),
                "SEGFAULT" => (
                    Some(&[
                        ("process", 1),
                        ("pid", 2),
                        ("address", 3),
                        ("ip", 4),
                        ("sp", 5),
                        ("error", 6),
                        ("binary", 7),
                    ]),
                    EventType::Kernel(KernelEvent::Segfault),
                ),
                "USB_ERROR" => (
                    Some(&[("device", 1), ("msg", 2), ("error_code", 3)]),
                    EventType::Kernel(KernelEvent::UsbError),
                ),
                "USB_DESCRIPTOR_ERROR" => (
                    Some(&[("device", 1), ("msg", 2), ("error_code", 3)]),
                    EventType::Kernel(KernelEvent::UsbDescriptorError),
                ),
                "USB_DEVICE_EVENT" => (
                    Some(&[
                        ("device", 1),
                        ("event", 2),
                        ("details", 3),
                        ("vendor_id", 4),
                        ("product_id", 5),
                    ]),
                    EventType::Kernel(KernelEvent::UsbDeviceEvent),
                ),
                "DISK_ERROR" => (
                    Some(&[("device", 1), ("sector", 2), ("operation", 3)]),
                    EventType::Kernel(KernelEvent::DiskError),
                ),
                "FS_MOUNT" => (
                    Some(&[("device", 1), ("action", 2), ("details", 3)]),
                    EventType::Kernel(KernelEvent::FsMount),
                ),
                "FS_ERROR" => (
                    Some(&[("device", 1), ("msg", 2)]),
                    EventType::Kernel(KernelEvent::FsError),
                ),
                "CPU_ERROR" => (
                    Some(&[("cpu", 1), ("msg", 2)]),
                    EventType::Kernel(KernelEvent::CpuError),
                ),
                "MEMORY_ERROR" => (
                    Some(&[("msg", 1), ("address", 2)]),
                    EventType::Kernel(KernelEvent::MemoryError),
                ),
                "DEVICE_DETECTED" => (
                    Some(&[("device", 1), ("location", 2)]),
                    EventType::Kernel(KernelEvent::DeviceDetected),
                ),
                "DRIVER_EVENT" => (
                    Some(&[("driver", 1), ("details", 2)]),
                    EventType::Kernel(KernelEvent::DriverEvent),
                ),
                "NET_INTERFACE" => (
                    Some(&[("interface", 1), ("old_name", 2), ("speed", 3)]),
                    EventType::Kernel(KernelEvent::NetInterface),
                ),
                "PCI_DEVICE" => (
                    Some(&[("device", 1), ("msg", 2)]),
                    EventType::Kernel(KernelEvent::PciDevice),
                ),
                "ACPI_EVENT" => (
                    Some(&[("msg", 1), ("details", 2)]),
                    EventType::Kernel(KernelEvent::AcpiEvent),
                ),
                "THERMAL_EVENT" => (
                    Some(&[("zone", 1), ("msg", 2), ("temperature", 3)]),
                    EventType::Kernel(KernelEvent::ThermalEvent),
                ),
                "DMA_ERROR" => (
                    Some(&[("msg", 1), ("device", 2)]),
                    EventType::Kernel(KernelEvent::DmaError),
                ),
                "AUDIT_EVENT" => (
                    Some(&[("type", 1), ("msg", 2)]),
                    EventType::Kernel(KernelEvent::AuditEvent),
                ),
                "KERNEL_TAINT" => (
                    Some(&[("module", 1), ("reason", 2)]),
                    EventType::Kernel(KernelEvent::KernelTaint),
                ),
                "FIRMWARE_LOAD" => (
                    Some(&[("firmware", 1), ("device", 2)]),
                    EventType::Kernel(KernelEvent::FirmwareLoad),
                ),
                "IRQ_EVENT" => (
                    Some(&[("irq", 1), ("msg", 2)]),
                    EventType::Kernel(KernelEvent::IrqEvent),
                ),
                "TASK_KILLED" => (
                    Some(&[("pid", 1), ("process", 2), ("reason", 3)]),
                    EventType::Kernel(KernelEvent::TaskKilled),
                ),
                "RCU_STALL" => (
                    Some(&[("cpus", 1)]),
                    EventType::Kernel(KernelEvent::RcuStall),
                ),
                "WATCHDOG" => (
                    Some(&[("msg", 1), ("cpu", 2)]),
                    EventType::Kernel(KernelEvent::Watchdog),
                ),
                "BOOT_EVENT" => (
                    Some(&[("version", 1), ("details", 2)]),
                    EventType::Kernel(KernelEvent::BootEvent),
                ),
                "EMERG" => (
                    Some(&[("msg", 1)]),
                    EventType::Kernel(KernelEvent::Emergency),
                ),
                "ALERT" => (Some(&[("msg", 1)]), EventType::Kernel(KernelEvent::Alert)),
                "CRITICAL" => (
                    Some(&[("msg", 1)]),
                    EventType::Kernel(KernelEvent::Critical),
                ),
                "ERROR" => (Some(&[("msg", 1)]), EventType::Kernel(KernelEvent::Error)),
                "WARNING" => (Some(&[("msg", 1)]), EventType::Kernel(KernelEvent::Warning)),
                "NOTICE" => (Some(&[("msg", 1)]), EventType::Kernel(KernelEvent::Notice)),
                "INFO" => (Some(&[("msg", 1)]), EventType::Kernel(KernelEvent::Info)),
                _ => (Some(&[("msg", 1)]), EventType::Kernel(KernelEvent::Other)),
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
                service: Service::Kernel,
                data: map,
                event_type,
                raw_msg: RawMsgType::Structured(entry_map),
            });
        }
    }
    None
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
                        EventType::User(UserEvent::NewUser),
                    ),
                    "NEW_GROUP" => (
                        Some(&[("name", 1), ("gid", 2)]),
                        EventType::User(UserEvent::NewGroup),
                    ),
                    "GROUP_ADDED_ETC_GROUP" => (
                        Some(&[("name", 1), ("gid", 2)]),
                        EventType::User(UserEvent::Info),
                    ),
                    "GROUP_ADDED_ETC_GSHADOW" => {
                        (Some(&[("name", 1)]), EventType::User(UserEvent::Info))
                    }
                    _ => (None, EventType::User(UserEvent::Other)),
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
                    "DELETE_USER" => (
                        Some(&[
                            ("name", 1),
                            ("uid", 2),
                            ("gid", 3),
                            ("home", 4),
                            ("shell", 5),
                        ]),
                        EventType::User(UserEvent::DeleteUser),
                    ),
                    "DELETE_USER_HOME" => (
                        Some(&[("name", 1)]),
                        EventType::User(UserEvent::DeleteGroup),
                    ),
                    "DELETE_USER_MAIL" => (Some(&[("name", 1)]), EventType::User(UserEvent::Info)),
                    "DELETE_GROUP" => (
                        Some(&[("name", 1), ("gid", 2)]),
                        EventType::User(UserEvent::DeleteGroup),
                    ),
                    _ => (None, EventType::User(UserEvent::Other)),
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
                    "MODIFY_USER" => (Some(&[("name", 1)]), EventType::User(UserEvent::ModifyUser)),
                    "MODIFY_GROUP" => (
                        Some(&[("name", 1)]),
                        EventType::User(UserEvent::DeleteGroup),
                    ),
                    "USER_PASSWD_CHANGE" => (
                        Some(&[("process_id", 1), ("user", 2)]),
                        EventType::User(UserEvent::Info),
                    ),
                    "USER_SHADOW_UPDATED" => (
                        Some(&[("name", 1)]),
                        EventType::User(UserEvent::DeleteGroup),
                    ),
                    _ => (None, EventType::User(UserEvent::Other)),
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
            let timestamp = s.get(1).unwrap().as_str().to_owned();

            let (data, event_type): (Option<&[(&str, usize)]>, EventType) = match *name {
                "INSTALLED" => (
                    Some(&[("pkg_name", 2)]),
                    EventType::Package(PkgEvent::Installed),
                ),
                "REMOVED" => (
                    Some(&[("pkg_name", 2)]),
                    EventType::Package(PkgEvent::Removed),
                ),
                "UPGRADED" => (
                    Some(&[("pkg_name", 2), ("version_from", 3), ("version_to", 4)]),
                    EventType::Package(PkgEvent::Upgraded),
                ),
                "DOWNGRADED" => (
                    Some(&[("pkg_name", 2), ("version_from", 3), ("version_to", 4)]),
                    EventType::Package(PkgEvent::Downgraded),
                ),
                "REINSTALLED" => (
                    Some(&[("pkg_name", 2), ("version", 3)]),
                    EventType::Package(PkgEvent::Reinstalled),
                ),
                _ => (None, EventType::Package(PkgEvent::Other)),
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
                    "CRON_CMD" => (
                        Some(&[("user", 1), ("cron_cmd", 2)]),
                        EventType::Config(ConfigEvent::CmdRun),
                    ),
                    "CRON_RELOAD" => (
                        Some(&[("user", 1), ("cron_reload", 2)]),
                        EventType::Config(ConfigEvent::CronReload),
                    ),
                    "CRON_ERROR_BAD_COMMAND" => {
                        (Some(&[("user", 1)]), EventType::Config(ConfigEvent::Info))
                    }
                    "CRON_ERROR_BAD_MINUTE" => {
                        (Some(&[("user", 1)]), EventType::Config(ConfigEvent::Info))
                    }
                    "CRON_ERROR_OTHER" => {
                        (Some(&[("user", 1)]), EventType::Config(ConfigEvent::Info))
                    }
                    "CRON_DENIED" => (
                        Some(&[("user", 1)]),
                        EventType::Config(ConfigEvent::Failure),
                    ),
                    "CRON_SESSION_OPEN" => (
                        Some(&[("user", 1), ("uid", 2)]),
                        EventType::Config(ConfigEvent::SessionOpened),
                    ),
                    "CRON_SESSION_CLOSE" => (
                        Some(&[("user", 1)]),
                        EventType::Config(ConfigEvent::SessionClosed),
                    ),
                    _ => (None, EventType::Config(ConfigEvent::Other)),
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

fn format_syslog_timestamp(ts_str: &str) -> String {
    if let Ok(value) = ts_str.parse::<i64>() {
        let dt: Option<DateTime<Local>> = if value > 1_000_000_000_000_000 {
            Local.timestamp_micros(value).single()
        } else if value > 10_000_000_000 {
            Local.timestamp_millis_opt(value).single()
        } else {
            Local.timestamp_opt(value, 0).single()
        };

        if let Some(datetime) = dt {
            datetime.format("%b %e %H:%M:%S").to_string()
        } else {
            "invalid".into()
        }
    } else {
        "invalid".into()
    }
}
pub fn parse_network_events(entry_map: Entry, ev_type: Option<Vec<&str>>) -> Option<EventData> {
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
                "ConnectionActivated" => (
                    Some(&[
                        ("level", 1),
                        ("ts", 2),
                        ("conn_old", 3),
                        ("device", 4),
                        ("conn_new", 5),
                    ]),
                    EventType::Network(NetworkEvent::ConnectionActivated),
                ),

                "ConnectionDeactivated" => (
                    Some(&[
                        ("level", 1),
                        ("ts", 2),
                        ("conn_old", 3),
                        ("reason_old", 4),
                        ("device", 5),
                        ("reason_new", 6),
                    ]),
                    EventType::Network(NetworkEvent::ConnectionDeactivated),
                ),

                "DEVICE_ACTIVATION" => (
                    Some(&[("device", 1), ("result", 2), ("details", 3)]),
                    EventType::Network(NetworkEvent::ConnectionActivated),
                ),

                "DEVICE_STATE_CHANGE" => (
                    Some(&[
                        ("device", 1),
                        ("from", 2),
                        ("to", 3),
                        ("reason", 4),
                        ("sys_state", 5),
                        ("mgmt_type", 6),
                    ]),
                    EventType::Network(NetworkEvent::StateChange),
                ),

                "MANAGER_STATE" => (
                    Some(&[("state", 1), ("version", 2), ("action", 3)]),
                    EventType::Network(NetworkEvent::StateChange),
                ),

                "DHCP_EVENT" => (
                    Some(&[
                        ("version", 1),
                        ("iface", 2),
                        ("from", 3),
                        ("to", 4),
                        ("option", 5),
                        ("value", 6),
                        ("msg", 7),
                    ]),
                    EventType::Network(NetworkEvent::DhcpLease),
                ),

                "DHCP_INIT" => (
                    Some(&[("client", 1)]),
                    EventType::Network(NetworkEvent::DhcpLease),
                ),

                "POLICY_SET" => (
                    Some(&[("connection", 1), ("iface", 2), ("purpose", 3)]),
                    EventType::Network(NetworkEvent::PolicyChange),
                ),

                "SUPPLICANT_STATE" => (
                    Some(&[("device", 1), ("from", 2), ("to", 3)]),
                    EventType::Network(NetworkEvent::WifiAssociationSuccess),
                ),

                "WIFI_SCAN" => (
                    Some(&[("device", 1)]),
                    EventType::Network(NetworkEvent::WifiScan),
                ),

                "PLATFORM_ERROR" => (
                    Some(&[
                        ("operation", 1),
                        ("details", 2),
                        ("errno", 3),
                        ("error", 4),
                        ("msg", 5),
                    ]),
                    EventType::Network(NetworkEvent::Warning),
                ),

                "SETTINGS_CONNECTION" => (
                    Some(&[("msg", 1)]),
                    EventType::Network(NetworkEvent::ConnectionAttempt),
                ),

                "DNS_CONFIG" => (
                    Some(&[("msg", 1)]),
                    EventType::Network(NetworkEvent::DnsConfig),
                ),

                "VPN_EVENT" => (
                    Some(&[("msg", 1)]),
                    EventType::Network(NetworkEvent::VpnEvent),
                ),

                "FIREWALL_EVENT" => (
                    Some(&[("msg", 1)]),
                    EventType::Network(NetworkEvent::FirewallEvent),
                ),

                "AGENT_REQUEST" => (
                    Some(&[("msg", 1)]),
                    EventType::Network(NetworkEvent::AgentRequest),
                ),

                "CONNECTIVITY_CHECK" => (
                    Some(&[("msg", 1)]),
                    EventType::Network(NetworkEvent::ConnectivityCheck),
                ),

                "DISPATCHER" => (
                    Some(&[("msg", 1)]),
                    EventType::Network(NetworkEvent::DispatcherEvent),
                ),

                "LINK_EVENT" => (
                    Some(&[("device", 1), ("state", 2), ("carrier", 3)]),
                    EventType::Network(NetworkEvent::LinkEvent),
                ),

                "VIRTUAL_DEVICE" => (
                    Some(&[("msg", 1)]),
                    EventType::Network(NetworkEvent::VirtualDeviceEvent),
                ),

                "AUDIT" => (
                    Some(&[("msg", 1)]),
                    EventType::Network(NetworkEvent::AuditEvent),
                ),

                "SYSTEMD" => (
                    Some(&[("msg", 1)]),
                    EventType::Network(NetworkEvent::SystemdEvent),
                ),

                "GENERIC" => (
                    Some(&[("component", 1), ("msg", 2)]),
                    EventType::Network(NetworkEvent::Other),
                ),

                "UNKNOWN" => (Some(&[("msg", 1)]), EventType::Network(NetworkEvent::Other)),

                "DEVICE_ACTIVATION_WARN" => (
                    Some(&[("device", 1), ("result", 2), ("details", 3)]),
                    EventType::Network(NetworkEvent::Warning),
                ),

                "MANAGER_WARN" => (
                    Some(&[("msg", 1)]),
                    EventType::Network(NetworkEvent::Warning),
                ),

                "MANAGER_ERROR" => (Some(&[("msg", 1)]), EventType::Network(NetworkEvent::Error)),

                "DHCP_ERROR" => (
                    Some(&[("iface", 1), ("version", 2), ("msg", 3)]),
                    EventType::Network(NetworkEvent::DhcpLease),
                ),

                "VPN_ERROR" => (
                    Some(&[("msg", 1)]),
                    EventType::Network(NetworkEvent::VpnEvent),
                ),

                "NM_WARNING" => (
                    Some(&[("component", 1), ("msg", 2)]),
                    EventType::Network(NetworkEvent::Warning),
                ),

                "NM_ERROR" => (
                    Some(&[("component", 1), ("msg", 2)]),
                    EventType::Network(NetworkEvent::Error),
                ),
                _ => (Some(&[("msg", 1)]), EventType::Network(NetworkEvent::Other)),
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
pub fn parse_firewalld_events(entry_map: Entry, ev_type: Option<Vec<&str>>) -> Option<EventData> {
    let timestamp = entry_map
        .get("SYSLOG_TIMESTAMP")
        .cloned()
        .unwrap_or_default();

    let filtered_regexes: Vec<_> = if let Some(ev_types) = ev_type {
        let names: Vec<&str> = ev_types
            .iter()
            .flat_map(|&s| str_to_regex_names(s).to_owned())
            .collect();

        FIREWALLD_REGEX
            .iter()
            .filter(|(name, _)| names.contains(name))
            .collect()
    } else {
        FIREWALLD_REGEX.iter().collect()
    };

    let mut map = AHashMap::new();
    let s = entry_map.get("MESSAGE")?;

    for (name, regex) in filtered_regexes {
        if let Some(caps) = regex.captures(s) {
            let (data, event_type): (Option<&[(&str, usize)]>, EventType) = match *name {
                "SERVICE_STARTED" => (None, EventType::Firewall(FirewallEvent::ServiceStarted)),
                "SERVICE_STOPPED" => (None, EventType::Firewall(FirewallEvent::ServiceStopped)),
                "CONFIG_RELOADED" => (None, EventType::Firewall(FirewallEvent::ConfigReloaded)),
                "ZONE_CHANGED" => (
                    Some(&[("zone", 1), ("interface", 2)]),
                    EventType::Firewall(FirewallEvent::ZoneChanged),
                ),
                "SERVICE_MODIFIED" => (
                    Some(&[("service", 1), ("zone", 2)]),
                    EventType::Firewall(FirewallEvent::ServiceModified),
                ),
                "PORT_MODIFIED" => (
                    Some(&[("port", 1), ("protocol", 2), ("zone", 3)]),
                    EventType::Firewall(FirewallEvent::PortModified),
                ),
                "RULE_APPLIED" => (
                    Some(&[("rule", 1)]),
                    EventType::Firewall(FirewallEvent::RuleApplied),
                ),
                "IPTABLES_COMMAND" => (
                    Some(&[("msg", 1)]),
                    EventType::Firewall(FirewallEvent::IptablesCommand),
                ),
                "INTERFACE_BINDING" => (
                    Some(&[("interface", 1), ("zone", 2)]),
                    EventType::Firewall(FirewallEvent::InterfaceBinding),
                ),
                "COMMAND_FAILED" => (
                    Some(&[("msg", 1)]),
                    EventType::Firewall(FirewallEvent::CommandFailed),
                ),
                "OPERATION_STATUS" => (
                    Some(&[("msg", 1)]),
                    EventType::Firewall(FirewallEvent::OperationStatus),
                ),
                "MODULE_MSG" => (
                    Some(&[("module", 1), ("msg", 2), ("details", 3)]),
                    EventType::Firewall(FirewallEvent::ModuleMessage),
                ),
                "DBUS_MSG" => (
                    Some(&[("msg", 1), ("details", 2)]),
                    EventType::Firewall(FirewallEvent::DBusMessage),
                ),
                "WARNING" => (
                    Some(&[("msg", 1)]),
                    EventType::Firewall(FirewallEvent::Warning),
                ),
                "ERROR" => (
                    Some(&[("msg", 1)]),
                    EventType::Firewall(FirewallEvent::Error),
                ),
                "INFO" => (
                    Some(&[("msg", 1)]),
                    EventType::Firewall(FirewallEvent::Info),
                ),
                _ => (
                    Some(&[("msg", 1)]),
                    EventType::Firewall(FirewallEvent::Other),
                ),
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
                service: Service::Firewalld,
                data: map,
                event_type,
                raw_msg: RawMsgType::Structured(entry_map),
            });
        }
    }
    None
}

pub fn get_service_configs() -> AHashMap<&'static str, ServiceConfig> {
    let mut map = AHashMap::new();
    map.insert(
        "pkgmanager.events",
        ServiceConfig {
            matches: None,
            parser: ParserFunctionType::ParserFnForManual(parse_pkg_events),
        },
    );

    map.insert(
        "sshd.events",
        ServiceConfig {
            matches: Some(vec![
                ("_COMM", "sshd"),
                ("_EXE", "/usr/sbin/sshd"),
                ("_SYSTEMD_UNIT", "sshd.service"),
            ]),
            parser: ParserFunctionType::ParserFn(parse_sshd_logs),
        },
    );

    map.insert(
        "sudo.events",
        ServiceConfig {
            matches: Some(vec![("_COMM", "su"), ("_COMM", "sudo")]),
            parser: ParserFunctionType::ParserFn(parse_sudo_login_attempts),
        },
    );

    map.insert(
        "login.events",
        ServiceConfig {
            matches: Some(vec![("SYSLOG_IDENTIFIER", "systemd-logind")]),
            parser: ParserFunctionType::ParserFn(parse_login_attempts),
        },
    );

    map.insert(
        "firewalld.events",
        ServiceConfig {
            matches: Some(vec![("_SYSTEMD_UNIT", "firewalld.service")]),
            parser: ParserFunctionType::ParserFn(parse_firewalld_events),
        },
    );

    map.insert(
        "networkmanager.events",
        ServiceConfig {
            matches: Some(vec![("_SYSTEMD_UNIT", "NetworkManager.service")]),
            parser: ParserFunctionType::ParserFn(parse_network_events),
        },
    );

    map.insert(
        "kernel.events",
        ServiceConfig {
            matches: Some(vec![("_TRANSPORT", "kernel")]),
            parser: ParserFunctionType::ParserFn(parse_kernel_events),
        },
    );

    map.insert(
        "userchange.events",
        ServiceConfig {
            matches: Some(vec![
                ("_COMM", "useradd"),
                ("_COMM", "groupadd"),
                ("_COMM", "passwd"),
            ]),
            parser: ParserFunctionType::ParserFn(parse_user_change_events),
        },
    );

    map.insert(
        "configchange.events",
        ServiceConfig {
            matches: Some(vec![("_SYSTEMD_UNIT", "cronie.service")]),
            parser: ParserFunctionType::ParserFn(parse_config_change_events),
        },
    );

    map
}

pub fn process_entries_in_parallel(
    data: VecDeque<Entry>,
    opts: &ParserFuncArgs,
    config: &ServiceConfig,
) -> Result<(), anyhow::Error> {
    let filter = &opts.filter;
    let tx = &opts.tx;
    let event_type = &opts.ev_type;
    let ParserFunctionType::ParserFn(parserfn) = config.parser else {
        return Err(anyhow!("ParserFn required here"));
    };

    data.par_iter().for_each(|val| {
        if let Some(ev) = parserfn(val.clone(), event_type.clone()) {
            if let Some(filter_val) = filter {
                if !ev.raw_msg.contains_bytes(filter_val) {
                    return;
                }
            }

            let _ = tx.try_send(ev);
        }
    });

    Ok(())
}

pub fn process_upto_n_entries(opts: ParserFuncArgs, config: &ServiceConfig) -> Result<String> {
    let limit = opts.limit;
    let mut journal = opts.journal.lock().unwrap();
    let mut batch = VecDeque::with_capacity(100);

    if let Some(values) = &config.matches {
        for (field, value) in values {
            journal.match_add(field, value.to_string())?;
            journal.match_or()?;
        }
    }

    journal.seek_head()?;

    let mut count = 0;
    while count < limit {
        if let Some(data) = journal.next_entry()? {
            count += 1;
            batch.push_back(data);

            if batch.len() >= 100 {
                let current_batch = std::mem::replace(&mut batch, VecDeque::with_capacity(100));
                process_entries_in_parallel(current_batch, &opts, config)?;
            }
        } else {
            break;
        }
    }

    if !batch.is_empty() {
        process_entries_in_parallel(batch, &opts, config)?;
    }

    let cursor = journal.cursor()?;
    Ok(cursor)
}

pub fn process_older_logs(
    opts: ParserFuncArgs,
    config: &ServiceConfig,
    cursor: String,
) -> Result<String> {
    let limit = opts.limit;
    let mut journal = opts.journal.lock().unwrap();
    let mut batch = VecDeque::with_capacity(100);

    if let Some(values) = &config.matches {
        for (field, value) in values {
            journal.match_add(field, value.to_string())?;
            journal.match_or()?;
        }
    }
    journal.seek_cursor(&cursor)?;
    journal.next_entry()?;

    let mut count = 0;
    let mut last_cursor = cursor.clone();
    while count < limit {
        match journal.next_entry()? {
            Some(data) => {
                count += 1;
                batch.push_back(data);

                if batch.len() >= 100 {
                    let current_batch = std::mem::replace(&mut batch, VecDeque::with_capacity(100));
                    process_entries_in_parallel(current_batch, &opts, config)?;
                }

                last_cursor = journal.cursor()?;
            }
            None => {
                info!("No More Entries!");
                break;
            }
        }
    }
    if !batch.is_empty() {
        process_entries_in_parallel(batch, &opts, config)?;
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
    let ParserFunctionType::ParserFn(parserfn) = config.parser else {
        return Err(anyhow!("ParserFn required here"));
    };

    if let Some(values) = &config.matches {
        for (field, value) in values {
            journal.match_add(field, value.to_string())?;
            journal.match_or()?;
        }
    }

    journal.seek_cursor(&cursor)?;

    let mut count = 0;
    let mut last_cursor = cursor.clone();
    while count < limit {
        match journal.previous_entry()? {
            Some(data) => {
                count += 1;
                if let Some(ev) = parserfn(data, event_type.clone()) {
                    if !ev.raw_msg.contains_bytes(keyword.as_str()) {
                        continue;
                    }
                    if tx.blocking_send(ev).is_err() {
                        error!("Event Dropped!");
                        continue;
                    }
                }
                last_cursor = journal.cursor()?;
            }
            None => break,
        }
    }
    Ok(last_cursor)
}

pub fn process_service_logs(
    opts: ParserFuncArgs,
    cursor: Option<String>,
) -> Result<String, anyhow::Error> {
    let configs = get_service_configs();
    let service_name = opts.service_name;
    let processlogtype = opts.processlogtype.clone();
    let Some(config) = configs.get(service_name) else {
        ::anyhow::bail!("Unknown Service: {}", service_name);
    };

    let new_cursor = match (cursor, processlogtype) {
        (Some(cursor), ProcessLogType::ProcessOlderLogs) => {
            process_older_logs(opts, config, cursor)?
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
        let mut count = 0;
        let mut buf = String::new();

        while reader.read_line(&mut buf).unwrap() > 0 && count < limit {
            let offset = reader.stream_position()?;
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
    let cursor = opts.cursor.clone();
    let processlogtype = opts.processlogtype.clone();
    let is_manual_service = MANUAL_PARSE_EVENTS.contains(&service_name);

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
                    "firewalld.events",
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
                    "firewalld.events",
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

pub fn read_journal_logs_manual(
    service_name: &str,
    filter: Option<String>,
    ev_type: Option<Vec<&str>>,
    tx: tokio::sync::broadcast::Sender<EventData>,
) -> anyhow::Result<()> {
    let configs = get_service_configs();
    let mut failed_ev_buf = VecDeque::with_capacity(MAX_FAILED_EVENTS);

    let Some(config) = configs.get(service_name) else {
        anyhow::bail!("Unknown Service: {}", service_name);
    };

    let ParserFunctionType::ParserFnForManual(parserfn) = config.parser else {
        return Err(anyhow!("ParserFnForManual required here"));
    };

    let keyword = filter.unwrap_or_default();

    let mut file = File::open("/var/log/pacman.log")?;
    let mut inotify = Inotify::init()?;
    inotify.watches().add(
        "/var/log/pacman.log",
        WatchMask::MODIFY | WatchMask::MOVE_SELF | WatchMask::DELETE_SELF | WatchMask::CREATE,
    )?;

    let mut buffer = [0u8; 4096];
    let mut last_pos = file.seek(SeekFrom::End(0))?;
    if service_name == "pkgmanager.events" {
        loop {
            let events = inotify.read_events_blocking(&mut buffer)?;
            for _ev in events {
                let new_len = file.metadata()?.len();

                if new_len < last_pos {
                    file = File::open("/var/log/pacman.log")?;
                    last_pos = 0;
                }

                if new_len > last_pos {
                    let read_len = new_len - last_pos;

                    file.seek(SeekFrom::Start(last_pos))?;
                    let mut buf = Vec::with_capacity(8192);
                    buf.resize(read_len as usize, 0);

                    file.read_exact(&mut buf)?;

                    let log_line = String::from_utf8_lossy(&buf);

                    for line in log_line.lines() {
                        if let Some(ev) = parserfn(line.to_string(), ev_type.clone()) {
                            if !ev.raw_msg.contains_bytes(&keyword) {
                                continue;
                            }
                            if tx.send(ev.clone()).is_err() {
                                info!("No active receiver, buffering event");
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
                        info!("Receiver reconnected, flushing buffering events...");
                        let mut still_failed = VecDeque::new();
                        while let Some(ev) = failed_ev_buf.pop_front() {
                            if tx.send(ev.clone()).is_err() {
                                still_failed.push_back(ev);
                                break;
                            }
                        }
                        failed_ev_buf = still_failed;
                    }

                    last_pos = new_len;
                }
            }
        }
    }

    Ok(())
}

pub fn read_journal_logs(
    service_name: &str,
    filter: Option<String>,
    ev_type: Option<Vec<&str>>,
    tx: tokio::sync::broadcast::Sender<EventData>,
) -> anyhow::Result<()> {
    let configs = get_service_configs();
    let mut failed_ev_buf = VecDeque::with_capacity(MAX_FAILED_EVENTS);

    let Some(config) = configs.get(service_name) else {
        anyhow::bail!("Unknown Service: {}", service_name);
    };

    let mut journal: Journal = journal::OpenOptions::default()
        .all_namespaces(true)
        .open()?;

    let ParserFunctionType::ParserFn(parserfn) = config.parser else {
        return Err(anyhow!("ParserFn required here"));
    };

    if let Some(values) = &config.matches {
        for (field, val) in values {
            journal.match_add(field, val.to_string())?;
            journal.match_or()?;
        }
    }

    let keyword = filter.unwrap_or_default();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_micros() as u64;

    journal.seek_realtime_usec(now)?;

    loop {
        while let Some(data) = journal.next_entry()? {
            if let Some(ev) = parserfn(data, ev_type.clone()) {
                if !ev.raw_msg.contains_bytes(&keyword) {
                    continue;
                }

                if tx.send(ev.clone()).is_err() {
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
