#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_imports)]

use crate::events;
use crate::events::receive_data;
use aho_corasick::AhoCorasick;
use anyhow::Result;
use axum::extract::State;
use libc::{PRIO_PROCESS, iw_pmkid_cand};
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

//TODO: wth? why so many enums? figure out something else bro
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

pub fn rg_capture(msg: &regex::Captures, i: usize) -> Option<String> {
    msg.get(i).map(|m| m.as_str().to_string())
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
            return Some(SshdEvent::AuthSuccess {
                timestamp: timestamp,
                user: rg_capture(&msg, 2)?,
                ip: rg_capture(&msg, 3)?,
                port: rg_capture(&msg, 4)?,
                method: rg_capture(&msg, 1)?,
                raw_msg: s.clone(),
            });
        }

        if let Some(msg) = AUTH_FAILURE.captures(s) {
            return Some(SshdEvent::AuthFailure {
                timestamp: timestamp,
                user: rg_capture(&msg, 2)?,
                ip: rg_capture(&msg, 3)?,
                port: rg_capture(&msg, 4)?,
                method: rg_capture(&msg, 1)?,
                raw_msg: s.clone(),
            });
        }

        if let Some(msg) = SESSION_OPENED.captures(s) {
            return Some(SshdEvent::SessionOpened {
                timestamp: timestamp,
                user: rg_capture(&msg, 1)?,
                uid: rg_capture(&msg, 2)?,
                raw_msg: s.clone(),
            });
        }

        if let Some(msg) = SESSION_CLOSED.captures(s) {
            return Some(SshdEvent::SessionClosed {
                timestamp: timestamp,
                user: rg_capture(&msg, 1)?,
                raw_msg: s.clone(),
            });
        }

        if let Some(msg) = CONNECTION_CLOSED.captures(s) {
            return Some(SshdEvent::ConnectionClosed {
                timestamp: timestamp,
                ip: rg_capture(&msg, 2)?,
                port: rg_capture(&msg, 3)?,
                user: Some(rg_capture(&msg, 1).unwrap()),
                msg: rg_capture(&msg, 4)?,
                raw_msg: s.clone(),
            });
        }

        for rgx in PROTOCOL_MISMATCH.iter() {
            if let Some(msg) = rgx.captures(s) {
                return Some(SshdEvent::ProtocolMismatch {
                    timestamp: timestamp,
                    ip: rg_capture(&msg, 1)?,
                    port: rg_capture(&msg, 2)?,
                    raw_msg: s.clone(),
                });
            }
        }

        if let Some(msg) = WARNING.captures(s) {
            return Some(SshdEvent::Warning {
                timestamp: timestamp,
                msg: rg_capture(&msg, 1)?,
                raw_msg: s.clone(),
            });
        }

        if let Some(msg) = UNKNOWN.captures(s) {
            return Some(SshdEvent::Unknown {
                timestamp: timestamp,
                msg: rg_capture(&msg, 1)?,
                raw_msg: s.clone(),
            });
        }

        if let Some(msg) = RECEIVED_DISCONNECT.captures(s) {
            return Some(SshdEvent::ReceivedDisconnect {
                timestamp: timestamp,
                ip: rg_capture(&msg, 1)?,
                port: rg_capture(&msg, 2)?,
                code: rg_capture(&msg, 3),
                msg: rg_capture(&msg, 4)?,
                raw_msg: s.clone(),
            });
        }

        if let Some(msg) = NEGOTIATION_FAILURE.captures(s) {
            return Some(SshdEvent::NegotiationFailure {
                timestamp: timestamp,
                ip: rg_capture(&msg, 1)?,
                port: rg_capture(&msg, 2),
                details: rg_capture(&msg, 3)?,
                raw_msg: s.clone(),
            });
        }

        if let Some(msg) = TOO_MANY_AUTH.captures(s) {
            return Some(SshdEvent::TooManyAuthFailures {
                timestamp: timestamp,
                user: rg_capture(&msg, 1),
                ip: rg_capture(&msg, 2),
                port: rg_capture(&msg, 3),
                raw_msg: s.clone(),
            });
        }
    }
    None
}

#[derive(Debug, Clone)]
pub enum LoginAttemptEvents {
    CommandRun {
        timestamp: String,
        invoking_user: String,
        tty: String,
        pwd: String,
        target_user: String,
        command: String,
        raw_msg: String,
    },
    SessionOpened {
        timestamp: String,
        target_user: String,
        uid: String,
        invoking_user: String,
        invoking_uid: String,
        raw_msg: String,
    },
    SessionClosed {
        timestamp: String,
        target_user: String,
        raw_msg: String,
    },
    AuthFailure {
        timestamp: String,
        logname: String,
        uid: String,
        euid: String,
        tty: String,
        ruser: String,
        rhost: String,
        target_user: String,
    },
    IncorrectPassword {
        timestamp: String,
        invoking_user: String,
        attempts: String,
        tty: String,
        pwd: String,
        target_user: String,
        command: String,
    },
    NotInSudoers {
        timestamp: String,
        user: String,
        raw_msg: String,
    },
    AuthError {
        timestamp: String,
        user: Option<String>,
        msg: String,
        raw_msg: String,
    },
    Warning {
        timestamp: String,
        msg: String,
        raw_msg: String,
    },
}
pub fn parse_login_attempts(map: Entry) -> Option<LoginAttemptEvents> {
    // need to check furthur.. does this make any difference?
    // static AC: Lazy<AhoCorasick> = Lazy::new(|| {
    //     AhoCorasick::new([
    //         "/usr/bin/su",
    //         "sudo",
    //         "pam_unix(sudo:session): session opened",
    //         "pam_unix(sudo:session): session closed",
    //     ])
    //     .unwrap()
    // });

    static COMMAND_RUN: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?x)^(\w+)\s+:\s+TTY=(\S+)\s+;\s+PWD=(\S+)\s+;\s+USER=(\S+)\s+;\s+COMMAND=(/usr/bin/su.*)$",)
        .unwrap()
    });

    static SESSION_OPENED: Lazy<Vec<Regex>> = Lazy::new(|| {
        vec![
            Regex::new(
            r"^pam_unix\(sudo:session\): session opened for user (\w+)\(uid=(\d+)\) by (\w+)\(uid=(\d+)\)$")
            .unwrap(),
            Regex::new(
            r"^pam_unix\(su:session\): session opened for user (\w+)\(uid=(\d+)\) by (\w+)\(uid=(\d+)\)$")
            .unwrap()
            ]
    });

    static SESSION_CLOSED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^pam_unix\(sudo:session\):\s+session closed for user (\S+)$").unwrap()
    });

    static AUTH_FAILURE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^pam_unix\(sudo:auth\): authentication failure; logname=(\S+) uid=(\d+) euid=(\d+) tty=(\S+) ruser=(\S+) rhost=(\S*)\s+user=(\S+)$")
        .unwrap()
    });

    static INCORRECT_PASSWORD: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^(\S+)\s+:\s+(\d+)\s+incorrect password attempt ; TTY=(\S+) ; PWD=(\S+) ; USER=(\S+) ; COMMAND=(\S+)$")
        .unwrap()
    });

    static NOT_IN_SUDOERS: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?x)^\s*(?P<user>\S+)\s+is\s+not\s+in\s+the\s+sudoers\s+file").unwrap()
    });

    static AUTH_ERROR: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?x)pam_unix\(sudo:auth\):\s+(?P<msg>.+?)(?:\s+\[ (?P<user>\w+) \])?\s*$")
            .unwrap()
    });

    static SUDO_WARNING: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?x)^sudo:\s+(?P<msg>.+)$").unwrap());

    if let Some(s) = map.get("MESSAGE") {
        // if AC.find(s).is_none() {
        //     return None;
        // }

        let mut timestamp = String::new();
        if let Some(tp) = map.get("SYSLOG_TIMESTAMP") {
            timestamp = tp.to_owned();
        }

        let s = s.trim_start();
        if let Some(msg) = COMMAND_RUN.captures(s) {
            return Some(LoginAttemptEvents::CommandRun {
                timestamp,
                invoking_user: rg_capture(&msg, 1)?,
                tty: rg_capture(&msg, 2)?,
                pwd: rg_capture(&msg, 3)?,
                target_user: rg_capture(&msg, 4)?,
                command: rg_capture(&msg, 5)?,
                raw_msg: s.to_string(),
            });
        }

        for rg in SESSION_OPENED.iter() {
            if let Some(msg) = rg.captures(s) {
                return Some(LoginAttemptEvents::SessionOpened {
                    timestamp,
                    target_user: rg_capture(&msg, 1)?,
                    uid: rg_capture(&msg, 2)?,
                    invoking_user: rg_capture(&msg, 3)?,
                    invoking_uid: rg_capture(&msg, 4)?,
                    raw_msg: s.to_string(),
                });
            }
        }

        if let Some(msg) = SESSION_CLOSED.captures(s) {
            return Some(LoginAttemptEvents::SessionClosed {
                timestamp,
                target_user: rg_capture(&msg, 1)?,
                raw_msg: s.to_string(),
            });
        }

        if let Some(msg) = AUTH_FAILURE.captures(s) {
            return Some(LoginAttemptEvents::AuthFailure {
                timestamp: timestamp,
                logname: rg_capture(&msg, 1)?,
                uid: rg_capture(&msg, 2)?,
                euid: rg_capture(&msg, 3)?,
                tty: rg_capture(&msg, 4)?,
                ruser: rg_capture(&msg, 5)?,
                rhost: rg_capture(&msg, 6)?,
                target_user: rg_capture(&msg, 7)?,
            });
        }

        if let Some(msg) = INCORRECT_PASSWORD.captures(s) {
            return Some(LoginAttemptEvents::IncorrectPassword {
                timestamp: timestamp,
                invoking_user: rg_capture(&msg, 1)?,
                attempts: rg_capture(&msg, 2)?,
                tty: rg_capture(&msg, 3)?,
                pwd: rg_capture(&msg, 4)?,
                target_user: rg_capture(&msg, 5)?,
                command: rg_capture(&msg, 6)?,
            });
        }
        if let Some(msg) = NOT_IN_SUDOERS.captures(s) {
            return Some(LoginAttemptEvents::NotInSudoers {
                timestamp: timestamp,
                user: rg_capture(&msg, 1)?,
                raw_msg: s.to_string(),
            });
        }

        if let Some(msg) = AUTH_ERROR.captures(s) {
            return Some(LoginAttemptEvents::AuthError {
                timestamp: timestamp,
                user: rg_capture(&msg, 2),
                msg: rg_capture(&msg, 1)?,
                raw_msg: s.to_string(),
            });
        }
        if let Some(msg) = SUDO_WARNING.captures(s) {
            return Some(LoginAttemptEvents::Warning {
                timestamp: timestamp,
                msg: rg_capture(&msg, 1)?,
                raw_msg: s.to_string(),
            });
        }
    }

    None
}

// fn parse_kernel_events()

#[derive(Clone, Debug)]
pub enum EventType {
    Sshd(SshdEvent),
    Login(LoginAttemptEvents),
}

//TODO: Need to check the name's of the services beacuse there are different on different distros
pub fn flush_previous_data(
    tx: tokio::sync::broadcast::Sender<EventType>,
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
                            if let Err(e) = tx.send(EventType::Sshd(ev)) {
                                println!("Dropped");
                            }
                        }
                    }
                }

                "sudo.events" => {
                    s.match_add("_COMM", "su")?;
                    s.match_add("_COMM", "sudo")?;
                    while let Some(data) = s.next_entry()? {
                        if let Some(ev) = parse_login_attempts(data) {
                            println!("{:?}", ev);
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
