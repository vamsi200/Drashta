use once_cell::sync::Lazy;
use regex::Regex;

pub static SSHD_REGEX: Lazy<Vec<(&str, Regex)>> = Lazy::new(|| {
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

pub static PROTOCOL_MISMATCH: Lazy<Vec<(&str, Regex)>> = Lazy::new(|| {
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

pub static SUDO_REGEX: Lazy<Vec<(&str, Regex)>> = Lazy::new(|| {
    vec![
            ("COMMAND_RUN", Regex::new(r"(?x)^(\w+)\s+:\s+TTY=(\S+)\s+;\s+PWD=(\S+)\s+;\s+USER=(\S+)\s+;\s+COMMAND=(/usr/bin/su.*)$").unwrap()),
            ("SESSION_OPENED_SUDO", Regex::new(r"^pam_unix\(sudo:session\): session opened for user (\w+)\(uid=(\d+)\) by (\w+)\(uid=(\d+)\)$").unwrap()),
            ("SESSION_OPENED_SU", Regex::new(r"^pam_unix\(su:session\): session opened for user (\w+)\(uid=(\d+)\) by (\w+)\(uid=(\d+)\)$").unwrap()),
            ("SESSION_CLOSED", Regex::new(r"^pam_unix\(sudo:session\):\s+session closed for user (\S+)$").unwrap()),
            ("AUTH_FAILURE", Regex::new(r"^pam_unix\(sudo:auth\): authentication failure; logname=(\S+) uid=(\d+) euid=(\d+) tty=(\S+) ruser=(\S+) rhost=(\S*)\s+user=(\S+)$").unwrap()),
            ("INCORRECT_PASSWORD", Regex::new(r"^\S+\s+:\s+(\d+)\s+incorrect password attempts?\s+;\s+TTY=(\S+)\s+;\s+PWD=(\S+)\s+;\s+USER=(\S+)\s+;\s+COMMAND=(.+)$").unwrap()),
            ("NOT_IN_SUDOERS", Regex::new(r"(?x)^\s*(?P<user>\S+)\s+is\s+not\s+in\s+the\s+sudoers\s+file").unwrap()),
            ("AUTH_ERROR", Regex::new(r"(?x)pam_unix\(sudo:auth\):\s+(?P<msg>.+?)(?:\s+\[ (?P<user>\w+) \])?\s*$").unwrap()),
            ("SUDO_WARNING", Regex::new(r"(?x)^sudo:\s+(?P<msg>.+)$").unwrap()),
        ]
});

pub static LOGIN_REGEXES: Lazy<Vec<(&str, Regex)>> = Lazy::new(|| {
    vec![
        (
            "AUTH_FAILURE",
            Regex::new(r"pam_unix\([^:]+:auth\): authentication failure").unwrap(),
        ),
        (
            "AUTH_USER_UNKNOWN",
            Regex::new(r"pam_unix\([^:]+:auth\): .*user .* unknown").unwrap(),
        ),
        (
            "FAILL0CK",
            Regex::new(r"pam_faillock\([^:]+:auth\):.*").unwrap(),
        ),
        (
            "ACCOUNT_EXPIRED",
            Regex::new(r"pam_unix\([^:]+:account\): account .* has expired").unwrap(),
        ),
        (
            "NOLOGIN_REFUSED",
            Regex::new(r"pam_nologin\([^:]+:auth\): Refused user (\S+)").unwrap(),
        ),
        (
            "SESSION_OPENED",
            Regex::new(r"pam_unix\([^:]+:session\): session opened for user (\S+)").unwrap(),
        ),
        (
            "SESSION_CLOSED",
            Regex::new(r"pam_unix\([^:]+:session\): session closed for user (\S+)").unwrap(),
        ),
        (
            "SYSTEMD_NEW_SESSION",
            Regex::new(r"New session \S+ of user (\S+)").unwrap(),
        ),
        (
            "SYSTEMD_SESSION_CLOSED",
            Regex::new(r"Removed session \S+\.").unwrap(),
        ),
        (
            "SDDM_LOGIN_SUCCESS",
            Regex::new(r"Authentication for user (\S+) successful").unwrap(),
        ),
        (
            "SDDM_LOGIN_FAILURE",
            Regex::new(r"Authentication failed for user (\S+)").unwrap(),
        ),
        (
            "FAILED_PASSWORD_SSH",
            Regex::new(r"Failed password for (\S+) from \S+ port \d+ ssh2").unwrap(),
        ),
        (
            "INVALID_USER_ATTEMPT",
            Regex::new(r"Invalid user (\S+) from \S+").unwrap(),
        ),
        (
            "ACCOUNT_LOCKED",
            Regex::new(r"pam_tally2\(.*:auth\): user (\S+) has been locked due to .*").unwrap(),
        ),
        (
            "PASSWORD_CHANGED",
            Regex::new(r"pam_unix\(passwd:chauthtok\): password changed for (\S+)").unwrap(),
        ),
        (
            "SYSTEMD_SESSION_OPENED_UID",
            Regex::new(
                r"pam_unix\(systemd-user:session\): session opened for user (\S+) \(uid=\d+\)",
            )
            .unwrap(),
        ),
        (
            "SYSTEMD_SESSION_CLOSED_UID",
            Regex::new(
                r"pam_unix\(systemd-user:session\): session closed for user (\S+) \(uid=\d+\)",
            )
            .unwrap(),
        ),
    ]
});

pub static USER_CREATION_REGEX: Lazy<Vec<(&str, Regex)>> = Lazy::new(|| {
    vec![
            ("NEW_USER", Regex::new(r"^new user: name=(\S+), UID=(\d+), GID=(\d+), home=(\S+), shell=(\S+), from=(\S+)$").unwrap()),
            ("NEW_GROUP", Regex::new(r"^new group: name=(\S+), GID=(\d+)$").unwrap()),
            ("GROUP_ADDED_ETC_GROUP", Regex::new(r"^group added to /etc/group: name=(\S+), GID=(\d+)$").unwrap()),
            ("GROUP_ADDED_ETC_GSHADOW", Regex::new(r"^group added to /etc/gshadow: name=(\S+)$").unwrap()),
        ]
});

pub static USER_DELETION_REGEX: Lazy<Vec<(&str, Regex)>> = Lazy::new(|| {
    vec![
        (
            "DELETE_USER",
            Regex::new(r"^delete user: name=(\S+), UID=(\d+), GID=(\d+), home=(\S+), shell=(\S+)$")
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

pub static USER_MODIFICATION_REGEX: Lazy<Vec<(&str, Regex)>> = Lazy::new(|| {
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

pub static PKG_EVENTS_REGEX: Lazy<Vec<(&str, Regex)>> = Lazy::new(|| {
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
            Regex::new(r"^\[(.+?)\] \[ALPM\] downgraded (\S+) \(([^)]+) -> ([^)]+)\)$").unwrap(),
        ),
        (
            "REINSTALLED",
            Regex::new(r"^\[(.+?)\] \[ALPM\] reinstalled (\S+) \(([^)]+)\)$").unwrap(),
        ),
    ]
});

pub static CRON_REGEX: Lazy<Vec<(&str, Regex)>> = Lazy::new(|| {
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

pub static NETWORK_REGEX: Lazy<Vec<(&str, Regex)>> = Lazy::new(|| {
    vec![
        (
            "CONNECTION_ACTIVATED",
            Regex::new(r"(?x)
                ^<(?P<level>info|warn)>\s+\[\s*(?P<ts>\d+\.\d+)\]\s+
                (?:
                    connection-activation:\s+
                    connection\s+'(?P<conn_old>[^']+)'\s+activated
                    |
                    device\s+\((?P<device>[^)]+)\):\s+
                    Activation:\s+successful,?\s+
                    (?:connection\s+'(?P<conn_new>[^']+)')?
                )
            ").unwrap(),
        ),
        (
            "CONNECTION_DEACTIVATED",
            Regex::new(r"(?x)
                ^<(?P<level>info|warn|error)>\s+\[\s*(?P<ts>\d+\.\d+)\]\s+
                (?:
                    connection-activation:\s+
                    deactivated\s+connection\s+'(?P<conn_old>[^']+)'
                    (?:\s+\(reason\s+'(?P<reason_old>[^']+)'\))?
                    |
                    device\s+\((?P<device>[^)]+)\):\s+
                    state\s+change:\s+\S+\s+->\s+deactivated
                    (?:\s+\(reason\s+'(?P<reason_new>[^']+)'\))?
                )
            ").unwrap(),
        ),

        (
            "DEVICE_ACTIVATION",
            Regex::new(
                r"(?x)
                ^<(?P<level>info|warn|error)>\s+\[\s*(?P<ts>\d+\.\d+)\]\s+
                device\s+\((?P<device>[^)]+)\):\s+
                Activation:\s+(?P<result>successful|starting\s+connection|failed),?\s+
                (?P<details>.*?)\.?\s*$
                "
            ).unwrap(),
        ),
        (
            "DEVICE_STATE_CHANGE",
            Regex::new(
                r"(?x)
                ^<(?P<level>info|warn|debug)>\s+\[\s*(?P<ts>\d+\.\d+)\]\s+
                device\s+\((?P<device>[^)]+)\):\s+
                state\s+change:\s+
                (?P<from>\S+)\s+->\s+(?P<to>\S+)\s+
                \(reason\s+'(?P<reason>[^']*)',?\s*
                (?:sys-iface-state:\s+'(?P<sys_state>[^']+)'|managed-type:\s+'(?P<mgmt_type>[^']+)')?\)
                "
            ).unwrap(),
        ),
        (
            "MANAGER_STATE",
            Regex::new(
                r"(?x)
                ^<(?P<level>info|warn)>\s+\[\s*(?P<ts>\d+\.\d+)\]\s+
                manager:\s+
                (?:NetworkManager\s+state\s+is\s+now\s+(?P<state>\S+)|
                   startup\s+complete|
                   NetworkManager\s+\(version\s+(?P<version>[^)]+)\)\s+is\s+(?P<action>starting|stopping))
                "
            ).unwrap(),
        ),
        (
            "DHCP_EVENT",
            Regex::new(
                r"(?x)
                ^<(?P<level>info|warn|debug)>\s+\[\s*(?P<ts>\d+\.\d+)\]\s+
                dhcp(?P<version>[46])?\s+\((?P<iface>[^)]+)\):\s+
                (?:state\s+changed\s+(?P<from>\S+)\s+->\s+(?P<to>\S+)|
                   option\s+(?P<option>\S+)\s+=>\s+'?(?P<value>[^']+)'?|
                   (?P<msg>.*))
                "
            ).unwrap(),
        ),
        (
            "DHCP_INIT",
            Regex::new(
                r"(?x)
                ^<(?P<level>info)>\s+\[\s*(?P<ts>\d+\.\d+)\]\s+
                dhcp-init:\s+Using\s+DHCP\s+client\s+'(?P<client>[^']+)'
                "
            ).unwrap(),
        ),
        (
            "POLICY_SET",
            Regex::new(
                r"(?x)
                ^<(?P<level>info|warn)>\s+\[\s*(?P<ts>\d+\.\d+)\]\s+
                policy:\s+set\s+'(?P<connection>[^']+)'\s+\((?P<iface>[^)]+)\)\s+
                as\s+default\s+for\s+(?P<purpose>IPv4|IPv6|DNS|routing).*?
                "
            ).unwrap(),
        ),
        (
            "SUPPLICANT_STATE",
            Regex::new(
                r"(?x)
                ^<(?P<level>info|debug)>\s+\[\s*(?P<ts>\d+\.\d+)\]\s+
                device\s+\((?P<device>[^)]+)\):\s+
                supplicant\s+(?:interface|management\s+interface)\s+state:\s+
                (?P<from>\S+)\s+->\s+(?P<to>\S+)
                "
            ).unwrap(),
        ),
        (
            "WIFI_SCAN",
            Regex::new(
                r"(?x)
                ^<(?P<level>info|debug)>\s+\[\s*(?P<ts>\d+\.\d+)\]\s+
                device\s+\((?P<device>[^)]+)\):\s+
                (?:wifi-scan:\s+.*|
                   supplicant\s+interface\s+state:\s+.*scanning.*)
                "
            ).unwrap(),
        ),
        (
            "PLATFORM_ERROR",
            Regex::new(
                r"(?x)
                ^<(?P<level>warn|error)>\s+\[\s*(?P<ts>\d+\.\d+)\]\s+
                platform(?:-linux)?:\s+
                (?P<operation>do-\S+)\[(?P<details>[^\]]+)\]:\s+
                (?:failure\s+(?P<errno>\d+)\s+\((?P<error>[^)]+)\)|(?P<msg>.*))
                "
            ).unwrap(),
        ),
        (
            "SETTINGS_CONNECTION",
            Regex::new(
                r"(?x)
                ^<(?P<level>info|warn)>\s+\[\s*(?P<ts>\d+\.\d+)\]\s+
                (?:settings|settings-connection):\s+
                (?P<msg>.*)
                "
            ).unwrap(),
        ),
        (
            "DNS_CONFIG",
            Regex::new(
                r"(?x)
                ^<(?P<level>info|warn)>\s+\[\s*(?P<ts>\d+\.\d+)\]\s+
                dns:\s+
                (?P<msg>.*)
                "
            ).unwrap(),
        ),
        (
            "VPN_EVENT",
            Regex::new(
                r"(?x)
                ^<(?P<level>info|warn|error)>\s+\[\s*(?P<ts>\d+\.\d+)\]\s+
                (?:vpn-connection|vpn):\s+
                (?P<msg>.*)
                "
            ).unwrap(),
        ),
        (
            "FIREWALL_EVENT",
            Regex::new(
                r"(?x)
                ^<(?P<level>info|warn)>\s+\[\s*(?P<ts>\d+\.\d+)\]\s+
                firewall:\s+
                (?P<msg>.*)
                "
            ).unwrap(),
        ),
        (
            "AGENT_REQUEST",
            Regex::new(
                r"(?x)
                ^<(?P<level>info|warn)>\s+\[\s*(?P<ts>\d+\.\d+)\]\s+
                agent-manager:\s+
                (?P<msg>.*)
                "
            ).unwrap(),
        ),
        (
            "CONNECTIVITY_CHECK",
            Regex::new(
                r"(?x)
                ^<(?P<level>info|warn)>\s+\[\s*(?P<ts>\d+\.\d+)\]\s+
                connectivity:\s+
                (?P<msg>.*)
                "
            ).unwrap(),
        ),
        (
            "DISPATCHER",
            Regex::new(
                r"(?x)
                ^<(?P<level>info|warn)>\s+\[\s*(?P<ts>\d+\.\d+)\]\s+
                dispatcher:\s+
                (?P<msg>.*)
                "
            ).unwrap(),
        ),
        (
            "LINK_EVENT",
            Regex::new(
                r"(?x)
                ^<(?P<level>info|warn|debug)>\s+\[\s*(?P<ts>\d+\.\d+)\]\s+
                device\s+\((?P<device>[^)]+)\):\s+
                (?:link\s+(?P<state>connected|disconnected)|
                   carrier:\s+link\s+(?P<carrier>connected|disconnected))
                "
            ).unwrap(),
        ),
        (
            "VIRTUAL_DEVICE",
            Regex::new(
                r"(?x)
                ^<(?P<level>info|warn)>\s+\[\s*(?P<ts>\d+\.\d+)\]\s+
                (?:bridge|bond|team|vlan):\s+
                (?P<msg>.*)
                "
            ).unwrap(),
        ),
        (
            "AUDIT",
            Regex::new(
                r"(?x)
                ^<(?P<level>info|warn)>\s+\[\s*(?P<ts>\d+\.\d+)\]\s+
                audit:\s+
                (?P<msg>.*)
                "
            ).unwrap(),
        ),
        (
            "SYSTEMD",
            Regex::new(
                r"(?x)
                ^<(?P<level>info|warn)>\s+\[\s*(?P<ts>\d+\.\d+)\]\s+
                systemd:\s+
                (?P<msg>.*)
                "
            ).unwrap(),
        ),
        (
            "GENERIC",
            Regex::new(
                r"(?x)
                ^<(?P<level>info|warn|error|debug)>\s+\[\s*(?P<ts>\d+\.\d+)\]\s+
                (?P<component>\S+):\s+
                (?P<msg>.+)$
                "
            ).unwrap(),
        ),
            (
            "DEVICE_ACTIVATION_WARN",
            Regex::new(r"(?x)
                ^<(?P<level>warn|error)>\s+\[\s*(?P<ts>\d+\.\d+)\]\s+
                device\s+\((?P<device>[^)]+)\):\s+
                Activation:\s+(?P<result>failed),?\s+
                (?P<details>.*?)\.?\s*$
            ").unwrap(),
        ),
        (
            "MANAGER_WARN",
            Regex::new(r"(?x)
                ^<(?P<level>warn)>\s+\[\s*(?P<ts>\d+\.\d+)\]\s+
                manager:\s+
                (?P<msg>.*)$
            ").unwrap(),
        ),
        (
            "MANAGER_ERROR",
            Regex::new(r"(?x)
                ^<(?P<level>error)>\s+\[\s*(?P<ts>\d+\.\d+)\]\s+
                manager:\s+
                (?P<msg>.*)$
            ").unwrap(),
        ),
        (
            "DHCP_ERROR",
            Regex::new(r"(?x)
                ^<(?P<level>warn|error)>\s+\[\s*(?P<ts>\d+\.\d+)\]\s+
                dhcp(?P<version>[46])?\s+\((?P<iface>[^)]+)\):\s+
                (?P<msg>.*)$
            ").unwrap(),
        ),
        (
            "VPN_ERROR",
            Regex::new(r"(?x)
                ^<(?P<level>error|warn)>\s+\[\s*(?P<ts>\d+\.\d+)\]\s+
                (?:vpn-connection|vpn):\s+
                (?P<msg>.*)$
            ").unwrap(),
        ),
        (
            "NM_WARNING",
            Regex::new(r"(?x)
                ^<(?P<level>warn)>\s+\[\s*(?P<ts>\d+\.\d+)\]\s+
                (?P<component>\S+):\s+
                (?P<msg>.*)$
            ").unwrap(),
        ),

        (
            "NM_ERROR",
            Regex::new(r"(?x)
                ^<(?P<level>error)>\s+\[\s*(?P<ts>\d+\.\d+)\]\s+
                (?P<component>\S+):\s+
                (?P<msg>.*)$
            ").unwrap(),
        ),

        (
            "UNKNOWN",
            Regex::new(r"(?s)^(?P<msg>.+)$").unwrap(),
        ),
    ]
});

pub static FIREWALLD_REGEX: Lazy<Vec<(&str, Regex)>> = Lazy::new(|| {
    vec![
            ("SERVICE_STARTED", Regex::new(r"(?x)^firewalld\s+(?:is\s+)?running\s*$").unwrap()),
            ("SERVICE_STOPPED", Regex::new(r"(?x)^firewalld\s+(?:is\s+)?stopped\s*$").unwrap()),
            ("CONFIG_RELOADED", Regex::new(r"(?x)^(?:firewalld|firewall):\s+(?:Configuration\s+)?reloaded|Reloading\s+firewall\s+rules").unwrap()),
            ("ZONE_CHANGED", Regex::new(r"(?x)^(?:Zone|Zone\s+changes)?:\s+(\w+)\s+(?:activated|changed|modified|added|removed)(?:\s+on\s+([a-z0-9\.]+))?\s*$").unwrap()),
            ("SERVICE_MODIFIED", Regex::new(r"(?x)^(?:Service|service)\s+(\S+)\s+(?:added|removed|enabled|disabled)(?:\s+in\s+zone\s+(\w+))?\s*$").unwrap()),
            ("PORT_MODIFIED", Regex::new(r"(?x)^(?:Port|port)\s+(\d+)/(\w+)\s+(?:opened|closed|added|removed)(?:\s+in\s+zone\s+(\w+))?\s*$").unwrap()),
            ("RULE_APPLIED", Regex::new(r"(?x)^(?:Rule|rule)\s+(?:added|removed|modified|applied)(?::\s+(.+))?\s*$").unwrap()),
            ("IPTABLES_COMMAND", Regex::new(r"(?x)^(?:WARNING|ERROR):\s+'(?:/usr/sbin/(?:ip6?tables|nft)(?:-restore|-save)?)'\s+(?:failed|succeeded):(.*)$").unwrap()),
            ("INTERFACE_BINDING", Regex::new(r"(?x)^(?:Interface|interface)\s+([a-z0-9\.:]+)\s+(?:added|removed|bound|unbound)(?:\s+(?:to|from)\s+zone\s+(\w+))?\s*$").unwrap()),
            ("COMMAND_FAILED", Regex::new(r"(?x)^ERROR:\s+COMMAND_FAILED|ERROR:\s+(.+)").unwrap()),
            ("OPERATION_STATUS", Regex::new(r"(?x)^(?:reload|restart|reload-and-restart)(?:ed)?\s+(?:completed|failed|successful)(?:\s+(.+))?\s*$").unwrap()),
            ("MODULE_MSG", Regex::new(r"(?x)^(?:ModuleConnector|Connector)(?:\(([^)]+)\))?\s+(?:MSG:)?\s*(.+?)(?:\s+\[(.+?)\])?\s*$").unwrap()),
            ("DBUS_MSG", Regex::new(r"(?x)^(?:DBus|dbus)\s+(?:error|warning|info)?:?\s*(.+?)(?:\s+\[(.+?)\])?\s*$").unwrap()),
            ("WARNING", Regex::new(r"(?x)^WARNING:\s+(.+\S)\s*$").unwrap()),
            ("ERROR", Regex::new(r"(?x)^ERROR:\s+(.+\S)\s*$").unwrap()),
            ("INFO", Regex::new(r"(?x)^INFO:\s+(.+\S)\s*$").unwrap()),
            ("UNKNOWN", Regex::new(r"(?s)^(.*\S.*)$").unwrap()),
        ]
});

pub static KERNEL_REGEX: Lazy<Vec<(&str, Regex)>> = Lazy::new(|| {
    vec![
            ("KERNEL_PANIC", Regex::new(r"(?x)^(?:Kernel\s+panic|kernel\s+panic)\s*[-:]\s*(.+?)(?:\s+CPU:\s*(\d+))?\s*$").unwrap()),
            ("OOM_KILL", Regex::new(r"(?x)^(?:Out\s+of\s+memory|OOM\s+killer):\s*(?:Kill(?:ed|ing))?\s+process\s+(\d+)\s+\(([^\)]+)\)(?:\s+score\s+(\d+))?\s*").unwrap()),
            ("SEGFAULT", Regex::new(r"(?x)^([^\[]+)\[(\d+)\]:\s+segfault\s+at\s+([0-9a-f]+)\s+ip\s+([0-9a-f]+)\s+sp\s+([0-9a-f]+)\s+error\s+(\d+)(?:\s+in\s+([^\[]+))?\s*").unwrap()),
            ("USB_ERROR", Regex::new(r"(?x)^usb\s+([\d\-\.]+):\s+(.+?),\s+error\s+(-?\d+)\s*$").unwrap()),
            ("USB_DESCRIPTOR_ERROR", Regex::new(r"(?x)^usb\s+([\d\-\.]+):\s+device\s+(?:descriptor|not\s+accepting\s+address)\s+(.+?),\s+error\s+(-?\d+)\s*$").unwrap()),
            ("USB_DEVICE_EVENT", Regex::new(r"(?x)^usb\s+([\d\-\.]+):\s+(New\s+USB\s+device\s+found|USB\s+disconnect),\s+(.+?)(?:\s+idVendor=([0-9a-f]+),\s+idProduct=([0-9a-f]+))?\s*$").unwrap()),
            ("DISK_ERROR", Regex::new(r"(?x)^(?:end_request|blk_update_request):\s+(?:I/O\s+error|critical\s+(?:medium|target)\s+error),\s+dev\s+(\S+),\s+sector\s+(\d+)(?:\s+op\s+([^\s]+))?\s*").unwrap()),
            ("FS_MOUNT", Regex::new(r"(?x)^(?:EXT[234]|XFS|BTRFS|F2FS|VFAT|NTFS|ZFS)-fs\s+\(([^\)]+)\):\s+(mounted|unmounted|remounted)\s*(.+?)?\s*$").unwrap()),
            ("FS_ERROR", Regex::new(r"(?x)^(?:EXT[234]|XFS|BTRFS|F2FS|NTFS|ZFS)-fs\s+(?:error|warning)\s+\(device\s+([^\)]+)\):(?:\s+(.+))?\s*$").unwrap()),
            ("CPU_ERROR", Regex::new(r"(?x)^(?:CPU|cpu)\s*(\d+)?:?\s+(?:temperature|Machine\s+Check\s+Exception|MCE|hardware\s+error)\s*(.+?)\s*$").unwrap()),
            ("MEMORY_ERROR", Regex::new(r"(?x)^(?:EDAC|Memory)\s+(?:error|CE|UE):?\s*(.+?)(?:\s+at\s+address\s+([0-9a-fx]+))?\s*$").unwrap()),
            ("DEVICE_DETECTED", Regex::new(r"(?x)^(?:Found|Detected|Registered)\s+(?:device|hardware):\s+(.+?)(?:\s+at\s+([0-9a-fx:]+))?\s*$").unwrap()),
            ("DRIVER_EVENT", Regex::new(r"(?x)^(?:Loading|Unloading|Loaded|Unloaded)\s+(?:module|driver):\s+([^\s]+)(?:\s+(.+))?\s*$").unwrap()),
            ("NET_INTERFACE", Regex::new(r"(?x)^([a-z0-9]+):\s+(?:link\s+(?:up|down)|renamed\s+from\s+([a-z0-9]+)|NIC\s+Link\s+is\s+(?:Up|Down))\s*(?:at\s+(\d+)\s*(?:Mbps|Gbps))?\s*").unwrap()),
            ("PCI_DEVICE", Regex::new(r"(?x)^pci\s+([0-9a-f:\.]+):\s+(.+?)\s*$").unwrap()),
            ("ACPI_EVENT", Regex::new(r"(?x)^ACPI:?\s+(.+?)(?:\s+\[([^\]]+)\])?\s*$").unwrap()),
            ("THERMAL_EVENT", Regex::new(r"(?x)^(?:thermal|Thermal|Critical\s+temperature):?\s+(?:CPU|cpu|GPU|gpu|zone\s*(\d+))?\s*(.+?)(?:\s+temperature:?\s+([0-9\.]+)(?:\s*°?C)?)?\s*$").unwrap()),
            ("DMA_ERROR", Regex::new(r"(?x)^(?:DMA|dma):\s+(.+?)(?:\s+on\s+device\s+([^\s]+))?\s*$").unwrap()),
            ("AUDIT_EVENT", Regex::new(r"(?x)^audit:?\s+type=(\d+)\s+(.+?)\s*$").unwrap()),
            ("KERNEL_TAINT", Regex::new(r"(?x)^(?:Kernel\s+tainted:|Loading\s+tainted\s+module)\s+([^\s]+)(?:\s+(.+))?\s*$").unwrap()),
            ("FIRMWARE_LOAD", Regex::new(r"(?x)^(?:firmware|Firmware):\s+(?:loading|loaded|failed\s+to\s+load)\s+([^\s]+)(?:\s+for\s+device\s+([^\s]+))?\s*$").unwrap()),
            ("IRQ_EVENT", Regex::new(r"(?x)^(?:irq|IRQ)\s+(\d+):?\s+(.+?)\s*$").unwrap()),
            ("TASK_KILLED", Regex::new(r"(?x)^(?:Killed|Killing)\s+process\s+(\d+)\s+\(([^\)]+)\)(?:\s+(.+))?\s*$").unwrap()),
            ("RCU_STALL", Regex::new(r"(?x)^(?:rcu_sched|rcu_preempt)\s+(?:detected\s+stalls?|self-detected\s+stall)\s+on\s+CPU[s]?\s+(.+?)\s*$").unwrap()),
            ("WATCHDOG", Regex::new(r"(?x)^(?:watchdog|Watchdog):\s+(.+?)(?:\s+on\s+CPU\s+(\d+))?\s*$").unwrap()),
            ("BOOT_EVENT", Regex::new(r"(?x)^(?:Booting|Starting)\s+(?:kernel|Linux)\s+(?:version\s+)?([^\s]+)?\s*(.+?)?\s*$").unwrap()),
            ("EMERG", Regex::new(r"(?x)^EMERGENCY:?\s+(.+\S)\s*$").unwrap()),
            ("ALERT", Regex::new(r"(?x)^ALERT:?\s+(.+\S)\s*$").unwrap()),
            ("CRITICAL", Regex::new(r"(?x)^(?:CRITICAL|critical):?\s+(.+\S)\s*$").unwrap()),
            ("ERROR", Regex::new(r"(?x)^(?:ERROR|error):?\s+(.+\S)\s*$").unwrap()),
            ("WARNING", Regex::new(r"(?x)^(?:WARNING|warning):?\s+(.+\S)\s*$").unwrap()),
            ("NOTICE", Regex::new(r"(?x)^(?:NOTICE|notice):?\s+(.+\S)\s*$").unwrap()),
            ("INFO", Regex::new(r"(?x)^(?:INFO|info):?\s+(.+\S)\s*$").unwrap()),
            ("UNKNOWN", Regex::new(r"(?s)^(.*\S.*)$").unwrap()),
        ]
});

pub fn str_to_regex_names(ev: &str) -> &'static [&'static str] {
    match ev {
        "Success" => &["AUTH_SUCCESS", "SDDM_LOGIN_SUCCESS"],
        "Failure" => &[
            "AUTH_FAILURE",
            "SDDM_LOGIN_FAILURE",
            "FAILED_PASSWORD_SSH",
            "INVALID_USER_ATTEMPT",
        ],
        "SessionOpened" => &[
            "SESSION_OPENED",
            "SYSTEMD_NEW_SESSION",
            "SYSTEMD_SESSION_OPENED_UID",
        ],
        "SessionClosed" => &[
            "SESSION_CLOSED",
            "SYSTEMD_SESSION_CLOSED",
            "SYSTEMD_SESSION_CLOSED_UID",
        ],

        "ConnectionClosed" => &["CONNECTION_CLOSED"],
        "TooManyAuthFailures" => &["TOO_MANY_AUTH"],
        "Warning" => &[
            "WARNING",
            "NM_WARNING",
            "DEVICE_ACTIVATION_WARN",
            "MANAGER_WARN",
            "SUDO_WARNING",
        ],
        "Info" => &["RECEIVED_DISCONNECT", "NEGOTIATION_FAILURE", "INFO"],
        "Other" => &["UNKNOWN", "GENERIC"],
        "Unknown" => &["UNKNOWN"],

        // SUDO Events
        "IncorrectPassword" => &["INCORRECT_PASSWORD"],
        "AuthError" => &["AUTH_ERROR"],
        "CmdRun" => &["COMMAND_RUN"],
        "SessionOpenedSudo" => &["SESSION_OPENED_SUDO", "SESSION_OPENED_SU"],
        "NotInSudoers" => &["NOT_IN_SUDOERS"],

        // Login Events
        "AuthUserUnknown" => &["AUTH_USER_UNKNOWN"],
        "FaillockUserUnknown" => &["FAILL0CK"],
        "NoLoginRefused" => &["NOLOGIN_REFUSED"],
        "AccountExpired" => &["ACCOUNT_EXPIRED"],
        "AccountLocked" => &["ACCOUNT_LOCKED"],
        "PasswordChanged" => &["PASSWORD_CHANGED"],

        // User Creation Events
        "NewUser" => &["NEW_USER"],
        "NewGroup" => &["NEW_GROUP"],
        "GroupAddedEtcGroup" => &["GROUP_ADDED_ETC_GROUP"],
        "GroupAddedEtcGshadow" => &["GROUP_ADDED_ETC_GSHADOW"],

        // User Deletion Events
        "DeleteUser" => &["DELETE_USER"],
        "DeleteUserHome" => &["DELETE_USER_HOME"],
        "DeleteUserMail" => &["DELETE_USER_MAIL"],
        "DeleteGroup" => &["DELETE_GROUP"],

        // User Modification Events
        "ModifyUser" => &["MODIFY_USER"],
        "ModifyGroup" => &["MODIFY_GROUP"],
        "PasswdChange" => &["USER_PASSWD_CHANGE"],
        "ShadowUpdated" => &["USER_SHADOW_UPDATED"],

        // Package Events
        "PkgInstalled" => &["INSTALLED"],
        "PkgRemoved" => &["REMOVED"],
        "PkgUpgraded" => &["UPGRADED"],
        "PkgDowngraded" => &["DOWNGRADED"],
        "PkgReinstalled" => &["REINSTALLED"],

        // Cron Events
        "CronCmd" => &["CRON_CMD"],
        "CronReload" => &["CRON_RELOAD"],
        "CronErrorBadCommand" => &["CRON_ERROR_BAD_COMMAND"],
        "CronErrorBadMinute" => &["CRON_ERROR_BAD_MINUTE"],
        "CronErrorOther" => &["CRON_ERROR_OTHER"],
        "CronDenied" => &["CRON_DENIED"],
        "CronSessionOpen" => &["CRON_SESSION_OPEN"],
        "CronSessionClose" => &["CRON_SESSION_CLOSE"],

        // Network Manager Events
        "DeviceActivation" => &["DEVICE_ACTIVATION"],
        "DeviceStateChange" => &["DEVICE_STATE_CHANGE"],
        "ConnectionActivated" => &["CONNECTION_ACTIVATED"],
        "ConnectionDeactivated" => &["CONNECTION_DEACTIVATED"],
        "ManagerState" => &["MANAGER_STATE"],
        "DhcpEvent" => &["DHCP_EVENT"],
        "DhcpInit" => &["DHCP_INIT"],
        "PolicySet" => &["POLICY_SET"],
        "SupplicantState" => &["SUPPLICANT_STATE"],
        "WifiScan" => &["WIFI_SCAN"],
        "PlatformError" => &["PLATFORM_ERROR"],
        "SettingsConnection" => &["SETTINGS_CONNECTION"],
        "DnsConfig" => &["DNS_CONFIG"],
        "VpnEvent" => &["VPN_EVENT"],
        "FirewallEvent" => &["FIREWALL_EVENT"],
        "AgentRequest" => &["AGENT_REQUEST"],
        "ConnectivityCheck" => &["CONNECTIVITY_CHECK"],
        "Dispatcher" => &["DISPATCHER"],
        "LinkEvent" => &["LINK_EVENT"],
        "VirtualDevice" => &["VIRTUAL_DEVICE"],
        "Audit" => &["AUDIT"],
        "Systemd" => &["SYSTEMD"],

        // Firewalld Events
        "FirewalldServiceStarted" => &["SERVICE_STARTED"],
        "FirewalldServiceStopped" => &["SERVICE_STOPPED"],
        "FirewalldConfigReloaded" => &["CONFIG_RELOADED"],
        "FirewalldZoneChanged" => &["ZONE_CHANGED"],
        "FirewalldServiceModified" => &["SERVICE_MODIFIED"],
        "FirewalldPortModified" => &["PORT_MODIFIED"],
        "FirewalldRuleApplied" => &["RULE_APPLIED"],
        "FirewalldIptablesCommand" => &["IPTABLES_COMMAND"],
        "FirewalldInterfaceBinding" => &["INTERFACE_BINDING"],
        "FirewalldCommandFailed" => &["COMMAND_FAILED"],
        "FirewalldOperationStatus" => &["OPERATION_STATUS"],
        "FirewalldModuleMessage" => &["MODULE_MSG"],
        "FirewalldDBusMessage" => &["DBUS_MSG"],

        // Kernel Events
        "KernelPanic" => &["KERNEL_PANIC"],
        "OomKill" => &["OOM_KILL"],
        "Segfault" => &["SEGFAULT"],
        "UsbError" => &["USB_ERROR"],
        "UsbDescriptorError" => &["USB_DESCRIPTOR_ERROR"],
        "UsbDeviceEvent" => &["USB_DEVICE_EVENT"],
        "DiskError" => &["DISK_ERROR"],
        "FsMount" => &["FS_MOUNT"],
        "FsError" => &["FS_ERROR"],
        "CpuError" => &["CPU_ERROR"],
        "MemoryError" => &["MEMORY_ERROR"],
        "DeviceDetected" => &["DEVICE_DETECTED"],
        "DriverEvent" => &["DRIVER_EVENT"],
        "NetInterface" => &["NET_INTERFACE"],
        "PciDevice" => &["PCI_DEVICE"],
        "AcpiEvent" => &["ACPI_EVENT"],
        "ThermalEvent" => &["THERMAL_EVENT"],
        "DmaError" => &["DMA_ERROR"],
        "AuditEvent" => &["AUDIT_EVENT"],
        "KernelTaint" => &["KERNEL_TAINT"],
        "FirmwareLoad" => &["FIRMWARE_LOAD"],
        "IrqEvent" => &["IRQ_EVENT"],
        "TaskKilled" => &["TASK_KILLED"],
        "RcuStall" => &["RCU_STALL"],
        "Watchdog" => &["WATCHDOG"],
        "BootEvent" => &["BOOT_EVENT"],
        "Emerg" => &["EMERG"],
        "Alert" => &["ALERT"],
        "Critical" => &["CRITICAL"],
        "Error" => &["ERROR"],
        "Notice" => &["NOTICE"],

        // Protocol Mismatch Events
        "InvalidProtocolId" => &["INVALID_PROTOCOL_ID"],
        "BadProtocolVersion" => &["BAD_PROTOCOL_VERSION"],
        "MajorVersionDiff" => &["MAJOR_VERSION_DIFF"],
        "BannerOrDispatchError" => &["BANNER_OR_DISPATCH_ERROR"],
        "SocketReadFailure" => &["SOCKET_READ_FAILURE"],

        _ => &[],
    }
}
