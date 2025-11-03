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
            ("INCORRECT_PASSWORD", Regex::new(r"^(\S+)\s+:\s+(\d+)\s+incorrect password attempt ; TTY=(\S+) ; PWD=(\S+) ; USER=(\S+) ; COMMAND=(\S+)$").unwrap()),
            ("NOT_IN_SUDOERS", Regex::new(r"(?x)^\s*(?P<user>\S+)\s+is\s+not\s+in\s+the\s+sudoers\s+file").unwrap()),
            ("AUTH_ERROR", Regex::new(r"(?x)pam_unix\(sudo:auth\):\s+(?P<msg>.+?)(?:\s+\[ (?P<user>\w+) \])?\s*$").unwrap()),
            ("SUDO_WARNING", Regex::new(r"(?x)^sudo:\s+(?P<msg>.+)$").unwrap()),
        ]
});

pub static LOGIN_REGEXES: Lazy<Vec<(&str, Regex)>> = Lazy::new(|| {
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
        // FIREWALLD
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
        "FirewalldWarning" => &["WARNING"],
        "FirewalldError" => &["ERROR"],
        "FirewalldInfo" => &["INFO"],
        "FirewalldUnknown" => &["UNKNOWN"],
        _ => &[],
    }
}
