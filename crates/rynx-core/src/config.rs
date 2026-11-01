use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::CoreResult;

fn sim_root() -> PathBuf {
    std::env::var_os("RYNXCP_SIM_ROOT")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("PROGRAMDATA").map(|p| PathBuf::from(p).join("RYNXCP")))
        .unwrap_or_else(std::env::temp_dir)
        .join("sim")
}

fn default_token_file() -> PathBuf {
    if cfg!(windows) {
        sim_root().join("daemon.token")
    } else {
        PathBuf::from("/etc/rynxcp/daemon.token")
    }
}

/// Configuration for the privileged daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DaemonConfig {
    /// Unix domain socket used by the API (ignored on Windows).
    pub socket_path: PathBuf,
    /// Optional TCP listener for local development only. Never expose remotely.
    pub tcp_listen: Option<String>,
    pub state_dir: PathBuf,
    pub token: Option<String>,
    pub token_file: PathBuf,
    pub audit_log: PathBuf,
    pub nginx_sites_dir: PathBuf,
    pub nginx_enabled_dir: PathBuf,
    pub nginx_main_config: PathBuf,
    pub nginx_test_args: String,
    pub php_fpm_root: PathBuf,
    pub php_socket_dir: PathBuf,
    pub systemd_dir: PathBuf,
    pub home_root: PathBuf,
    pub apps_root: PathBuf,
    pub app_env_dir: PathBuf,
    pub webroot_root: PathBuf,
    pub acme_root: PathBuf,
    pub certs_root: PathBuf,
    pub certbot_bin: String,
    pub tls_email: Option<String>,
    /// Never touch the real operating system. Used for local development.
    pub simulate: bool,
    /// UID range reserved for hosting accounts.
    pub uid_min: u32,
    pub uid_max: u32,
    /// Unix group allowed to talk to the daemon socket.
    pub socket_group: String,
    /// Directories that may be written by reconciliation (defense in depth).
    pub managed_roots: Vec<PathBuf>,
    /// Where account backups are stored.
    pub backup_dir: PathBuf,
    /// Number of backups kept per account before rotating the oldest.
    pub backup_retention: usize,
    /// Shared directory where the API stages verified installer archives.
    pub installer_staging: PathBuf,
    /// Encrypted offsite copies through restic (S3, B2, SFTP, ...).
    pub offsite_enabled: bool,
    pub offsite_repository: String,
    pub offsite_password_file: Option<PathBuf>,
    pub restic_bin: String,
    /// Per-account resource limits enforced by the reconciler.
    pub max_websites_per_account: usize,
    pub max_apps_per_account: usize,

    pub dns_enabled: bool,
    pub bind_zones_dir: PathBuf,
    pub bind_conf_file: PathBuf,
    pub bind_checkzone_bin: String,
    pub bind_reload_unit: String,
    /// Public nameservers announced in every zone.
    pub dns_nameservers: Vec<String>,
    pub default_ipv4: Option<String>,
    pub default_ipv6: Option<String>,

    pub mail_enabled: bool,
    pub mail_hostname: Option<String>,
    pub dkim_selector: String,
    pub dkim_key_dir: PathBuf,
    pub opendkim_keytable: Option<PathBuf>,
    pub opendkim_signingtable: Option<PathBuf>,

    pub db_enabled: bool,
    pub mysql_bin: String,

    pub ftp_enabled: bool,
    pub pure_pw_bin: String,
    pub pure_pdb: PathBuf,
    pub pure_passwd: PathBuf,
    pub pure_ftpd_unit: String,
    pub ftp_readonly_user: String,

    pub firewall_enabled: bool,
    pub firewall_backend: String,
    pub firewall_ssh_port: u16,
    /// TCP port where the panel vhost is published. Kept open in the default
    /// nftables rules when it is not 80/443.
    pub panel_port: u16,
    pub nft_bin: String,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        if cfg!(windows) {
            let root = sim_root();
            Self {
                socket_path: root.join("rynxd.sock"),
                tcp_listen: Some("127.0.0.1:7801".into()),
                state_dir: root.join("daemon"),
                token: None,
                token_file: default_token_file(),
                audit_log: root.join("audit.log"),
                nginx_sites_dir: root.join("nginx/sites-available"),
                nginx_enabled_dir: root.join("nginx/sites-enabled"),
                nginx_main_config: root.join("nginx/nginx.conf"),
                nginx_test_args: "-t".into(),
                php_fpm_root: root.join("php"),
                php_socket_dir: root.join("php/run"),
                systemd_dir: root.join("systemd"),
                home_root: root.join("home"),
                apps_root: root.join("apps"),
                app_env_dir: root.join("apps-env"),
                webroot_root: root.join("www"),
                acme_root: root.join("www/_acme"),
                certs_root: root.join("certs"),
                certbot_bin: "certbot".into(),
                tls_email: None,
                simulate: true,
                uid_min: 2000,
                uid_max: 60000,
                socket_group: "rynx".into(),
                managed_roots: vec![root.clone()],
                backup_dir: root.join("backups"),
                backup_retention: 7,
                installer_staging: root.join("installer-staging"),
                offsite_enabled: false,
                offsite_repository: String::new(),
                offsite_password_file: None,
                restic_bin: "restic".into(),
                max_websites_per_account: 50,
                max_apps_per_account: 20,
                dns_enabled: true,
                bind_zones_dir: root.join("bind/zones"),
                bind_conf_file: root.join("bind/named.conf.rynxcp"),
                bind_checkzone_bin: "named-checkzone".into(),
                bind_reload_unit: "bind9".into(),
                dns_nameservers: vec!["ns1.example.com".into(), "ns2.example.com".into()],
                default_ipv4: Some("203.0.113.10".into()),
                default_ipv6: None,
                mail_enabled: true,
                mail_hostname: Some("mail.example.com".into()),
                dkim_selector: "mail".into(),
                dkim_key_dir: root.join("opendkim/keys"),
                opendkim_keytable: Some(root.join("opendkim/KeyTable")),
                opendkim_signingtable: Some(root.join("opendkim/SigningTable")),
                db_enabled: true,
                mysql_bin: "mysql".into(),
                ftp_enabled: true,
                pure_pw_bin: "pure-pw".into(),
                pure_pdb: root.join("pure-ftpd/pureftpd.pdb"),
                pure_passwd: root.join("pure-ftpd/pureftpd.passwd"),
                pure_ftpd_unit: "pure-ftpd".into(),
                ftp_readonly_user: "rynxftp".into(),
                firewall_enabled: true,
                firewall_backend: "sim".into(),
                firewall_ssh_port: 22,
                panel_port: 2083,
                nft_bin: "nft".into(),
            }
        } else {
            Self {
                socket_path: PathBuf::from("/run/rynxcp/rynxd.sock"),
                tcp_listen: None,
                state_dir: PathBuf::from("/var/lib/rynxcp/rynxd"),
                token: None,
                token_file: default_token_file(),
                audit_log: PathBuf::from("/var/log/rynxcp/audit.log"),
                nginx_sites_dir: PathBuf::from("/etc/nginx/sites-available/rynxcp"),
                nginx_enabled_dir: PathBuf::from("/etc/nginx/sites-enabled"),
                nginx_main_config: PathBuf::from("/etc/nginx/nginx.conf"),
                nginx_test_args: "-t".into(),
                php_fpm_root: PathBuf::from("/etc/php"),
                php_socket_dir: PathBuf::from("/run/php"),
                systemd_dir: PathBuf::from("/etc/systemd/system"),
                home_root: PathBuf::from("/home"),
                apps_root: PathBuf::from("/var/lib/rynxcp/apps"),
                app_env_dir: PathBuf::from("/etc/rynxcp/apps"),
                webroot_root: PathBuf::from("/var/www"),
                acme_root: PathBuf::from("/var/www/_acme"),
                certs_root: PathBuf::from("/etc/letsencrypt/live"),
                certbot_bin: "certbot".into(),
                tls_email: None,
                simulate: false,
                uid_min: 2000,
                uid_max: 60000,
                socket_group: "rynx".into(),
                managed_roots: vec![
                    PathBuf::from("/etc/nginx"),
                    PathBuf::from("/etc/php"),
                    PathBuf::from("/etc/systemd/system"),
                    PathBuf::from("/etc/rynxcp"),
                    PathBuf::from("/var/lib/rynxcp"),
                    PathBuf::from("/var/www"),
                    PathBuf::from("/home"),
                    PathBuf::from("/run/php"),
                    PathBuf::from("/etc/letsencrypt"),
                ],
                backup_dir: PathBuf::from("/var/backups/rynxcp"),
                backup_retention: 7,
                installer_staging: PathBuf::from("/var/lib/rynxcp/staging"),
                offsite_enabled: false,
                offsite_repository: String::new(),
                offsite_password_file: None,
                restic_bin: "restic".into(),
                max_websites_per_account: 50,
                max_apps_per_account: 20,
                dns_enabled: false,
                bind_zones_dir: PathBuf::from("/etc/bind/zones"),
                bind_conf_file: PathBuf::from("/etc/bind/named.conf.rynxcp"),
                bind_checkzone_bin: "named-checkzone".into(),
                bind_reload_unit: "bind9".into(),
                dns_nameservers: Vec::new(),
                default_ipv4: None,
                default_ipv6: None,
                mail_enabled: false,
                mail_hostname: None,
                dkim_selector: "mail".into(),
                dkim_key_dir: PathBuf::from("/etc/opendkim/keys"),
                opendkim_keytable: Some(PathBuf::from("/etc/opendkim/KeyTable")),
                opendkim_signingtable: Some(PathBuf::from("/etc/opendkim/SigningTable")),
                db_enabled: false,
                mysql_bin: "mysql".into(),
                ftp_enabled: false,
                pure_pw_bin: "pure-pw".into(),
                pure_pdb: PathBuf::from("/etc/pure-ftpd/pureftpd.pdb"),
                pure_passwd: PathBuf::from("/etc/pure-ftpd/pureftpd.passwd"),
                pure_ftpd_unit: "pure-ftpd".into(),
                ftp_readonly_user: "rynxftp".into(),
                firewall_enabled: false,
                firewall_backend: "nftables".into(),
                firewall_ssh_port: 22,
                panel_port: 2083,
                nft_bin: "nft".into(),
            }
        }
    }
}

impl DaemonConfig {
    /// Redirect every managed path into a disposable sandbox. Used whenever
    /// `simulate` is enabled, even on Linux, so development never touches the
    /// real system.
    pub fn sandboxed(mut self) -> Self {
        if !self.simulate {
            return self;
        }
        let root = self.state_dir.join("sandbox");
        self.socket_path = root.join("run/rynxd.sock");
        self.audit_log = root.join("log/audit.log");
        self.nginx_sites_dir = root.join("nginx/sites-available");
        self.nginx_enabled_dir = root.join("nginx/sites-enabled");
        self.nginx_main_config = root.join("nginx/nginx.conf");
        self.php_fpm_root = root.join("php");
        self.php_socket_dir = root.join("php/run");
        self.systemd_dir = root.join("systemd");
        self.home_root = root.join("home");
        self.apps_root = root.join("apps-data");
        self.app_env_dir = root.join("apps-env");
        self.webroot_root = root.join("www");
        self.acme_root = root.join("www/_acme");
        self.certs_root = root.join("certs");
        self.backup_dir = root.join("backups");
        self.bind_zones_dir = root.join("bind/zones");
        self.bind_conf_file = root.join("bind/named.conf.rynxcp");
        self.dkim_key_dir = root.join("opendkim/keys");
        self.opendkim_keytable = Some(root.join("opendkim/KeyTable"));
        self.opendkim_signingtable = Some(root.join("opendkim/SigningTable"));
        self.pure_pdb = root.join("pure-ftpd/pureftpd.pdb");
        self.pure_passwd = root.join("pure-ftpd/pureftpd.passwd");
        self.managed_roots = vec![root];
        self
    }

    pub fn load(path: &Path) -> CoreResult<Self> {
        let mut cfg = if path.exists() {
            let raw = std::fs::read_to_string(path)
                .map_err(|e| crate::CoreError::Config(format!("{}: {e}", path.display())))?;
            toml::from_str(&raw)
                .map_err(|e| crate::CoreError::Config(format!("{}: {e}", path.display())))?
        } else {
            DaemonConfig::default()
        };

        if let Ok(v) = std::env::var("RYNXCP_SOCKET") {
            cfg.socket_path = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("RYNXCP_STATE_DIR") {
            cfg.state_dir = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("RYNXCP_TOKEN") {
            if !v.is_empty() {
                cfg.token = Some(v);
            }
        }
        if let Ok(v) = std::env::var("RYNXCP_SIMULATE") {
            cfg.simulate = matches!(v.as_str(), "1" | "true" | "yes");
            if cfg.simulate && cfg.tcp_listen.is_none() {
                cfg.tcp_listen = Some("127.0.0.1:7801".into());
            }
        }
        Ok(cfg)
    }
}

/// Deterministic system analyzer with optional LLM assistance.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    /// Run the analyzer in the background.
    pub enabled: bool,
    /// Seconds between background analyses.
    pub interval_secs: u64,
    /// Maximum journal events inspected per run.
    pub max_events: u32,
    /// Email high and critical findings to `smtp_alert_to`.
    pub email_alerts: bool,
    /// `rules` today; `local` and `hybrid` reserve the optional LLM providers.
    pub mode: String,
    /// OpenAI-compatible endpoint for a local model (Ollama, llama.cpp).
    pub local_base_url: String,
    pub local_model: String,
    pub local_timeout_secs: u64,
    /// External providers stay disabled until an administrator opts in.
    pub external_enabled: bool,
    pub external_base_url: String,
    pub external_model: String,
    pub external_api_key_env: String,
    pub external_timeout_secs: u64,
    pub external_max_tokens: u32,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 300,
            max_events: 200,
            email_alerts: true,
            mode: "rules".into(),
            local_base_url: "http://127.0.0.1:11434/v1".into(),
            local_model: "qwen3:8b".into(),
            local_timeout_secs: 120,
            external_enabled: false,
            external_base_url: String::new(),
            external_model: String::new(),
            external_api_key_env: "RYNXCP_AGENT_API_KEY".into(),
            external_timeout_secs: 120,
            external_max_tokens: 1200,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ApiConfig {
    pub bind: String,
    pub database: PathBuf,
    pub web_root: PathBuf,
    pub daemon_socket: PathBuf,
    pub daemon_tcp: Option<String>,
    pub daemon_token: Option<String>,
    pub daemon_token_file: PathBuf,
    pub secure_cookies: bool,
    pub session_ttl_secs: i64,
    pub login_max_attempts: u32,
    pub login_window_secs: u64,
    pub login_ip_max_attempts: u32,
    pub login_lockout_secs: u64,
    pub auth_log: PathBuf,
    /// Shared directory where installer archives are staged for the daemon.
    pub installer_staging: PathBuf,
    pub password_min_len: usize,
    pub password_min_classes: u8,
    pub session_idle_secs: i64,
    pub trust_proxy_headers: bool,
    pub public_url: Option<String>,
    /// Outbound transactional email for the panel. The default targets a local
    /// Postfix instance over loopback, so no credentials or TLS are needed.
    pub smtp_enabled: bool,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_from: Option<String>,
    pub smtp_alert_to: Option<String>,
    /// Only `none` is supported; TLS is provided by the local SMTP hop or a
    /// future relay implementation.
    pub smtp_tls: String,
    pub log_level: String,
    pub agent: AgentConfig,
}

impl Default for ApiConfig {
    fn default() -> Self {
        if cfg!(windows) {
            let root = sim_root();
            Self {
                bind: "127.0.0.1:8080".into(),
                database: root.join("panel.db"),
                web_root: PathBuf::from("web"),
                daemon_socket: root.join("rynxd.sock"),
                daemon_tcp: Some("127.0.0.1:7801".into()),
                daemon_token: None,
                daemon_token_file: default_token_file(),
                secure_cookies: false,
                session_ttl_secs: 8 * 60 * 60,
                login_max_attempts: 8,
                login_window_secs: 300,
                login_ip_max_attempts: 30,
                login_lockout_secs: 900,
                auth_log: root.join("auth.log"),
                installer_staging: root.join("installer-staging"),
                password_min_len: 12,
                password_min_classes: 3,
                session_idle_secs: 3600,
                trust_proxy_headers: false,
                public_url: None,
                smtp_enabled: false,
                smtp_host: "127.0.0.1".into(),
                smtp_port: 25,
                smtp_from: None,
                smtp_alert_to: None,
                smtp_tls: "none".into(),
                log_level: "info,tower_http=info".into(),
                agent: AgentConfig::default(),
            }
        } else {
            Self {
                bind: "127.0.0.1:8080".into(),
                database: PathBuf::from("/var/lib/rynxcp/panel/panel.db"),
                web_root: PathBuf::from("/usr/share/rynxcp/web"),
                daemon_socket: PathBuf::from("/run/rynxcp/rynxd.sock"),
                daemon_tcp: None,
                daemon_token: None,
                daemon_token_file: default_token_file(),
                secure_cookies: true,
                session_ttl_secs: 8 * 60 * 60,
                login_max_attempts: 8,
                login_window_secs: 300,
                login_ip_max_attempts: 30,
                login_lockout_secs: 900,
                auth_log: PathBuf::from("/var/log/rynxcp/auth.log"),
                installer_staging: PathBuf::from("/var/lib/rynxcp/staging"),
                password_min_len: 12,
                password_min_classes: 3,
                session_idle_secs: 3600,
                trust_proxy_headers: false,
                public_url: None,
                smtp_enabled: false,
                smtp_host: "127.0.0.1".into(),
                smtp_port: 25,
                smtp_from: None,
                smtp_alert_to: None,
                smtp_tls: "none".into(),
                log_level: "info,tower_http=info".into(),
                agent: AgentConfig::default(),
            }
        }
    }
}

impl ApiConfig {
    pub fn load(path: &Path) -> CoreResult<Self> {
        let mut cfg = if path.exists() {
            let raw = std::fs::read_to_string(path)
                .map_err(|e| crate::CoreError::Config(format!("{}: {e}", path.display())))?;
            toml::from_str(&raw)
                .map_err(|e| crate::CoreError::Config(format!("{}: {e}", path.display())))?
        } else {
            ApiConfig::default()
        };

        if let Ok(v) = std::env::var("RYNXCP_BIND") {
            cfg.bind = v;
        }
        if let Ok(v) = std::env::var("RYNXCP_DATABASE") {
            cfg.database = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("RYNXCP_WEB_ROOT") {
            cfg.web_root = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("RYNXCP_DAEMON_SOCKET") {
            cfg.daemon_socket = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("RYNXCP_DAEMON_TCP") {
            cfg.daemon_tcp = Some(v);
        }
        if let Ok(v) = std::env::var("RYNXCP_DAEMON_TOKEN") {
            if !v.is_empty() {
                cfg.daemon_token = Some(v);
            }
        }
        if let Ok(v) = std::env::var("RYNXCP_SECURE_COOKIES") {
            cfg.secure_cookies = matches!(v.as_str(), "1" | "true" | "yes");
        }
        if let Ok(v) = std::env::var("RYNXCP_LOG") {
            cfg.log_level = v;
        }
        if let Ok(v) = std::env::var("RYNXCP_AUTH_LOG") {
            cfg.auth_log = PathBuf::from(v);
        }
        Ok(cfg)
    }
}

/// Reject dangerous configuration before the daemon starts.
pub fn validate_daemon_config(cfg: &DaemonConfig) -> CoreResult<()> {
    if cfg.simulate {
        return Ok(());
    }
    if cfg.uid_min >= cfg.uid_max {
        return Err(crate::CoreError::Config("uid_min must be < uid_max".into()));
    }
    if cfg.uid_min < 1000 {
        return Err(crate::CoreError::Config(
            "refusing uid_min below 1000 (system accounts)".into(),
        ));
    }
    if cfg.socket_group.trim().is_empty() {
        return Err(crate::CoreError::Config("socket_group is required".into()));
    }
    if cfg.firewall_ssh_port == 0 {
        return Err(crate::CoreError::Config(
            "firewall_ssh_port must be between 1 and 65535".into(),
        ));
    }
    if cfg.panel_port == 0 {
        return Err(crate::CoreError::Config(
            "panel_port must be between 1 and 65535".into(),
        ));
    }
    if cfg.backup_retention == 0 {
        return Err(crate::CoreError::Config(
            "backup_retention must be at least 1".into(),
        ));
    }
    if cfg.max_websites_per_account == 0 || cfg.max_apps_per_account == 0 {
        return Err(crate::CoreError::Config(
            "per-account resource limits must be greater than zero".into(),
        ));
    }
    if cfg.mail_enabled && cfg.mail_hostname.is_none() {
        return Err(crate::CoreError::Config(
            "mail_enabled requires mail_hostname".into(),
        ));
    }
    if let Some(ipv4) = &cfg.default_ipv4 {
        if ipv4.parse::<std::net::Ipv4Addr>().is_err() {
            return Err(crate::CoreError::Config(
                "default_ipv4 must be a valid IPv4 address".into(),
            ));
        }
    }
    if let Some(ipv6) = &cfg.default_ipv6 {
        if ipv6.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(crate::CoreError::Config(
                "default_ipv6 must be a valid IPv6 address".into(),
            ));
        }
    }
    if !matches!(cfg.firewall_backend.as_str(), "sim" | "nftables") {
        return Err(crate::CoreError::Config(
            "firewall_backend must be sim or nftables".into(),
        ));
    }
    Ok(())
}
