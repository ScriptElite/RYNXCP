use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Wire protocol revision. Bump on any breaking change to the envelopes.
pub const PROTOCOL_VERSION: u16 = 1;
/// Hard cap for a single CBOR frame (8 MiB).
pub const MAX_FRAME_LEN: usize = 8 * 1024 * 1024;
pub const DAEMON_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Envelope<T> {
    pub protocol: u16,
    pub request_id: String,
    /// Hex encoded daemon token. Never logged.
    pub auth: String,
    /// Authenticated panel user that originated the request.
    #[serde(default)]
    pub actor: String,
    pub body: T,
}

impl<T> Envelope<T> {
    pub fn new(request_id: impl Into<String>, auth: impl Into<String>, body: T) -> Self {
        Self {
            protocol: PROTOCOL_VERSION,
            request_id: request_id.into(),
            auth: auth.into(),
            actor: String::new(),
            body,
        }
    }

    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = actor.into();
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerEnvelope<T> {
    pub protocol: u16,
    pub request_id: String,
    pub result: Result<T, WireError>,
}

/// Requests accepted by `rynxd`.
///
/// Every mutation is expressed as a declarative "upsert" of the desired state
/// for a resource. The daemon reconciles the operating system towards that
/// state and records the result in the tamper-evident audit log.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Health,
    SystemInfo,

    AccountCreate(AccountSpec),
    AccountDelete {
        username: String,
        purge: bool,
    },
    AccountList,

    FileList {
        username: String,
        domain: String,
        path: String,
    },
    FileRead {
        username: String,
        domain: String,
        path: String,
    },
    FileWrite {
        username: String,
        domain: String,
        path: String,
        data: Vec<u8>,
    },
    FileMkdir {
        username: String,
        domain: String,
        path: String,
    },
    FileRename {
        username: String,
        domain: String,
        path: String,
        new_name: String,
    },
    FileDelete {
        username: String,
        domain: String,
        path: String,
        recursive: bool,
    },

    WebsiteUpsert(WebsiteSpec),
    WebsiteDelete {
        domain: String,
    },
    WebsiteClone {
        source: String,
        target: String,
        #[serde(default = "default_true")]
        with_database: bool,
    },
    WebsiteList,

    PhpPoolUpsert(PhpPoolSpec),
    PhpPoolDelete {
        username: String,
    },
    PhpPoolList,
    PhpVersions,

    AppUpsert(AppSpec),
    AppDelete {
        username: String,
        name: String,
    },
    AppList,
    InstallerApply(InstallerApplySpec),
    SshKeys {
        username: String,
    },
    SshKeyAdd {
        username: String,
        key: String,
    },
    SshKeyDelete {
        username: String,
        key: String,
    },

    CertIssue {
        domain: String,
        email: String,
        staging: bool,
    },
    CertRenew {
        #[serde(default)]
        staging: bool,
    },
    CertList,

    MailDomainUpsert(MailDomainSpec),
    MailDomainDelete {
        domain: String,
    },
    MailDomainList,
    MailTls {
        domain: String,
        email: String,
    },
    MailAccountUpsert(MailAccountSpec),
    MailAccountDelete {
        id: String,
    },
    MailAccountList,

    BackupCreate {
        username: String,
    },
    BackupList,
    BackupDelete {
        id: String,
    },
    BackupRestore {
        id: String,
    },

    CronList,
    CronUpsert(CronSpec),
    CronDelete {
        id: String,
    },

    DnsZone {
        domain: String,
    },
    DnsZoneList,
    DnsRecordUpsert(DnsRecordSpec),
    DnsRecordDelete {
        domain: String,
        id: String,
    },
    DnsMailProvision {
        domain: String,
    },

    DatabaseCreate {
        domain: String,
        name: String,
    },
    DatabaseList,
    DatabaseDelete {
        id: String,
    },

    FtpList,
    FtpCreate(FtpSpec),
    FtpDelete {
        id: String,
    },

    FirewallStatus,
    FirewallRuleUpsert(FirewallRuleSpec),
    FirewallRuleDelete {
        id: String,
    },
    FirewallBlock {
        ip: String,
        #[serde(default)]
        seconds: u32,
        #[serde(default)]
        reason: String,
    },
    FirewallUnblock {
        ip: String,
    },
    FirewallWhitelistAdd {
        ip: String,
    },
    FirewallWhitelistRemove {
        ip: String,
    },

    ServiceStats,
    Programs,
    Updates,
    ApplyUpdates,
    FilterActivity {
        #[serde(default = "default_filter_limit")]
        limit: u32,
    },
    MetricsHistory {
        #[serde(default = "default_metrics_minutes")]
        minutes: u32,
    },
    ConsoleRun {
        action: ConsoleAction,
    },

    AuditTail {
        limit: u32,
    },
    /// Re-render every managed artifact from persisted state (drift repair).
    ReconcileAll,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    Pong {
        daemon_version: String,
        mode: String,
    },
    SystemInfo {
        info: SystemInfo,
    },
    Account {
        account: AccountView,
    },
    Accounts {
        accounts: Vec<AccountView>,
    },
    Files {
        entries: Vec<FileEntry>,
        path: String,
    },
    FileData {
        data: Vec<u8>,
    },
    Website {
        website: WebsiteView,
    },
    Websites {
        websites: Vec<WebsiteView>,
    },
    PhpPool {
        pool: PhpPoolView,
    },
    PhpPools {
        pools: Vec<PhpPoolView>,
    },
    PhpVersions {
        versions: Vec<String>,
    },
    App {
        app: AppView,
    },
    Apps {
        apps: Vec<AppView>,
    },
    InstallerResult {
        message: String,
    },
    SshKeys {
        keys: Vec<String>,
    },
    Cert {
        cert: CertView,
    },
    Certs {
        certs: Vec<CertView>,
    },
    MailDomain {
        domain: MailDomainView,
    },
    MailDomains {
        domains: Vec<MailDomainView>,
    },
    MailAccount {
        account: MailAccountView,
    },
    MailAccounts {
        accounts: Vec<MailAccountView>,
    },
    Backup {
        backup: BackupView,
    },
    Backups {
        backups: Vec<BackupView>,
    },
    CronJob {
        job: CronJobView,
    },
    CronJobs {
        jobs: Vec<CronJobView>,
    },
    DnsZone {
        zone: DnsZoneView,
    },
    DnsZones {
        zones: Vec<DnsZoneView>,
    },
    Database {
        database: DatabaseView,
    },
    Databases {
        databases: Vec<DatabaseView>,
    },
    Ftp {
        account: FtpView,
    },
    Ftps {
        accounts: Vec<FtpView>,
    },
    Firewall {
        state: FirewallView,
    },
    ServiceStats {
        services: Vec<ServiceStat>,
    },
    Programs {
        programs: Vec<ProgramInfo>,
    },
    Updates {
        updates: Vec<PackageUpdate>,
    },
    UpdateResult {
        updated: u32,
        output: String,
    },
    FilterActivity {
        events: Vec<FilterEvent>,
    },
    MetricsHistory {
        samples: Vec<MetricSample>,
    },
    ConsoleOutput {
        action: String,
        output: String,
    },
    Audit {
        entries: Vec<AuditEntry>,
    },
    Ack {
        message: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Protocol,
    Unauthorized,
    InvalidInput,
    NotFound,
    Conflict,
    Unsupported,
    Io,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, thiserror::Error)]
#[error("{code:?}: {message}")]
pub struct WireError {
    pub code: ErrorCode,
    pub message: String,
}

impl WireError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidInput, message)
    }
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Conflict, message)
    }
    pub fn unauthorized() -> Self {
        Self::new(ErrorCode::Unauthorized, "authentication failed")
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, message)
    }
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unsupported, message)
    }
}

/// Language runtimes supported by the panel.
///
/// PHP is served by a dedicated FPM pool. Every other engine runs as a
/// long-lived process supervised by systemd and is reverse-proxied by Nginx.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "engine", rename_all = "snake_case")]
pub enum Runtime {
    Static,
    Php { version: String },
    Node { version: String },
    Python { version: String },
    Ruby { version: String },
    Java { version: String },
    Dotnet { version: String },
    Go,
}

impl Runtime {
    pub fn engine(&self) -> &'static str {
        match self {
            Runtime::Static => "static",
            Runtime::Php { .. } => "php",
            Runtime::Node { .. } => "node",
            Runtime::Python { .. } => "python",
            Runtime::Ruby { .. } => "ruby",
            Runtime::Java { .. } => "java",
            Runtime::Dotnet { .. } => "dotnet",
            Runtime::Go => "go",
        }
    }

    pub fn version(&self) -> Option<&str> {
        match self {
            Runtime::Static | Runtime::Go => None,
            Runtime::Php { version }
            | Runtime::Node { version }
            | Runtime::Python { version }
            | Runtime::Ruby { version }
            | Runtime::Java { version }
            | Runtime::Dotnet { version } => Some(version),
        }
    }

    pub fn is_php(&self) -> bool {
        matches!(self, Runtime::Php { .. })
    }

    pub fn is_static(&self) -> bool {
        matches!(self, Runtime::Static)
    }

    /// Managed runtimes need a backing application process listening on a port.
    pub fn is_managed(&self) -> bool {
        !self.is_php() && !self.is_static()
    }

    pub fn supports_app(&self) -> bool {
        self.is_managed()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    Disabled,
    LetsEncrypt,
    Manual,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PhpProcessManager {
    Dynamic,
    Ondemand,
    Static,
}

impl PhpProcessManager {
    pub fn as_str(&self) -> &'static str {
        match self {
            PhpProcessManager::Dynamic => "dynamic",
            PhpProcessManager::Ondemand => "ondemand",
            PhpProcessManager::Static => "static",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountSpec {
    pub username: String,
    pub email: String,
    pub disk_limit_mb: u64,
    pub php_version: Option<String>,
    pub enabled: bool,
    /// Optional interactive SSH access for the Linux account (key-based).
    #[serde(default)]
    pub ssh_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountView {
    pub id: String,
    pub spec: AccountSpec,
    pub uid: u32,
    pub home: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileEntry {
    pub name: String,
    /// `file`, `dir`, `symlink` or `other`.
    pub kind: String,
    pub size: u64,
    pub modified: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebsiteSpec {
    pub domain: String,
    pub username: String,
    pub aliases: Vec<String>,
    pub runtime: Runtime,
    /// Application name for managed runtimes (Node, Python, Ruby, Java, .NET, Go).
    pub app: Option<String>,
    /// Document root relative to the account home, e.g. `public_html`.
    pub docroot: String,
    pub tls: TlsMode,
    pub enabled: bool,
    /// Redirect plain HTTP requests to HTTPS. Defaults to true for existing sites.
    #[serde(default = "default_force_https")]
    pub force_https: bool,
    /// UI language of the creator, used for the initial welcome page.
    #[serde(default)]
    pub locale: Option<String>,
}

fn default_force_https() -> bool {
    true
}

fn default_ssh_port() -> u16 {
    22
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebsiteView {
    pub id: String,
    pub spec: WebsiteSpec,
    pub document_root: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailDomainSpec {
    pub domain: String,
    pub username: String,
    pub enabled: bool,
    #[serde(default)]
    pub catch_all: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailDomainView {
    pub domain: String,
    pub username: String,
    pub enabled: bool,
    pub catch_all: Option<String>,
    pub webmail_url: String,
    pub tls_status: CertificateStatus,
    pub tls_not_after: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailAccountSpec {
    #[serde(default)]
    pub id: Option<String>,
    pub domain: String,
    pub local_part: String,
    #[serde(default)]
    pub password: Option<String>,
    pub quota_mb: u64,
    pub enabled: bool,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub forward_to: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailAccountView {
    pub id: String,
    pub domain: String,
    pub username: String,
    pub local_part: String,
    pub address: String,
    pub quota_mb: u64,
    pub enabled: bool,
    pub aliases: Vec<String>,
    pub forward_to: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PhpPoolSpec {
    pub username: String,
    pub version: String,
    pub process_manager: PhpProcessManager,
    pub max_children: u16,
    pub memory_limit_mb: u32,
    pub upload_max_mb: u32,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PhpPoolView {
    pub username: String,
    pub spec: PhpPoolSpec,
    pub socket: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppSpec {
    pub username: String,
    pub name: String,
    pub runtime: Runtime,
    pub port: u16,
    /// Entry file or artifact, relative to the application directory.
    pub entrypoint: String,
    /// Allow-listed executable (resolved through PATH, never a shell).
    pub command: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppView {
    pub id: String,
    pub spec: AppSpec,
    pub unit: String,
    pub working_dir: String,
    pub created_at: String,
    pub updated_at: String,
}

/// One-click web application installers.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InstallerApp {
    Wordpress,
    Laravel,
}

impl InstallerApp {
    pub fn as_str(&self) -> &'static str {
        match self {
            InstallerApp::Wordpress => "wordpress",
            InstallerApp::Laravel => "laravel",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "wordpress" => Some(InstallerApp::Wordpress),
            "laravel" => Some(InstallerApp::Laravel),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstallerApplySpec {
    pub username: String,
    pub domain: String,
    pub app: InstallerApp,
    /// Document root relative to the account home, e.g. `public_html`.
    pub docroot: String,
    pub php_version: String,
    pub tls: bool,
    pub database: String,
    pub db_user: String,
    pub db_password: String,
    pub db_host: String,
    #[serde(default)]
    pub site_title: String,
    #[serde(default)]
    pub admin_user: String,
    #[serde(default)]
    pub admin_email: String,
    #[serde(default)]
    pub admin_password: String,
    pub archive_path: Option<String>,
    pub archive_sha256: Option<String>,
    #[serde(default)]
    pub archive_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CertificateStatus {
    Active,
    Expiring,
    Expired,
    Missing,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertView {
    pub domain: String,
    pub issuer: String,
    pub not_after: String,
    pub status: CertificateStatus,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupView {
    pub id: String,
    pub username: String,
    pub created_at: String,
    pub size_bytes: u64,
    pub path: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CronSpec {
    pub id: Option<String>,
    pub username: String,
    pub schedule: String,
    pub command: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CronJobView {
    pub id: String,
    pub username: String,
    pub schedule: String,
    pub command: String,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServiceStat {
    pub name: String,
    /// `app`, `php`, `nginx` or `daemon`.
    pub kind: String,
    /// `active`, `inactive`, `failed` or `unknown`.
    pub status: String,
    pub pid: u32,
    pub memory_kb: u64,
    pub cpu_percent: f32,
    pub uptime_secs: u64,
    pub unit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetricSample {
    pub at: String,
    pub at_unix: i64,
    /// Load average 1m multiplied by 100 (integer transport).
    pub load1: u32,
    pub mem_used_kb: u64,
    pub disk_used_kb: u64,
    pub services_active: u32,
    pub services_total: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProgramInfo {
    pub name: String,
    pub version: String,
    /// `web`, `runtime`, `database`, `dns`, `mail`, `security` or `panel`.
    pub kind: String,
    pub status: String,
    pub detail: String,
    /// Systemd unit used by the restart/stop controls, when the program is a service.
    #[serde(default)]
    pub unit: Option<String>,
    /// Current systemd state: active, inactive, failed, ...
    #[serde(default)]
    pub service_status: Option<String>,
}

/// One recent antivirus or antispam event collected from the host journal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FilterEvent {
    /// RFC 3339 timestamp.
    pub at: String,
    /// `antivirus` or `antispam`.
    pub kind: String,
    /// Systemd unit that emitted the event.
    pub service: String,
    /// `info`, `warn`, `error` or `alert`.
    pub severity: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageUpdate {
    pub package: String,
    pub current_version: String,
    pub candidate_version: String,
    pub security: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsRecordSpec {
    pub domain: String,
    /// Relative label: `@`, `www`, `_dmarc`, `mail._domainkey`, ...
    pub name: String,
    /// A, AAAA, CNAME, MX, TXT, NS, SRV or CAA.
    pub rtype: String,
    pub value: String,
    pub ttl: u32,
    #[serde(default)]
    pub priority: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsRecordView {
    pub id: String,
    pub spec: DnsRecordSpec,
    pub managed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsZoneView {
    pub domain: String,
    pub records: Vec<DnsRecordView>,
    pub zone_file: String,
    pub serial: u32,
    pub nameservers: Vec<String>,
    pub mail_ready: bool,
    pub dkim_selector: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DatabaseView {
    pub id: String,
    pub domain: String,
    pub username: String,
    pub password: String,
    pub engine: String,
    pub host: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FtpSpec {
    pub domain: String,
    pub username: String,
    /// Optional password. When absent the daemon generates one.
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub readonly: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FtpView {
    pub id: String,
    pub domain: String,
    /// Pure-FTPd login (globally unique).
    pub login: String,
    pub home: String,
    pub readonly: bool,
    pub password: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallRuleSpec {
    /// Existing rule id when updating.
    #[serde(default)]
    pub id: Option<String>,
    /// `allow` or `deny`.
    pub action: String,
    /// `tcp`, `udp` or `any`.
    pub proto: String,
    pub port: u16,
    /// Optional source IP or CIDR.
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub comment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallRuleView {
    pub id: String,
    pub spec: FirewallRuleSpec,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockedIpView {
    pub ip: String,
    pub reason: String,
    /// `manual`, `brute-force` or `fail2ban`.
    pub source: String,
    pub expires_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallView {
    pub enabled: bool,
    pub backend: String,
    pub rules: Vec<FirewallRuleView>,
    pub blocked: Vec<BlockedIpView>,
    pub whitelist: Vec<String>,
    pub ssh_port: u16,
}

/// Admin console actions. The set is closed on purpose: the daemon never
/// executes arbitrary shell strings. Every variant maps to a fixed argv, and
/// any user-supplied identifiers are validated against persisted state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ConsoleAction {
    NginxTest,
    NginxReload,
    Services,
    DiskUsage,
    Reconcile,
    CertRenew,
    BackupAll,
    PhpReload {
        version: String,
    },
    AppRestart {
        username: String,
        name: String,
    },
    AppLogs {
        username: String,
        name: String,
        #[serde(default = "default_log_lines")]
        lines: u32,
    },
    ServiceRestart {
        program: String,
    },
    ServiceStop {
        program: String,
    },
}

impl ConsoleAction {
    pub fn label(&self) -> String {
        match self {
            ConsoleAction::NginxTest => "nginx_test".into(),
            ConsoleAction::NginxReload => "nginx_reload".into(),
            ConsoleAction::Services => "services".into(),
            ConsoleAction::DiskUsage => "disk_usage".into(),
            ConsoleAction::Reconcile => "reconcile".into(),
            ConsoleAction::CertRenew => "cert_renew".into(),
            ConsoleAction::BackupAll => "backup_all".into(),
            ConsoleAction::PhpReload { version } => format!("php_reload:{version}"),
            ConsoleAction::AppRestart { username, name } => {
                format!("app_restart:{username}/{name}")
            }
            ConsoleAction::AppLogs { username, name, .. } => {
                format!("app_logs:{username}/{name}")
            }
            ConsoleAction::ServiceRestart { program } => format!("service_restart:{program}"),
            ConsoleAction::ServiceStop { program } => format!("service_stop:{program}"),
        }
    }
}

fn default_filter_limit() -> u32 {
    200
}

fn default_metrics_minutes() -> u32 {
    1440
}

fn default_log_lines() -> u32 {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SystemInfo {
    pub hostname: String,
    /// Public address advertised to users (for SSH, DNS hints, etc.).
    #[serde(default)]
    pub primary_ip: Option<String>,
    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16,
    pub os: String,
    pub kernel: String,
    pub uptime_secs: u64,
    pub load: [u32; 3],
    pub cpu_count: u32,
    pub mem_total_kb: u64,
    pub mem_available_kb: u64,
    pub disk_total_kb: u64,
    pub disk_available_kb: u64,
    pub daemon_version: String,
    pub mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEntry {
    pub seq: i64,
    pub at: String,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub detail: String,
    pub prev_hash: String,
    pub hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip_is_stable() {
        let req = Request::WebsiteUpsert(WebsiteSpec {
            domain: "example.com".into(),
            username: "acme".into(),
            aliases: vec!["www.example.com".into()],
            runtime: Runtime::Node {
                version: "22".into(),
            },
            app: Some("web".into()),
            docroot: "public_html".into(),
            tls: TlsMode::LetsEncrypt,
            enabled: true,
            force_https: true,
            locale: Some("es".into()),
        });
        let bytes = crate::encode(&req).unwrap();
        let back: Request = crate::decode(&bytes).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn runtime_classification() {
        assert!(Runtime::Php {
            version: "8.3".into()
        }
        .is_php());
        assert!(Runtime::Go.is_managed());
        assert!(!Runtime::Static.is_managed());
        assert_eq!(
            Runtime::Dotnet {
                version: "9".into()
            }
            .engine(),
            "dotnet"
        );
    }
}
