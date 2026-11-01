use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use once_cell::sync::OnceCell;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use rynx_core::crypto::{now_rfc3339, now_unix, random_hex, sha256_hex};
use rynx_core::{validate_email, validate_panel_username, PasswordPolicy};

use crate::packages::{
    default_package, normalize_and_validate, AccountPackageView, PackageInput, PackageView,
    WEB_BACKENDS,
};
use crate::role::Role;

pub const SESSION_COOKIE: &str = "rynx_session";
pub const CSRF_HEADER: &str = "x-csrf-token";
pub const MIN_PASSWORD_LEN: usize = 12;

const SCHEMA: &str = r#"
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS panel_users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    email         TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL,
    active        INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    account       TEXT,
    locale        TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash  TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES panel_users(id) ON DELETE CASCADE,
    csrf_token  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    ip          TEXT NOT NULL DEFAULT '',
    user_agent  TEXT NOT NULL DEFAULT '',
    impersonated_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS api_tokens (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES panel_users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    created_at   TEXT NOT NULL,
    last_used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id);

CREATE TABLE IF NOT EXISTS webhooks (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES panel_users(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    url        TEXT NOT NULL,
    secret     TEXT NOT NULL,
    events     TEXT NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_webhooks_user ON webhooks(user_id);

CREATE TABLE IF NOT EXISTS passkeys (
    id             TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL REFERENCES panel_users(id) ON DELETE CASCADE,
    name           TEXT NOT NULL,
    credential_id  TEXT NOT NULL UNIQUE,
    credential     TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    last_used_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_passkeys_user ON passkeys(user_id);

CREATE TABLE IF NOT EXISTS password_resets (
    token_hash  TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES panel_users(id) ON DELETE CASCADE,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_password_resets_user ON password_resets(user_id);
CREATE INDEX IF NOT EXISTS idx_password_resets_expiry ON password_resets(expires_at);

CREATE TABLE IF NOT EXISTS panel_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    at         TEXT NOT NULL,
    at_unix    INTEGER NOT NULL,
    username   TEXT NOT NULL,
    ip         TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    outcome    TEXT NOT NULL,
    reason     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_events_at ON auth_events(at_unix);
CREATE INDEX IF NOT EXISTS idx_auth_events_outcome ON auth_events(outcome, at_unix);

CREATE TABLE IF NOT EXISTS packages (
    id                 TEXT PRIMARY KEY,
    name               TEXT NOT NULL,
    is_default         INTEGER NOT NULL DEFAULT 0,
    account_mb         INTEGER NOT NULL DEFAULT 0,
    bandwidth_mb       INTEGER NOT NULL DEFAULT 0,
    backups            INTEGER NOT NULL DEFAULT 3,
    incremental_backup INTEGER NOT NULL DEFAULT 0,
    web_domains        INTEGER NOT NULL DEFAULT 0,
    web_aliases        INTEGER NOT NULL DEFAULT 0,
    web_backend        TEXT NOT NULL DEFAULT 'php',
    nginx_template     TEXT NOT NULL DEFAULT 'hosting',
    dns_template       TEXT NOT NULL DEFAULT 'child-ns',
    dns_zones          INTEGER NOT NULL DEFAULT 0,
    dns_records        INTEGER NOT NULL DEFAULT 0,
    nameservers        TEXT NOT NULL DEFAULT '["ns1.example.tld","ns2.example.tld"]',
    mail_domains       INTEGER NOT NULL DEFAULT 0,
    mail_accounts      INTEGER NOT NULL DEFAULT 0,
    mail_rate_limit    INTEGER NOT NULL DEFAULT 0,
    databases          INTEGER NOT NULL DEFAULT 0,
    system_databases   INTEGER NOT NULL DEFAULT 0,
    ftp_accounts       INTEGER NOT NULL DEFAULT 0,
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    memory_mb          INTEGER NOT NULL DEFAULT 0,
    cpu_percent        INTEGER NOT NULL DEFAULT 0,
    process_limit      INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_packages_name_lower ON packages(lower(name));
CREATE UNIQUE INDEX IF NOT EXISTS idx_packages_default ON packages(is_default) WHERE is_default = 1;

CREATE TABLE IF NOT EXISTS account_packages (
    account     TEXT PRIMARY KEY,
    package_id  TEXT NOT NULL REFERENCES packages(id) ON DELETE RESTRICT,
    web_backend TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_account_packages_package ON account_packages(package_id);

CREATE TABLE IF NOT EXISTS agent_findings (
    id             TEXT PRIMARY KEY,
    fingerprint    TEXT NOT NULL UNIQUE,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    first_seen     INTEGER NOT NULL,
    last_seen      INTEGER NOT NULL,
    occurrences    INTEGER NOT NULL DEFAULT 1,
    severity       TEXT NOT NULL,
    category       TEXT NOT NULL,
    title          TEXT NOT NULL,
    summary        TEXT NOT NULL,
    evidence       TEXT NOT NULL DEFAULT '[]',
    recommendation TEXT NOT NULL DEFAULT '',
    source         TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'open'
);
CREATE INDEX IF NOT EXISTS idx_agent_findings_status ON agent_findings(status, last_seen);
CREATE INDEX IF NOT EXISTS idx_agent_findings_severity ON agent_findings(severity, last_seen);

CREATE TABLE IF NOT EXISTS agent_runs (
    id         TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    status     TEXT NOT NULL,
    findings   INTEGER NOT NULL DEFAULT 0,
    error      TEXT NOT NULL DEFAULT '',
    model      TEXT NOT NULL DEFAULT '',
    summary    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_agent_runs_started ON agent_runs(started_at);
"#;

#[derive(Debug, thiserror::Error)]
pub enum PanelError {
    #[error("database error: {0}")]
    Db(String),
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("validation: {0}")]
    Validation(String),
    #[error("cryptographic error: {0}")]
    Crypto(String),
}

impl From<rusqlite::Error> for PanelError {
    fn from(value: rusqlite::Error) -> Self {
        PanelError::Db(value.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserView {
    pub id: String,
    pub username: String,
    pub email: String,
    pub role: Role,
    pub active: bool,
    pub created_at: String,
    pub updated_at: String,
    /// Hosting account linked to this panel user, when it was auto-created.
    pub account: Option<String>,
    /// Preferred panel/email language.
    pub locale: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiTokenView {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebhookView {
    pub id: String,
    pub name: String,
    pub url: String,
    pub events: Vec<String>,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct WebhookTarget {
    pub url: String,
    pub secret: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PasskeyView {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StoredPasskey {
    pub id: String,
    pub credential_id: String,
    pub credential: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionView {
    pub id: String,
    pub created_at: String,
    pub last_seen: i64,
    pub ip: String,
    pub user_agent: String,
}

#[derive(Debug, Clone)]
pub struct SessionContext {
    pub user: UserView,
    pub csrf_token: String,
    pub expires_at: i64,
    pub impersonated_by: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NewSession {
    pub token: String,
    pub csrf_token: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthEventView {
    pub id: i64,
    pub at: String,
    pub at_unix: i64,
    pub username: String,
    pub ip: String,
    pub user_agent: String,
    pub outcome: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthStats {
    pub window_secs: i64,
    pub successes: i64,
    pub failures: i64,
    pub blocked: i64,
    pub unique_ips: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentFinding {
    pub id: String,
    pub fingerprint: String,
    pub created_at: String,
    pub updated_at: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub occurrences: i64,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub summary: String,
    pub evidence: Vec<String>,
    pub recommendation: String,
    pub source: String,
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct AgentFindingInput {
    pub fingerprint: String,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub summary: String,
    pub evidence: Vec<String>,
    pub recommendation: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRun {
    pub id: String,
    pub started_at: String,
    pub finished_at: String,
    pub status: String,
    pub findings: i64,
    pub error: String,
    pub model: String,
    pub summary: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentStats {
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub info: i64,
    pub open: i64,
    pub acknowledged: i64,
    pub ignored: i64,
    pub resolved: i64,
}

struct UserRecord {
    view: UserView,
    password_hash: String,
}

pub struct PanelDb {
    path: PathBuf,
}

static DUMMY_HASH: OnceCell<String> = OnceCell::new();

fn dummy_hash() -> &'static str {
    DUMMY_HASH.get_or_init(|| {
        hash_password("rynx-dummy-password-not-used")
            .unwrap_or_else(|_| "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$Zm9vYmFy".into())
    })
}

fn hash_password(password: &str) -> Result<String, PanelError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| PanelError::Crypto(e.to_string()))
}

fn verify_password(password: &str, encoded: &str) -> bool {
    match PasswordHash::new(encoded) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

pub fn validate_password_with(
    policy: &PasswordPolicy,
    password: &str,
    username: &str,
    email: &str,
) -> Result<(), PanelError> {
    policy
        .validate(password, username, email)
        .map_err(|e| PanelError::Validation(e.to_string()))
}

pub fn validate_password(password: &str) -> Result<(), PanelError> {
    let policy = PasswordPolicy::default();
    validate_password_with(&policy, password, "", "")
}

fn map_user(row: &rusqlite::Row<'_>) -> rusqlite::Result<UserView> {
    let role_raw: String = row.get(3)?;
    let role = Role::parse(&role_raw).unwrap_or(Role::Viewer);
    Ok(UserView {
        id: row.get(0)?,
        username: row.get(1)?,
        email: row.get(2)?,
        role,
        active: row.get::<_, i64>(4)? != 0,
        created_at: row.get(5)?,
        updated_at: row.get(6)?,
        account: row.get(7)?,
        locale: row.get(8)?,
    })
}

/// Keeps database upgrades working when an older build allowed duplicate
/// emails. The first row keeps the address; later duplicates get a `+dupN`
/// suffix so the unique index can be created. Affected users can edit it later.
fn deduplicate_panel_emails(conn: &Connection) -> Result<(), PanelError> {
    let mut stmt = conn.prepare("SELECT rowid, email FROM panel_users ORDER BY rowid")?;
    let rows: Vec<(i64, String)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<_, _>>()?;
    drop(stmt);
    let mut seen = HashSet::new();
    for (rowid, email) in rows {
        if seen.insert(email.to_ascii_lowercase()) {
            continue;
        }
        let (local, domain) = email.split_once('@').unwrap_or((email.as_str(), "invalid"));
        let unique = format!("{local}+dup{rowid}@{domain}");
        conn.execute(
            "UPDATE panel_users SET email = ?1 WHERE rowid = ?2",
            params![unique, rowid],
        )?;
    }
    Ok(())
}

fn email_conflict(err: rusqlite::Error) -> PanelError {
    if err.to_string().contains("UNIQUE constraint failed") {
        PanelError::Conflict("email is already used by another panel user".into())
    } else {
        err.into()
    }
}

impl PanelDb {
    pub fn open(path: &Path) -> Result<Self, PanelError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| PanelError::Db(format!("cannot create database dir: {e}")))?;
        }
        let db = Self {
            path: path.to_path_buf(),
        };
        let conn = db.conn()?;
        conn.execute_batch(SCHEMA)?;
        let has_impersonation: bool = conn
            .prepare("PRAGMA table_info(sessions)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .filter_map(Result::ok)
            .any(|name| name == "impersonated_by");
        if !has_impersonation {
            conn.execute("ALTER TABLE sessions ADD COLUMN impersonated_by TEXT", [])?;
        }
        let has_account: bool = conn
            .prepare("PRAGMA table_info(panel_users)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .filter_map(Result::ok)
            .any(|name| name == "account");
        if !has_account {
            conn.execute("ALTER TABLE panel_users ADD COLUMN account TEXT", [])?;
        }
        let has_locale: bool = conn
            .prepare("PRAGMA table_info(panel_users)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .filter_map(Result::ok)
            .any(|name| name == "locale");
        if !has_locale {
            conn.execute("ALTER TABLE panel_users ADD COLUMN locale TEXT", [])?;
        }
        let has_ftp_limit: bool = conn
            .prepare("PRAGMA table_info(packages)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .filter_map(Result::ok)
            .any(|name| name == "ftp_accounts");
        if !has_ftp_limit {
            conn.execute(
                "ALTER TABLE packages ADD COLUMN ftp_accounts INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        for column in ["memory_mb", "cpu_percent", "process_limit"] {
            let exists: bool = conn
                .prepare("PRAGMA table_info(packages)")?
                .query_map([], |row| row.get::<_, String>(1))?
                .filter_map(Result::ok)
                .any(|name| name == column);
            if !exists {
                conn.execute(
                    &format!("ALTER TABLE packages ADD COLUMN {column} INTEGER NOT NULL DEFAULT 0"),
                    [],
                )?;
            }
        }
        let has_agent_summary: bool = conn
            .prepare("PRAGMA table_info(agent_runs)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .filter_map(Result::ok)
            .any(|name| name == "summary");
        if !has_agent_summary {
            conn.execute(
                "ALTER TABLE agent_runs ADD COLUMN summary TEXT NOT NULL DEFAULT ''",
                [],
            )?;
        }
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_panel_users_account ON panel_users(account);
             CREATE INDEX IF NOT EXISTS idx_panel_users_email_lower ON panel_users(lower(email));",
        )?;
        deduplicate_panel_emails(&conn)?;
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_panel_users_email_lower_unique \
             ON panel_users(lower(email))",
            [],
        )?;
        drop(conn);
        db.ensure_default_package()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(db)
    }

    fn conn(&self) -> Result<Connection, PanelError> {
        let conn = Connection::open(&self.path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        Ok(conn)
    }

    fn get_user(
        &self,
        conn: &Connection,
        username: &str,
    ) -> Result<Option<UserRecord>, PanelError> {
        let record = conn
            .query_row(
                "SELECT id, username, email, role, active, created_at, updated_at, account, locale, password_hash \
                 FROM panel_users WHERE username = ?1",
                params![username],
                |row| {
                    let view = map_user(row)?;
                    let password_hash: String = row.get(9)?;
                    Ok(UserRecord {
                        view,
                        password_hash,
                    })
                },
            )
            .optional()?;
        Ok(record)
    }

    pub fn count_users(&self) -> Result<i64, PanelError> {
        let conn = self.conn()?;
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM panel_users", [], |row| row.get(0))?;
        Ok(count)
    }

    pub fn has_owner(&self) -> Result<bool, PanelError> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM panel_users WHERE role = 'owner'",
            [],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    pub fn create_user(
        &self,
        username: &str,
        email: &str,
        password: &str,
        role: Role,
    ) -> Result<UserView, PanelError> {
        self.create_user_with_policy(&PasswordPolicy::default(), username, email, password, role)
    }

    pub fn create_user_with_policy(
        &self,
        policy: &PasswordPolicy,
        username: &str,
        email: &str,
        password: &str,
        role: Role,
    ) -> Result<UserView, PanelError> {
        self.create_user_inner(policy, username, email, password, role, None)
    }

    /// Create a panel user linked to a hosting account. The link lets the
    /// admin impersonate the account owner from the Accounts view.
    pub fn create_account_user(
        &self,
        policy: &PasswordPolicy,
        username: &str,
        email: &str,
        password: &str,
        role: Role,
        account: &str,
    ) -> Result<UserView, PanelError> {
        self.create_user_inner(policy, username, email, password, role, Some(account))
    }

    fn create_user_inner(
        &self,
        policy: &PasswordPolicy,
        username: &str,
        email: &str,
        password: &str,
        role: Role,
        account: Option<&str>,
    ) -> Result<UserView, PanelError> {
        validate_panel_username(username).map_err(|e| PanelError::Validation(e.to_string()))?;
        validate_email(email).map_err(|e| PanelError::Validation(e.to_string()))?;
        validate_password_with(policy, password, username, email)?;

        let conn = self.conn()?;
        if self.get_user(&conn, username)?.is_some() {
            return Err(PanelError::Conflict(format!(
                "user '{username}' already exists"
            )));
        }
        let email_taken: i64 = conn.query_row(
            "SELECT COUNT(*) FROM panel_users WHERE lower(email) = lower(?1)",
            params![email],
            |row| row.get(0),
        )?;
        if email_taken > 0 {
            return Err(PanelError::Conflict(
                "email is already used by another panel user".into(),
            ));
        }
        let hash = hash_password(password)?;
        let now = now_rfc3339();
        let id = uuid::Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO panel_users (id, username, email, password_hash, role, active, created_at, updated_at, account, locale) \
             VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?6, ?7, NULL)",
            params![id, username, email, hash, role.as_str(), now, account],
        )
        .map_err(email_conflict)?;
        Ok(UserView {
            id,
            username: username.to_string(),
            email: email.to_string(),
            role,
            active: true,
            created_at: now.clone(),
            updated_at: now,
            account: account.map(str::to_string),
            locale: None,
        })
    }

    pub fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<UserView>, PanelError> {
        let conn = self.conn()?;
        let record = self.get_user(&conn, username)?;
        // Always perform a verification so account existence cannot be
        // inferred from timing.
        let Some(record) = record else {
            let _ = verify_password(password, dummy_hash());
            return Ok(None);
        };
        if !verify_password(password, &record.password_hash) {
            return Ok(None);
        }
        if !record.view.active {
            return Ok(None);
        }
        Ok(Some(record.view))
    }

    pub fn find_user(&self, username: &str) -> Result<Option<UserView>, PanelError> {
        let conn = self.conn()?;
        Ok(self.get_user(&conn, username)?.map(|record| record.view))
    }

    pub fn find_user_by_account(&self, account: &str) -> Result<Option<UserView>, PanelError> {
        let conn = self.conn()?;
        let record = conn
            .query_row(
                "SELECT id, username, email, role, active, created_at, updated_at, account, locale \
                 FROM panel_users WHERE account = ?1",
                params![account],
                map_user,
            )
            .optional()?;
        Ok(record)
    }

    pub fn find_user_by_email(&self, email: &str) -> Result<Option<UserView>, PanelError> {
        let conn = self.conn()?;
        let record = conn
            .query_row(
                "SELECT id, username, email, role, active, created_at, updated_at, account, locale \
                 FROM panel_users WHERE lower(email) = lower(?1)",
                params![email],
                map_user,
            )
            .optional()?;
        Ok(record)
    }

    pub fn email_exists(&self, email: &str) -> Result<bool, PanelError> {
        Ok(self.find_user_by_email(email)?.is_some())
    }

    pub fn count_owners(&self) -> Result<i64, PanelError> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM panel_users WHERE role = 'owner' AND active = 1",
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Locale of the most recently active owner or administrator. The
    /// background agent uses it so its findings and emails match the language
    /// the administrator is actually using in the panel.
    pub fn latest_admin_locale(&self) -> Result<Option<String>, PanelError> {
        let conn = self.conn()?;
        Ok(conn
            .query_row(
                "SELECT u.locale FROM sessions s JOIN panel_users u ON u.id = s.user_id \
                 WHERE u.active = 1 AND u.role IN ('owner', 'admin') \
                   AND u.locale IS NOT NULL AND u.locale <> '' AND s.expires_at > ?1 \
                 ORDER BY s.last_seen DESC, s.rowid DESC LIMIT 1",
                params![now_unix()],
                |row| row.get::<_, String>(0),
            )
            .optional()?)
    }

    pub fn list_users(&self) -> Result<Vec<UserView>, PanelError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, username, email, role, active, created_at, updated_at, account, locale \
             FROM panel_users ORDER BY username",
        )?;
        let rows = stmt.query_map([], map_user)?;
        let mut users = Vec::new();
        for row in rows {
            users.push(row?);
        }
        Ok(users)
    }

    pub fn set_password(&self, username: &str, password: &str) -> Result<(), PanelError> {
        self.set_password_with_policy(&PasswordPolicy::default(), username, password)
    }

    pub fn set_password_with_policy(
        &self,
        policy: &PasswordPolicy,
        username: &str,
        password: &str,
    ) -> Result<(), PanelError> {
        let conn = self.conn()?;
        let record = self
            .get_user(&conn, username)?
            .ok_or_else(|| PanelError::NotFound(username.into()))?;
        validate_password_with(policy, password, username, &record.view.email)?;
        let hash = hash_password(password)?;
        let changed = conn.execute(
            "UPDATE panel_users SET password_hash = ?2, updated_at = ?3 WHERE username = ?1",
            params![username, hash, now_rfc3339()],
        )?;
        if changed == 0 {
            return Err(PanelError::NotFound(username.into()));
        }
        conn.execute(
            "DELETE FROM sessions WHERE user_id = (SELECT id FROM panel_users WHERE username = ?1)",
            params![username],
        )?;
        let _ = conn.execute(
            "DELETE FROM password_resets WHERE user_id = (SELECT id FROM panel_users WHERE username = ?1)",
            params![username],
        );
        Ok(())
    }

    pub fn set_email(&self, username: &str, email: &str) -> Result<(), PanelError> {
        validate_email(email).map_err(|e| PanelError::Validation(e.to_string()))?;
        let conn = self.conn()?;
        let email_taken: i64 = conn.query_row(
            "SELECT COUNT(*) FROM panel_users WHERE lower(email) = lower(?1) AND username <> ?2",
            params![email, username],
            |row| row.get(0),
        )?;
        if email_taken > 0 {
            return Err(PanelError::Conflict(
                "email is already used by another panel user".into(),
            ));
        }
        let changed = conn
            .execute(
                "UPDATE panel_users SET email = ?2, updated_at = ?3 WHERE username = ?1",
                params![username, email, now_rfc3339()],
            )
            .map_err(email_conflict)?;
        if changed == 0 {
            return Err(PanelError::NotFound(username.into()));
        }
        let _ = conn.execute(
            "DELETE FROM password_resets WHERE user_id = (SELECT id FROM panel_users WHERE username = ?1)",
            params![username],
        );
        Ok(())
    }

    pub fn set_user_locale(&self, username: &str, locale: Option<&str>) -> Result<(), PanelError> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE panel_users SET locale = ?2, updated_at = ?3 WHERE username = ?1",
            params![username, locale, now_rfc3339()],
        )?;
        Ok(())
    }

    pub fn create_api_token(
        &self,
        user_id: &str,
        name: &str,
    ) -> Result<(String, ApiTokenView), PanelError> {
        let name = name.trim();
        if name.is_empty() || name.len() > 100 || name.chars().any(|ch| ch.is_control()) {
            return Err(PanelError::Validation("invalid token name".into()));
        }
        let token = format!("rynx_{}", random_hex(32));
        let id = uuid::Uuid::new_v4().to_string();
        let created_at = now_rfc3339();
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO api_tokens (id, user_id, name, token_hash, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, user_id, name, sha256_hex(token.as_bytes()), created_at],
        )?;
        Ok((
            token,
            ApiTokenView {
                id,
                name: name.to_string(),
                created_at,
                last_used_at: None,
            },
        ))
    }

    pub fn list_api_tokens(&self, user_id: &str) -> Result<Vec<ApiTokenView>, PanelError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, name, created_at, last_used_at \
             FROM api_tokens WHERE user_id = ?1 ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map(params![user_id], |row| {
            Ok(ApiTokenView {
                id: row.get(0)?,
                name: row.get(1)?,
                created_at: row.get(2)?,
                last_used_at: row.get(3)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn revoke_api_token(&self, user_id: &str, id: &str) -> Result<bool, PanelError> {
        let conn = self.conn()?;
        let changed = conn.execute(
            "DELETE FROM api_tokens WHERE id = ?1 AND user_id = ?2",
            params![id, user_id],
        )?;
        Ok(changed > 0)
    }

    pub fn authenticate_api_token(&self, token: &str) -> Result<Option<UserView>, PanelError> {
        if token.len() > 200 {
            return Ok(None);
        }
        let conn = self.conn()?;
        let hash = sha256_hex(token.as_bytes());
        let user = conn
            .query_row(
                "SELECT u.id, u.username, u.email, u.role, u.active, u.created_at, \
                        u.updated_at, u.account, u.locale \
                 FROM api_tokens t JOIN panel_users u ON u.id = t.user_id \
                 WHERE t.token_hash = ?1 AND u.active = 1",
                params![hash],
                map_user,
            )
            .optional()?;
        if user.is_some() {
            let _ = conn.execute(
                "UPDATE api_tokens SET last_used_at = ?2 WHERE token_hash = ?1",
                params![hash, now_rfc3339()],
            );
        }
        Ok(user)
    }

    pub fn create_webhook(
        &self,
        user_id: &str,
        name: &str,
        url: &str,
        events: &[String],
        secret: &str,
    ) -> Result<WebhookView, PanelError> {
        let id = uuid::Uuid::new_v4().to_string();
        let created_at = now_rfc3339();
        let events_json =
            serde_json::to_string(events).map_err(|err| PanelError::Validation(err.to_string()))?;
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO webhooks (id, user_id, name, url, secret, events, enabled, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7)",
            params![id, user_id, name, url, secret, events_json, created_at],
        )?;
        Ok(WebhookView {
            id,
            name: name.to_string(),
            url: url.to_string(),
            events: events.to_vec(),
            enabled: true,
            created_at,
        })
    }

    pub fn list_webhooks(&self, user_id: &str) -> Result<Vec<WebhookView>, PanelError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, name, url, events, enabled, created_at \
             FROM webhooks WHERE user_id = ?1 ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map(params![user_id], |row| {
            let events_raw: String = row.get(3)?;
            Ok(WebhookView {
                id: row.get(0)?,
                name: row.get(1)?,
                url: row.get(2)?,
                events: serde_json::from_str(&events_raw).unwrap_or_default(),
                enabled: row.get::<_, i64>(4)? != 0,
                created_at: row.get(5)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn delete_webhook(&self, user_id: &str, id: &str) -> Result<bool, PanelError> {
        let conn = self.conn()?;
        let changed = conn.execute(
            "DELETE FROM webhooks WHERE id = ?1 AND user_id = ?2",
            params![id, user_id],
        )?;
        Ok(changed > 0)
    }

    pub fn list_passkeys(&self, user_id: &str) -> Result<Vec<PasskeyView>, PanelError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, name, created_at, last_used_at \
             FROM passkeys WHERE user_id = ?1 ORDER BY created_at ASC",
        )?;
        let rows = stmt.query_map(params![user_id], |row| {
            Ok(PasskeyView {
                id: row.get(0)?,
                name: row.get(1)?,
                created_at: row.get(2)?,
                last_used_at: row.get(3)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn count_passkeys(&self, user_id: &str) -> Result<u64, PanelError> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM passkeys WHERE user_id = ?1",
            params![user_id],
            |row| row.get(0),
        )?;
        Ok(count.max(0) as u64)
    }

    pub fn list_passkey_credentials(
        &self,
        user_id: &str,
    ) -> Result<Vec<StoredPasskey>, PanelError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, credential_id, credential FROM passkeys WHERE user_id = ?1 ORDER BY created_at ASC",
        )?;
        let rows = stmt.query_map(params![user_id], |row| {
            Ok(StoredPasskey {
                id: row.get(0)?,
                credential_id: row.get(1)?,
                credential: row.get(2)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn create_passkey(
        &self,
        user_id: &str,
        name: &str,
        credential_id: &str,
        credential: &str,
    ) -> Result<PasskeyView, PanelError> {
        let id = uuid::Uuid::new_v4().to_string();
        let created_at = now_rfc3339();
        let conn = self.conn()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM passkeys WHERE user_id = ?1",
            params![user_id],
            |row| row.get(0),
        )?;
        if count >= 20 {
            return Err(PanelError::Validation(
                "too many passkeys registered".into(),
            ));
        }
        conn.execute(
            "INSERT INTO passkeys (id, user_id, name, credential_id, credential, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, user_id, name, credential_id, credential, created_at],
        )
        .map_err(|err| {
            if err.to_string().contains("UNIQUE") {
                PanelError::Validation("this passkey is already registered".into())
            } else {
                PanelError::Db(err.to_string())
            }
        })?;
        Ok(PasskeyView {
            id,
            name: name.to_string(),
            created_at,
            last_used_at: None,
        })
    }

    pub fn delete_passkey(&self, user_id: &str, id: &str) -> Result<bool, PanelError> {
        let conn = self.conn()?;
        let changed = conn.execute(
            "DELETE FROM passkeys WHERE id = ?1 AND user_id = ?2",
            params![id, user_id],
        )?;
        Ok(changed > 0)
    }

    pub fn touch_passkey(
        &self,
        user_id: &str,
        credential_id: &str,
        credential: Option<&str>,
    ) -> Result<(), PanelError> {
        let conn = self.conn()?;
        let now = now_rfc3339();
        if let Some(credential) = credential {
            conn.execute(
                "UPDATE passkeys SET last_used_at = ?1, credential = ?2 \
                 WHERE user_id = ?3 AND credential_id = ?4",
                params![now, credential, user_id, credential_id],
            )?;
        } else {
            conn.execute(
                "UPDATE passkeys SET last_used_at = ?1 WHERE user_id = ?2 AND credential_id = ?3",
                params![now, user_id, credential_id],
            )?;
        }
        Ok(())
    }

    pub fn webhooks_for_event(&self, event: &str) -> Result<Vec<WebhookTarget>, PanelError> {
        let conn = self.conn()?;
        let mut stmt =
            conn.prepare("SELECT url, secret, events FROM webhooks WHERE enabled = 1")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (url, secret, events_raw) = row?;
            let events: Vec<String> = serde_json::from_str(&events_raw).unwrap_or_default();
            if events.iter().any(|item| item == event) {
                out.push(WebhookTarget { url, secret });
            }
        }
        Ok(out)
    }

    pub fn list_user_sessions(&self, user_id: &str) -> Result<Vec<SessionView>, PanelError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT token_hash, created_at, last_seen, ip, user_agent \
             FROM sessions WHERE user_id = ?1 AND expires_at > ?2 \
             ORDER BY last_seen DESC",
        )?;
        let rows = stmt.query_map(params![user_id, now_unix()], |row| {
            Ok(SessionView {
                id: row.get(0)?,
                created_at: row.get(1)?,
                last_seen: row.get(2)?,
                ip: row.get(3)?,
                user_agent: row.get(4)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn revoke_user_session(&self, user_id: &str, id: &str) -> Result<bool, PanelError> {
        let conn = self.conn()?;
        let changed = conn.execute(
            "DELETE FROM sessions WHERE token_hash = ?1 AND user_id = ?2",
            params![id, user_id],
        )?;
        Ok(changed > 0)
    }

    pub fn revoke_other_sessions(&self, user_id: &str, current: &str) -> Result<usize, PanelError> {
        let conn = self.conn()?;
        let changed = conn.execute(
            "DELETE FROM sessions WHERE user_id = ?1 AND token_hash <> ?2",
            params![user_id, current],
        )?;
        Ok(changed)
    }

    pub fn set_active(&self, username: &str, active: bool) -> Result<(), PanelError> {
        let conn = self.conn()?;
        let changed = conn.execute(
            "UPDATE panel_users SET active = ?2, updated_at = ?3 WHERE username = ?1",
            params![username, if active { 1 } else { 0 }, now_rfc3339()],
        )?;
        if changed == 0 {
            return Err(PanelError::NotFound(username.into()));
        }
        if !active {
            conn.execute(
                "DELETE FROM sessions WHERE user_id = (SELECT id FROM panel_users WHERE username = ?1)",
                params![username],
            )?;
            let _ = conn.execute(
                "DELETE FROM password_resets WHERE user_id = (SELECT id FROM panel_users WHERE username = ?1)",
                params![username],
            );
        }
        Ok(())
    }

    pub fn set_role(&self, username: &str, role: Role) -> Result<(), PanelError> {
        let conn = self.conn()?;
        let changed = conn.execute(
            "UPDATE panel_users SET role = ?2, updated_at = ?3 WHERE username = ?1",
            params![username, role.as_str(), now_rfc3339()],
        )?;
        if changed == 0 {
            return Err(PanelError::NotFound(username.into()));
        }
        Ok(())
    }

    pub fn delete_user(&self, username: &str) -> Result<(), PanelError> {
        let conn = self.conn()?;
        let changed = conn.execute(
            "DELETE FROM panel_users WHERE username = ?1",
            params![username],
        )?;
        if changed == 0 {
            return Err(PanelError::NotFound(username.into()));
        }
        Ok(())
    }

    /// Create a single-use password-reset token for an active user.
    ///
    /// Returns `None` for unknown or disabled accounts so callers can reply
    /// generically without exposing whether an email is registered.
    pub fn create_password_reset(
        &self,
        email: &str,
        ttl_secs: i64,
    ) -> Result<Option<(String, UserView)>, PanelError> {
        let Some(user) = self.find_user_by_email(email)? else {
            return Ok(None);
        };
        if !user.active {
            return Ok(None);
        }
        let conn = self.conn()?;
        let token = random_hex(32);
        let token_hash = sha256_hex(token.as_bytes());
        let now = now_unix();
        let expires_at = now + ttl_secs.clamp(300, 24 * 60 * 60);
        conn.execute(
            "DELETE FROM password_resets WHERE user_id = ?1",
            params![user.id],
        )?;
        conn.execute(
            "INSERT INTO password_resets (token_hash, user_id, created_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4)",
            params![token_hash, user.id, now, expires_at],
        )?;
        let _ = conn.execute(
            "DELETE FROM password_resets WHERE expires_at < ?1",
            params![now],
        );
        Ok(Some((token, user)))
    }

    /// Consume a reset token and atomically replace the password.
    ///
    /// Invalid, expired or already-used tokens return `Ok(None)`. A weak new
    /// password returns a validation error and leaves the token usable.
    pub fn consume_password_reset(
        &self,
        policy: &PasswordPolicy,
        token: &str,
        password: &str,
    ) -> Result<Option<String>, PanelError> {
        if token.len() != 64 || !token.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Ok(None);
        }
        let token_hash = sha256_hex(token.as_bytes());
        let mut conn = self.conn()?;
        let row: Option<(String, String, String, i64)> = conn
            .query_row(
                "SELECT u.id, u.username, u.email, r.expires_at \
                 FROM password_resets r JOIN panel_users u ON u.id = r.user_id \
                 WHERE r.token_hash = ?1 AND u.active = 1",
                params![token_hash],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((user_id, username, email, expires_at)) = row else {
            return Ok(None);
        };
        if expires_at <= now_unix() {
            let _ = conn.execute(
                "DELETE FROM password_resets WHERE token_hash = ?1",
                params![token_hash],
            );
            return Ok(None);
        }
        validate_password_with(policy, password, &username, &email)?;
        let hash = hash_password(password)?;
        let tx = conn.transaction()?;
        let consumed = tx.execute(
            "DELETE FROM password_resets WHERE token_hash = ?1 AND user_id = ?2 AND expires_at > ?3",
            params![token_hash, user_id, now_unix()],
        )?;
        if consumed == 0 {
            return Ok(None);
        }
        let changed = tx.execute(
            "UPDATE panel_users SET password_hash = ?2, updated_at = ?3 WHERE id = ?1",
            params![user_id, hash, now_rfc3339()],
        )?;
        if changed == 0 {
            return Ok(None);
        }
        tx.execute("DELETE FROM sessions WHERE user_id = ?1", params![user_id])?;
        tx.execute(
            "DELETE FROM password_resets WHERE user_id = ?1",
            params![user_id],
        )?;
        tx.commit()?;
        Ok(Some(username))
    }

    pub fn create_session(
        &self,
        user_id: &str,
        ttl_secs: i64,
        ip: &str,
        user_agent: &str,
        impersonated_by: Option<&str>,
    ) -> Result<NewSession, PanelError> {
        let conn = self.conn()?;
        let token = random_hex(32);
        let token_hash = sha256_hex(token.as_bytes());
        let csrf = random_hex(24);
        let now = now_unix();
        let expires_at = now + ttl_secs.max(60);
        conn.execute(
            "INSERT INTO sessions (token_hash, user_id, csrf_token, created_at, expires_at, last_seen, ip, user_agent, impersonated_by) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?4, ?6, ?7, ?8)",
            params![
                token_hash,
                user_id,
                csrf,
                now.to_string(),
                expires_at,
                ip,
                user_agent,
                impersonated_by
            ],
        )?;
        let _ = conn.execute("DELETE FROM sessions WHERE expires_at < ?1", params![now]);
        Ok(NewSession {
            token,
            csrf_token: csrf,
            expires_at,
        })
    }

    pub fn lookup_session(
        &self,
        token: &str,
        idle_secs: i64,
    ) -> Result<Option<SessionContext>, PanelError> {
        if token.len() != 64 {
            return Ok(None);
        }
        let token_hash = sha256_hex(token.as_bytes());
        let conn = self.conn()?;
        let row = conn
            .query_row(
                "SELECT s.csrf_token, s.expires_at, s.last_seen, s.impersonated_by, u.id, u.username, u.email, u.role, u.active, u.created_at, u.updated_at, u.account, u.locale \
                 FROM sessions s JOIN panel_users u ON u.id = s.user_id WHERE s.token_hash = ?1",
                params![token_hash],
                |row| {
                    let role_raw: String = row.get(7)?;
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        UserView {
                            id: row.get(4)?,
                            username: row.get(5)?,
                            email: row.get(6)?,
                            role: Role::parse(&role_raw).unwrap_or(Role::Viewer),
                            active: row.get::<_, i64>(8)? != 0,
                            created_at: row.get(9)?,
                            updated_at: row.get(10)?,
                            account: row.get(11)?,
                            locale: row.get(12)?,
                        },
                    ))
                },
            )
            .optional()?;

        let Some((csrf_token, expires_at, last_seen, impersonated_by, user)) = row else {
            return Ok(None);
        };
        let now = now_unix();
        let idle_expired = idle_secs > 0 && now.saturating_sub(last_seen) > idle_secs;
        if expires_at <= now || idle_expired || !user.active {
            let _ = conn.execute(
                "DELETE FROM sessions WHERE token_hash = ?1",
                params![token_hash],
            );
            return Ok(None);
        }
        let _ = conn.execute(
            "UPDATE sessions SET last_seen = ?2 WHERE token_hash = ?1",
            params![token_hash, now],
        );
        Ok(Some(SessionContext {
            user,
            csrf_token,
            expires_at,
            impersonated_by,
        }))
    }

    pub fn record_auth_event(
        &self,
        username: &str,
        ip: &str,
        user_agent: &str,
        outcome: &str,
        reason: &str,
    ) -> Result<(), PanelError> {
        let conn = self.conn()?;
        let now = now_unix();
        conn.execute(
            "INSERT INTO auth_events (at, at_unix, username, ip, user_agent, outcome, reason) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                now_rfc3339(),
                now,
                username,
                ip,
                user_agent,
                outcome,
                reason
            ],
        )?;
        let _ = conn.execute(
            "DELETE FROM auth_events WHERE at_unix < ?1",
            params![now - 30 * 24 * 60 * 60],
        );
        Ok(())
    }

    pub fn list_auth_events(&self, limit: u32) -> Result<Vec<AuthEventView>, PanelError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, at, at_unix, username, ip, user_agent, outcome, reason \
             FROM auth_events ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit.clamp(1, 1000) as i64], |row| {
            Ok(AuthEventView {
                id: row.get(0)?,
                at: row.get(1)?,
                at_unix: row.get(2)?,
                username: row.get(3)?,
                ip: row.get(4)?,
                user_agent: row.get(5)?,
                outcome: row.get(6)?,
                reason: row.get(7)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn auth_stats(&self, window_secs: i64) -> Result<AuthStats, PanelError> {
        let conn = self.conn()?;
        let since = now_unix() - window_secs.max(60);
        let successes: i64 = conn.query_row(
            "SELECT COUNT(*) FROM auth_events WHERE outcome = 'success' AND at_unix >= ?1",
            params![since],
            |row| row.get(0),
        )?;
        let failures: i64 = conn.query_row(
            "SELECT COUNT(*) FROM auth_events WHERE outcome = 'failure' AND at_unix >= ?1",
            params![since],
            |row| row.get(0),
        )?;
        let blocked: i64 = conn.query_row(
            "SELECT COUNT(*) FROM auth_events WHERE outcome = 'blocked' AND at_unix >= ?1",
            params![since],
            |row| row.get(0),
        )?;
        let unique_ips: i64 = conn.query_row(
            "SELECT COUNT(DISTINCT ip) FROM auth_events WHERE outcome <> 'success' AND at_unix >= ?1",
            params![since],
            |row| row.get(0),
        )?;
        Ok(AuthStats {
            window_secs,
            successes,
            failures,
            blocked,
            unique_ips,
        })
    }

    pub fn delete_session(&self, token: &str) -> Result<(), PanelError> {
        let token_hash = sha256_hex(token.as_bytes());
        let conn = self.conn()?;
        conn.execute(
            "DELETE FROM sessions WHERE token_hash = ?1",
            params![token_hash],
        )?;
        Ok(())
    }

    pub fn purge_expired_sessions(&self) -> Result<usize, PanelError> {
        let conn = self.conn()?;
        Ok(conn.execute(
            "DELETE FROM sessions WHERE expires_at < ?1",
            params![now_unix()],
        )?)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), PanelError> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO panel_settings (key, value) VALUES (?1, ?2) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn get_setting(&self, key: &str) -> Result<Option<String>, PanelError> {
        let conn = self.conn()?;
        Ok(conn
            .query_row(
                "SELECT value FROM panel_settings WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Ensures the seeded editable "Por defecto" package exists.
    pub fn ensure_default_package(&self) -> Result<(), PanelError> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM packages WHERE is_default = 1",
            [],
            |row| row.get(0),
        )?;
        if count > 0 {
            return Ok(());
        }
        let existing: Option<String> = conn
            .query_row(
                "SELECT id FROM packages WHERE lower(name) = lower('Por defecto') LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(id) = existing {
            conn.execute(
                "UPDATE packages SET is_default = 1, updated_at = ?2 WHERE id = ?1",
                params![id, now_rfc3339()],
            )?;
            return Ok(());
        }
        let input = default_package();
        let now = now_rfc3339();
        conn.execute(
            "INSERT INTO packages (id, name, is_default, account_mb, bandwidth_mb, backups, \
                 incremental_backup, web_domains, web_aliases, web_backend, nginx_template, \
                 dns_template, dns_zones, dns_records, nameservers, mail_domains, mail_accounts, \
                 mail_rate_limit, databases, system_databases, ftp_accounts, created_at, updated_at, \
                 memory_mb, cpu_percent, process_limit) \
             VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, \
                 ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25)",
            params![
                uuid::Uuid::new_v4().to_string(),
                input.name,
                input.account_mb,
                input.bandwidth_mb,
                input.backups,
                input.incremental_backup as i64,
                input.web_domains,
                input.web_aliases,
                input.web_backend,
                input.nginx_template,
                input.dns_template,
                input.dns_zones,
                input.dns_records,
                serde_json::to_string(&input.nameservers).unwrap_or_else(|_| "[]".into()),
                input.mail_domains,
                input.mail_accounts,
                input.mail_rate_limit,
                input.databases,
                input.system_databases,
                input.ftp_accounts,
                now,
                now,
                input.memory_mb,
                input.cpu_percent,
                input.process_limit,
            ],
        )?;
        Ok(())
    }

    pub fn list_packages(&self) -> Result<Vec<PackageView>, PanelError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, name, is_default, account_mb, bandwidth_mb, backups, incremental_backup, \
                    web_domains, web_aliases, web_backend, nginx_template, dns_template, dns_zones, \
                    dns_records, nameservers, mail_domains, mail_accounts, mail_rate_limit, \
                    databases, system_databases, ftp_accounts, created_at, updated_at, \
                    memory_mb, cpu_percent, process_limit \
             FROM packages ORDER BY is_default DESC, lower(name) ASC",
        )?;
        let rows = stmt.query_map([], map_package)?;
        let mut packages = Vec::new();
        for row in rows {
            packages.push(row?);
        }
        Ok(packages)
    }

    pub fn get_package(&self, id: &str) -> Result<Option<PackageView>, PanelError> {
        let conn = self.conn()?;
        Ok(conn
            .query_row(
                "SELECT id, name, is_default, account_mb, bandwidth_mb, backups, incremental_backup, \
                        web_domains, web_aliases, web_backend, nginx_template, dns_template, dns_zones, \
                        dns_records, nameservers, mail_domains, mail_accounts, mail_rate_limit, \
                        databases, system_databases, ftp_accounts, created_at, updated_at, \
                        memory_mb, cpu_percent, process_limit \
                 FROM packages WHERE id = ?1",
                params![id],
                map_package,
            )
            .optional()?)
    }

    pub fn create_package(&self, input: PackageInput) -> Result<PackageView, PanelError> {
        let input = normalize_and_validate(input)?;
        let conn = self.conn()?;
        if package_name_exists(&conn, &input.name, None)? {
            return Err(PanelError::Conflict(format!(
                "a package named '{}' already exists",
                input.name
            )));
        }
        let id = uuid::Uuid::new_v4().to_string();
        let now = now_rfc3339();
        conn.execute(
            "INSERT INTO packages (id, name, is_default, account_mb, bandwidth_mb, backups, \
                 incremental_backup, web_domains, web_aliases, web_backend, nginx_template, \
                 dns_template, dns_zones, dns_records, nameservers, mail_domains, mail_accounts, \
                 mail_rate_limit, databases, system_databases, ftp_accounts, created_at, updated_at, \
                 memory_mb, cpu_percent, process_limit) \
             VALUES (?1, ?2, 0, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, \
                 ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25)",
            params![
                id,
                input.name,
                input.account_mb,
                input.bandwidth_mb,
                input.backups,
                input.incremental_backup as i64,
                input.web_domains,
                input.web_aliases,
                input.web_backend,
                input.nginx_template,
                input.dns_template,
                input.dns_zones,
                input.dns_records,
                serde_json::to_string(&input.nameservers).unwrap_or_else(|_| "[]".into()),
                input.mail_domains,
                input.mail_accounts,
                input.mail_rate_limit,
                input.databases,
                input.system_databases,
                input.ftp_accounts,
                now,
                now,
                input.memory_mb,
                input.cpu_percent,
                input.process_limit,
            ],
        )?;
        self.get_package(&id)?
            .ok_or_else(|| PanelError::NotFound(format!("package '{id}' not found")))
    }

    pub fn update_package(&self, id: &str, input: PackageInput) -> Result<PackageView, PanelError> {
        let input = normalize_and_validate(input)?;
        let conn = self.conn()?;
        if conn
            .query_row("SELECT 1 FROM packages WHERE id = ?1", params![id], |_| {
                Ok(())
            })
            .optional()?
            .is_none()
        {
            return Err(PanelError::NotFound(format!("package '{id}' not found")));
        }
        if package_name_exists(&conn, &input.name, Some(id))? {
            return Err(PanelError::Conflict(format!(
                "a package named '{}' already exists",
                input.name
            )));
        }
        conn.execute(
            "UPDATE packages SET name = ?2, account_mb = ?3, bandwidth_mb = ?4, backups = ?5, \
                 incremental_backup = ?6, web_domains = ?7, web_aliases = ?8, web_backend = ?9, \
                 nginx_template = ?10, dns_template = ?11, dns_zones = ?12, dns_records = ?13, \
                 nameservers = ?14, mail_domains = ?15, mail_accounts = ?16, mail_rate_limit = ?17, \
                 databases = ?18, system_databases = ?19, ftp_accounts = ?20, updated_at = ?21, \
                 memory_mb = ?22, cpu_percent = ?23, process_limit = ?24 \
             WHERE id = ?1",
            params![
                id,
                input.name,
                input.account_mb,
                input.bandwidth_mb,
                input.backups,
                input.incremental_backup as i64,
                input.web_domains,
                input.web_aliases,
                input.web_backend,
                input.nginx_template,
                input.dns_template,
                input.dns_zones,
                input.dns_records,
                serde_json::to_string(&input.nameservers).unwrap_or_else(|_| "[]".into()),
                input.mail_domains,
                input.mail_accounts,
                input.mail_rate_limit,
                input.databases,
                input.system_databases,
                input.ftp_accounts,
                now_rfc3339(),
                input.memory_mb,
                input.cpu_percent,
                input.process_limit,
            ],
        )?;
        self.get_package(id)?
            .ok_or_else(|| PanelError::NotFound(format!("package '{id}' not found")))
    }

    pub fn delete_package(&self, id: &str) -> Result<(), PanelError> {
        let existing = self
            .get_package(id)?
            .ok_or_else(|| PanelError::NotFound(format!("package '{id}' not found")))?;
        if existing.is_default {
            return Err(PanelError::Conflict(
                "the default package cannot be deleted".into(),
            ));
        }
        if self.package_is_assigned(id)? {
            return Err(PanelError::Conflict(
                "the package is assigned to one or more accounts".into(),
            ));
        }
        let conn = self.conn()?;
        conn.execute("DELETE FROM packages WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn set_account_package(
        &self,
        account: &str,
        package_id: &str,
        web_backend: &str,
    ) -> Result<AccountPackageView, PanelError> {
        if !WEB_BACKENDS.contains(&web_backend) {
            return Err(PanelError::Validation(format!(
                "invalid web backend '{web_backend}'"
            )));
        }
        let package = self
            .get_package(package_id)?
            .ok_or_else(|| PanelError::NotFound(format!("package '{package_id}' not found")))?;
        let conn = self.conn()?;
        let now = now_rfc3339();
        conn.execute(
            "INSERT INTO account_packages (account, package_id, web_backend, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?4) \
             ON CONFLICT(account) DO UPDATE SET package_id = excluded.package_id, \
                 web_backend = excluded.web_backend, updated_at = excluded.updated_at",
            params![account, package_id, web_backend, now],
        )?;
        Ok(AccountPackageView {
            account: account.to_string(),
            package_id: package_id.to_string(),
            package_name: package.package.name,
            web_backend: web_backend.to_string(),
        })
    }

    pub fn get_account_package(
        &self,
        account: &str,
    ) -> Result<Option<AccountPackageView>, PanelError> {
        let conn = self.conn()?;
        Ok(conn
            .query_row(
                "SELECT ap.account, ap.package_id, p.name, ap.web_backend \
                 FROM account_packages ap JOIN packages p ON p.id = ap.package_id \
                 WHERE ap.account = ?1",
                params![account],
                map_account_package,
            )
            .optional()?)
    }

    pub fn list_account_packages(&self) -> Result<Vec<AccountPackageView>, PanelError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT ap.account, ap.package_id, p.name, ap.web_backend \
             FROM account_packages ap JOIN packages p ON p.id = ap.package_id \
             ORDER BY ap.account",
        )?;
        let rows = stmt.query_map([], map_account_package)?;
        let mut assignments = Vec::new();
        for row in rows {
            assignments.push(row?);
        }
        Ok(assignments)
    }

    pub fn delete_account_package(&self, account: &str) -> Result<(), PanelError> {
        let conn = self.conn()?;
        conn.execute(
            "DELETE FROM account_packages WHERE account = ?1",
            params![account],
        )?;
        Ok(())
    }

    pub fn package_is_assigned(&self, package_id: &str) -> Result<bool, PanelError> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM account_packages WHERE package_id = ?1",
            params![package_id],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Inserts a new finding or refreshes the existing one with the same
    /// fingerprint. Returns the stored finding, whether it is new, whether its
    /// severity increased and whether it was reopened from `resolved`.
    pub fn upsert_agent_finding(
        &self,
        input: &AgentFindingInput,
    ) -> Result<(AgentFinding, bool, bool, bool), PanelError> {
        let conn = self.conn()?;
        let now = now_rfc3339();
        let now_unix = now_unix();
        let evidence = serde_json::to_string(&input.evidence)
            .map_err(|e| PanelError::Validation(e.to_string()))?;
        let existing: Option<(String, i64, String, String)> = conn
            .query_row(
                "SELECT id, occurrences, severity, status \
                 FROM agent_findings WHERE fingerprint = ?1",
                params![input.fingerprint],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        if let Some((id, occurrences, old_severity, old_status)) = existing {
            let escalated = severity_rank(&input.severity) > severity_rank(&old_severity);
            let reopened = old_status == "resolved";
            let status = if reopened {
                "open"
            } else {
                old_status.as_str()
            };
            conn.execute(
                "UPDATE agent_findings SET updated_at = ?1, last_seen = ?2, \
                 occurrences = ?3, severity = ?4, category = ?5, title = ?6, \
                 summary = ?7, evidence = ?8, recommendation = ?9, source = ?10, \
                 status = ?11 WHERE id = ?12",
                params![
                    now,
                    now_unix,
                    occurrences + 1,
                    input.severity,
                    input.category,
                    input.title,
                    input.summary,
                    evidence,
                    input.recommendation,
                    input.source,
                    status,
                    id
                ],
            )?;
            let finding = self
                .get_agent_finding(&id)?
                .ok_or_else(|| PanelError::NotFound(format!("finding '{id}' not found")))?;
            return Ok((finding, false, escalated, reopened));
        }
        let id = uuid::Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO agent_findings \
             (id, fingerprint, created_at, updated_at, first_seen, last_seen, \
              occurrences, severity, category, title, summary, evidence, \
              recommendation, source, status) \
             VALUES (?1, ?2, ?3, ?3, ?4, ?4, 1, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'open')",
            params![
                id,
                input.fingerprint,
                now,
                now_unix,
                input.severity,
                input.category,
                input.title,
                input.summary,
                evidence,
                input.recommendation,
                input.source
            ],
        )?;
        let finding = self
            .get_agent_finding(&id)?
            .ok_or_else(|| PanelError::NotFound(format!("finding '{id}' not found")))?;
        Ok((finding, true, false, false))
    }

    /// Marks findings that were not observed again as resolved. Acknowledged
    /// findings are resolved automatically; ignored findings keep their status.
    pub fn resolve_stale_agent_findings(&self, before_unix: i64) -> Result<usize, PanelError> {
        let conn = self.conn()?;
        let changed = conn.execute(
            "UPDATE agent_findings SET status = 'resolved', updated_at = ?1 \
             WHERE last_seen < ?2 AND status IN ('open', 'acknowledged')",
            params![now_rfc3339(), before_unix],
        )?;
        Ok(changed)
    }

    fn get_agent_finding(&self, id: &str) -> Result<Option<AgentFinding>, PanelError> {
        let conn = self.conn()?;
        Ok(conn
            .query_row(
                "SELECT id, fingerprint, created_at, updated_at, first_seen, \
                 last_seen, occurrences, severity, category, title, summary, \
                 evidence, recommendation, source, status \
                 FROM agent_findings WHERE id = ?1",
                params![id],
                map_agent_finding,
            )
            .optional()?)
    }

    pub fn list_agent_findings(
        &self,
        limit: u32,
        status: Option<&str>,
    ) -> Result<Vec<AgentFinding>, PanelError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, fingerprint, created_at, updated_at, first_seen, \
             last_seen, occurrences, severity, category, title, summary, \
             evidence, recommendation, source, status \
             FROM agent_findings \
             WHERE (?1 IS NULL OR status = ?1) \
             ORDER BY CASE severity \
                 WHEN 'critical' THEN 0 WHEN 'high' THEN 1 \
                 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, \
             last_seen DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(
            params![status, limit.clamp(1, 1000) as i64],
            map_agent_finding,
        )?;
        let mut findings = Vec::new();
        for row in rows {
            findings.push(row?);
        }
        Ok(findings)
    }

    pub fn set_agent_finding_status(&self, id: &str, status: &str) -> Result<(), PanelError> {
        if !matches!(status, "open" | "acknowledged" | "ignored") {
            return Err(PanelError::Validation(format!(
                "invalid finding status: {status}"
            )));
        }
        let conn = self.conn()?;
        let changed = conn.execute(
            "UPDATE agent_findings SET status = ?1, updated_at = ?2 WHERE id = ?3",
            params![status, now_rfc3339(), id],
        )?;
        if changed == 0 {
            return Err(PanelError::NotFound(format!("finding '{id}' not found")));
        }
        Ok(())
    }

    pub fn agent_stats(&self) -> Result<AgentStats, PanelError> {
        let conn = self.conn()?;
        let mut stats = AgentStats::default();
        let mut stmt = conn.prepare(
            "SELECT severity, status, COUNT(*) FROM agent_findings GROUP BY severity, status",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        for row in rows {
            let (severity, status, count) = row?;
            match severity.as_str() {
                "critical" => stats.critical += count,
                "high" => stats.high += count,
                "medium" => stats.medium += count,
                "low" => stats.low += count,
                _ => stats.info += count,
            }
            match status.as_str() {
                "acknowledged" => stats.acknowledged += count,
                "ignored" => stats.ignored += count,
                "resolved" => stats.resolved += count,
                _ => stats.open += count,
            }
        }
        Ok(stats)
    }

    pub fn record_agent_run(&self, run: &AgentRun) -> Result<(), PanelError> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO agent_runs \
             (id, started_at, finished_at, status, findings, error, model, summary) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                run.id,
                run.started_at,
                run.finished_at,
                run.status,
                run.findings,
                run.error,
                run.model,
                run.summary
            ],
        )?;
        conn.execute(
            "DELETE FROM agent_runs WHERE id NOT IN \
             (SELECT id FROM agent_runs ORDER BY started_at DESC LIMIT 200)",
            [],
        )?;
        Ok(())
    }

    pub fn latest_agent_run(&self) -> Result<Option<AgentRun>, PanelError> {
        let conn = self.conn()?;
        Ok(conn
            .query_row(
                "SELECT id, started_at, finished_at, status, findings, error, model, summary \
                 FROM agent_runs ORDER BY started_at DESC LIMIT 1",
                [],
                |row| {
                    Ok(AgentRun {
                        id: row.get(0)?,
                        started_at: row.get(1)?,
                        finished_at: row.get(2)?,
                        status: row.get(3)?,
                        findings: row.get(4)?,
                        error: row.get(5)?,
                        model: row.get(6)?,
                        summary: row.get(7)?,
                    })
                },
            )
            .optional()?)
    }
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        _ => 1,
    }
}

fn map_agent_finding(row: &rusqlite::Row<'_>) -> rusqlite::Result<AgentFinding> {
    let evidence: String = row.get(11)?;
    Ok(AgentFinding {
        id: row.get(0)?,
        fingerprint: row.get(1)?,
        created_at: row.get(2)?,
        updated_at: row.get(3)?,
        first_seen: row.get(4)?,
        last_seen: row.get(5)?,
        occurrences: row.get(6)?,
        severity: row.get(7)?,
        category: row.get(8)?,
        title: row.get(9)?,
        summary: row.get(10)?,
        evidence: serde_json::from_str(&evidence).unwrap_or_default(),
        recommendation: row.get(12)?,
        source: row.get(13)?,
        status: row.get(14)?,
    })
}

fn map_account_package(row: &rusqlite::Row<'_>) -> rusqlite::Result<AccountPackageView> {
    Ok(AccountPackageView {
        account: row.get(0)?,
        package_id: row.get(1)?,
        package_name: row.get(2)?,
        web_backend: row.get(3)?,
    })
}

fn package_name_exists(
    conn: &Connection,
    name: &str,
    exclude_id: Option<&str>,
) -> Result<bool, PanelError> {
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM packages WHERE lower(name) = lower(?1) \
             AND (?2 IS NULL OR id <> ?2) LIMIT 1",
            params![name, exclude_id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

fn map_package(row: &rusqlite::Row<'_>) -> rusqlite::Result<PackageView> {
    let nameservers: String = row.get(14)?;
    Ok(PackageView {
        id: row.get(0)?,
        is_default: row.get::<_, i64>(2)? != 0,
        package: PackageInput {
            name: row.get(1)?,
            account_mb: row.get(3)?,
            bandwidth_mb: row.get(4)?,
            backups: row.get(5)?,
            incremental_backup: row.get::<_, i64>(6)? != 0,
            web_domains: row.get(7)?,
            web_aliases: row.get(8)?,
            web_backend: row.get(9)?,
            nginx_template: row.get(10)?,
            dns_template: row.get(11)?,
            dns_zones: row.get(12)?,
            dns_records: row.get(13)?,
            nameservers: serde_json::from_str(&nameservers).unwrap_or_default(),
            mail_domains: row.get(15)?,
            mail_accounts: row.get(16)?,
            mail_rate_limit: row.get(17)?,
            databases: row.get(18)?,
            system_databases: row.get(19)?,
            ftp_accounts: row.get(20)?,
            memory_mb: row.get(23)?,
            cpu_percent: row.get(24)?,
            process_limit: row.get(25)?,
        },
        created_at: row.get(21)?,
        updated_at: row.get(22)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db() -> (tempfile::TempDir, PanelDb) {
        let dir = tempfile::tempdir().unwrap();
        let db = PanelDb::open(&dir.path().join("panel.db")).unwrap();
        (dir, db)
    }

    #[test]
    fn create_and_authenticate() {
        let (_dir, db) = temp_db();
        let user = db
            .create_user(
                "admin",
                "admin@example.com",
                "Very-Strong-Pass1",
                Role::Owner,
            )
            .unwrap();
        assert_eq!(user.username, "admin");
        assert!(db
            .authenticate("admin", "Very-Strong-Pass1")
            .unwrap()
            .is_some());
        assert!(db
            .authenticate("admin", "wrong-password")
            .unwrap()
            .is_none());
        assert!(db
            .authenticate("ghost", "Very-Strong-Pass1")
            .unwrap()
            .is_none());
    }

    #[test]
    fn stores_user_locale() {
        let (_dir, db) = temp_db();
        let user = db
            .create_user(
                "admin",
                "admin@example.com",
                "Very-Strong-Pass1",
                Role::Owner,
            )
            .unwrap();
        assert_eq!(user.locale, None);
        db.set_user_locale("admin", Some("fr")).unwrap();
        assert_eq!(
            db.find_user("admin").unwrap().unwrap().locale.as_deref(),
            Some("fr")
        );
        assert_eq!(
            db.find_user_by_email("admin@example.com")
                .unwrap()
                .unwrap()
                .locale
                .as_deref(),
            Some("fr")
        );
        db.set_user_locale("admin", None).unwrap();
        assert_eq!(db.find_user("admin").unwrap().unwrap().locale, None);
    }

    #[test]
    fn latest_admin_locale_follows_most_recent_session() {
        let (_dir, db) = temp_db();
        let owner = db
            .create_user(
                "owner",
                "owner@example.com",
                "Very-Strong-Pass1",
                Role::Owner,
            )
            .unwrap();
        db.set_user_locale("owner", Some("en")).unwrap();
        let admin = db
            .create_user(
                "admin",
                "admin@example.com",
                "Very-Strong-Pass1",
                Role::Admin,
            )
            .unwrap();
        db.set_user_locale("admin", Some("es")).unwrap();

        db.create_session(&owner.id, 3600, "", "", None).unwrap();
        assert_eq!(db.latest_admin_locale().unwrap().as_deref(), Some("en"));

        db.create_session(&admin.id, 3600, "", "", None).unwrap();
        assert_eq!(db.latest_admin_locale().unwrap().as_deref(), Some("es"));
    }

    #[test]
    fn email_uniqueness_is_case_insensitive_and_enforced_by_index() {
        let (_dir, db) = temp_db();
        db.create_user(
            "admin",
            "Admin@Example.com",
            "Very-Strong-Pass1",
            Role::Owner,
        )
        .unwrap();
        assert!(matches!(
            db.create_user(
                "other",
                "admin@example.com",
                "Very-Strong-Pass1",
                Role::Viewer
            ),
            Err(PanelError::Conflict(_))
        ));
        let conn = db.conn().unwrap();
        let indexes: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master \
                 WHERE type = 'index' AND name = 'idx_panel_users_email_lower_unique'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(indexes, 1);
    }

    #[test]
    fn links_account_users_and_checks_email() {
        let (_dir, db) = temp_db();
        let policy = PasswordPolicy::default();
        let user = db
            .create_account_user(
                &policy,
                "acme",
                "acme@example.com",
                "Very-Strong-Pass1",
                Role::Viewer,
                "acme",
            )
            .unwrap();
        assert_eq!(user.account.as_deref(), Some("acme"));
        assert!(db.email_exists("ACME@example.com").unwrap());
        assert_eq!(
            db.find_user_by_account("acme").unwrap().unwrap().username,
            "acme"
        );
        assert!(db.find_user_by_email("acme@example.com").unwrap().is_some());
        assert!(matches!(
            db.create_user("bob", "acme@example.com", "Very-Strong-Pass1", Role::Viewer),
            Err(PanelError::Conflict(_))
        ));
    }

    #[test]
    fn rejects_duplicate_and_weak_password() {
        let (_dir, db) = temp_db();
        db.create_user(
            "admin",
            "admin@example.com",
            "Very-Strong-Pass1",
            Role::Owner,
        )
        .unwrap();
        assert!(matches!(
            db.create_user(
                "admin",
                "other@example.com",
                "Very-Strong-Pass1",
                Role::Admin
            ),
            Err(PanelError::Conflict(_))
        ));
        assert!(matches!(
            db.create_user("bob", "bob@example.com", "short", Role::Admin),
            Err(PanelError::Validation(_))
        ));
    }

    #[test]
    fn session_lifecycle() {
        let (_dir, db) = temp_db();
        let user = db
            .create_user(
                "admin",
                "admin@example.com",
                "Very-Strong-Pass1",
                Role::Owner,
            )
            .unwrap();
        let session = db
            .create_session(&user.id, 3600, "127.0.0.1", "test", None)
            .unwrap();
        let ctx = db.lookup_session(&session.token, 3600).unwrap().unwrap();
        assert_eq!(ctx.user.username, "admin");
        assert_eq!(ctx.csrf_token, session.csrf_token);
        db.delete_session(&session.token).unwrap();
        assert!(db.lookup_session(&session.token, 3600).unwrap().is_none());
    }

    #[test]
    fn password_change_revokes_sessions() {
        let (_dir, db) = temp_db();
        let user = db
            .create_user(
                "admin",
                "admin@example.com",
                "Very-Strong-Pass1",
                Role::Owner,
            )
            .unwrap();
        let session = db
            .create_session(&user.id, 3600, "127.0.0.1", "test", None)
            .unwrap();
        db.set_password("admin", "Another-Strong-Pass2").unwrap();
        assert!(db.lookup_session(&session.token, 3600).unwrap().is_none());
        assert!(db
            .authenticate("admin", "Another-Strong-Pass2")
            .unwrap()
            .is_some());
    }

    #[test]
    fn password_reset_tokens_are_single_use() {
        let (_dir, db) = temp_db();
        let user = db
            .create_user(
                "admin",
                "admin@example.com",
                "Very-Strong-Pass1",
                Role::Owner,
            )
            .unwrap();
        let session = db
            .create_session(&user.id, 3600, "127.0.0.1", "test", None)
            .unwrap();
        let (token, target) = db
            .create_password_reset("ADMIN@example.com", 3600)
            .unwrap()
            .unwrap();
        assert_eq!(target.username, "admin");
        assert!(db
            .create_password_reset("ghost@example.com", 3600)
            .unwrap()
            .is_none());
        assert_eq!(
            db.consume_password_reset(&PasswordPolicy::default(), &token, "Reset-Strong-Pass2")
                .unwrap()
                .as_deref(),
            Some("admin")
        );
        assert!(db.lookup_session(&session.token, 3600).unwrap().is_none());
        assert!(db
            .authenticate("admin", "Reset-Strong-Pass2")
            .unwrap()
            .is_some());
        assert!(db
            .consume_password_reset(&PasswordPolicy::default(), &token, "Again-Strong-Pass3")
            .unwrap()
            .is_none());
    }

    #[test]
    fn new_reset_token_invalidates_previous_one() {
        let (_dir, db) = temp_db();
        db.create_user(
            "admin",
            "admin@example.com",
            "Very-Strong-Pass1",
            Role::Owner,
        )
        .unwrap();
        let (first, _) = db
            .create_password_reset("admin@example.com", 3600)
            .unwrap()
            .unwrap();
        let (second, _) = db
            .create_password_reset("admin@example.com", 3600)
            .unwrap()
            .unwrap();
        assert_ne!(first, second);
        assert!(db
            .consume_password_reset(&PasswordPolicy::default(), &first, "Reset-Strong-Pass2")
            .unwrap()
            .is_none());
        assert!(db
            .consume_password_reset(&PasswordPolicy::default(), &second, "Reset-Strong-Pass2")
            .unwrap()
            .is_some());
    }

    #[test]
    fn seeds_the_default_package() {
        let (_dir, db) = temp_db();
        let packages = db.list_packages().unwrap();
        assert_eq!(packages.len(), 1);
        let default = &packages[0];
        assert!(default.is_default);
        assert_eq!(default.package.name, "Por defecto");
        assert_eq!(default.package.backups, 3);
        assert_eq!(default.package.mail_rate_limit, 200);
        assert_eq!(
            default.package.nameservers,
            vec!["ns1.example.tld", "ns2.example.tld"]
        );
    }

    #[test]
    fn creates_updates_and_protects_packages() {
        let (_dir, db) = temp_db();
        let mut input = default_package();
        input.name = "Starter".into();
        input.account_mb = 500;
        let created = db.create_package(input).unwrap();
        assert!(!created.is_default);
        assert_eq!(created.package.account_mb, 500);

        let mut update = created.package.clone();
        update.mail_accounts = 25;
        let updated = db.update_package(&created.id, update).unwrap();
        assert_eq!(updated.package.mail_accounts, 25);

        let mut duplicate = default_package();
        duplicate.name = "starter".into();
        assert!(matches!(
            db.create_package(duplicate),
            Err(PanelError::Conflict(_))
        ));

        db.delete_package(&created.id).unwrap();
        let default_id = db.list_packages().unwrap()[0].id.clone();
        assert!(matches!(
            db.delete_package(&default_id),
            Err(PanelError::Conflict(_))
        ));
    }

    #[test]
    fn assigns_packages_and_blocks_in_use_deletion() {
        let (_dir, db) = temp_db();
        let default = db.list_packages().unwrap()[0].clone();
        let assignment = db.set_account_package("acme", &default.id, "php").unwrap();
        assert_eq!(assignment.package_name, "Por defecto");
        assert!(db.package_is_assigned(&default.id).unwrap());
        assert_eq!(
            db.get_account_package("acme").unwrap().unwrap().web_backend,
            "php"
        );
        assert_eq!(
            db.set_account_package("acme", &default.id, "node")
                .unwrap()
                .web_backend,
            "node"
        );
        assert!(matches!(
            db.set_account_package("acme", &default.id, "perl"),
            Err(PanelError::Validation(_))
        ));

        let mut input = default_package();
        input.name = "Custom".into();
        let custom = db.create_package(input).unwrap();
        db.set_account_package("acme", &custom.id, "php").unwrap();
        assert!(matches!(
            db.delete_package(&custom.id),
            Err(PanelError::Conflict(_))
        ));
        db.delete_account_package("acme").unwrap();
        assert!(db.delete_package(&custom.id).is_ok());
    }

    #[test]
    fn passkey_lifecycle() {
        let (_dir, db) = temp_db();
        let user = db
            .create_user(
                "admin",
                "admin@example.com",
                "Very-Strong-Pass1",
                Role::Owner,
            )
            .unwrap();
        assert_eq!(db.count_passkeys(&user.id).unwrap(), 0);

        let created = db
            .create_passkey(&user.id, "Laptop", "credential-1", "{\"cred\":1}")
            .unwrap();
        assert_eq!(db.count_passkeys(&user.id).unwrap(), 1);
        assert_eq!(db.list_passkeys(&user.id).unwrap()[0].name, "Laptop");

        let stored = db.list_passkey_credentials(&user.id).unwrap();
        assert_eq!(stored[0].credential_id, "credential-1");
        assert_eq!(stored[0].credential, "{\"cred\":1}");

        db.touch_passkey(&user.id, "credential-1", Some("{\"cred\":2}"))
            .unwrap();
        assert!(db.list_passkeys(&user.id).unwrap()[0]
            .last_used_at
            .is_some());
        assert_eq!(
            db.list_passkey_credentials(&user.id).unwrap()[0].credential,
            "{\"cred\":2}"
        );

        assert!(db.delete_passkey(&user.id, &created.id).unwrap());
        assert_eq!(db.count_passkeys(&user.id).unwrap(), 0);
    }

    #[test]
    fn agent_findings_dedupe_and_track_status() {
        let (_dir, db) = temp_db();
        let input = AgentFindingInput {
            fingerprint: "rule:target".into(),
            severity: "high".into(),
            category: "security".into(),
            title: "Test finding".into(),
            summary: "first summary".into(),
            evidence: vec!["evidence one".into()],
            recommendation: "do something".into(),
            source: "rules".into(),
        };
        let (first, is_new, escalated, reopened) = db.upsert_agent_finding(&input).unwrap();
        assert!(is_new);
        assert!(!escalated);
        assert!(!reopened);
        assert_eq!(first.occurrences, 1);
        assert_eq!(first.status, "open");

        let mut updated = input.clone();
        updated.summary = "second summary".into();
        updated.severity = "critical".into();
        let (second, is_new, escalated, reopened) = db.upsert_agent_finding(&updated).unwrap();
        assert!(!is_new);
        assert!(escalated);
        assert!(!reopened);
        assert_eq!(second.id, first.id);
        assert_eq!(second.occurrences, 2);
        assert_eq!(second.summary, "second summary");
        assert_eq!(second.severity, "critical");
        assert_eq!(db.agent_stats().unwrap().critical, 1);

        db.set_agent_finding_status(&first.id, "acknowledged")
            .unwrap();
        let (third, _, _, _) = db.upsert_agent_finding(&input).unwrap();
        assert_eq!(third.status, "acknowledged");

        let resolved = db
            .resolve_stale_agent_findings(now_unix().saturating_add(1))
            .unwrap();
        assert_eq!(resolved, 1);
        let stats = db.agent_stats().unwrap();
        assert_eq!(stats.high, 1);
        assert_eq!(stats.resolved, 1);
        assert_eq!(stats.open, 0);

        let (reopened, is_new, escalated, was_reopened) = db.upsert_agent_finding(&input).unwrap();
        assert!(!is_new);
        assert!(!escalated);
        assert!(was_reopened);
        assert_eq!(reopened.status, "open");
        assert!(matches!(
            db.set_agent_finding_status(&first.id, "unknown"),
            Err(PanelError::Validation(_))
        ));

        let run = AgentRun {
            id: "run-1".into(),
            started_at: now_rfc3339(),
            finished_at: now_rfc3339(),
            status: "ok".into(),
            findings: 1,
            error: String::new(),
            model: "rules".into(),
            summary: "everything is fine".into(),
        };
        db.record_agent_run(&run).unwrap();
        assert_eq!(db.latest_agent_run().unwrap().unwrap().id, "run-1");
    }
}
