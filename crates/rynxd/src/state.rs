//! Durable desired-state for the daemon. Rendered artifacts are derived from
//! this database, so `ReconcileAll` can always repair drift.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

use rynx_core::crypto::{now_rfc3339, now_unix};
use rynx_proto::{
    AccountSpec, AccountView, AppSpec, AppView, BackupView, BlockedIpView, CertificateStatus,
    CronJobView, CronSpec, DatabaseView, DnsRecordSpec, DnsRecordView, FirewallRuleSpec,
    FirewallRuleView, FtpView, MailAccountSpec, MailAccountView, MailDomainSpec, MailDomainView,
    MetricSample, PhpPoolSpec, PhpPoolView, Runtime, TlsMode, WebsiteSpec, WebsiteView,
};

const SCHEMA: &str = r#"
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS accounts (
    username      TEXT PRIMARY KEY,
    id            TEXT NOT NULL,
    email         TEXT NOT NULL,
    disk_limit_mb INTEGER NOT NULL,
    php_version   TEXT,
    enabled       INTEGER NOT NULL,
    ssh_enabled   INTEGER NOT NULL DEFAULT 0,
    uid           INTEGER NOT NULL,
    home          TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    memory_mb     INTEGER NOT NULL DEFAULT 0,
    cpu_percent   INTEGER NOT NULL DEFAULT 0,
    process_limit INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS websites (
    domain        TEXT PRIMARY KEY,
    id            TEXT NOT NULL,
    username      TEXT NOT NULL,
    aliases       TEXT NOT NULL,
    runtime       TEXT NOT NULL,
    app           TEXT,
    docroot       TEXT NOT NULL,
    tls           TEXT NOT NULL,
    enabled       INTEGER NOT NULL,
    document_root TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    force_https   INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_websites_user ON websites(username);

CREATE TABLE IF NOT EXISTS mail_domains (
    domain     TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    enabled    INTEGER NOT NULL,
    catch_all  TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mail_domains_user ON mail_domains(username);

CREATE TABLE IF NOT EXISTS mail_accounts (
    id            TEXT PRIMARY KEY,
    domain        TEXT NOT NULL,
    username      TEXT NOT NULL,
    local_part    TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    quota_mb      INTEGER NOT NULL,
    enabled       INTEGER NOT NULL,
    aliases       TEXT NOT NULL,
    forward_to    TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    UNIQUE(domain, local_part)
);
CREATE INDEX IF NOT EXISTS idx_mail_accounts_domain ON mail_accounts(domain);

CREATE TABLE IF NOT EXISTS php_pools (
    username        TEXT PRIMARY KEY,
    version         TEXT NOT NULL,
    process_manager TEXT NOT NULL,
    max_children    INTEGER NOT NULL,
    memory_limit_mb INTEGER NOT NULL,
    upload_max_mb   INTEGER NOT NULL,
    enabled         INTEGER NOT NULL,
    socket          TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS apps (
    username    TEXT NOT NULL,
    name        TEXT NOT NULL,
    runtime     TEXT NOT NULL,
    port        INTEGER NOT NULL,
    entrypoint  TEXT NOT NULL,
    command     TEXT NOT NULL,
    args        TEXT NOT NULL,
    env         TEXT NOT NULL,
    enabled     INTEGER NOT NULL,
    unit        TEXT NOT NULL,
    working_dir TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (username, name)
);
CREATE INDEX IF NOT EXISTS idx_apps_port ON apps(port);

CREATE TABLE IF NOT EXISTS backups (
    id         TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    created_at TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    path       TEXT NOT NULL,
    status     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_backups_user ON backups(username, created_at);

CREATE TABLE IF NOT EXISTS cron_jobs (
    id         TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    schedule   TEXT NOT NULL,
    command    TEXT NOT NULL,
    enabled    INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cron_jobs_user ON cron_jobs(username, created_at);

CREATE TABLE IF NOT EXISTS metrics (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    at              TEXT NOT NULL,
    at_unix         INTEGER NOT NULL,
    load1           INTEGER NOT NULL,
    mem_used_kb     INTEGER NOT NULL,
    disk_used_kb    INTEGER NOT NULL,
    services_active INTEGER NOT NULL,
    services_total  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_metrics_at ON metrics(at_unix);

CREATE TABLE IF NOT EXISTS dns_zones (
    domain        TEXT PRIMARY KEY,
    serial        INTEGER NOT NULL,
    mail_ready    INTEGER NOT NULL,
    dkim_selector TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dns_records (
    id         TEXT PRIMARY KEY,
    domain     TEXT NOT NULL,
    name       TEXT NOT NULL,
    rtype      TEXT NOT NULL,
    value      TEXT NOT NULL,
    ttl        INTEGER NOT NULL,
    priority   INTEGER,
    managed    INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dns_records_domain ON dns_records(domain);

CREATE TABLE IF NOT EXISTS databases (
    id         TEXT PRIMARY KEY,
    domain     TEXT NOT NULL,
    username   TEXT NOT NULL UNIQUE,
    password   TEXT NOT NULL,
    engine     TEXT NOT NULL,
    host       TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS firewall_rules (
    id         TEXT PRIMARY KEY,
    action     TEXT NOT NULL,
    proto      TEXT NOT NULL,
    port       INTEGER NOT NULL,
    source     TEXT,
    comment    TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    ip         TEXT PRIMARY KEY,
    reason     TEXT NOT NULL,
    source     TEXT NOT NULL,
    expires_at INTEGER,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS whitelist_ips (
    ip         TEXT PRIMARY KEY,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ftp_accounts (
    id         TEXT PRIMARY KEY,
    domain     TEXT NOT NULL,
    login      TEXT NOT NULL UNIQUE,
    home       TEXT NOT NULL,
    readonly   INTEGER NOT NULL,
    password   TEXT NOT NULL,
    uid        INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
"#;

#[derive(Clone)]
pub struct StateStore {
    path: PathBuf,
}

fn to_json<T: Serialize>(value: &T) -> Result<String> {
    Ok(serde_json::to_string(value)?)
}

fn map_account(row: &rusqlite::Row<'_>) -> rusqlite::Result<AccountView> {
    let username: String = row.get(0)?;
    Ok(AccountView {
        id: row.get(1)?,
        spec: AccountSpec {
            username,
            email: row.get(2)?,
            disk_limit_mb: row.get::<_, i64>(3)? as u64,
            memory_mb: row.get::<_, i64>(11)? as u64,
            cpu_percent: row.get::<_, i64>(12)? as u64,
            process_limit: row.get::<_, i64>(13)? as u64,
            php_version: row.get(4)?,
            enabled: row.get::<_, i64>(5)? != 0,
            ssh_enabled: row.get::<_, i64>(6)? != 0,
        },
        uid: row.get::<_, i64>(7)? as u32,
        home: row.get(8)?,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
    })
}

impl StateStore {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create state dir {}", parent.display()))?;
        }
        let store = Self {
            path: path.to_path_buf(),
        };
        let conn = store.conn()?;
        conn.execute_batch(SCHEMA)?;
        let has_force_https: i64 = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('websites') WHERE name = 'force_https'",
            [],
            |row| row.get(0),
        )?;
        if has_force_https == 0 {
            conn.execute(
                "ALTER TABLE websites ADD COLUMN force_https INTEGER NOT NULL DEFAULT 1",
                [],
            )?;
        }
        let has_ssh_enabled: i64 = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('accounts') WHERE name = 'ssh_enabled'",
            [],
            |row| row.get(0),
        )?;
        if has_ssh_enabled == 0 {
            conn.execute(
                "ALTER TABLE accounts ADD COLUMN ssh_enabled INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        for column in ["memory_mb", "cpu_percent", "process_limit"] {
            let exists: i64 = conn.query_row(
                "SELECT COUNT(*) FROM pragma_table_info('accounts') WHERE name = ?1",
                params![column],
                |row| row.get(0),
            )?;
            if exists == 0 {
                conn.execute(
                    &format!("ALTER TABLE accounts ADD COLUMN {column} INTEGER NOT NULL DEFAULT 0"),
                    [],
                )?;
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(store)
    }

    fn conn(&self) -> Result<Connection> {
        let conn = Connection::open(&self.path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        Ok(conn)
    }

    pub fn list_accounts(&self) -> Result<Vec<AccountView>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT username, id, email, disk_limit_mb, php_version, enabled, ssh_enabled, uid, home, created_at, updated_at, memory_mb, cpu_percent, process_limit \
             FROM accounts ORDER BY username",
        )?;
        let rows = stmt.query_map([], map_account)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn get_account(&self, username: &str) -> Result<Option<AccountView>> {
        let conn = self.conn()?;
        Ok(conn
            .query_row(
                "SELECT username, id, email, disk_limit_mb, php_version, enabled, ssh_enabled, uid, home, created_at, updated_at, memory_mb, cpu_percent, process_limit \
                 FROM accounts WHERE username = ?1",
                params![username],
                map_account,
            )
            .optional()?)
    }

    pub fn max_uid(&self) -> Result<Option<u32>> {
        let conn = self.conn()?;
        let value: Option<i64> =
            conn.query_row("SELECT MAX(uid) FROM accounts", [], |row| row.get(0))?;
        Ok(value.map(|v| v as u32))
    }

    pub fn upsert_account(&self, spec: &AccountSpec, uid: u32, home: &str) -> Result<AccountView> {
        let now = now_rfc3339();
        let existing = self.get_account(&spec.username)?;
        let (id, created_at) = match &existing {
            Some(view) => (view.id.clone(), view.created_at.clone()),
            None => (uuid::Uuid::new_v4().to_string(), now.clone()),
        };
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO accounts (username, id, email, disk_limit_mb, php_version, enabled, ssh_enabled, uid, home, created_at, updated_at, memory_mb, cpu_percent, process_limit) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14) \
             ON CONFLICT(username) DO UPDATE SET \
               email = excluded.email, disk_limit_mb = excluded.disk_limit_mb, \
               memory_mb = excluded.memory_mb, cpu_percent = excluded.cpu_percent, \
               process_limit = excluded.process_limit, \
               php_version = excluded.php_version, enabled = excluded.enabled, \
               ssh_enabled = excluded.ssh_enabled, uid = excluded.uid, \
               home = excluded.home, updated_at = excluded.updated_at",
            params![
                spec.username,
                id,
                spec.email,
                spec.disk_limit_mb as i64,
                spec.php_version,
                if spec.enabled { 1 } else { 0 },
                if spec.ssh_enabled { 1 } else { 0 },
                uid as i64,
                home,
                created_at,
                now,
                spec.memory_mb as i64,
                spec.cpu_percent as i64,
                spec.process_limit as i64,
            ],
        )?;
        Ok(AccountView {
            id,
            spec: spec.clone(),
            uid,
            home: home.to_string(),
            created_at,
            updated_at: now,
        })
    }

    pub fn delete_account(&self, username: &str) -> Result<()> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM websites WHERE username = ?1",
            params![username],
        )?;
        tx.execute(
            "DELETE FROM php_pools WHERE username = ?1",
            params![username],
        )?;
        tx.execute("DELETE FROM apps WHERE username = ?1", params![username])?;
        tx.execute(
            "DELETE FROM accounts WHERE username = ?1",
            params![username],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn list_websites(&self) -> Result<Vec<WebsiteView>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT domain, id, username, aliases, runtime, app, docroot, tls, enabled, document_root, created_at, updated_at, force_https \
             FROM websites ORDER BY domain",
        )?;
        let rows = stmt.query_map([], map_website)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn get_website(&self, domain: &str) -> Result<Option<WebsiteView>> {
        let conn = self.conn()?;
        Ok(conn
            .query_row(
                "SELECT domain, id, username, aliases, runtime, app, docroot, tls, enabled, document_root, created_at, updated_at, force_https \
                 FROM websites WHERE domain = ?1",
                params![domain],
                map_website,
            )
            .optional()?)
    }

    pub fn upsert_website(&self, spec: &WebsiteSpec, document_root: &str) -> Result<WebsiteView> {
        let now = now_rfc3339();
        let existing = self.get_website(&spec.domain)?;
        let (id, created_at) = match &existing {
            Some(view) => (view.id.clone(), view.created_at.clone()),
            None => (uuid::Uuid::new_v4().to_string(), now.clone()),
        };
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO websites (domain, id, username, aliases, runtime, app, docroot, tls, enabled, document_root, created_at, updated_at, force_https) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13) \
             ON CONFLICT(domain) DO UPDATE SET \
               username = excluded.username, aliases = excluded.aliases, runtime = excluded.runtime, \
               app = excluded.app, docroot = excluded.docroot, tls = excluded.tls, \
               enabled = excluded.enabled, document_root = excluded.document_root, \
               force_https = excluded.force_https, updated_at = excluded.updated_at",
            params![
                spec.domain,
                id,
                spec.username,
                to_json(&spec.aliases)?,
                to_json(&spec.runtime)?,
                spec.app,
                spec.docroot,
                to_json(&spec.tls)?,
                if spec.enabled { 1 } else { 0 },
                document_root,
                created_at,
                now,
                if spec.force_https { 1 } else { 0 }
            ],
        )?;
        Ok(WebsiteView {
            id,
            spec: spec.clone(),
            document_root: document_root.to_string(),
            created_at,
            updated_at: now,
        })
    }

    pub fn delete_website(&self, domain: &str) -> Result<()> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM websites WHERE domain = ?1", params![domain])?;
        Ok(())
    }

    pub fn list_mail_domains(&self) -> Result<Vec<MailDomainView>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT domain, username, enabled, catch_all, created_at, updated_at \
             FROM mail_domains ORDER BY domain",
        )?;
        let rows = stmt.query_map([], map_mail_domain)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn get_mail_domain(&self, domain: &str) -> Result<Option<MailDomainView>> {
        let conn = self.conn()?;
        Ok(conn
            .query_row(
                "SELECT domain, username, enabled, catch_all, created_at, updated_at \
                 FROM mail_domains WHERE domain = ?1",
                params![domain],
                map_mail_domain,
            )
            .optional()?)
    }

    pub fn upsert_mail_domain(&self, spec: &MailDomainSpec) -> Result<MailDomainView> {
        let now = now_rfc3339();
        let existing = self.get_mail_domain(&spec.domain)?;
        let created_at = existing
            .as_ref()
            .map(|view| view.created_at.clone())
            .unwrap_or_else(|| now.clone());
        let catch_all = spec
            .catch_all
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO mail_domains (domain, username, enabled, catch_all, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
             ON CONFLICT(domain) DO UPDATE SET \
               username = excluded.username, enabled = excluded.enabled, \
               catch_all = excluded.catch_all, updated_at = excluded.updated_at",
            params![
                spec.domain,
                spec.username,
                spec.enabled as i64,
                catch_all,
                created_at,
                now
            ],
        )?;
        self.get_mail_domain(&spec.domain)?
            .ok_or_else(|| anyhow::anyhow!("mail domain disappeared after upsert"))
    }

    pub fn delete_mail_domain(&self, domain: &str) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "DELETE FROM mail_accounts WHERE domain = ?1",
            params![domain],
        )?;
        conn.execute(
            "DELETE FROM mail_domains WHERE domain = ?1",
            params![domain],
        )?;
        Ok(())
    }

    pub fn list_mail_accounts(&self) -> Result<Vec<MailAccountView>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, domain, username, local_part, quota_mb, enabled, aliases, forward_to, created_at, updated_at \
             FROM mail_accounts ORDER BY domain, local_part",
        )?;
        let rows = stmt.query_map([], map_mail_account)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn list_mail_accounts_for_domain(&self, domain: &str) -> Result<Vec<MailAccountView>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, domain, username, local_part, quota_mb, enabled, aliases, forward_to, created_at, updated_at \
             FROM mail_accounts WHERE domain = ?1 ORDER BY local_part",
        )?;
        let rows = stmt.query_map(params![domain], map_mail_account)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn mail_account_hash(&self, id: &str) -> Result<Option<String>> {
        let conn = self.conn()?;
        Ok(conn
            .query_row(
                "SELECT password_hash FROM mail_accounts WHERE id = ?1",
                params![id],
                |row| row.get::<_, String>(0),
            )
            .optional()?)
    }

    pub fn get_mail_account(&self, id: &str) -> Result<Option<MailAccountView>> {
        let conn = self.conn()?;
        Ok(conn
            .query_row(
                "SELECT id, domain, username, local_part, quota_mb, enabled, aliases, forward_to, created_at, updated_at \
                 FROM mail_accounts WHERE id = ?1",
                params![id],
                map_mail_account,
            )
            .optional()?)
    }

    pub fn find_mail_account(
        &self,
        domain: &str,
        local_part: &str,
    ) -> Result<Option<MailAccountView>> {
        let conn = self.conn()?;
        Ok(conn
            .query_row(
                "SELECT id, domain, username, local_part, quota_mb, enabled, aliases, forward_to, created_at, updated_at \
                 FROM mail_accounts WHERE domain = ?1 AND local_part = ?2",
                params![domain, local_part],
                map_mail_account,
            )
            .optional()?)
    }

    pub fn upsert_mail_account(
        &self,
        spec: &MailAccountSpec,
        username: &str,
        password_hash: Option<&str>,
    ) -> Result<MailAccountView> {
        let now = now_rfc3339();
        let existing = match &spec.id {
            Some(id) => self.get_mail_account(id)?,
            None => self.find_mail_account(&spec.domain, &spec.local_part)?,
        };
        let existing_hash = if let Some(view) = &existing {
            let conn = self.conn()?;
            conn.query_row(
                "SELECT password_hash FROM mail_accounts WHERE id = ?1",
                params![view.id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        } else {
            None
        };
        let hash = password_hash
            .map(str::to_string)
            .or(existing_hash)
            .ok_or_else(|| anyhow::anyhow!("mailbox password is required"))?;
        let id = spec
            .id
            .clone()
            .or_else(|| existing.as_ref().map(|view| view.id.clone()))
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let created_at = existing
            .as_ref()
            .map(|view| view.created_at.clone())
            .unwrap_or_else(|| now.clone());
        let aliases = serde_json::to_string(&spec.aliases).unwrap_or_else(|_| "[]".into());
        let forward_to = serde_json::to_string(&spec.forward_to).unwrap_or_else(|_| "[]".into());
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO mail_accounts \
               (id, domain, username, local_part, password_hash, quota_mb, enabled, aliases, forward_to, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11) \
             ON CONFLICT(id) DO UPDATE SET \
               domain = excluded.domain, username = excluded.username, local_part = excluded.local_part, \
               password_hash = excluded.password_hash, quota_mb = excluded.quota_mb, enabled = excluded.enabled, \
               aliases = excluded.aliases, forward_to = excluded.forward_to, updated_at = excluded.updated_at",
            params![
                id,
                spec.domain,
                username,
                spec.local_part,
                hash,
                spec.quota_mb as i64,
                spec.enabled as i64,
                aliases,
                forward_to,
                created_at,
                now
            ],
        )?;
        self.get_mail_account(&id)?
            .ok_or_else(|| anyhow::anyhow!("mailbox disappeared after upsert"))
    }

    pub fn delete_mail_account(&self, id: &str) -> Result<Option<MailAccountView>> {
        let existing = self.get_mail_account(id)?;
        if existing.is_some() {
            let conn = self.conn()?;
            conn.execute("DELETE FROM mail_accounts WHERE id = ?1", params![id])?;
        }
        Ok(existing)
    }

    pub fn list_php_pools(&self) -> Result<Vec<PhpPoolView>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT username, version, process_manager, max_children, memory_limit_mb, upload_max_mb, enabled, socket, updated_at \
             FROM php_pools ORDER BY username",
        )?;
        let rows = stmt.query_map([], map_php_pool)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn get_php_pool(&self, username: &str) -> Result<Option<PhpPoolView>> {
        let conn = self.conn()?;
        Ok(conn
            .query_row(
                "SELECT username, version, process_manager, max_children, memory_limit_mb, upload_max_mb, enabled, socket, updated_at \
                 FROM php_pools WHERE username = ?1",
                params![username],
                map_php_pool,
            )
            .optional()?)
    }

    pub fn upsert_php_pool(&self, spec: &PhpPoolSpec, socket: &str) -> Result<PhpPoolView> {
        let now = now_rfc3339();
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO php_pools (username, version, process_manager, max_children, memory_limit_mb, upload_max_mb, enabled, socket, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) \
             ON CONFLICT(username) DO UPDATE SET \
               version = excluded.version, process_manager = excluded.process_manager, \
               max_children = excluded.max_children, memory_limit_mb = excluded.memory_limit_mb, \
               upload_max_mb = excluded.upload_max_mb, enabled = excluded.enabled, \
               socket = excluded.socket, updated_at = excluded.updated_at",
            params![
                spec.username,
                spec.version,
                spec.process_manager.as_str(),
                spec.max_children as i64,
                spec.memory_limit_mb as i64,
                spec.upload_max_mb as i64,
                if spec.enabled { 1 } else { 0 },
                socket,
                now
            ],
        )?;
        Ok(PhpPoolView {
            username: spec.username.clone(),
            spec: spec.clone(),
            socket: socket.to_string(),
            updated_at: now,
        })
    }

    pub fn delete_php_pool(&self, username: &str) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "DELETE FROM php_pools WHERE username = ?1",
            params![username],
        )?;
        Ok(())
    }

    pub fn list_apps(&self) -> Result<Vec<AppView>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT username, name, runtime, port, entrypoint, command, args, env, enabled, unit, working_dir, created_at, updated_at \
             FROM apps ORDER BY username, name",
        )?;
        let rows = stmt.query_map([], map_app)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn get_app(&self, username: &str, name: &str) -> Result<Option<AppView>> {
        let conn = self.conn()?;
        Ok(conn
            .query_row(
                "SELECT username, name, runtime, port, entrypoint, command, args, env, enabled, unit, working_dir, created_at, updated_at \
                 FROM apps WHERE username = ?1 AND name = ?2",
                params![username, name],
                map_app,
            )
            .optional()?)
    }

    pub fn upsert_app(&self, spec: &AppSpec, unit: &str, working_dir: &str) -> Result<AppView> {
        let now = now_rfc3339();
        let existing = self.get_app(&spec.username, &spec.name)?;
        let created_at = existing
            .as_ref()
            .map(|view| view.created_at.clone())
            .unwrap_or_else(|| now.clone());
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO apps (username, name, runtime, port, entrypoint, command, args, env, enabled, unit, working_dir, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13) \
             ON CONFLICT(username, name) DO UPDATE SET \
               runtime = excluded.runtime, port = excluded.port, entrypoint = excluded.entrypoint, \
               command = excluded.command, args = excluded.args, env = excluded.env, \
               enabled = excluded.enabled, unit = excluded.unit, working_dir = excluded.working_dir, \
               updated_at = excluded.updated_at",
            params![
                spec.username,
                spec.name,
                to_json(&spec.runtime)?,
                spec.port as i64,
                spec.entrypoint,
                spec.command,
                to_json(&spec.args)?,
                to_json(&spec.env)?,
                if spec.enabled { 1 } else { 0 },
                unit,
                working_dir,
                created_at,
                now
            ],
        )?;
        Ok(AppView {
            id: format!("{}/{}", spec.username, spec.name),
            spec: spec.clone(),
            unit: unit.to_string(),
            working_dir: working_dir.to_string(),
            created_at,
            updated_at: now,
        })
    }

    pub fn delete_app(&self, username: &str, name: &str) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "DELETE FROM apps WHERE username = ?1 AND name = ?2",
            params![username, name],
        )?;
        Ok(())
    }

    pub fn websites_using_app(&self, username: &str, name: &str) -> Result<Vec<String>> {
        let websites = self.list_websites()?;
        Ok(websites
            .into_iter()
            .filter(|w| w.spec.username == username && w.spec.app.as_deref() == Some(name))
            .map(|w| w.spec.domain)
            .collect())
    }

    pub fn port_in_use(
        &self,
        port: u16,
        exclude_username: &str,
        exclude_name: &str,
    ) -> Result<bool> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM apps WHERE port = ?1 AND NOT (username = ?2 AND name = ?3)",
            params![port as i64, exclude_username, exclude_name],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    pub fn count_websites(&self, username: &str) -> Result<usize> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM websites WHERE username = ?1",
            params![username],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    pub fn count_apps(&self, username: &str) -> Result<usize> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM apps WHERE username = ?1",
            params![username],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    pub fn insert_backup(&self, backup: &BackupView) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO backups (id, username, created_at, size_bytes, path, status) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                backup.id,
                backup.username,
                backup.created_at,
                backup.size_bytes as i64,
                backup.path,
                backup.status
            ],
        )?;
        Ok(())
    }

    pub fn list_backups(&self) -> Result<Vec<BackupView>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, username, created_at, size_bytes, path, status \
             FROM backups ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], map_backup)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn backups_for(&self, username: &str) -> Result<Vec<BackupView>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, username, created_at, size_bytes, path, status \
             FROM backups WHERE username = ?1 ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map(params![username], map_backup)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn get_backup(&self, id: &str) -> Result<Option<BackupView>> {
        let conn = self.conn()?;
        Ok(conn
            .query_row(
                "SELECT id, username, created_at, size_bytes, path, status \
                 FROM backups WHERE id = ?1",
                params![id],
                map_backup,
            )
            .optional()?)
    }

    pub fn delete_backup(&self, id: &str) -> Result<()> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM backups WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn upsert_cron(&self, spec: &CronSpec) -> Result<CronJobView> {
        let now = now_rfc3339();
        let existing = match &spec.id {
            Some(id) => self.get_cron(id)?,
            None => None,
        };
        let id = spec
            .id
            .clone()
            .or_else(|| existing.as_ref().map(|job| job.id.clone()))
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let created_at = existing
            .as_ref()
            .map(|job| job.created_at.clone())
            .unwrap_or_else(|| now.clone());
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO cron_jobs (id, username, schedule, command, enabled, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
             ON CONFLICT(id) DO UPDATE SET username = excluded.username, \
                 schedule = excluded.schedule, command = excluded.command, \
                 enabled = excluded.enabled, updated_at = excluded.updated_at",
            params![
                id,
                spec.username,
                spec.schedule,
                spec.command,
                if spec.enabled { 1 } else { 0 },
                created_at,
                now
            ],
        )?;
        self.get_cron(&id)?
            .ok_or_else(|| anyhow::anyhow!("cron job disappeared after upsert"))
    }

    pub fn list_cron(&self) -> Result<Vec<CronJobView>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, username, schedule, command, enabled, created_at, updated_at \
             FROM cron_jobs ORDER BY username, created_at",
        )?;
        let rows = stmt.query_map([], map_cron)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn cron_for(&self, username: &str) -> Result<Vec<CronJobView>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, username, schedule, command, enabled, created_at, updated_at \
             FROM cron_jobs WHERE username = ?1 ORDER BY created_at",
        )?;
        let rows = stmt.query_map(params![username], map_cron)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn get_cron(&self, id: &str) -> Result<Option<CronJobView>> {
        let conn = self.conn()?;
        Ok(conn
            .query_row(
                "SELECT id, username, schedule, command, enabled, created_at, updated_at \
                 FROM cron_jobs WHERE id = ?1",
                params![id],
                map_cron,
            )
            .optional()?)
    }

    pub fn delete_cron(&self, id: &str) -> Result<()> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM cron_jobs WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn delete_cron_for(&self, username: &str) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "DELETE FROM cron_jobs WHERE username = ?1",
            params![username],
        )?;
        Ok(())
    }

    pub fn cron_count(&self, username: &str) -> Result<usize> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM cron_jobs WHERE username = ?1",
            params![username],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    pub fn insert_metric(&self, sample: &MetricSample) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO metrics (at, at_unix, load1, mem_used_kb, disk_used_kb, services_active, services_total) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                sample.at,
                sample.at_unix,
                sample.load1 as i64,
                sample.mem_used_kb as i64,
                sample.disk_used_kb as i64,
                sample.services_active as i64,
                sample.services_total as i64
            ],
        )?;
        Ok(())
    }

    pub fn list_metrics(&self, since_unix: i64) -> Result<Vec<MetricSample>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT at, at_unix, load1, mem_used_kb, disk_used_kb, services_active, services_total \
             FROM metrics WHERE at_unix >= ?1 ORDER BY at_unix ASC",
        )?;
        let rows = stmt.query_map(params![since_unix], |row| {
            Ok(MetricSample {
                at: row.get(0)?,
                at_unix: row.get(1)?,
                load1: row.get::<_, i64>(2)? as u32,
                mem_used_kb: row.get::<_, i64>(3)? as u64,
                disk_used_kb: row.get::<_, i64>(4)? as u64,
                services_active: row.get::<_, i64>(5)? as u32,
                services_total: row.get::<_, i64>(6)? as u32,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn prune_metrics(&self, before_unix: i64) -> Result<usize> {
        let conn = self.conn()?;
        Ok(conn.execute(
            "DELETE FROM metrics WHERE at_unix < ?1",
            params![before_unix],
        )?)
    }

    pub fn get_dns_zone_meta(&self, domain: &str) -> Result<Option<(u32, bool, String)>> {
        let conn = self.conn()?;
        Ok(conn
            .query_row(
                "SELECT serial, mail_ready, dkim_selector FROM dns_zones WHERE domain = ?1",
                params![domain],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)? as u32,
                        row.get::<_, i64>(1)? != 0,
                        row.get(2)?,
                    ))
                },
            )
            .optional()?)
    }

    pub fn upsert_dns_zone_meta(
        &self,
        domain: &str,
        serial: u32,
        mail_ready: bool,
        dkim_selector: &str,
    ) -> Result<()> {
        let now = now_rfc3339();
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO dns_zones (domain, serial, mail_ready, dkim_selector, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?5) \
             ON CONFLICT(domain) DO UPDATE SET serial = excluded.serial, \
               mail_ready = excluded.mail_ready, dkim_selector = excluded.dkim_selector, \
               updated_at = excluded.updated_at",
            params![
                domain,
                serial as i64,
                if mail_ready { 1 } else { 0 },
                dkim_selector,
                now
            ],
        )?;
        Ok(())
    }

    pub fn list_dns_zone_domains(&self) -> Result<Vec<String>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT domain FROM dns_zones ORDER BY domain")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn delete_dns_zone(&self, domain: &str) -> Result<()> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM dns_records WHERE domain = ?1", params![domain])?;
        tx.execute("DELETE FROM dns_zones WHERE domain = ?1", params![domain])?;
        tx.commit()?;
        Ok(())
    }

    pub fn list_dns_records(&self, domain: &str) -> Result<Vec<DnsRecordView>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, domain, name, rtype, value, ttl, priority, managed \
             FROM dns_records WHERE domain = ?1 ORDER BY name, rtype, id",
        )?;
        let rows = stmt.query_map(params![domain], map_dns_record)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn find_dns_record(
        &self,
        domain: &str,
        name: &str,
        rtype: &str,
    ) -> Result<Option<DnsRecordView>> {
        let conn = self.conn()?;
        Ok(conn
            .query_row(
                "SELECT id, domain, name, rtype, value, ttl, priority, managed \
                 FROM dns_records WHERE domain = ?1 AND name = ?2 AND rtype = ?3 LIMIT 1",
                params![domain, name, rtype],
                map_dns_record,
            )
            .optional()?)
    }

    pub fn upsert_dns_record(
        &self,
        spec: &DnsRecordSpec,
        managed: bool,
        existing_id: Option<&str>,
    ) -> Result<DnsRecordView> {
        let now = now_rfc3339();
        let id = existing_id
            .map(str::to_string)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO dns_records (id, domain, name, rtype, value, ttl, priority, managed, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9) \
             ON CONFLICT(id) DO UPDATE SET value = excluded.value, ttl = excluded.ttl, \
               priority = excluded.priority, managed = excluded.managed, updated_at = excluded.updated_at",
            params![
                id,
                spec.domain,
                spec.name,
                spec.rtype,
                spec.value,
                spec.ttl as i64,
                spec.priority.map(|p| p as i64),
                if managed { 1 } else { 0 },
                now
            ],
        )?;
        Ok(DnsRecordView {
            id,
            spec: spec.clone(),
            managed,
        })
    }

    pub fn delete_dns_record(&self, domain: &str, id: &str) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "DELETE FROM dns_records WHERE domain = ?1 AND id = ?2",
            params![domain, id],
        )?;
        Ok(())
    }

    pub fn insert_database(&self, database: &DatabaseView) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO databases (id, domain, username, password, engine, host, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                database.id,
                database.domain,
                database.username,
                database.password,
                database.engine,
                database.host,
                database.created_at
            ],
        )?;
        Ok(())
    }

    pub fn list_databases(&self) -> Result<Vec<DatabaseView>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, domain, username, password, engine, host, created_at \
             FROM databases ORDER BY domain",
        )?;
        let rows = stmt.query_map([], map_database)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn get_database(&self, id: &str) -> Result<Option<DatabaseView>> {
        let conn = self.conn()?;
        Ok(conn
            .query_row(
                "SELECT id, domain, username, password, engine, host, created_at \
                 FROM databases WHERE id = ?1",
                params![id],
                map_database,
            )
            .optional()?)
    }

    pub fn delete_database(&self, id: &str) -> Result<()> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM databases WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn insert_ftp(&self, account: &FtpView, uid: u32) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO ftp_accounts (id, domain, login, home, readonly, password, uid, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                account.id,
                account.domain,
                account.login,
                account.home,
                if account.readonly { 1 } else { 0 },
                account.password,
                uid as i64,
                account.created_at
            ],
        )?;
        Ok(())
    }

    pub fn list_ftp(&self) -> Result<Vec<FtpView>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, domain, login, home, readonly, password, created_at \
             FROM ftp_accounts ORDER BY domain, login",
        )?;
        let rows = stmt.query_map([], map_ftp)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn set_ftp_home(&self, id: &str, home: &str) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE ftp_accounts SET home = ?1 WHERE id = ?2",
            params![home, id],
        )?;
        Ok(())
    }

    pub fn get_ftp(&self, id: &str) -> Result<Option<FtpView>> {
        let conn = self.conn()?;
        Ok(conn
            .query_row(
                "SELECT id, domain, login, home, readonly, password, created_at \
                 FROM ftp_accounts WHERE id = ?1",
                params![id],
                map_ftp,
            )
            .optional()?)
    }

    pub fn delete_ftp(&self, id: &str) -> Result<()> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM ftp_accounts WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn ftp_login_exists(&self, login: &str) -> Result<bool> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM ftp_accounts WHERE login = ?1",
            params![login],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    pub fn list_firewall_rules(&self) -> Result<Vec<FirewallRuleView>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, action, proto, port, source, comment, created_at \
             FROM firewall_rules ORDER BY created_at",
        )?;
        let rows = stmt.query_map([], map_firewall_rule)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn upsert_firewall_rule(&self, spec: &FirewallRuleSpec) -> Result<FirewallRuleView> {
        let id = spec
            .id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let created_at = self
            .list_firewall_rules()?
            .into_iter()
            .find(|rule| rule.id == id)
            .map(|rule| rule.created_at)
            .unwrap_or_else(now_rfc3339);
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO firewall_rules (id, action, proto, port, source, comment, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
             ON CONFLICT(id) DO UPDATE SET action = excluded.action, proto = excluded.proto, \
               port = excluded.port, source = excluded.source, comment = excluded.comment",
            params![
                id,
                spec.action,
                spec.proto,
                spec.port as i64,
                spec.source,
                spec.comment,
                created_at
            ],
        )?;
        let mut spec = spec.clone();
        spec.id = Some(id.clone());
        Ok(FirewallRuleView {
            id,
            spec,
            created_at,
        })
    }

    pub fn delete_firewall_rule(&self, id: &str) -> Result<()> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM firewall_rules WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn list_blocked_ips(&self) -> Result<Vec<BlockedIpView>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT ip, reason, source, expires_at, created_at \
             FROM blocked_ips ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], map_blocked_ip)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn block_ip(
        &self,
        ip: &str,
        reason: &str,
        source: &str,
        seconds: u32,
    ) -> Result<BlockedIpView> {
        let now = now_unix();
        let expires_at = if seconds > 0 {
            Some(now + seconds as i64)
        } else {
            None
        };
        let created_at = now_rfc3339();
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO blocked_ips (ip, reason, source, expires_at, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5) \
             ON CONFLICT(ip) DO UPDATE SET reason = excluded.reason, source = excluded.source, \
               expires_at = excluded.expires_at, created_at = excluded.created_at",
            params![ip, reason, source, expires_at, created_at],
        )?;
        Ok(BlockedIpView {
            ip: ip.to_string(),
            reason: reason.to_string(),
            source: source.to_string(),
            expires_at: expires_at.and_then(|ts| {
                time::OffsetDateTime::from_unix_timestamp(ts)
                    .ok()
                    .and_then(|dt| {
                        dt.format(&time::format_description::well_known::Rfc3339)
                            .ok()
                    })
            }),
            created_at,
        })
    }

    pub fn unblock_ip(&self, ip: &str) -> Result<()> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM blocked_ips WHERE ip = ?1", params![ip])?;
        Ok(())
    }

    pub fn prune_blocked_ips(&self, now: i64) -> Result<usize> {
        let conn = self.conn()?;
        Ok(conn.execute(
            "DELETE FROM blocked_ips WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            params![now],
        )?)
    }

    pub fn list_whitelist(&self) -> Result<Vec<String>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT ip FROM whitelist_ips ORDER BY ip")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn add_whitelist(&self, ip: &str) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT OR IGNORE INTO whitelist_ips (ip, created_at) VALUES (?1, ?2)",
            params![ip, now_rfc3339()],
        )?;
        Ok(())
    }

    pub fn remove_whitelist(&self, ip: &str) -> Result<()> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM whitelist_ips WHERE ip = ?1", params![ip])?;
        Ok(())
    }

    pub fn is_whitelisted(&self, ip: &str) -> Result<bool> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM whitelist_ips WHERE ip = ?1",
            params![ip],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }
}

fn map_firewall_rule(row: &rusqlite::Row<'_>) -> rusqlite::Result<FirewallRuleView> {
    let id: String = row.get(0)?;
    Ok(FirewallRuleView {
        spec: FirewallRuleSpec {
            id: Some(id.clone()),
            action: row.get(1)?,
            proto: row.get(2)?,
            port: row.get::<_, i64>(3)? as u16,
            source: row.get(4)?,
            comment: row.get(5)?,
        },
        id,
        created_at: row.get(6)?,
    })
}

fn map_blocked_ip(row: &rusqlite::Row<'_>) -> rusqlite::Result<BlockedIpView> {
    let expires_at: Option<i64> = row.get(3)?;
    Ok(BlockedIpView {
        ip: row.get(0)?,
        reason: row.get(1)?,
        source: row.get(2)?,
        expires_at: expires_at.and_then(|ts| {
            time::OffsetDateTime::from_unix_timestamp(ts)
                .ok()
                .and_then(|dt| {
                    dt.format(&time::format_description::well_known::Rfc3339)
                        .ok()
                })
        }),
        created_at: row.get(4)?,
    })
}

fn map_dns_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<DnsRecordView> {
    Ok(DnsRecordView {
        id: row.get(0)?,
        spec: DnsRecordSpec {
            domain: row.get(1)?,
            name: row.get(2)?,
            rtype: row.get(3)?,
            value: row.get(4)?,
            ttl: row.get::<_, i64>(5)? as u32,
            priority: row.get::<_, Option<i64>>(6)?.map(|p| p as u16),
        },
        managed: row.get::<_, i64>(7)? != 0,
    })
}

fn map_database(row: &rusqlite::Row<'_>) -> rusqlite::Result<DatabaseView> {
    Ok(DatabaseView {
        id: row.get(0)?,
        domain: row.get(1)?,
        username: row.get(2)?,
        password: row.get(3)?,
        engine: row.get(4)?,
        host: row.get(5)?,
        created_at: row.get(6)?,
    })
}

fn map_ftp(row: &rusqlite::Row<'_>) -> rusqlite::Result<FtpView> {
    Ok(FtpView {
        id: row.get(0)?,
        domain: row.get(1)?,
        login: row.get(2)?,
        home: row.get(3)?,
        readonly: row.get::<_, i64>(4)? != 0,
        password: row.get(5)?,
        created_at: row.get(6)?,
    })
}

fn map_backup(row: &rusqlite::Row<'_>) -> rusqlite::Result<BackupView> {
    Ok(BackupView {
        id: row.get(0)?,
        username: row.get(1)?,
        created_at: row.get(2)?,
        size_bytes: row.get::<_, i64>(3)? as u64,
        path: row.get(4)?,
        status: row.get(5)?,
    })
}

fn map_cron(row: &rusqlite::Row<'_>) -> rusqlite::Result<CronJobView> {
    Ok(CronJobView {
        id: row.get(0)?,
        username: row.get(1)?,
        schedule: row.get(2)?,
        command: row.get(3)?,
        enabled: row.get::<_, i64>(4)? != 0,
        created_at: row.get(5)?,
        updated_at: row.get(6)?,
    })
}

fn map_mail_domain(row: &rusqlite::Row<'_>) -> rusqlite::Result<MailDomainView> {
    let domain: String = row.get(0)?;
    Ok(MailDomainView {
        webmail_url: format!("https://webmail.{domain}/"),
        domain,
        username: row.get(1)?,
        enabled: row.get::<_, i64>(2)? != 0,
        catch_all: row.get(3)?,
        tls_status: CertificateStatus::Missing,
        tls_not_after: None,
        created_at: row.get(4)?,
        updated_at: row.get(5)?,
    })
}

fn map_mail_account(row: &rusqlite::Row<'_>) -> rusqlite::Result<MailAccountView> {
    let domain: String = row.get(1)?;
    let local_part: String = row.get(3)?;
    let aliases_raw: String = row.get(6)?;
    let forward_raw: String = row.get(7)?;
    Ok(MailAccountView {
        id: row.get(0)?,
        address: format!("{local_part}@{domain}"),
        local_part,
        domain,
        username: row.get(2)?,
        quota_mb: row.get::<_, i64>(4)? as u64,
        enabled: row.get::<_, i64>(5)? != 0,
        aliases: serde_json::from_str(&aliases_raw).unwrap_or_default(),
        forward_to: serde_json::from_str(&forward_raw).unwrap_or_default(),
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
    })
}

fn map_website(row: &rusqlite::Row<'_>) -> rusqlite::Result<WebsiteView> {
    let domain: String = row.get(0)?;
    let aliases_raw: String = row.get(3)?;
    let runtime_raw: String = row.get(4)?;
    let tls_raw: String = row.get(7)?;
    let aliases: Vec<String> = serde_json::from_str(&aliases_raw).unwrap_or_default();
    let runtime: Runtime = serde_json::from_str(&runtime_raw).unwrap_or(Runtime::Static);
    let tls: TlsMode = serde_json::from_str(&tls_raw).unwrap_or(TlsMode::Disabled);
    Ok(WebsiteView {
        id: row.get(1)?,
        spec: WebsiteSpec {
            domain,
            username: row.get(2)?,
            aliases,
            runtime,
            app: row.get(5)?,
            docroot: row.get(6)?,
            tls,
            enabled: row.get::<_, i64>(8)? != 0,
            force_https: row.get::<_, i64>(12)? != 0,
            locale: None,
        },
        document_root: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
    })
}

fn map_php_pool(row: &rusqlite::Row<'_>) -> rusqlite::Result<PhpPoolView> {
    let manager_raw: String = row.get(2)?;
    let process_manager = match manager_raw.as_str() {
        "ondemand" => rynx_proto::PhpProcessManager::Ondemand,
        "static" => rynx_proto::PhpProcessManager::Static,
        _ => rynx_proto::PhpProcessManager::Dynamic,
    };
    Ok(PhpPoolView {
        username: row.get(0)?,
        spec: PhpPoolSpec {
            username: row.get(0)?,
            version: row.get(1)?,
            process_manager,
            max_children: row.get::<_, i64>(3)? as u16,
            memory_limit_mb: row.get::<_, i64>(4)? as u32,
            upload_max_mb: row.get::<_, i64>(5)? as u32,
            enabled: row.get::<_, i64>(6)? != 0,
        },
        socket: row.get(7)?,
        updated_at: row.get(8)?,
    })
}

fn map_app(row: &rusqlite::Row<'_>) -> rusqlite::Result<AppView> {
    let username: String = row.get(0)?;
    let name: String = row.get(1)?;
    let runtime_raw: String = row.get(2)?;
    let args_raw: String = row.get(6)?;
    let env_raw: String = row.get(7)?;
    let runtime: Runtime = serde_json::from_str(&runtime_raw).unwrap_or(Runtime::Node {
        version: "22".into(),
    });
    let args: Vec<String> = serde_json::from_str(&args_raw).unwrap_or_default();
    let env: std::collections::BTreeMap<String, String> =
        serde_json::from_str(&env_raw).unwrap_or_default();
    Ok(AppView {
        id: format!("{username}/{name}"),
        spec: AppSpec {
            username,
            name,
            runtime,
            port: row.get::<_, i64>(3)? as u16,
            entrypoint: row.get(4)?,
            command: row.get(5)?,
            args,
            env,
            enabled: row.get::<_, i64>(8)? != 0,
        },
        unit: row.get(9)?,
        working_dir: row.get(10)?,
        created_at: row.get(11)?,
        updated_at: row.get(12)?,
    })
}
