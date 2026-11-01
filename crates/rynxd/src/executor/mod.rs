//! Privileged system mutations, isolated behind a trait so the whole panel can
//! run against a disposable sandbox during development.

pub mod sim;
#[cfg(unix)]
pub mod unix;

pub use sim::SimExecutor;
#[cfg(unix)]
pub use unix::RealExecutor;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;

use rynx_core::{CoreError, DaemonConfig};
use rynx_proto::{
    AccountSpec, AppSpec, CertView, FileEntry, InstallerApplySpec, MailDomainSpec, PackageUpdate,
    ProgramInfo, SystemInfo,
};

#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    #[error("command `{program} {args}` failed with status {status}: {stderr}")]
    Command {
        program: String,
        args: String,
        status: i32,
        stderr: String,
    },
    #[error("io error: {0}")]
    Io(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("account '{0}' does not exist")]
    MissingAccount(String),
}

impl From<std::io::Error> for ExecError {
    fn from(value: std::io::Error) -> Self {
        ExecError::Io(value.to_string())
    }
}

impl From<CoreError> for ExecError {
    fn from(value: CoreError) -> Self {
        ExecError::Io(value.to_string())
    }
}

pub type ExecResult<T> = Result<T, ExecError>;

/// Upper bound for files read or written through the panel file manager.
pub const MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;

fn invalid_path(message: &str) -> ExecError {
    ExecError::InvalidInput(format!("invalid file path: {message}"))
}

/// Rejects absolute paths, traversal, backslashes and NUL bytes. An empty path
/// is allowed and means the site document root.
pub fn validate_relative_path(path: &str) -> ExecResult<()> {
    if path.is_empty() {
        return Ok(());
    }
    if path.starts_with('/')
        || path.contains('\\')
        || path.contains('\0')
        || path.chars().any(|c| c.is_control())
    {
        return Err(invalid_path(
            "absolute, backslash, NUL or control character",
        ));
    }
    for component in Path::new(path).components() {
        if !matches!(component, std::path::Component::Normal(_)) {
            return Err(invalid_path("'.', '..' or root component"));
        }
    }
    Ok(())
}

/// Rejects names that could escape the current directory or break the protocol.
pub fn validate_file_name(name: &str) -> ExecResult<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
        || name.chars().any(|c| c.is_control())
        || name.len() > 255
    {
        return Err(invalid_path("invalid file name"));
    }
    Ok(())
}

/// Ensures a site root is a valid account/docroot pair.
pub fn validate_site_root(username: &str, docroot: &str) -> ExecResult<()> {
    rynx_core::validate_username(username)
        .map_err(|err| ExecError::InvalidInput(format!("invalid account: {err}")))?;
    rynx_core::validate_docroot(docroot)
        .map_err(|err| ExecError::InvalidInput(format!("invalid document root: {err}")))?;
    validate_relative_path(docroot)?;
    Ok(())
}

/// Merge service-managed panel entries into a generated OpenDKIM table.
///
/// Reconcile rewrites KeyTable/SigningTable from managed DNS zones. The panel
/// hostname is not one of those zones, so its entries live in a sidecar file
/// (`KeyTable.panel` / `SigningTable.panel`) that is appended on every write.
pub(crate) fn merge_dkim_table(path: &Path, content: &str) -> String {
    let Some(name) = path.file_name() else {
        return content.to_string();
    };
    let panel = path.with_file_name(format!("{}.panel", name.to_string_lossy()));
    let Ok(extra) = std::fs::read_to_string(panel) else {
        return content.to_string();
    };
    let mut out = content.to_string();
    if !out.ends_with('\n') {
        out.push('\n');
    }
    for line in extra.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || out.lines().any(|existing| existing.trim() == line)
        {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct UnitStatus {
    pub active: bool,
    pub state: String,
    pub pid: u32,
    pub memory_kb: u64,
    pub cpu_percent: f32,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone, Default)]
pub struct MailAccountConfig {
    pub domain: String,
    pub local_part: String,
    pub password_hash: String,
    pub quota_mb: u64,
    pub enabled: bool,
    pub aliases: Vec<String>,
    pub forward_to: Vec<String>,
}

#[async_trait]
pub trait Executor: Send + Sync {
    fn mode(&self) -> &'static str;
    fn home(&self, username: &str) -> PathBuf;
    fn apps_dir(&self, username: &str) -> PathBuf;
    fn working_dir(&self, username: &str, app: &str) -> PathBuf;
    fn acme_root(&self) -> PathBuf;

    async fn ensure_account(&self, spec: &AccountSpec, uid: u32) -> ExecResult<()>;
    async fn remove_account(&self, username: &str, purge: bool) -> ExecResult<()>;
    async fn set_ssh_access(&self, username: &str, enabled: bool) -> ExecResult<()>;
    async fn ssh_keys(&self, username: &str) -> ExecResult<Vec<String>>;
    async fn add_ssh_key(&self, username: &str, key: &str) -> ExecResult<()>;
    async fn remove_ssh_key(&self, username: &str, key: &str) -> ExecResult<()>;
    async fn remove_website_root(&self, username: &str, relative: &str) -> ExecResult<()>;
    async fn ensure_docroot(&self, username: &str, uid: u32, path: &Path) -> ExecResult<()>;

    async fn file_list(
        &self,
        username: &str,
        docroot: &str,
        path: &str,
    ) -> ExecResult<Vec<FileEntry>>;
    async fn file_read(&self, username: &str, docroot: &str, path: &str) -> ExecResult<Vec<u8>>;
    async fn file_write(
        &self,
        username: &str,
        docroot: &str,
        path: &str,
        data: &[u8],
    ) -> ExecResult<()>;
    async fn file_mkdir(&self, username: &str, docroot: &str, path: &str) -> ExecResult<()>;
    async fn file_rename(
        &self,
        username: &str,
        docroot: &str,
        path: &str,
        new_name: &str,
    ) -> ExecResult<()>;
    async fn file_delete(
        &self,
        username: &str,
        docroot: &str,
        path: &str,
        recursive: bool,
    ) -> ExecResult<()>;

    #[allow(clippy::too_many_arguments)]
    async fn ensure_welcome(
        &self,
        username: &str,
        uid: u32,
        docroot: &Path,
        domain: &str,
        locale: &str,
        php: bool,
    ) -> ExecResult<()>;

    async fn apply_site(&self, domain: &str, content: &str, enable: bool) -> ExecResult<()>;
    async fn remove_site(&self, domain: &str) -> ExecResult<()>;

    async fn apply_php_pool(
        &self,
        username: &str,
        version: &str,
        content: &str,
        enable: bool,
    ) -> ExecResult<()>;
    async fn remove_php_pool(&self, username: &str, version: &str) -> ExecResult<()>;

    async fn ensure_app_dir(&self, username: &str, uid: u32, dir: &Path) -> ExecResult<()>;
    #[allow(clippy::too_many_arguments)]
    async fn installer_apply(
        &self,
        spec: &InstallerApplySpec,
        archive: Option<&Path>,
    ) -> ExecResult<String>;

    #[allow(clippy::too_many_arguments)]
    async fn apply_app(
        &self,
        spec: &AppSpec,
        uid: u32,
        unit: &str,
        unit_content: &str,
        env_filename: &str,
        env_content: &str,
        working_dir: &Path,
        enable: bool,
    ) -> ExecResult<()>;
    async fn remove_app(
        &self,
        username: &str,
        unit: &str,
        env_filename: &str,
        working_dir: &Path,
        purge: bool,
    ) -> ExecResult<()>;

    async fn issue_cert(
        &self,
        domain: &str,
        domains: &[String],
        email: &str,
        webroot: &Path,
        staging: bool,
    ) -> ExecResult<()>;
    async fn renew_certs(&self, staging: bool) -> ExecResult<()>;
    async fn remove_cert(&self, domain: &str) -> ExecResult<()>;
    async fn cert_info(&self, domain: &str) -> ExecResult<Option<CertView>>;

    async fn status_unit(&self, unit: &str) -> ExecResult<UnitStatus>;
    async fn restart_unit(&self, unit: &str) -> ExecResult<()>;
    async fn reload_unit(&self, unit: &str) -> ExecResult<()>;
    async fn set_unit_running(&self, unit: &str, running: bool) -> ExecResult<()>;
    async fn journal_unit(&self, unit: &str, lines: u32) -> ExecResult<String>;
    async fn fail2ban_bans(&self) -> ExecResult<Vec<(String, String)>>;
    async fn fail2ban_unban(&self, ip: &str) -> ExecResult<()>;
    async fn disk_usage(&self) -> ExecResult<String>;
    async fn nginx_test_text(&self) -> ExecResult<String>;

    async fn create_backup(&self, paths: &[String], dest: &Path) -> ExecResult<u64>;
    async fn restore_backup(&self, archive: &Path, username: &str, uid: u32) -> ExecResult<()>;
    async fn delete_backup_file(&self, path: &Path) -> ExecResult<()>;
    async fn repair_backup_permissions(&self, path: &Path) -> ExecResult<()>;
    async fn offsite_backup(&self, path: &Path, tag: &str) -> ExecResult<bool>;
    async fn copy_site_tree(&self, username: &str, source: &str, target: &str) -> ExecResult<()>;
    async fn clone_database(&self, source: &str, target: &str) -> ExecResult<()>;
    async fn rewrite_clone_config(
        &self,
        username: &str,
        root: &str,
        old_db: &str,
        old_password: &str,
        new_db: &str,
        new_password: &str,
    ) -> ExecResult<bool>;
    async fn remove_backup_dir(&self, username: &str) -> ExecResult<()>;
    async fn apply_cron(&self, username: &str, content: &str) -> ExecResult<()>;

    async fn apply_zone(&self, domain: &str, content: &str) -> ExecResult<()>;
    async fn remove_zone(&self, domain: &str) -> ExecResult<()>;
    async fn write_dns_conf(&self, content: &str) -> ExecResult<()>;
    async fn generate_dkim_key(&self, domain: &str, selector: &str) -> ExecResult<String>;
    async fn remove_dkim_key(&self, domain: &str) -> ExecResult<()>;
    async fn write_dkim_tables(&self, keytable: &str, signingtable: &str) -> ExecResult<()>;

    async fn hash_mail_password(&self, password: &str) -> ExecResult<String>;
    async fn sync_mail(
        &self,
        domains: &[MailDomainSpec],
        accounts: &[MailAccountConfig],
    ) -> ExecResult<()>;
    async fn remove_mailbox(&self, domain: &str, local_part: &str) -> ExecResult<()>;
    async fn remove_mail_domain(&self, domain: &str) -> ExecResult<()>;
    async fn reload_mail(&self) -> ExecResult<()>;

    async fn create_database(&self, database: &str, user: &str, password: &str) -> ExecResult<()>;
    async fn drop_database(&self, database: &str, user: &str) -> ExecResult<()>;

    async fn apply_ftp_user(
        &self,
        login: &str,
        uid: u32,
        gid: u32,
        home: &Path,
        password: &str,
    ) -> ExecResult<()>;
    async fn remove_ftp_user(&self, login: &str) -> ExecResult<()>;
    async fn apply_ftp_certificate(&self, domain: &str) -> ExecResult<()>;
    async fn apply_firewall(&self, ruleset: &str) -> ExecResult<()>;
    async fn resolve_user_ids(&self, username: &str) -> ExecResult<Option<(u32, u32)>>;

    async fn installed_programs(&self) -> ExecResult<Vec<ProgramInfo>>;
    async fn php_versions(&self) -> ExecResult<Vec<String>>;
    async fn available_updates(&self) -> ExecResult<Vec<PackageUpdate>>;
    async fn apply_updates(&self) -> ExecResult<String>;

    async fn system_info(&self) -> ExecResult<SystemInfo>;
    async fn uid_in_use(&self, uid: u32) -> ExecResult<bool>;
}

pub fn build(cfg: &DaemonConfig) -> anyhow::Result<Arc<dyn Executor>> {
    if cfg.simulate {
        Ok(Arc::new(SimExecutor::new(cfg.clone())))
    } else {
        #[cfg(unix)]
        {
            Ok(Arc::new(RealExecutor::new(cfg.clone())))
        }
        #[cfg(not(unix))]
        {
            anyhow::bail!(
                "simulate=false is only supported on Linux; enable simulate for this platform"
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_paths_reject_traversal_and_absolute_paths() {
        assert!(validate_relative_path("assets/app.js").is_ok());
        assert!(validate_relative_path("").is_ok());
        assert!(validate_relative_path("../other").is_err());
        assert!(validate_relative_path("a/../../b").is_err());
        assert!(validate_relative_path("/etc/passwd").is_err());
        assert!(validate_relative_path("a\\b").is_err());
        assert!(validate_relative_path("a\nb").is_err());
    }

    #[test]
    fn file_names_reject_separators() {
        assert!(validate_file_name("index.php").is_ok());
        assert!(validate_file_name("..").is_err());
        assert!(validate_file_name("a/b").is_err());
        assert!(validate_file_name("a\nb").is_err());
    }
}
