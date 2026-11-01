//! Reconciliation engine: validates intent, applies it to the operating system
//! through the executor, persists the desired state and appends an audit entry.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use rynx_core::audit::{self, AuditLog};
use rynx_core::crypto::{now_rfc3339, now_unix, random_hex, sha256_hex};
use rynx_core::templates::{self, NginxContext};
use rynx_core::validate::{
    self, validate_account_spec, validate_app_spec, validate_ban_ip, validate_cron_spec,
    validate_database_name, validate_dns_record_spec, validate_domain, validate_email,
    validate_firewall_rule_spec, validate_ftp_spec, validate_ip_or_cidr,
    validate_mail_account_spec, validate_mail_domain_spec, validate_php_pool_spec,
    validate_php_version, validate_website_spec,
};
use rynx_core::DaemonConfig;
use rynx_proto::{
    AccountSpec, AccountView, AppSpec, AppView, AuditEntry, BackupView, BlockedIpView, CertView,
    CertificateStatus, ConsoleAction, CronJobView, CronSpec, DatabaseView, DnsRecordSpec,
    DnsRecordView, DnsZoneView, FirewallRuleSpec, FirewallRuleView, FirewallView, FtpSpec, FtpView,
    InstallerApp, InstallerApplySpec, MailAccountSpec, MailDomainSpec, MailDomainView,
    MetricSample, PhpPoolSpec, PhpPoolView, Request, Response, Runtime, ServiceStat, SystemInfo,
    TlsMode, WebsiteSpec, WebsiteView, WireError,
};

use crate::executor::{validate_site_root, ExecError, Executor, MailAccountConfig};
use crate::state::StateStore;

const WEBMAIL_ROOT: &str = "/usr/share/roundcube";
const WEBMAIL_PUBLIC_ROOT: &str = "/usr/share/roundcube/public_html";
const WEBMAIL_PHP_SOCKET: &str = "/run/php/php8.5-fpm.sock";

fn webmail_root() -> &'static str {
    if Path::new(WEBMAIL_PUBLIC_ROOT).is_dir() {
        WEBMAIL_PUBLIC_ROOT
    } else {
        WEBMAIL_ROOT
    }
}

const MAX_INSTALLER_ARCHIVE: u64 = 128 * 1024 * 1024;

fn validate_wordpress_fields(spec: &InstallerApplySpec) -> Result<(), WireError> {
    let title = spec.site_title.trim();
    if title.is_empty() || title.len() > 200 || title.chars().any(|ch| ch.is_control()) {
        return Err(WireError::invalid("invalid WordPress site title"));
    }
    let user = spec.admin_user.trim();
    if user.is_empty()
        || user.len() > 60
        || !user
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '@'))
    {
        return Err(WireError::invalid("invalid WordPress administrator user"));
    }
    validate_email(&spec.admin_email).map_err(invalid)?;
    if spec.admin_password.len() < 8
        || spec.admin_password.len() > 128
        || spec.admin_password.chars().any(|ch| ch.is_control())
    {
        return Err(WireError::invalid(
            "the WordPress administrator password must be 8-128 printable characters",
        ));
    }
    Ok(())
}

fn validate_ssh_key(key: &str) -> Result<(), WireError> {
    let line = key.trim();
    if line.is_empty()
        || line.len() > 4096
        || line.contains('\n')
        || line.contains('\r')
        || line.contains('\0')
        || line.starts_with('#')
    {
        return Err(WireError::invalid("invalid SSH public key"));
    }
    let mut parts = line.split_whitespace();
    let kind = parts.next().unwrap_or_default();
    let data = parts.next().unwrap_or_default();
    const KINDS: [&str; 7] = [
        "ssh-ed25519",
        "ssh-rsa",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
    ];
    if !KINDS.contains(&kind) || data.is_empty() {
        return Err(WireError::invalid("unsupported SSH public key"));
    }
    base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(|_| WireError::invalid("invalid SSH public key encoding"))?;
    Ok(())
}

fn validate_staged_archive(
    staging: &Path,
    raw_path: &str,
    expected_sha256: &str,
    expected_size: u64,
) -> Result<PathBuf, WireError> {
    let staging = staging
        .canonicalize()
        .map_err(|err| WireError::invalid(format!("installer staging is unavailable: {err}")))?;
    let path = Path::new(raw_path);
    let meta = std::fs::symlink_metadata(path)
        .map_err(|_| WireError::invalid("installer archive not found"))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(WireError::invalid(
            "installer archive must be a regular file",
        ));
    }
    if meta.len() != expected_size || expected_size == 0 || expected_size > MAX_INSTALLER_ARCHIVE {
        return Err(WireError::invalid("invalid installer archive size"));
    }
    let canonical = path
        .canonicalize()
        .map_err(|_| WireError::invalid("installer archive not found"))?;
    if !canonical.starts_with(&staging) {
        return Err(WireError::invalid(
            "installer archive is outside the staging directory",
        ));
    }
    let data = std::fs::read(&canonical)
        .map_err(|_| WireError::invalid("installer archive could not be read"))?;
    if sha256_hex(&data) != expected_sha256.to_ascii_lowercase() {
        return Err(WireError::invalid("installer archive checksum mismatch"));
    }
    Ok(canonical)
}

fn exec_error(err: ExecError) -> WireError {
    match err {
        ExecError::MissingAccount(name) => {
            WireError::not_found(format!("account '{name}' not found"))
        }
        ExecError::NotFound(msg) => WireError::not_found(msg),
        ExecError::Unsupported(msg) => WireError::unsupported(msg),
        ExecError::InvalidInput(msg) => WireError::invalid(msg),
        other => WireError::internal(other.to_string()),
    }
}

pub struct Reconciler {
    pub cfg: Arc<DaemonConfig>,
    pub state: Arc<StateStore>,
    pub audit: Arc<AuditLog>,
    pub exec: Arc<dyn Executor>,
}

impl Reconciler {
    pub fn mode(&self) -> &'static str {
        self.exec.mode()
    }

    pub async fn dispatch(&self, request: Request, actor: &str) -> Result<Response, WireError> {
        match request {
            Request::Health => Ok(Response::Pong {
                daemon_version: rynx_proto::DAEMON_VERSION.into(),
                mode: self.exec.mode().into(),
            }),
            Request::SystemInfo => {
                let info: SystemInfo = self.exec.system_info().await.map_err(exec_error)?;
                Ok(Response::SystemInfo { info })
            }

            Request::AccountCreate(spec) => self.account_create(spec, actor).await,
            Request::AccountDelete { username, purge } => {
                self.account_delete(&username, purge, actor).await
            }
            Request::AccountList => {
                let accounts = self.state.list_accounts().map_err(internal)?;
                Ok(Response::Accounts { accounts })
            }

            Request::FileList {
                username,
                domain,
                path,
            } => self.file_list(&username, &domain, &path, actor).await,
            Request::FileRead {
                username,
                domain,
                path,
            } => self.file_read(&username, &domain, &path, actor).await,
            Request::FileWrite {
                username,
                domain,
                path,
                data,
            } => {
                self.file_write(&username, &domain, &path, &data, actor)
                    .await
            }
            Request::FileMkdir {
                username,
                domain,
                path,
            } => self.file_mkdir(&username, &domain, &path, actor).await,
            Request::FileRename {
                username,
                domain,
                path,
                new_name,
            } => {
                self.file_rename(&username, &domain, &path, &new_name, actor)
                    .await
            }
            Request::FileDelete {
                username,
                domain,
                path,
                recursive,
            } => {
                self.file_delete(&username, &domain, &path, recursive, actor)
                    .await
            }

            Request::WebsiteUpsert(spec) => self.website_upsert(spec, actor).await,
            Request::WebsiteDelete { domain } => self.website_delete(&domain, actor).await,
            Request::WebsiteClone {
                source,
                target,
                with_database,
            } => {
                self.website_clone(&source, &target, with_database, actor)
                    .await
            }
            Request::WebsiteList => {
                let websites = self.state.list_websites().map_err(internal)?;
                Ok(Response::Websites { websites })
            }

            Request::PhpPoolUpsert(spec) => self.php_pool_upsert(spec, actor).await,
            Request::PhpPoolDelete { username } => self.php_pool_delete(&username, actor).await,
            Request::PhpVersions => {
                let versions = self.exec.php_versions().await.map_err(exec_error)?;
                Ok(Response::PhpVersions { versions })
            }
            Request::PhpPoolList => {
                let pools = self.state.list_php_pools().map_err(internal)?;
                Ok(Response::PhpPools { pools })
            }

            Request::AppUpsert(spec) => self.app_upsert(spec, actor).await,
            Request::AppDelete { username, name } => self.app_delete(&username, &name, actor).await,
            Request::AppList => {
                let apps = self.state.list_apps().map_err(internal)?;
                Ok(Response::Apps { apps })
            }
            Request::InstallerApply(spec) => self.installer_apply(spec, actor).await,
            Request::WebsiteLogs {
                domain,
                kind,
                lines,
            } => self.website_logs(&domain, &kind, lines).await,
            Request::MailQueue => self.mail_queue().await,
            Request::MailQueueAction { action, id } => {
                self.mail_queue_action(&action, id.as_deref(), actor).await
            }
            Request::SshKeys { username } => self.ssh_keys(&username).await,
            Request::SshKeyAdd { username, key } => self.ssh_key_add(&username, &key, actor).await,
            Request::SshKeyDelete { username, key } => {
                self.ssh_key_delete(&username, &key, actor).await
            }

            Request::CertIssue {
                domain,
                email,
                staging,
            } => self.cert_issue(&domain, &email, staging, actor).await,
            Request::CertRenew { staging } => self.cert_renew(staging, actor).await,
            Request::CertList => self.cert_list().await,

            Request::MailDomainUpsert(spec) => self.mail_domain_upsert(spec, actor).await,
            Request::MailDomainDelete { domain } => self.mail_domain_delete(&domain, actor).await,
            Request::MailDomainList => self.mail_domain_list().await,
            Request::MailTls { domain, email } => self.mail_tls(&domain, &email, actor).await,
            Request::MailAccountUpsert(spec) => self.mail_account_upsert(spec, actor).await,
            Request::MailAccountDelete { id } => self.mail_account_delete(&id, actor).await,
            Request::MailAccountList => self.mail_account_list().await,

            Request::BackupCreate { username } => self.backup_create(&username, actor).await,
            Request::BackupList => {
                let backups = self.state.list_backups().map_err(internal)?;
                Ok(Response::Backups { backups })
            }
            Request::BackupDelete { id } => self.backup_delete(&id, actor).await,
            Request::BackupRestore { id } => self.backup_restore(&id, actor).await,

            Request::CronList => {
                let jobs = self.state.list_cron().map_err(internal)?;
                Ok(Response::CronJobs { jobs })
            }
            Request::CronUpsert(spec) => self.cron_upsert(spec, actor).await,
            Request::CronDelete { id } => self.cron_delete(&id, actor).await,

            Request::DnsZone { domain } => self.dns_zone(&domain).await,
            Request::DnsZoneList => self.dns_zone_list().await,
            Request::DnsRecordUpsert(spec) => self.dns_record_upsert(spec, actor).await,
            Request::DnsRecordDelete { domain, id } => {
                self.dns_record_delete(&domain, &id, actor).await
            }
            Request::DnsMailProvision { domain } => self.dns_mail_provision(&domain, actor).await,

            Request::DatabaseCreate { domain, name } => {
                self.database_create(&domain, &name, actor).await
            }
            Request::DatabaseList => {
                let databases = self.state.list_databases().map_err(internal)?;
                Ok(Response::Databases { databases })
            }
            Request::DatabaseDelete { id } => self.database_delete(&id, actor).await,

            Request::FtpList => {
                let accounts = self.state.list_ftp().map_err(internal)?;
                Ok(Response::Ftps { accounts })
            }
            Request::FtpCreate(spec) => self.ftp_create(spec, actor).await,
            Request::FtpDelete { id } => self.ftp_delete(&id, actor).await,

            Request::FirewallStatus => self.firewall_state().await,
            Request::FirewallRuleUpsert(spec) => self.firewall_rule_upsert(spec, actor).await,
            Request::FirewallRuleDelete { id } => self.firewall_rule_delete(&id, actor).await,
            Request::FirewallBlock {
                ip,
                seconds,
                reason,
            } => self.firewall_block(&ip, seconds, &reason, actor).await,
            Request::FirewallUnblock { ip } => self.firewall_unblock(&ip, actor).await,
            Request::FirewallWhitelistAdd { ip } => self.firewall_whitelist_add(&ip, actor).await,
            Request::FirewallWhitelistRemove { ip } => {
                self.firewall_whitelist_remove(&ip, actor).await
            }

            Request::ServiceStats => self.service_stats().await,
            Request::Programs => self.programs().await,
            Request::Updates => self.updates().await,
            Request::ApplyUpdates => self.apply_updates(actor).await,
            Request::FilterActivity { limit } => {
                let limit = limit.clamp(1, 500);
                let events = if self.mode() == "simulation" {
                    crate::filters::simulated_activity()
                } else {
                    crate::filters::recent_activity(limit).await
                };
                Ok(Response::FilterActivity { events })
            }
            Request::MetricsHistory { minutes } => {
                let since = now_unix() - (minutes.clamp(1, 10_080) as i64 * 60);
                let samples = self.state.list_metrics(since).map_err(internal)?;
                Ok(Response::MetricsHistory { samples })
            }
            Request::ConsoleRun { action } => self.console_run(action, actor).await,

            Request::AuditTail { limit } => {
                let entries: Vec<AuditEntry> =
                    audit::tail(&self.cfg.audit_log, limit.clamp(1, 1000) as usize)
                        .map_err(internal)?;
                Ok(Response::Audit { entries })
            }

            Request::ReconcileAll => self.reconcile_all(actor).await,
        }
    }

    fn require_account(&self, username: &str) -> Result<AccountView, WireError> {
        self.state
            .get_account(username)
            .map_err(internal)?
            .ok_or_else(|| WireError::not_found(format!("account '{username}' not found")))
    }

    async fn allocate_uid(&self) -> Result<u32, WireError> {
        let max = self.state.max_uid().map_err(internal)?;
        let mut candidate = max
            .unwrap_or_else(|| self.cfg.uid_min.saturating_sub(1))
            .saturating_add(1)
            .max(self.cfg.uid_min);
        if candidate > self.cfg.uid_max {
            candidate = self.cfg.uid_min;
        }
        for _ in 0..4096 {
            if candidate > self.cfg.uid_max {
                candidate = self.cfg.uid_min;
            }
            if !self.exec.uid_in_use(candidate).await.map_err(exec_error)? {
                return Ok(candidate);
            }
            candidate = candidate.saturating_add(1);
        }
        Err(WireError::internal("no free UID in the configured range"))
    }

    async fn account_create(&self, spec: AccountSpec, actor: &str) -> Result<Response, WireError> {
        validate_account_spec(&spec).map_err(invalid)?;
        let accounts = self.state.list_accounts().map_err(internal)?;
        if accounts.iter().any(|account| {
            account.spec.username != spec.username
                && account.spec.email.eq_ignore_ascii_case(&spec.email)
        }) {
            return Err(WireError::conflict(
                "email is already used by another account",
            ));
        }
        let existing = self.state.get_account(&spec.username).map_err(internal)?;
        let uid = match &existing {
            Some(account) => account.uid,
            None => self.allocate_uid().await?,
        };
        let home = self.exec.home(&spec.username).display().to_string();
        self.exec
            .ensure_account(&spec, uid)
            .await
            .map_err(exec_error)?;
        self.exec
            .set_ssh_access(&spec.username, spec.enabled && spec.ssh_enabled)
            .await
            .map_err(exec_error)?;
        // A pre-existing Linux user may have a different UID than the value
        // allocated from the panel state. Trust the real system UID so the home
        // and all file operations stay consistent.
        let actual_uid = self
            .exec
            .resolve_user_ids(&spec.username)
            .await
            .map_err(exec_error)?
            .map(|(uid, _)| uid)
            .unwrap_or(uid);
        let view = self
            .state
            .upsert_account(&spec, actual_uid, &home)
            .map_err(internal)?;

        match existing {
            Some(previous) => {
                if previous.spec.enabled != spec.enabled {
                    if spec.enabled {
                        self.resume_account(&spec.username).await;
                        self.log(actor, "account.resume", &spec.username, "")?;
                    } else {
                        self.suspend_account(&spec.username).await;
                        self.log(actor, "account.suspend", &spec.username, "")?;
                    }
                }
                self.log(
                    actor,
                    "account.update",
                    &spec.username,
                    &format!("disk={}MB enabled={}", spec.disk_limit_mb, spec.enabled),
                )?;
            }
            None => {
                self.log(
                    actor,
                    "account.create",
                    &spec.username,
                    &format!("uid={actual_uid} home={home} disk={}MB", spec.disk_limit_mb),
                )?;
            }
        }
        Ok(Response::Account { account: view })
    }

    async fn suspend_account(&self, username: &str) {
        let websites: Vec<WebsiteView> = self
            .state
            .list_websites()
            .unwrap_or_default()
            .into_iter()
            .filter(|website| website.spec.username == username)
            .collect();
        for website in &websites {
            if let Err(err) = self.exec.remove_site(&website.spec.domain).await {
                tracing::warn!(domain = %website.spec.domain, error = %err, "suspend: remove_site failed");
            }
        }
        if let Ok(apps) = self.state.list_apps() {
            for app in apps.iter().filter(|app| app.spec.username == username) {
                let _ = self.exec.set_unit_running(&app.unit, false).await;
            }
        }
        let domains: Vec<String> = websites.iter().map(|w| w.spec.domain.clone()).collect();
        if let Ok(accounts) = self.state.list_ftp() {
            for ftp in accounts
                .iter()
                .filter(|account| domains.contains(&account.domain))
            {
                let _ = self.exec.remove_ftp_user(&ftp.login).await;
            }
        }
        let _ = self.exec.apply_cron(username, "").await;
    }

    async fn resume_account(&self, username: &str) {
        let websites: Vec<WebsiteView> = self
            .state
            .list_websites()
            .unwrap_or_default()
            .into_iter()
            .filter(|website| website.spec.username == username)
            .collect();
        for website in &websites {
            if let Err(err) = self.apply_website(&website.spec).await {
                tracing::warn!(domain = %website.spec.domain, error = %err.message, "resume: website failed");
            }
        }
        if let Ok(apps) = self.state.list_apps() {
            for app in apps.iter().filter(|app| app.spec.username == username) {
                let _ = self.apply_app(&app.spec).await;
            }
        }
        let domains: Vec<String> = websites.iter().map(|w| w.spec.domain.clone()).collect();
        if let Ok(accounts) = self.state.list_ftp() {
            for ftp in accounts
                .iter()
                .filter(|account| domains.contains(&account.domain))
            {
                let ids = if ftp.readonly {
                    self.exec
                        .resolve_user_ids(&self.cfg.ftp_readonly_user)
                        .await
                } else {
                    self.exec.resolve_user_ids(username).await
                };
                let Some((uid, gid)) = ids.ok().flatten() else {
                    tracing::warn!(login = %ftp.login, "resume: FTP uid could not be resolved");
                    continue;
                };
                let _ = self
                    .exec
                    .apply_ftp_user(&ftp.login, uid, gid, Path::new(&ftp.home), &ftp.password)
                    .await;
            }
        }
        let _ = self.cron_render(username).await;
    }

    async fn account_delete(
        &self,
        username: &str,
        purge: bool,
        actor: &str,
    ) -> Result<Response, WireError> {
        validate::validate_username(username).map_err(invalid)?;
        if self
            .state
            .get_account(username)
            .map_err(internal)?
            .is_none()
        {
            return Err(WireError::not_found(format!(
                "account '{username}' not found"
            )));
        }

        let websites: Vec<WebsiteView> = self
            .state
            .list_websites()
            .map_err(internal)?
            .into_iter()
            .filter(|w| w.spec.username == username)
            .collect();
        let domains: Vec<String> = websites.iter().map(|w| w.spec.domain.clone()).collect();

        for mail in self
            .state
            .list_mail_domains()
            .map_err(internal)?
            .into_iter()
            .filter(|mail| mail.username == username)
        {
            let _ = self.mail_domain_delete(&mail.domain, actor).await;
        }

        for website in &websites {
            self.exec
                .remove_site(&website.spec.domain)
                .await
                .map_err(exec_error)?;
            let _ = self.exec.remove_cert(&website.spec.domain).await;
            if self.cfg.dns_enabled {
                self.dns_remove_zone(&website.spec.domain).await;
            }
        }
        for ftp in self
            .state
            .list_ftp()
            .map_err(internal)?
            .into_iter()
            .filter(|account| domains.contains(&account.domain))
        {
            let _ = self.exec.remove_ftp_user(&ftp.login).await;
            let _ = self.state.delete_ftp(&ftp.id);
        }
        for database in self
            .state
            .list_databases()
            .map_err(internal)?
            .into_iter()
            .filter(|db| domains.contains(&db.domain))
        {
            let _ = self
                .exec
                .drop_database(&database.username, &database.username)
                .await;
            let _ = self.state.delete_database(&database.id);
        }

        for backup in self.state.backups_for(username).map_err(internal)? {
            let _ = self.exec.delete_backup_file(Path::new(&backup.path)).await;
            let _ = self.state.delete_backup(&backup.id);
        }
        let _ = self.exec.remove_backup_dir(username).await;
        let _ = self.exec.apply_cron(username, "").await;
        let _ = self.state.delete_cron_for(username);

        for app in self
            .state
            .list_apps()
            .map_err(internal)?
            .into_iter()
            .filter(|a| a.spec.username == username)
        {
            let env = templates::app_env_filename(username, &app.spec.name);
            let _ = self
                .exec
                .remove_app(
                    username,
                    &app.unit,
                    &env,
                    std::path::Path::new(&app.working_dir),
                    purge,
                )
                .await;
        }
        if let Some(pool) = self.state.get_php_pool(username).map_err(internal)? {
            let _ = self
                .exec
                .remove_php_pool(username, &pool.spec.version)
                .await;
        }
        self.exec
            .remove_account(username, purge)
            .await
            .map_err(exec_error)?;
        self.state.delete_account(username).map_err(internal)?;
        self.log(
            actor,
            "account.delete",
            username,
            if purge { "purged" } else { "kept home" },
        )?;
        Ok(Response::Ack {
            message: format!("account '{username}' deleted"),
        })
    }

    fn website_docroot(&self, username: &str, domain: &str) -> Result<String, WireError> {
        let website = self
            .state
            .get_website(domain)
            .map_err(internal)?
            .ok_or_else(|| WireError::not_found("website not found"))?;
        if website.spec.username != username {
            return Err(WireError::not_found("website not found"));
        }
        Ok(website.spec.docroot)
    }

    async fn file_list(
        &self,
        username: &str,
        domain: &str,
        path: &str,
        actor: &str,
    ) -> Result<Response, WireError> {
        let docroot = self.website_docroot(username, domain)?;
        let entries = self
            .exec
            .file_list(username, &docroot, path)
            .await
            .map_err(exec_error)?;
        self.log(actor, "file.list", &format!("{domain}:{path}"), "")?;
        Ok(Response::Files {
            entries,
            path: path.to_string(),
        })
    }

    async fn file_read(
        &self,
        username: &str,
        domain: &str,
        path: &str,
        actor: &str,
    ) -> Result<Response, WireError> {
        let docroot = self.website_docroot(username, domain)?;
        let data = self
            .exec
            .file_read(username, &docroot, path)
            .await
            .map_err(exec_error)?;
        self.log(actor, "file.read", &format!("{domain}:{path}"), "")?;
        Ok(Response::FileData { data })
    }

    async fn file_write(
        &self,
        username: &str,
        domain: &str,
        path: &str,
        data: &[u8],
        actor: &str,
    ) -> Result<Response, WireError> {
        let docroot = self.website_docroot(username, domain)?;
        self.exec
            .file_write(username, &docroot, path, data)
            .await
            .map_err(exec_error)?;
        self.log(
            actor,
            "file.write",
            &format!("{domain}:{path}"),
            &format!("{} bytes", data.len()),
        )?;
        Ok(Response::Ack {
            message: "file saved".into(),
        })
    }

    async fn file_mkdir(
        &self,
        username: &str,
        domain: &str,
        path: &str,
        actor: &str,
    ) -> Result<Response, WireError> {
        let docroot = self.website_docroot(username, domain)?;
        self.exec
            .file_mkdir(username, &docroot, path)
            .await
            .map_err(exec_error)?;
        self.log(actor, "file.mkdir", &format!("{domain}:{path}"), "")?;
        Ok(Response::Ack {
            message: "directory created".into(),
        })
    }

    async fn file_rename(
        &self,
        username: &str,
        domain: &str,
        path: &str,
        new_name: &str,
        actor: &str,
    ) -> Result<Response, WireError> {
        let docroot = self.website_docroot(username, domain)?;
        self.exec
            .file_rename(username, &docroot, path, new_name)
            .await
            .map_err(exec_error)?;
        self.log(actor, "file.rename", &format!("{domain}:{path}"), new_name)?;
        Ok(Response::Ack {
            message: "renamed".into(),
        })
    }

    async fn file_delete(
        &self,
        username: &str,
        domain: &str,
        path: &str,
        recursive: bool,
        actor: &str,
    ) -> Result<Response, WireError> {
        let docroot = self.website_docroot(username, domain)?;
        self.exec
            .file_delete(username, &docroot, path, recursive)
            .await
            .map_err(exec_error)?;
        self.log(
            actor,
            "file.delete",
            &format!("{domain}:{path}"),
            if recursive { "recursive" } else { "" },
        )?;
        Ok(Response::Ack {
            message: "deleted".into(),
        })
    }

    async fn website_upsert(
        &self,
        mut spec: WebsiteSpec,
        actor: &str,
    ) -> Result<Response, WireError> {
        validate_website_spec(&spec).map_err(invalid)?;
        if let Runtime::Php { version } = &spec.runtime {
            self.ensure_php_version(version).await?;
        }
        for prefix in [
            "webmail",
            "mail",
            "imap",
            "smtp",
            "pop",
            "autodiscover",
            "autoconfig",
        ] {
            if let Some(parent) = spec.domain.strip_prefix(&format!("{prefix}.")) {
                if self
                    .state
                    .get_mail_domain(parent)
                    .map_err(internal)?
                    .is_some()
                {
                    return Err(WireError::conflict(format!(
                        "{} is reserved by the mail service for {parent}",
                        spec.domain
                    )));
                }
            }
        }
        let is_new = self
            .state
            .get_website(&spec.domain)
            .map_err(internal)?
            .is_none();
        // New domains and subdomains get their own document root. Existing
        // websites keep their stored path so an edit never moves their files.
        if is_new && spec.docroot == "public_html" {
            spec.docroot = format!("{}/public_html", spec.domain);
        }
        if is_new
            && self
                .state
                .count_websites(&spec.username)
                .map_err(internal)?
                >= self.cfg.max_websites_per_account
        {
            return Err(WireError::conflict(format!(
                "account '{}' reached the limit of {} websites",
                spec.username, self.cfg.max_websites_per_account
            )));
        }
        let view = self.apply_website(&spec).await?;
        if self.cfg.dns_enabled {
            if let Err(err) = self
                .dns_ensure_zone(&spec.domain, self.cfg.mail_enabled)
                .await
            {
                tracing::warn!(domain = %spec.domain, error = %err.message, "dns provisioning failed");
            } else if let Err(err) = self.dns_render(&spec.domain).await {
                tracing::warn!(domain = %spec.domain, error = %err.message, "dns render failed");
            }
        }
        self.log(
            actor,
            "website.upsert",
            &spec.domain,
            &format!(
                "user={} engine={} tls={:?} enabled={}",
                spec.username,
                spec.runtime.engine(),
                spec.tls,
                spec.enabled
            ),
        )?;
        Ok(Response::Website { website: view })
    }

    async fn apply_website(&self, spec: &WebsiteSpec) -> Result<WebsiteView, WireError> {
        let account = self.require_account(&spec.username)?;
        if !account.spec.enabled {
            return Err(WireError::conflict(format!(
                "account '{}' is suspended",
                spec.username
            )));
        }

        let docroot_path = PathBuf::from(&account.home).join(&spec.docroot);
        let home = PathBuf::from(&account.home);
        if !docroot_path.starts_with(&home) {
            return Err(WireError::invalid("docroot escapes the account home"));
        }
        self.exec
            .ensure_docroot(&spec.username, account.uid, &docroot_path)
            .await
            .map_err(exec_error)?;

        if matches!(&spec.runtime, Runtime::Static | Runtime::Php { .. }) {
            let php = matches!(&spec.runtime, Runtime::Php { .. });
            if let Err(err) = self
                .exec
                .ensure_welcome(
                    &spec.username,
                    account.uid,
                    &docroot_path,
                    &spec.domain,
                    spec.locale.as_deref().unwrap_or("en"),
                    php,
                )
                .await
            {
                tracing::warn!(domain = %spec.domain, error = %err, "welcome page creation failed");
            }
        }

        let docroot = docroot_path.display().to_string();

        let (app_port, php_socket) = match &spec.runtime {
            Runtime::Static => (None, None),
            Runtime::Php { version } => {
                let pool = self
                    .ensure_default_php_pool(&spec.username, version)
                    .await?;
                (None, Some(pool.socket))
            }
            _ => {
                let app_name = spec
                    .app
                    .as_deref()
                    .ok_or_else(|| WireError::invalid("managed runtime requires an application"))?;
                let app = self
                    .state
                    .get_app(&spec.username, app_name)
                    .map_err(internal)?
                    .ok_or_else(|| {
                        WireError::not_found(format!("application '{app_name}' not found"))
                    })?;
                if app.spec.runtime.engine() != spec.runtime.engine() {
                    return Err(WireError::conflict(format!(
                        "application '{app_name}' runs {} but the website requests {}",
                        app.spec.runtime.engine(),
                        spec.runtime.engine()
                    )));
                }
                (Some(app.spec.port), None)
            }
        };

        let content = self.nginx_content(spec, &docroot, app_port, php_socket.as_deref());
        self.exec
            .apply_site(&spec.domain, &content, spec.enabled)
            .await
            .map_err(exec_error)?;
        self.state.upsert_website(spec, &docroot).map_err(internal)
    }

    fn nginx_content(
        &self,
        spec: &WebsiteSpec,
        docroot: &str,
        app_port: Option<u16>,
        php_socket: Option<&str>,
    ) -> String {
        let cert_dir = self.cfg.certs_root.join(&spec.domain);
        let tls_active =
            !matches!(spec.tls, TlsMode::Disabled) && cert_dir.join("fullchain.pem").exists();
        let effective_tls = if tls_active {
            spec.tls.clone()
        } else {
            TlsMode::Disabled
        };
        let acme_root = self.cfg.acme_root.display().to_string();
        let ctx = NginxContext {
            domain: &spec.domain,
            aliases: &spec.aliases,
            docroot,
            runtime: &spec.runtime,
            app_port,
            php_socket,
            tls: &effective_tls,
            cert_dir: if tls_active {
                Some(cert_dir.as_path())
            } else {
                None
            },
            acme_root: &acme_root,
            force_https: spec.force_https,
        };
        templates::nginx_site(&ctx)
    }

    async fn website_clone(
        &self,
        source_domain: &str,
        target_domain: &str,
        with_database: bool,
        actor: &str,
    ) -> Result<Response, WireError> {
        validate_domain(source_domain).map_err(invalid)?;
        validate_domain(target_domain).map_err(invalid)?;
        if source_domain.eq_ignore_ascii_case(target_domain) {
            return Err(WireError::invalid("source and target domains must differ"));
        }
        let source = self
            .state
            .get_website(source_domain)
            .map_err(internal)?
            .ok_or_else(|| WireError::not_found(format!("website '{source_domain}' not found")))?;
        if self
            .state
            .get_website(target_domain)
            .map_err(internal)?
            .is_some()
        {
            return Err(WireError::conflict(format!(
                "website '{target_domain}' already exists"
            )));
        }
        if !matches!(source.spec.runtime, Runtime::Static | Runtime::Php { .. }) {
            return Err(WireError::conflict(
                "the staging clone supports static and PHP sites only",
            ));
        }
        if source.spec.docroot == "public_html" {
            return Err(WireError::conflict(
                "legacy sites with a shared public_html cannot be cloned",
            ));
        }
        let laravel = source.spec.docroot.ends_with("/public");
        let source_root = if laravel {
            source.spec.docroot.trim_end_matches("/public").to_string()
        } else {
            source.spec.docroot.clone()
        };
        let target_root = format!("{target_domain}/public_html");
        let target_docroot = if laravel {
            format!("{target_root}/public")
        } else {
            target_root.clone()
        };

        let databases: Vec<_> = self
            .state
            .list_databases()
            .map_err(internal)?
            .into_iter()
            .filter(|database| database.domain.eq_ignore_ascii_case(source_domain))
            .collect();
        if databases.len() > 1 {
            return Err(WireError::conflict(
                "the staging clone supports at most one database",
            ));
        }
        let source_db = databases.into_iter().next();
        if source_db.is_some() && !with_database {
            return Err(WireError::conflict(
                "the source site has a database; enable database cloning",
            ));
        }
        if source_db.is_some() {
            let root = self.exec.home(&source.spec.username).join(&source_root);
            if !root.join("wp-config.php").is_file() && !root.join(".env").is_file() {
                return Err(WireError::conflict(
                    "the source database config (wp-config.php or .env) was not found",
                ));
            }
        }

        let mut spec = source.spec.clone();
        spec.domain = target_domain.to_string();
        spec.aliases.clear();
        spec.tls = TlsMode::Disabled;
        spec.force_https = false;
        spec.docroot = target_root.clone();
        let mut view = match self.website_upsert(spec.clone(), actor).await? {
            Response::Website { website } => website,
            _ => return Err(WireError::internal("unexpected website response")),
        };

        self.exec
            .copy_site_tree(&spec.username, &source_root, &target_root)
            .await
            .map_err(exec_error)?;

        if let Some(source_db) = source_db {
            let response = self
                .database_create(target_domain, &format!("clone{}", random_hex(2)), actor)
                .await?;
            let target_db = match response {
                Response::Database { database } => database,
                _ => return Err(WireError::internal("unexpected database response")),
            };
            self.exec
                .clone_database(&source_db.username, &target_db.username)
                .await
                .map_err(exec_error)?;
            let rewritten = self
                .exec
                .rewrite_clone_config(
                    &spec.username,
                    &target_root,
                    &source_db.username,
                    &source_db.password,
                    &target_db.username,
                    &target_db.password,
                )
                .await
                .map_err(exec_error)?;
            if !rewritten {
                return Err(WireError::conflict(
                    "the application database config could not be rewritten",
                ));
            }
        }

        if laravel {
            spec.docroot = target_docroot;
            view = match self.website_upsert(spec, actor).await? {
                Response::Website { website } => website,
                _ => return Err(WireError::internal("unexpected website response")),
            };
        }
        self.log(
            actor,
            "website.clone",
            target_domain,
            &format!("source={source_domain} database={with_database}"),
        )?;
        Ok(Response::Website { website: view })
    }

    async fn website_delete(&self, domain: &str, actor: &str) -> Result<Response, WireError> {
        validate_domain(domain).map_err(invalid)?;
        let website = self
            .state
            .get_website(domain)
            .map_err(internal)?
            .ok_or_else(|| WireError::not_found(format!("website '{domain}' not found")))?;
        let databases: Vec<_> = self
            .state
            .list_databases()
            .map_err(internal)?
            .into_iter()
            .filter(|database| database.domain == domain)
            .collect();
        for database in databases {
            self.database_delete(&database.id, actor).await?;
        }
        if self
            .state
            .get_mail_domain(domain)
            .map_err(internal)?
            .is_some()
        {
            self.mail_domain_delete(domain, actor).await?;
        }
        let webmail = Self::webmail_domain(domain);
        let _ = self.exec.remove_site(&webmail).await;
        let _ = self.exec.remove_cert(&webmail).await;
        for ftp in self
            .state
            .list_ftp()
            .map_err(internal)?
            .into_iter()
            .filter(|account| account.domain == domain)
        {
            let _ = self.exec.remove_ftp_user(&ftp.login).await;
            let _ = self.state.delete_ftp(&ftp.id);
        }
        let _ = self.exec.remove_cert(domain).await;
        self.exec.remove_site(domain).await.map_err(exec_error)?;
        if self.cfg.dns_enabled {
            self.dns_remove_zone(domain).await;
        }
        // New sites own a dedicated <domain>/ directory. Legacy sites that
        // still point at the shared public_html keep their files untouched.
        let dedicated = website.spec.docroot == domain
            || website.spec.docroot.starts_with(&format!("{domain}/"));
        if dedicated {
            if let Err(err) = self
                .exec
                .remove_website_root(&website.spec.username, domain)
                .await
            {
                tracing::warn!(domain, error = %err, "website directory could not be removed");
            }
        }
        self.state.delete_website(domain).map_err(internal)?;
        self.log(actor, "website.delete", domain, "removed")?;
        Ok(Response::Ack {
            message: format!("website '{domain}' deleted"),
        })
    }

    async fn ensure_default_php_pool(
        &self,
        username: &str,
        version: &str,
    ) -> Result<PhpPoolView, WireError> {
        if let Some(pool) = self.state.get_php_pool(username).map_err(internal)? {
            if pool.spec.version != version {
                return Err(WireError::conflict(format!(
                    "account '{username}' already has a PHP {} pool; update it to {version} first",
                    pool.spec.version
                )));
            }
            return Ok(pool);
        }
        let spec = PhpPoolSpec {
            username: username.to_string(),
            version: version.to_string(),
            process_manager: rynx_proto::PhpProcessManager::Dynamic,
            max_children: 8,
            memory_limit_mb: 256,
            upload_max_mb: 64,
            enabled: true,
        };
        self.apply_php_pool(&spec).await
    }

    async fn apply_php_pool(&self, spec: &PhpPoolSpec) -> Result<PhpPoolView, WireError> {
        let account = self.require_account(&spec.username)?;
        let socket = self
            .cfg
            .php_socket_dir
            .join(format!("php{}-fpm-{}.sock", spec.version, spec.username))
            .display()
            .to_string();
        let home = account.home.clone();
        let content = templates::php_fpm_pool(spec, &socket, &home);

        if let Some(existing) = self.state.get_php_pool(&spec.username).map_err(internal)? {
            if existing.spec.version != spec.version {
                self.exec
                    .remove_php_pool(&spec.username, &existing.spec.version)
                    .await
                    .map_err(exec_error)?;
            }
        }
        self.exec
            .apply_php_pool(&spec.username, &spec.version, &content, spec.enabled)
            .await
            .map_err(exec_error)?;
        self.state.upsert_php_pool(spec, &socket).map_err(internal)
    }

    async fn ensure_php_version(&self, version: &str) -> Result<(), WireError> {
        let versions = self.exec.php_versions().await.map_err(exec_error)?;
        if versions.iter().any(|installed| installed == version) {
            Ok(())
        } else {
            Err(WireError::unsupported(format!(
                "PHP {version} is not installed on this server"
            )))
        }
    }

    async fn php_pool_upsert(&self, spec: PhpPoolSpec, actor: &str) -> Result<Response, WireError> {
        validate_php_pool_spec(&spec).map_err(invalid)?;
        self.ensure_php_version(&spec.version).await?;
        let view = self.apply_php_pool(&spec).await?;
        self.log(
            actor,
            "php_pool.upsert",
            &spec.username,
            &format!("php={} pm={}", spec.version, spec.process_manager.as_str()),
        )?;
        Ok(Response::PhpPool { pool: view })
    }

    async fn php_pool_delete(&self, username: &str, actor: &str) -> Result<Response, WireError> {
        validate::validate_username(username).map_err(invalid)?;
        let pool = self
            .state
            .get_php_pool(username)
            .map_err(internal)?
            .ok_or_else(|| WireError::not_found("PHP pool not found"))?;
        self.exec
            .remove_php_pool(username, &pool.spec.version)
            .await
            .map_err(exec_error)?;
        self.state.delete_php_pool(username).map_err(internal)?;
        self.log(actor, "php_pool.delete", username, "removed")?;
        Ok(Response::Ack {
            message: "PHP pool deleted".into(),
        })
    }

    async fn app_upsert(&self, spec: AppSpec, actor: &str) -> Result<Response, WireError> {
        validate_app_spec(&spec).map_err(invalid)?;
        let is_new = self
            .state
            .get_app(&spec.username, &spec.name)
            .map_err(internal)?
            .is_none();
        if is_new
            && self.state.count_apps(&spec.username).map_err(internal)?
                >= self.cfg.max_apps_per_account
        {
            return Err(WireError::conflict(format!(
                "account '{}' reached the limit of {} applications",
                spec.username, self.cfg.max_apps_per_account
            )));
        }
        let view = self.apply_app(&spec).await?;
        self.log(
            actor,
            "app.upsert",
            &format!("{}/{}", spec.username, spec.name),
            &format!(
                "engine={} version={:?} port={} enabled={}",
                spec.runtime.engine(),
                spec.runtime.version(),
                spec.port,
                spec.enabled
            ),
        )?;
        Ok(Response::App { app: view })
    }

    async fn apply_app(&self, spec: &AppSpec) -> Result<AppView, WireError> {
        let account = self.require_account(&spec.username)?;
        if self
            .state
            .port_in_use(spec.port, &spec.username, &spec.name)
            .map_err(internal)?
        {
            return Err(WireError::conflict(format!(
                "port {} is already assigned to another application",
                spec.port
            )));
        }
        let unit = validate::unit_name(&spec.username, &spec.name);
        let working_dir = self.exec.working_dir(&spec.username, &spec.name);
        let env_filename = templates::app_env_filename(&spec.username, &spec.name);
        let unit_content = templates::systemd_unit(
            spec,
            &working_dir.display().to_string(),
            &self
                .cfg
                .app_env_dir
                .join(&env_filename)
                .display()
                .to_string(),
        );
        let env_content = templates::app_env_file(spec);

        self.exec
            .apply_app(
                spec,
                account.uid,
                &unit,
                &unit_content,
                &env_filename,
                &env_content,
                &working_dir,
                spec.enabled,
            )
            .await
            .map_err(exec_error)?;
        self.state
            .upsert_app(spec, &unit, &working_dir.display().to_string())
            .map_err(internal)
    }

    async fn app_delete(
        &self,
        username: &str,
        name: &str,
        actor: &str,
    ) -> Result<Response, WireError> {
        validate::validate_username(username).map_err(invalid)?;
        validate::validate_app_name(name).map_err(invalid)?;
        let app = self
            .state
            .get_app(username, name)
            .map_err(internal)?
            .ok_or_else(|| WireError::not_found("application not found"))?;
        let used_by = self
            .state
            .websites_using_app(username, name)
            .map_err(internal)?;
        if !used_by.is_empty() {
            return Err(WireError::conflict(format!(
                "application is still used by: {}",
                used_by.join(", ")
            )));
        }
        let env_filename = templates::app_env_filename(username, name);
        self.exec
            .remove_app(
                username,
                &app.unit,
                &env_filename,
                std::path::Path::new(&app.working_dir),
                false,
            )
            .await
            .map_err(exec_error)?;
        self.state.delete_app(username, name).map_err(internal)?;
        self.log(
            actor,
            "app.delete",
            &format!("{username}/{name}"),
            "removed",
        )?;
        Ok(Response::Ack {
            message: format!("application '{username}/{name}' deleted"),
        })
    }

    async fn installer_apply(
        &self,
        spec: InstallerApplySpec,
        actor: &str,
    ) -> Result<Response, WireError> {
        validate::validate_username(&spec.username).map_err(invalid)?;
        validate_domain(&spec.domain).map_err(invalid)?;
        validate_php_version(&spec.php_version).map_err(invalid)?;
        validate_site_root(&spec.username, &spec.docroot).map_err(invalid)?;
        if spec.docroot != format!("{}/public_html", spec.domain) {
            return Err(WireError::invalid(
                "installer document root must be dedicated to the domain",
            ));
        }
        if spec.database.len() > 64
            || !spec
                .database
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            || !spec.database.starts_with(&format!("{}_", spec.username))
        {
            return Err(WireError::invalid(
                "invalid installer database for this account",
            ));
        }
        if spec.site_title.trim().is_empty()
            || spec.site_title.len() > 200
            || spec.site_title.chars().any(|ch| ch.is_control())
        {
            return Err(WireError::invalid("invalid application title"));
        }
        let website = self
            .state
            .get_website(&spec.domain)
            .map_err(internal)?
            .ok_or_else(|| {
                WireError::not_found("website not found; create it before installing")
            })?;
        if website.spec.username != spec.username || website.spec.docroot != spec.docroot {
            return Err(WireError::invalid(
                "the website does not match the installer target",
            ));
        }
        if spec.app == InstallerApp::Wordpress {
            validate_wordpress_fields(&spec)?;
        }
        let archive = match (spec.archive_path.as_deref(), spec.archive_sha256.as_deref()) {
            (Some(path), Some(sha)) => Some(validate_staged_archive(
                &self.cfg.installer_staging,
                path,
                sha,
                spec.archive_size,
            )?),
            (None, None) if spec.app == InstallerApp::Laravel => None,
            _ => return Err(WireError::invalid("invalid installer archive metadata")),
        };
        let message = self
            .exec
            .installer_apply(&spec, archive.as_deref())
            .await
            .map_err(exec_error)?;
        self.log(
            actor,
            "installer.install",
            &spec.domain,
            &format!("app={}", spec.app.as_str()),
        )?;
        Ok(Response::InstallerResult { message })
    }

    async fn website_logs(
        &self,
        domain: &str,
        kind: &str,
        lines: u32,
    ) -> Result<Response, WireError> {
        validate_domain(domain).map_err(invalid)?;
        if !matches!(kind, "access" | "error" | "php") {
            return Err(WireError::invalid("unsupported log kind"));
        }
        let website = self
            .state
            .get_website(domain)
            .map_err(internal)?
            .ok_or_else(|| WireError::not_found(format!("website '{domain}' not found")))?;
        let path = if kind == "php" {
            self.exec
                .home(&website.spec.username)
                .join("logs")
                .join("php-error.log")
        } else {
            PathBuf::from(format!("/var/log/nginx/{domain}.{kind}.log"))
        };
        let content = self
            .exec
            .read_log_tail(&path, lines.clamp(1, 500))
            .await
            .map_err(exec_error)?;
        Ok(Response::LogText { content })
    }

    async fn mail_queue(&self) -> Result<Response, WireError> {
        if !self.cfg.mail_enabled {
            return Err(WireError::unsupported("mail management is disabled"));
        }
        let entries = self.exec.mail_queue().await.map_err(exec_error)?;
        Ok(Response::MailQueue { entries })
    }

    async fn mail_queue_action(
        &self,
        action: &str,
        id: Option<&str>,
        actor: &str,
    ) -> Result<Response, WireError> {
        if !self.cfg.mail_enabled {
            return Err(WireError::unsupported("mail management is disabled"));
        }
        if !matches!(action, "flush" | "delete" | "hold" | "release") {
            return Err(WireError::invalid("invalid mail queue action"));
        }
        if action != "flush" {
            let id = id.unwrap_or_default();
            if id.is_empty() || id.len() > 32 || !id.chars().all(|ch| ch.is_ascii_alphanumeric()) {
                return Err(WireError::invalid("invalid message id"));
            }
        }
        self.exec
            .mail_queue_action(action, id)
            .await
            .map_err(exec_error)?;
        self.log(actor, "mail.queue", id.unwrap_or("all"), action)?;
        Ok(Response::Ack {
            message: format!("mail queue action '{action}' applied"),
        })
    }

    async fn ssh_keys(&self, username: &str) -> Result<Response, WireError> {
        validate::validate_username(username).map_err(invalid)?;
        let account = self.require_account(username)?;
        if !account.spec.enabled || !account.spec.ssh_enabled {
            return Err(WireError::conflict(
                "SSH access is disabled for this account",
            ));
        }
        let keys = self.exec.ssh_keys(username).await.map_err(exec_error)?;
        Ok(Response::SshKeys { keys })
    }

    async fn ssh_key_add(
        &self,
        username: &str,
        key: &str,
        actor: &str,
    ) -> Result<Response, WireError> {
        validate::validate_username(username).map_err(invalid)?;
        validate_ssh_key(key)?;
        let account = self.require_account(username)?;
        if !account.spec.enabled || !account.spec.ssh_enabled {
            return Err(WireError::conflict(
                "SSH access is disabled for this account",
            ));
        }
        self.exec
            .add_ssh_key(username, key.trim())
            .await
            .map_err(exec_error)?;
        self.log(actor, "ssh.key.add", username, "")?;
        Ok(Response::Ack {
            message: "SSH key added".into(),
        })
    }

    async fn ssh_key_delete(
        &self,
        username: &str,
        key: &str,
        actor: &str,
    ) -> Result<Response, WireError> {
        validate::validate_username(username).map_err(invalid)?;
        let account = self.require_account(username)?;
        if !account.spec.enabled || !account.spec.ssh_enabled {
            return Err(WireError::conflict(
                "SSH access is disabled for this account",
            ));
        }
        self.exec
            .remove_ssh_key(username, key.trim())
            .await
            .map_err(exec_error)?;
        self.log(actor, "ssh.key.delete", username, "")?;
        Ok(Response::Ack {
            message: "SSH key removed".into(),
        })
    }

    async fn cert_issue(
        &self,
        domain: &str,
        email: &str,
        staging: bool,
        actor: &str,
    ) -> Result<Response, WireError> {
        validate_domain(domain).map_err(invalid)?;
        validate_email(email).map_err(invalid)?;
        let website = self
            .state
            .get_website(domain)
            .map_err(internal)?
            .ok_or_else(|| WireError::not_found(format!("website '{domain}' not found")))?;
        if website.spec.tls != TlsMode::LetsEncrypt {
            return Err(WireError::invalid(
                "website TLS mode must be lets_encrypt to request a certificate",
            ));
        }
        let webroot = self.exec.acme_root();
        let mut domains = vec![domain.to_string()];
        for alias in &website.spec.aliases {
            if !domains.contains(alias) {
                domains.push(alias.clone());
            }
        }
        if self.cfg.dns_enabled {
            self.dns_ensure_zone(domain, self.cfg.mail_enabled).await?;
            self.dns_render(domain).await?;
        }
        // `ftp.<domain>` is intentionally not added automatically: when the
        // domain uses external DNS the extra SAN fails the HTTP-01 challenge
        // and rejects the whole certificate. Add it as an explicit alias when
        // the record exists and is reachable.
        // Ensure the vhost serves the ACME challenge for ftp.<domain> too.
        self.apply_website(&website.spec).await?;
        self.exec
            .issue_cert(domain, &domains, email, &webroot, staging)
            .await
            .map_err(exec_error)?;

        // Re-render the site so Nginx starts serving TLS. Re-read the website
        // because a concurrent edit may have changed TLS or redirect settings.
        let latest = self
            .state
            .get_website(domain)
            .map_err(internal)?
            .unwrap_or(website);
        self.apply_website(&latest.spec).await?;
        if let Err(err) = self.exec.apply_ftp_certificate(domain).await {
            tracing::warn!(domain = %domain, error = %err, "FTP certificate update failed");
        }
        self.log(
            actor,
            "cert.issue",
            domain,
            if staging { "staging" } else { "production" },
        )?;

        let cert = match self.exec.cert_info(domain).await.map_err(exec_error)? {
            Some(cert) => cert,
            None => CertView {
                domain: domain.to_string(),
                issuer: "unknown".into(),
                not_after: "unknown".into(),
                status: CertificateStatus::Missing,
                path: self.cfg.certs_root.join(domain).display().to_string(),
            },
        };
        Ok(Response::Cert { cert })
    }

    async fn cert_list(&self) -> Result<Response, WireError> {
        let mut certs = Vec::new();
        for website in self.state.list_websites().map_err(internal)? {
            if matches!(website.spec.tls, TlsMode::Disabled) {
                continue;
            }
            let domain = website.spec.domain.clone();
            match self.exec.cert_info(&domain).await {
                Ok(Some(cert)) => certs.push(cert),
                Ok(None) => certs.push(CertView {
                    domain: domain.clone(),
                    issuer: String::new(),
                    not_after: String::new(),
                    status: CertificateStatus::Missing,
                    path: self.cfg.certs_root.join(&domain).display().to_string(),
                }),
                Err(_) => certs.push(CertView {
                    domain: domain.clone(),
                    issuer: String::new(),
                    not_after: String::new(),
                    status: CertificateStatus::Error,
                    path: self.cfg.certs_root.join(&domain).display().to_string(),
                }),
            }
        }
        for mail in self.state.list_mail_domains().map_err(internal)? {
            if !mail.enabled {
                continue;
            }
            let domain = Self::webmail_domain(&mail.domain);
            match self.exec.cert_info(&domain).await {
                Ok(Some(cert)) => certs.push(cert),
                Ok(None) => certs.push(CertView {
                    domain: domain.clone(),
                    issuer: String::new(),
                    not_after: String::new(),
                    status: CertificateStatus::Missing,
                    path: self.cfg.certs_root.join(&domain).display().to_string(),
                }),
                Err(_) => certs.push(CertView {
                    domain: domain.clone(),
                    issuer: String::new(),
                    not_after: String::new(),
                    status: CertificateStatus::Error,
                    path: self.cfg.certs_root.join(&domain).display().to_string(),
                }),
            }
        }
        Ok(Response::Certs { certs })
    }

    fn webmail_aliases(domain: &str) -> Vec<String> {
        ["mail", "imap", "smtp", "pop", "autodiscover", "autoconfig"]
            .into_iter()
            .map(|prefix| format!("{prefix}.{domain}"))
            .collect()
    }

    fn webmail_domain(domain: &str) -> String {
        format!("webmail.{domain}")
    }

    fn mail_subdomains(domain: &str) -> Vec<String> {
        let mut names = vec![Self::webmail_domain(domain)];
        names.extend(Self::webmail_aliases(domain));
        names
    }

    async fn enrich_mail_domain(&self, mut view: MailDomainView) -> MailDomainView {
        let webmail = Self::webmail_domain(&view.domain);
        match self.exec.cert_info(&webmail).await {
            Ok(Some(cert)) => {
                view.tls_status = cert.status;
                view.tls_not_after = Some(cert.not_after);
            }
            Ok(None) => {
                view.tls_status = CertificateStatus::Missing;
                view.tls_not_after = None;
            }
            Err(_) => {
                view.tls_status = CertificateStatus::Error;
                view.tls_not_after = None;
            }
        }
        view.webmail_url = format!("https://{webmail}/");
        view
    }

    async fn apply_webmail_vhost(&self, domain: &str) -> Result<(), WireError> {
        let webmail = Self::webmail_domain(domain);
        let aliases = Self::webmail_aliases(domain);
        let cert_dir = self.cfg.certs_root.join(&webmail);
        let cert =
            if cert_dir.join("fullchain.pem").exists() && cert_dir.join("privkey.pem").exists() {
                Some(cert_dir.as_path())
            } else {
                None
            };
        let content = templates::webmail_site(
            &webmail,
            &aliases,
            cert,
            &self.cfg.acme_root.display().to_string(),
            webmail_root(),
            WEBMAIL_PHP_SOCKET,
        );
        self.exec
            .apply_site(&webmail, &content, true)
            .await
            .map_err(exec_error)
    }

    async fn sync_mail_config(&self) -> Result<(), WireError> {
        let views = self.state.list_mail_domains().map_err(internal)?;
        let domains: Vec<MailDomainSpec> = views
            .iter()
            .map(|view| MailDomainSpec {
                domain: view.domain.clone(),
                username: view.username.clone(),
                enabled: view.enabled,
                catch_all: view.catch_all.clone(),
            })
            .collect();
        let accounts = self.state.list_mail_accounts().map_err(internal)?;
        let mut configs = Vec::with_capacity(accounts.len());
        for account in accounts {
            let Some(hash) = self
                .state
                .mail_account_hash(&account.id)
                .map_err(internal)?
            else {
                continue;
            };
            configs.push(MailAccountConfig {
                domain: account.domain.clone(),
                local_part: account.local_part.clone(),
                password_hash: hash,
                quota_mb: account.quota_mb,
                enabled: account.enabled,
                aliases: account.aliases.clone(),
                forward_to: account.forward_to.clone(),
            });
        }
        self.exec
            .sync_mail(&domains, &configs)
            .await
            .map_err(exec_error)
    }

    async fn mail_domain_upsert(
        &self,
        spec: MailDomainSpec,
        actor: &str,
    ) -> Result<Response, WireError> {
        validate_mail_domain_spec(&spec).map_err(invalid)?;
        if !self.cfg.mail_enabled {
            return Err(WireError::unsupported("mail management is disabled"));
        }
        let website = self
            .state
            .get_website(&spec.domain)
            .map_err(internal)?
            .ok_or_else(|| WireError::not_found(format!("website '{}' not found", spec.domain)))?;
        if website.spec.username != spec.username {
            return Err(WireError::conflict(
                "mail domain owner does not match the website owner",
            ));
        }
        let account = self.require_account(&spec.username)?;
        if !account.spec.enabled {
            return Err(WireError::conflict(format!(
                "account '{}' is suspended",
                spec.username
            )));
        }
        for name in Self::mail_subdomains(&spec.domain) {
            if self.state.get_website(&name).map_err(internal)?.is_some() {
                return Err(WireError::conflict(format!(
                    "{name} is already a website; remove or rename it before enabling mail"
                )));
            }
        }
        self.state.upsert_mail_domain(&spec).map_err(internal)?;
        self.dns_ensure_zone(&spec.domain, true).await?;
        self.dns_render(&spec.domain).await?;
        if spec.enabled {
            self.apply_webmail_vhost(&spec.domain).await?;
        } else {
            let _ = self
                .exec
                .remove_site(&Self::webmail_domain(&spec.domain))
                .await;
        }
        self.sync_mail_config().await?;
        self.log(
            actor,
            "mail.domain.upsert",
            &spec.domain,
            &format!(
                "user={} enabled={} catch_all={}",
                spec.username,
                spec.enabled,
                spec.catch_all.as_deref().unwrap_or("-")
            ),
        )?;
        let view = self
            .state
            .get_mail_domain(&spec.domain)
            .map_err(internal)?
            .ok_or_else(|| WireError::internal("mail domain disappeared after upsert"))?;
        Ok(Response::MailDomain {
            domain: self.enrich_mail_domain(view).await,
        })
    }

    async fn mail_domain_delete(&self, domain: &str, actor: &str) -> Result<Response, WireError> {
        validate_domain(domain).map_err(invalid)?;
        if self
            .state
            .get_mail_domain(domain)
            .map_err(internal)?
            .is_none()
        {
            return Err(WireError::not_found(format!(
                "mail domain '{domain}' not found"
            )));
        }
        for account in self
            .state
            .list_mail_accounts_for_domain(domain)
            .map_err(internal)?
        {
            let _ = self
                .exec
                .remove_mailbox(&account.domain, &account.local_part)
                .await;
        }
        self.state.delete_mail_domain(domain).map_err(internal)?;
        let webmail = Self::webmail_domain(domain);
        let _ = self.exec.remove_site(&webmail).await;
        let _ = self.exec.remove_cert(&webmail).await;
        let _ = self.exec.remove_mail_domain(domain).await;
        if let Ok(Some((serial, _, selector))) = self.state.get_dns_zone_meta(domain) {
            let _ = self
                .state
                .upsert_dns_zone_meta(domain, serial, false, &selector);
        }
        let _ = self.exec.remove_dkim_key(domain).await;
        self.remove_mail_dns(domain).await;
        let _ = self.dns_sync_dkim_tables().await;
        self.sync_mail_config().await?;
        self.log(actor, "mail.domain.delete", domain, "")?;
        Ok(Response::Ack {
            message: format!("mail domain '{domain}' deleted"),
        })
    }

    async fn remove_mail_dns(&self, domain: &str) {
        let Ok(records) = self.state.list_dns_records(domain) else {
            return;
        };
        for record in records {
            if !record.managed {
                continue;
            }
            let name = record.spec.name.as_str();
            let rtype = record.spec.rtype.as_str();
            let remove = match name {
                "@" => rtype == "MX",
                "mail" | "webmail" | "imap" | "smtp" | "pop" | "autodiscover" | "autoconfig"
                | "mta-sts" | "_dmarc" | "_domainkey" | "mail._domainkey" | "_imaps._tcp"
                | "_imap._tcp" | "_pop3s._tcp" | "_pop3._tcp" | "_submissions._tcp"
                | "_submission._tcp" | "_autodiscover._tcp" | "_sieve._tcp" | "_smtp._tls"
                | "_mta-sts" => true,
                _ => false,
            };
            if remove {
                let _ = self.state.delete_dns_record(domain, &record.id);
            }
        }
        let _ = self.dns_render(domain).await;
    }

    async fn mail_tls(
        &self,
        domain: &str,
        email: &str,
        actor: &str,
    ) -> Result<Response, WireError> {
        validate_domain(domain).map_err(invalid)?;
        validate_email(email).map_err(invalid)?;
        let mail = self
            .state
            .get_mail_domain(domain)
            .map_err(internal)?
            .ok_or_else(|| WireError::not_found(format!("mail domain '{domain}' not found")))?;
        if !mail.enabled {
            return Err(WireError::conflict("mail domain is disabled"));
        }
        self.apply_webmail_vhost(domain).await?;
        let webmail = Self::webmail_domain(domain);
        let mut names = vec![webmail.clone()];
        names.extend(Self::webmail_aliases(domain));
        self.exec
            .issue_cert(&webmail, &names, email, &self.exec.acme_root(), false)
            .await
            .map_err(exec_error)?;
        self.sync_mail_config().await?;
        self.apply_webmail_vhost(domain).await?;
        let cert = self
            .exec
            .cert_info(&webmail)
            .await
            .map_err(exec_error)?
            .ok_or_else(|| WireError::internal("certificate was not installed"))?;
        self.log(actor, "mail.tls.issue", domain, &webmail)?;
        Ok(Response::Cert { cert })
    }

    async fn mail_domain_list(&self) -> Result<Response, WireError> {
        let mut domains = Vec::new();
        for view in self.state.list_mail_domains().map_err(internal)? {
            domains.push(self.enrich_mail_domain(view).await);
        }
        Ok(Response::MailDomains { domains })
    }

    async fn mail_account_upsert(
        &self,
        spec: MailAccountSpec,
        actor: &str,
    ) -> Result<Response, WireError> {
        validate_mail_account_spec(&spec).map_err(invalid)?;
        let domain = self
            .state
            .get_mail_domain(&spec.domain)
            .map_err(internal)?
            .ok_or_else(|| {
                WireError::not_found(format!("mail domain '{}' not found", spec.domain))
            })?;
        if !domain.enabled {
            return Err(WireError::conflict("mail domain is disabled"));
        }
        if let Some(id) = &spec.id {
            let existing = self
                .state
                .get_mail_account(id)
                .map_err(internal)?
                .ok_or_else(|| WireError::not_found(format!("mailbox '{id}' not found")))?;
            if existing.domain != spec.domain || existing.username != domain.username {
                return Err(WireError::conflict("mailbox id belongs to another domain"));
            }
        }
        let password_hash = match spec.password.as_deref() {
            Some(password) => Some(
                self.exec
                    .hash_mail_password(password)
                    .await
                    .map_err(exec_error)?,
            ),
            None => None,
        };
        let view = self
            .state
            .upsert_mail_account(&spec, &domain.username, password_hash.as_deref())
            .map_err(internal)?;
        self.sync_mail_config().await?;
        self.log(
            actor,
            "mail.account.upsert",
            &view.address,
            &format!(
                "quota_mb={} enabled={} aliases={} forwards={}",
                view.quota_mb,
                view.enabled,
                view.aliases.len(),
                view.forward_to.len()
            ),
        )?;
        Ok(Response::MailAccount { account: view })
    }

    async fn mail_account_delete(&self, id: &str, actor: &str) -> Result<Response, WireError> {
        let Some(account) = self.state.get_mail_account(id).map_err(internal)? else {
            return Err(WireError::not_found(format!("mailbox '{id}' not found")));
        };
        let _ = self
            .exec
            .remove_mailbox(&account.domain, &account.local_part)
            .await;
        self.state.delete_mail_account(id).map_err(internal)?;
        self.sync_mail_config().await?;
        self.log(actor, "mail.account.delete", &account.address, "")?;
        Ok(Response::Ack {
            message: format!("mailbox '{}' deleted", account.address),
        })
    }

    async fn mail_account_list(&self) -> Result<Response, WireError> {
        let accounts = self.state.list_mail_accounts().map_err(internal)?;
        Ok(Response::MailAccounts { accounts })
    }

    async fn cert_renew(&self, staging: bool, actor: &str) -> Result<Response, WireError> {
        let websites: Vec<WebsiteView> = self
            .state
            .list_websites()
            .map_err(internal)?
            .into_iter()
            .filter(|website| website.spec.tls == TlsMode::LetsEncrypt)
            .collect();
        if websites.is_empty() {
            return Ok(Response::Ack {
                message: "no Let's Encrypt websites configured".into(),
            });
        }
        self.exec.renew_certs(staging).await.map_err(exec_error)?;
        let _ = self.sync_mail_config().await;
        for mail in self.state.list_mail_domains().map_err(internal)? {
            if mail.enabled {
                let _ = self.apply_webmail_vhost(&mail.domain).await;
            }
        }

        let mut failures = 0usize;
        for website in &websites {
            if self.apply_website(&website.spec).await.is_err() {
                failures += 1;
            }
        }
        self.log(
            actor,
            "cert.renew",
            "all",
            &format!(
                "staging={staging} websites={} failures={failures}",
                websites.len()
            ),
        )?;
        Ok(Response::Ack {
            message: format!(
                "renewed {} certificate(s), {failures} render failure(s)",
                websites.len()
            ),
        })
    }

    fn backup_paths(&self, username: &str) -> Vec<String> {
        let mut paths: Vec<PathBuf> = Vec::new();
        if let Ok(Some(account)) = self.state.get_account(username) {
            paths.push(PathBuf::from(account.home));
        }
        if let Ok(websites) = self.state.list_websites() {
            for website in websites.iter().filter(|w| w.spec.username == username) {
                paths.push(
                    self.cfg
                        .nginx_sites_dir
                        .join(format!("{}.conf", website.spec.domain)),
                );
                paths.push(
                    self.cfg
                        .bind_zones_dir
                        .join(format!("{}.db", website.spec.domain)),
                );
            }
        }
        if let Ok(Some(pool)) = self.state.get_php_pool(username) {
            paths.push(
                self.cfg
                    .php_fpm_root
                    .join(&pool.spec.version)
                    .join("fpm/pool.d")
                    .join(format!("rynx-{username}.conf")),
            );
        }
        if let Ok(apps) = self.state.list_apps() {
            for app in apps.iter().filter(|a| a.spec.username == username) {
                paths.push(self.cfg.systemd_dir.join(&app.unit));
                paths.push(
                    self.cfg
                        .app_env_dir
                        .join(rynx_core::templates::app_env_filename(
                            username,
                            &app.spec.name,
                        )),
                );
            }
        }
        paths
            .into_iter()
            .filter(|path| path.exists())
            .map(|path| path.display().to_string())
            .collect()
    }

    async fn backup_create(&self, username: &str, actor: &str) -> Result<Response, WireError> {
        validate::validate_username(username).map_err(invalid)?;
        let account = self.require_account(username)?;
        let id = uuid::Uuid::new_v4().to_string();
        let timestamp = now_unix();
        let dest = self
            .cfg
            .backup_dir
            .join(username)
            .join(format!("{timestamp}-{id}.tar.gz"));
        let paths = self.backup_paths(username);
        let size = self
            .exec
            .create_backup(&paths, &dest)
            .await
            .map_err(exec_error)?;
        self.exec
            .repair_backup_permissions(&dest)
            .await
            .map_err(exec_error)?;
        let offsite = match self.exec.offsite_backup(&dest, username).await {
            Ok(uploaded) => uploaded,
            Err(err) => {
                tracing::warn!(username, error = %err, "offsite backup failed");
                false
            }
        };
        let view = BackupView {
            id: id.clone(),
            username: username.to_string(),
            created_at: now_rfc3339(),
            size_bytes: size,
            path: dest.display().to_string(),
            status: if self.cfg.simulate {
                "simulated".into()
            } else {
                "complete".into()
            },
        };
        self.state.insert_backup(&view).map_err(internal)?;

        let retention = self.cfg.backup_retention.max(1);
        let backups = self.state.backups_for(username).map_err(internal)?;
        for old in backups.iter().skip(retention) {
            let _ = self.exec.delete_backup_file(Path::new(&old.path)).await;
            let _ = self.state.delete_backup(&old.id);
        }

        self.log(
            actor,
            "backup.create",
            &format!("{username}/{id}"),
            &format!("bytes={size} paths={} offsite={offsite}", paths.len()),
        )?;
        let _ = account;
        Ok(Response::Backup { backup: view })
    }

    async fn backup_delete(&self, id: &str, actor: &str) -> Result<Response, WireError> {
        let backup = self
            .state
            .get_backup(id)
            .map_err(internal)?
            .ok_or_else(|| WireError::not_found("backup not found"))?;
        self.exec
            .delete_backup_file(Path::new(&backup.path))
            .await
            .map_err(exec_error)?;
        self.state.delete_backup(id).map_err(internal)?;
        self.log(actor, "backup.delete", id, &backup.username)?;
        Ok(Response::Ack {
            message: "backup deleted".into(),
        })
    }

    async fn backup_restore(&self, id: &str, actor: &str) -> Result<Response, WireError> {
        let backup = self
            .state
            .get_backup(id)
            .map_err(internal)?
            .ok_or_else(|| WireError::not_found("backup not found"))?;
        let account = self.require_account(&backup.username)?;
        self.exec
            .restore_backup(Path::new(&backup.path), &backup.username, account.uid)
            .await
            .map_err(exec_error)?;

        // Restore desired state artifacts after the filesystem snapshot.
        self.exec
            .ensure_account(&account.spec, account.uid)
            .await
            .map_err(exec_error)?;
        if let Some(pool) = self
            .state
            .get_php_pool(&backup.username)
            .map_err(internal)?
        {
            let _ = self.apply_php_pool(&pool.spec).await;
        }
        for app in self
            .state
            .list_apps()
            .map_err(internal)?
            .into_iter()
            .filter(|a| a.spec.username == backup.username)
        {
            let _ = self.apply_app(&app.spec).await;
        }
        for website in self
            .state
            .list_websites()
            .map_err(internal)?
            .into_iter()
            .filter(|w| w.spec.username == backup.username)
        {
            let _ = self.apply_website(&website.spec).await;
        }
        self.log(
            actor,
            "backup.restore",
            id,
            &format!("user={}", backup.username),
        )?;
        Ok(Response::Ack {
            message: format!("backup restored for '{}'", backup.username),
        })
    }

    fn cron_content(&self, username: &str) -> Result<String, WireError> {
        let jobs = self.state.cron_for(username).map_err(internal)?;
        let active: Vec<&CronJobView> = jobs.iter().filter(|job| job.enabled).collect();
        if active.is_empty() {
            return Ok(String::new());
        }
        let mut content = String::from(
            "# managed-by: RYNXCP\n\
             SHELL=/bin/sh\n\
             PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n\
             MAILTO=\"\"\n",
        );
        for job in active {
            content.push_str(&format!(
                "{} {} {}\n",
                job.schedule, job.username, job.command
            ));
        }
        Ok(content)
    }

    async fn cron_render(&self, username: &str) -> Result<(), WireError> {
        let content = self.cron_content(username)?;
        self.exec
            .apply_cron(username, &content)
            .await
            .map_err(exec_error)
    }

    async fn cron_upsert(&self, spec: CronSpec, actor: &str) -> Result<Response, WireError> {
        validate_cron_spec(&spec).map_err(invalid)?;
        let account = self.require_account(&spec.username)?;
        if !account.spec.enabled {
            return Err(WireError::conflict(format!(
                "account '{}' is suspended",
                spec.username
            )));
        }
        if let Some(id) = &spec.id {
            let existing = self
                .state
                .get_cron(id)
                .map_err(internal)?
                .ok_or_else(|| WireError::not_found("cron job not found"))?;
            if existing.username != spec.username {
                return Err(WireError::conflict("cron job belongs to another account"));
            }
        } else if self.state.cron_count(&spec.username).map_err(internal)? >= 50 {
            return Err(WireError::conflict(
                "the account reached the limit of 50 cron jobs",
            ));
        }
        let job = self.state.upsert_cron(&spec).map_err(internal)?;
        self.cron_render(&spec.username).await?;
        self.log(
            actor,
            "cron.upsert",
            &format!("{}/{}", spec.username, job.id),
            &format!("schedule={} enabled={}", job.schedule, job.enabled),
        )?;
        Ok(Response::CronJob { job })
    }

    async fn cron_delete(&self, id: &str, actor: &str) -> Result<Response, WireError> {
        let job = self
            .state
            .get_cron(id)
            .map_err(internal)?
            .ok_or_else(|| WireError::not_found("cron job not found"))?;
        self.state.delete_cron(id).map_err(internal)?;
        self.cron_render(&job.username).await?;
        self.log(
            actor,
            "cron.delete",
            &format!("{}/{}", job.username, job.id),
            "",
        )?;
        Ok(Response::Ack {
            message: "cron job deleted".into(),
        })
    }

    fn dns_put(
        &self,
        domain: &str,
        name: &str,
        rtype: &str,
        value: &str,
        priority: Option<u16>,
        managed: bool,
    ) -> Result<(), WireError> {
        let spec = DnsRecordSpec {
            domain: domain.to_string(),
            name: name.to_string(),
            rtype: rtype.to_string(),
            value: value.to_string(),
            ttl: 300,
            priority,
        };
        validate_dns_record_spec(&spec).map_err(invalid)?;
        let existing = self
            .state
            .find_dns_record(domain, name, rtype)
            .map_err(internal)?;
        self.state
            .upsert_dns_record(&spec, managed, existing.as_ref().map(|r| r.id.as_str()))
            .map_err(internal)?;
        Ok(())
    }

    async fn dns_seed_defaults(&self, domain: &str) -> Result<(), WireError> {
        let website = self
            .state
            .get_website(domain)
            .map_err(internal)?
            .ok_or_else(|| WireError::not_found(format!("website '{domain}' not found")))?;
        if let Some(ipv4) = &self.cfg.default_ipv4 {
            self.dns_put(domain, "@", "A", ipv4, None, true)?;
            if let Some(mail_host) = &self.cfg.mail_hostname {
                if let Some(prefix) = mail_host.strip_suffix(&format!(".{domain}")) {
                    self.dns_put(domain, prefix, "A", ipv4, None, true)?;
                }
            }
        }
        if let Some(ipv6) = &self.cfg.default_ipv6 {
            self.dns_put(domain, "@", "AAAA", ipv6, None, true)?;
        }
        let www_exists = self
            .state
            .find_dns_record(domain, "www", "CNAME")
            .map_err(internal)?
            .is_some();
        if !www_exists {
            self.dns_put(domain, "www", "CNAME", domain, None, true)?;
        }
        if website.spec.tls != TlsMode::Disabled {
            self.dns_put(
                domain,
                "@",
                "CAA",
                "0 issue \"letsencrypt.org\"",
                None,
                true,
            )?;
        }
        Ok(())
    }

    async fn dns_seed_aliases(&self, domain: &str) -> Result<(), WireError> {
        let website = self
            .state
            .get_website(domain)
            .map_err(internal)?
            .ok_or_else(|| WireError::not_found(format!("website '{domain}' not found")))?;
        let suffix = format!(".{domain}");
        for alias in &website.spec.aliases {
            let Some(label) = alias.strip_suffix(&suffix) else {
                continue;
            };
            if label.is_empty() {
                continue;
            }
            self.dns_put(domain, label, "CNAME", domain, None, true)?;
        }
        Ok(())
    }

    async fn dns_seed_mail(&self, domain: &str) -> Result<(), WireError> {
        let mail_host = format!("mail.{domain}");
        let webmail_host = format!("webmail.{domain}");
        if let Some(ipv4) = &self.cfg.default_ipv4 {
            self.dns_put(domain, "mail", "A", ipv4, None, true)?;
            self.dns_put(domain, "webmail", "A", ipv4, None, true)?;
        }
        if let Some(ipv6) = &self.cfg.default_ipv6 {
            self.dns_put(domain, "mail", "AAAA", ipv6, None, true)?;
            self.dns_put(domain, "webmail", "AAAA", ipv6, None, true)?;
        }
        for (name, target) in [
            ("imap", mail_host.as_str()),
            ("smtp", mail_host.as_str()),
            ("pop", mail_host.as_str()),
            ("autodiscover", webmail_host.as_str()),
            ("autoconfig", webmail_host.as_str()),
        ] {
            self.dns_put(domain, name, "CNAME", target, None, true)?;
        }
        self.dns_put(domain, "@", "MX", &mail_host, Some(10), true)?;
        self.dns_put(
            domain,
            "@",
            "TXT",
            &format!("v=spf1 mx a:{mail_host} -all"),
            None,
            true,
        )?;
        self.dns_put(
            domain,
            "_dmarc",
            "TXT",
            &format!(
                "v=DMARC1; p=quarantine; rua=mailto:postmaster@{domain}; ruf=mailto:postmaster@{domain}; adkim=s; aspf=s; pct=100; fo=1"
            ),
            None,
            true,
        )?;
        self.dns_put(
            domain,
            "_smtp._tls",
            "TXT",
            &format!("v=TLSRPTv1; rua=mailto:tlsrpt@{domain}"),
            None,
            true,
        )?;
        self.dns_put(domain, "_domainkey", "TXT", "t=y; o=~", None, true)?;
        for (name, port) in [
            ("_imaps._tcp", 993),
            ("_imap._tcp", 143),
            ("_pop3s._tcp", 995),
            ("_pop3._tcp", 110),
            ("_submissions._tcp", 465),
            ("_submission._tcp", 587),
            ("_sieve._tcp", 4190),
        ] {
            self.dns_put(
                domain,
                name,
                "SRV",
                &format!("0 1 {port} {mail_host}"),
                None,
                true,
            )?;
        }
        self.dns_put(
            domain,
            "_autodiscover._tcp",
            "SRV",
            &format!("0 1 443 {webmail_host}"),
            None,
            true,
        )?;

        let selector = self.cfg.dkim_selector.clone();
        let dkim_name = format!("{selector}._domainkey");
        if self
            .state
            .find_dns_record(domain, &dkim_name, "TXT")
            .map_err(internal)?
            .is_none()
        {
            let pem = self
                .exec
                .generate_dkim_key(domain, &selector)
                .await
                .map_err(exec_error)?;
            let txt = templates::dkim_txt_record(&pem);
            self.dns_put(domain, &dkim_name, "TXT", &txt, None, true)?;
        }

        let serial = now_unix() as u32;
        self.state
            .upsert_dns_zone_meta(domain, serial, true, &selector)
            .map_err(internal)?;
        self.dns_sync_dkim_tables().await?;
        let _ = self.exec.reload_unit("opendkim").await;
        Ok(())
    }

    async fn dns_sync_dkim_tables(&self) -> Result<(), WireError> {
        if let Err(err) = self.exec.repair_dkim_key_permissions().await {
            tracing::warn!(error = %err, "DKIM key permissions could not be repaired");
        }
        let mut keytable = String::from("# managed-by: RYNXCP\n");
        let mut signingtable = String::from("# managed-by: RYNXCP\n");
        for domain in self.state.list_dns_zone_domains().map_err(internal)? {
            let Some((_, mail_ready, selector)) =
                self.state.get_dns_zone_meta(&domain).map_err(internal)?
            else {
                continue;
            };
            if !mail_ready {
                continue;
            }
            let key = self
                .cfg
                .dkim_key_dir
                .join(&domain)
                .join(format!("{selector}.private"));
            keytable.push_str(&format!(
                "{selector}._domainkey.{domain} {domain}:{selector}:{}\n",
                key.display()
            ));
            signingtable.push_str(&format!("*@{domain} {selector}._domainkey.{domain}\n"));
        }
        self.exec
            .write_dkim_tables(&keytable, &signingtable)
            .await
            .map_err(exec_error)
    }

    async fn dns_ensure_zone(&self, domain: &str, enable_mail: bool) -> Result<(), WireError> {
        validate_domain(domain).map_err(invalid)?;
        if !self.cfg.dns_enabled {
            return Err(WireError::unsupported(
                "DNS management is disabled (dns_enabled = false)",
            ));
        }
        if self.state.get_website(domain).map_err(internal)?.is_none() {
            return Err(WireError::not_found(format!(
                "website '{domain}' not found"
            )));
        }
        let existed = self
            .state
            .get_dns_zone_meta(domain)
            .map_err(internal)?
            .is_some();
        if !existed {
            let serial = now_unix() as u32;
            self.state
                .upsert_dns_zone_meta(domain, serial, false, &self.cfg.dkim_selector)
                .map_err(internal)?;
            self.dns_seed_defaults(domain).await?;
        }
        self.dns_seed_aliases(domain).await?;
        self.dns_seed_nameserver_glue(domain).await?;
        self.dns_seed_ftp_host(domain).await?;
        if enable_mail || self.cfg.mail_enabled {
            self.dns_seed_mail(domain).await?;
        }
        Ok(())
    }

    fn effective_nameservers(&self, domain: &str) -> Vec<String> {
        if self.cfg.dns_nameservers.is_empty() {
            vec![format!("ns1.{domain}"), format!("ns2.{domain}")]
        } else {
            self.cfg.dns_nameservers.clone()
        }
    }

    async fn dns_seed_nameserver_glue(&self, domain: &str) -> Result<(), WireError> {
        let suffix = format!(".{domain}");
        for ns in self.effective_nameservers(domain) {
            let Some(label) = ns.strip_suffix(&suffix) else {
                continue;
            };
            if label.is_empty() {
                continue;
            }
            if let Some(ipv4) = &self.cfg.default_ipv4 {
                if self
                    .state
                    .find_dns_record(domain, label, "A")
                    .map_err(internal)?
                    .is_none()
                {
                    self.dns_put(domain, label, "A", ipv4, None, true)?;
                }
            }
            if let Some(ipv6) = &self.cfg.default_ipv6 {
                if self
                    .state
                    .find_dns_record(domain, label, "AAAA")
                    .map_err(internal)?
                    .is_none()
                {
                    self.dns_put(domain, label, "AAAA", ipv6, None, true)?;
                }
            }
        }
        Ok(())
    }

    async fn dns_seed_ftp_host(&self, domain: &str) -> Result<(), WireError> {
        if let Some(ipv4) = &self.cfg.default_ipv4 {
            if self
                .state
                .find_dns_record(domain, "ftp", "A")
                .map_err(internal)?
                .is_none()
            {
                self.dns_put(domain, "ftp", "A", ipv4, None, true)?;
            }
        }
        if let Some(ipv6) = &self.cfg.default_ipv6 {
            if self
                .state
                .find_dns_record(domain, "ftp", "AAAA")
                .map_err(internal)?
                .is_none()
            {
                self.dns_put(domain, "ftp", "AAAA", ipv6, None, true)?;
            }
        }
        Ok(())
    }

    async fn dns_zone(&self, domain: &str) -> Result<Response, WireError> {
        self.dns_ensure_zone(domain, self.cfg.mail_enabled).await?;
        let zone = self.dns_render(domain).await?;
        Ok(Response::DnsZone { zone })
    }

    fn dns_view(&self, domain: &str) -> Result<DnsZoneView, WireError> {
        let records = self.state.list_dns_records(domain).map_err(internal)?;
        let (serial, mail_ready, selector) = self
            .state
            .get_dns_zone_meta(domain)
            .map_err(internal)?
            .unwrap_or((0, false, self.cfg.dkim_selector.clone()));
        Ok(DnsZoneView {
            domain: domain.to_string(),
            records,
            zone_file: self
                .cfg
                .bind_zones_dir
                .join(format!("{domain}.db"))
                .display()
                .to_string(),
            serial,
            nameservers: self.cfg.dns_nameservers.clone(),
            mail_ready,
            dkim_selector: selector,
        })
    }

    async fn dns_render(&self, domain: &str) -> Result<DnsZoneView, WireError> {
        let records = self.state.list_dns_records(domain).map_err(internal)?;
        let serial = now_unix() as u32;
        let (_, mail_ready, selector) = self
            .state
            .get_dns_zone_meta(domain)
            .map_err(internal)?
            .unwrap_or((serial, false, self.cfg.dkim_selector.clone()));
        self.state
            .upsert_dns_zone_meta(domain, serial, mail_ready, &selector)
            .map_err(internal)?;
        let content =
            templates::bind_zone(domain, &records, &self.cfg.dns_nameservers, serial, 300);
        self.exec
            .apply_zone(domain, &content)
            .await
            .map_err(exec_error)?;
        self.dns_write_conf().await?;
        Ok(DnsZoneView {
            domain: domain.to_string(),
            records,
            zone_file: self
                .cfg
                .bind_zones_dir
                .join(format!("{domain}.db"))
                .display()
                .to_string(),
            serial,
            nameservers: self.cfg.dns_nameservers.clone(),
            mail_ready,
            dkim_selector: selector,
        })
    }

    async fn dns_write_conf(&self) -> Result<(), WireError> {
        let domains = self.state.list_dns_zone_domains().map_err(internal)?;
        let mut conf = String::from("# managed-by: RYNXCP\n");
        for domain in domains {
            conf.push_str(&format!(
                "zone \"{domain}\" {{ type master; file \"{}/{}.db\"; }};\n",
                self.cfg.bind_zones_dir.display(),
                domain
            ));
        }
        self.exec.write_dns_conf(&conf).await.map_err(exec_error)
    }

    async fn dns_zone_list(&self) -> Result<Response, WireError> {
        let mut zones = Vec::new();
        for domain in self.state.list_dns_zone_domains().map_err(internal)? {
            zones.push(self.dns_view(&domain)?);
        }
        Ok(Response::DnsZones { zones })
    }

    async fn dns_record_upsert(
        &self,
        spec: DnsRecordSpec,
        actor: &str,
    ) -> Result<Response, WireError> {
        validate_dns_record_spec(&spec).map_err(invalid)?;
        self.dns_ensure_zone(&spec.domain, false).await?;
        let siblings: Vec<DnsRecordView> = self
            .state
            .list_dns_records(&spec.domain)
            .map_err(internal)?
            .into_iter()
            .filter(|record| record.spec.name == spec.name && record.spec.rtype != spec.rtype)
            .collect();
        if spec.rtype == "CNAME" && !siblings.is_empty() {
            return Err(WireError::conflict(
                "CNAME cannot coexist with other records for the same name",
            ));
        }
        if siblings.iter().any(|record| record.spec.rtype == "CNAME") {
            return Err(WireError::conflict("a CNAME already exists for this name"));
        }
        let existing = self
            .state
            .find_dns_record(&spec.domain, &spec.name, &spec.rtype)
            .map_err(internal)?;
        self.state
            .upsert_dns_record(&spec, false, existing.as_ref().map(|r| r.id.as_str()))
            .map_err(internal)?;
        let zone = self.dns_render(&spec.domain).await?;
        self.log(
            actor,
            "dns.record.upsert",
            &format!("{}/{}", spec.domain, spec.name),
            &format!("{} {}", spec.rtype, spec.value),
        )?;
        Ok(Response::DnsZone { zone })
    }

    async fn dns_record_delete(
        &self,
        domain: &str,
        id: &str,
        actor: &str,
    ) -> Result<Response, WireError> {
        validate_domain(domain).map_err(invalid)?;
        self.state.delete_dns_record(domain, id).map_err(internal)?;
        let zone = self.dns_render(domain).await?;
        self.log(actor, "dns.record.delete", &format!("{domain}/{id}"), "")?;
        Ok(Response::DnsZone { zone })
    }

    async fn dns_mail_provision(&self, domain: &str, actor: &str) -> Result<Response, WireError> {
        if !self.cfg.mail_enabled {
            return Err(WireError::unsupported("mail management is disabled"));
        }
        self.dns_ensure_zone(domain, true).await?;
        let zone = self.dns_render(domain).await?;
        self.log(
            actor,
            "dns.mail.provision",
            domain,
            "mx+a+spf+dkim+dmarc+srv+tlsrpt+webmail",
        )?;
        Ok(Response::DnsZone { zone })
    }

    async fn dns_remove_zone(&self, domain: &str) {
        let _ = self.exec.remove_zone(domain).await;
        let _ = self.state.delete_dns_zone(domain);
        let _ = self.dns_write_conf().await;
        let _ = self.dns_sync_dkim_tables().await;
    }

    async fn database_create(
        &self,
        domain: &str,
        name: &str,
        actor: &str,
    ) -> Result<Response, WireError> {
        validate_domain(domain).map_err(invalid)?;
        validate_database_name(name).map_err(invalid)?;
        if !self.cfg.db_enabled {
            return Err(WireError::unsupported(
                "database management is disabled (db_enabled = false)",
            ));
        }
        let website = self
            .state
            .get_website(domain)
            .map_err(internal)?
            .ok_or_else(|| WireError::not_found(format!("website '{domain}' not found")))?;
        let identifier = format!("{}_{}", website.spec.username, name);
        if identifier.len() > 64 {
            return Err(WireError::invalid("the prefixed database name is too long"));
        }
        if self
            .state
            .list_databases()
            .map_err(internal)?
            .iter()
            .any(|db| db.username == identifier)
        {
            return Err(WireError::conflict(format!(
                "database '{identifier}' already exists"
            )));
        }
        let password = random_hex(16);
        self.exec
            .create_database(&identifier, &identifier, &password)
            .await
            .map_err(exec_error)?;
        let view = DatabaseView {
            id: uuid::Uuid::new_v4().to_string(),
            domain: domain.to_string(),
            username: identifier.clone(),
            password,
            engine: "mariadb".into(),
            host: "localhost".into(),
            created_at: now_rfc3339(),
        };
        self.state.insert_database(&view).map_err(internal)?;
        self.log(
            actor,
            "database.create",
            domain,
            &format!("database={identifier}"),
        )?;
        Ok(Response::Database { database: view })
    }

    async fn database_delete(&self, id: &str, actor: &str) -> Result<Response, WireError> {
        let database = self
            .state
            .get_database(id)
            .map_err(internal)?
            .ok_or_else(|| WireError::not_found("database not found"))?;
        self.exec
            .drop_database(&database.username, &database.username)
            .await
            .map_err(exec_error)?;
        self.state.delete_database(id).map_err(internal)?;
        self.log(
            actor,
            "database.delete",
            &database.domain,
            &database.username,
        )?;
        Ok(Response::Ack {
            message: format!("database '{}' deleted", database.username),
        })
    }

    async fn ftp_create(&self, spec: FtpSpec, actor: &str) -> Result<Response, WireError> {
        validate_ftp_spec(&spec).map_err(invalid)?;
        if !self.cfg.ftp_enabled {
            return Err(WireError::unsupported(
                "FTP management is disabled (ftp_enabled = false)",
            ));
        }
        let website = self
            .state
            .get_website(&spec.domain)
            .map_err(internal)?
            .ok_or_else(|| WireError::not_found(format!("website '{}' not found", spec.domain)))?;
        let account = self.require_account(&website.spec.username)?;
        let login = format!("{}_{}", account.spec.username, spec.username);
        if login.len() > 64 {
            return Err(WireError::invalid("the prefixed FTP login is too long"));
        }
        if self.state.ftp_login_exists(&login).map_err(internal)? {
            return Err(WireError::conflict(format!(
                "FTP login '{login}' already exists"
            )));
        }
        let password = spec.password.unwrap_or_else(|| random_hex(12));
        let (uid, gid) = if spec.readonly {
            match self
                .exec
                .resolve_user_ids(&self.cfg.ftp_readonly_user)
                .await
                .map_err(exec_error)?
            {
                Some(ids) => ids,
                None => {
                    return Err(WireError::unsupported(format!(
                        "read-only FTP user '{}' does not exist; create it on the server",
                        self.cfg.ftp_readonly_user
                    )))
                }
            }
        } else {
            self.exec
                .resolve_user_ids(&account.spec.username)
                .await
                .map_err(exec_error)?
                .unwrap_or((account.uid, account.uid))
        };
        let home = PathBuf::from(&account.home);
        self.exec
            .apply_ftp_user(&login, uid, gid, &home, &password)
            .await
            .map_err(exec_error)?;
        if let Err(err) = self.exec.apply_ftp_certificate(&spec.domain).await {
            tracing::warn!(domain = %spec.domain, error = %err, "FTP certificate update failed");
        }
        let view = FtpView {
            id: uuid::Uuid::new_v4().to_string(),
            domain: spec.domain.clone(),
            login: login.clone(),
            home: home.display().to_string(),
            readonly: spec.readonly,
            password,
            created_at: now_rfc3339(),
        };
        self.state.insert_ftp(&view, uid).map_err(internal)?;
        self.log(
            actor,
            "ftp.create",
            &format!("{}/{}", spec.domain, login),
            &format!("readonly={}", spec.readonly),
        )?;
        Ok(Response::Ftp { account: view })
    }

    async fn ftp_delete(&self, id: &str, actor: &str) -> Result<Response, WireError> {
        let account = self
            .state
            .get_ftp(id)
            .map_err(internal)?
            .ok_or_else(|| WireError::not_found("FTP account not found"))?;
        self.exec
            .remove_ftp_user(&account.login)
            .await
            .map_err(exec_error)?;
        self.state.delete_ftp(id).map_err(internal)?;
        self.log(actor, "ftp.delete", &account.login, &account.domain)?;
        Ok(Response::Ack {
            message: format!("FTP account '{}' deleted", account.login),
        })
    }

    async fn stat_for(&self, name: &str, kind: &str, unit: &str) -> ServiceStat {
        match self.exec.status_unit(unit).await {
            Ok(status) => ServiceStat {
                name: name.to_string(),
                kind: kind.to_string(),
                status: if status.active {
                    "active".to_string()
                } else if status.state.contains("failed") {
                    "failed".to_string()
                } else if status.state.contains("activating") {
                    "activating".to_string()
                } else if status.state.contains("deactivating") {
                    "deactivating".to_string()
                } else {
                    "inactive".to_string()
                },
                pid: status.pid,
                memory_kb: status.memory_kb,
                cpu_percent: status.cpu_percent,
                uptime_secs: status.uptime_secs,
                unit: unit.to_string(),
            },
            Err(_) => ServiceStat {
                name: name.to_string(),
                kind: kind.to_string(),
                status: "unknown".to_string(),
                pid: 0,
                memory_kb: 0,
                cpu_percent: 0.0,
                uptime_secs: 0,
                unit: unit.to_string(),
            },
        }
    }

    async fn collect_service_stats(&self) -> Result<Vec<ServiceStat>, WireError> {
        let mut services = Vec::new();
        services.push(self.stat_for("nginx", "nginx", "nginx").await);
        services.push(self.stat_for("rynxd", "daemon", "rynxd").await);

        if self.cfg.db_enabled {
            services.push(self.stat_for("mariadb", "database", "mariadb").await);
        }
        if self.cfg.dns_enabled {
            services.push(self.stat_for("bind9", "dns", "named").await);
        }
        if self.cfg.mail_enabled {
            services.push(self.stat_for("postfix", "mail", "postfix").await);
            services.push(self.stat_for("dovecot", "mail", "dovecot").await);
            services.push(self.stat_for("opendkim", "mail", "opendkim").await);
        }
        if self.cfg.ftp_enabled {
            services.push(self.stat_for("pure-ftpd", "ftp", "pure-ftpd").await);
        }
        services.push(self.stat_for("fail2ban", "security", "fail2ban").await);

        let mut versions: Vec<String> = self
            .state
            .list_php_pools()
            .map_err(internal)?
            .into_iter()
            .map(|pool| pool.spec.version)
            .collect();
        // Monitor every installed PHP-FPM version, even when no site has a
        // pool for it yet (for example the version used by the panel webmail).
        if let Ok(installed) = self.exec.php_versions().await {
            versions.extend(installed);
        }
        versions.sort();
        versions.dedup();
        for version in versions {
            let unit = format!("php{version}-fpm");
            services.push(self.stat_for(&unit, "php", &unit).await);
        }

        for app in self.state.list_apps().map_err(internal)? {
            let name = format!("{}/{}", app.spec.username, app.spec.name);
            services.push(self.stat_for(&name, "app", &app.unit).await);
        }

        services.sort_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.name.cmp(&b.name)));
        Ok(services)
    }

    async fn service_stats(&self) -> Result<Response, WireError> {
        let services = self.collect_service_stats().await?;
        Ok(Response::ServiceStats { services })
    }

    pub async fn sample_metrics(&self) -> Result<(), WireError> {
        let info = self.exec.system_info().await.map_err(exec_error)?;
        let services = self.collect_service_stats().await?;
        let active = services
            .iter()
            .filter(|service| service.status == "active")
            .count() as u32;
        let sample = MetricSample {
            at: now_rfc3339(),
            at_unix: now_unix(),
            load1: info.load.first().copied().unwrap_or(0),
            mem_used_kb: info.mem_total_kb.saturating_sub(info.mem_available_kb),
            disk_used_kb: info.disk_total_kb.saturating_sub(info.disk_available_kb),
            services_active: active,
            services_total: services.len() as u32,
        };
        self.state.insert_metric(&sample).map_err(internal)?;
        let _ = self.state.prune_metrics(now_unix() - 7 * 24 * 60 * 60);
        let removed = self.state.prune_blocked_ips(now_unix()).unwrap_or(0);
        if removed > 0 {
            let _ = self.firewall_apply().await;
        }
        Ok(())
    }

    async fn programs(&self) -> Result<Response, WireError> {
        let programs = self.exec.installed_programs().await.map_err(exec_error)?;
        Ok(Response::Programs { programs })
    }

    async fn updates(&self) -> Result<Response, WireError> {
        let updates = self.exec.available_updates().await.map_err(exec_error)?;
        Ok(Response::Updates { updates })
    }

    async fn apply_updates(&self, actor: &str) -> Result<Response, WireError> {
        let pending = self
            .exec
            .available_updates()
            .await
            .map(|updates| updates.len() as u32)
            .unwrap_or(0);
        let output = self.exec.apply_updates().await.map_err(exec_error)?;
        let output = trim_console_output(output);
        self.log(
            actor,
            "system.updates.apply",
            "apt",
            &format!("packages={pending}"),
        )?;
        Ok(Response::UpdateResult {
            updated: pending,
            output,
        })
    }

    async fn console_run(&self, action: ConsoleAction, actor: &str) -> Result<Response, WireError> {
        let label = action.label();
        let output = match action {
            ConsoleAction::NginxTest => self.exec.nginx_test_text().await.map_err(exec_error)?,
            ConsoleAction::NginxReload => {
                self.exec.reload_unit("nginx").await.map_err(exec_error)?;
                "nginx reloaded".into()
            }
            ConsoleAction::Services => {
                let services = self.collect_service_stats().await?;
                let mut text = String::from("KIND     STATUS    NAME                 UNIT\n");
                for service in services {
                    text.push_str(&format!(
                        "{:<8} {:<9} {:<20} {}\n",
                        service.kind, service.status, service.name, service.unit
                    ));
                }
                text
            }
            ConsoleAction::DiskUsage => self.exec.disk_usage().await.map_err(exec_error)?,
            ConsoleAction::Reconcile => match self.reconcile_all(actor).await? {
                Response::Ack { message } => message,
                _ => "reconciled".into(),
            },
            ConsoleAction::CertRenew => match self.cert_renew(false, actor).await? {
                Response::Ack { message } => message,
                _ => "certificates renewed".into(),
            },
            ConsoleAction::BackupAll => {
                let accounts = self.state.list_accounts().map_err(internal)?;
                let mut ok = 0usize;
                for account in &accounts {
                    if self
                        .backup_create(&account.spec.username, actor)
                        .await
                        .is_ok()
                    {
                        ok += 1;
                    }
                }
                format!("backups created: {ok}/{}", accounts.len())
            }
            ConsoleAction::PhpReload { version } => {
                validate::validate_php_version(&version).map_err(invalid)?;
                let unit = format!("php{version}-fpm");
                self.exec.reload_unit(&unit).await.map_err(exec_error)?;
                format!("{unit} reloaded")
            }
            ConsoleAction::AppRestart { username, name } => {
                validate::validate_username(&username).map_err(invalid)?;
                validate::validate_app_name(&name).map_err(invalid)?;
                let app = self
                    .state
                    .get_app(&username, &name)
                    .map_err(internal)?
                    .ok_or_else(|| WireError::not_found("application not found"))?;
                self.exec
                    .restart_unit(&app.unit)
                    .await
                    .map_err(exec_error)?;
                format!("{} restarted", app.unit)
            }
            ConsoleAction::AppLogs {
                username,
                name,
                lines,
            } => {
                validate::validate_username(&username).map_err(invalid)?;
                validate::validate_app_name(&name).map_err(invalid)?;
                let app = self
                    .state
                    .get_app(&username, &name)
                    .map_err(internal)?
                    .ok_or_else(|| WireError::not_found("application not found"))?;
                self.exec
                    .journal_unit(&app.unit, lines)
                    .await
                    .map_err(exec_error)?
            }
            ConsoleAction::ServiceRestart { program } => {
                let unit = rynx_core::service_unit_for_program(&program)
                    .ok_or_else(|| WireError::unsupported("program has no systemd service"))?;
                self.exec.restart_unit(&unit).await.map_err(exec_error)?;
                format!("{unit} restarted")
            }
            ConsoleAction::ServiceStop { program } => {
                let unit = rynx_core::service_unit_for_program(&program)
                    .ok_or_else(|| WireError::unsupported("program has no systemd service"))?;
                self.exec
                    .set_unit_running(&unit, false)
                    .await
                    .map_err(exec_error)?;
                format!("{unit} stopped")
            }
        };

        let output = trim_console_output(output);
        self.log(
            actor,
            "console.run",
            &label,
            &format!("output_bytes={}", output.len()),
        )?;
        Ok(Response::ConsoleOutput {
            action: label,
            output,
        })
    }

    fn firewall_view(&self) -> Result<FirewallView, WireError> {
        let _ = self.state.prune_blocked_ips(now_unix());
        Ok(FirewallView {
            enabled: self.cfg.firewall_enabled,
            backend: self.cfg.firewall_backend.clone(),
            rules: self.state.list_firewall_rules().map_err(internal)?,
            blocked: self.state.list_blocked_ips().map_err(internal)?,
            whitelist: self.state.list_whitelist().map_err(internal)?,
            ssh_port: self.cfg.firewall_ssh_port,
        })
    }

    fn render_firewall(&self, state: &FirewallView) -> String {
        fn is_v6(value: &str) -> bool {
            value
                .split('/')
                .next()
                .and_then(|ip| ip.parse::<std::net::IpAddr>().ok())
                .map(|ip| ip.is_ipv6())
                .unwrap_or(false)
        }
        fn set(name: &str, family: &str, entries: &[String]) -> String {
            if entries.is_empty() {
                format!("  set {name} {{ type {family}; flags interval; }}\n")
            } else {
                format!(
                    "  set {name} {{ type {family}; flags interval; elements = {{ {} }}; }}\n",
                    entries.join(", ")
                )
            }
        }
        fn rule_lines(rule: &FirewallRuleView) -> Vec<String> {
            let verb = if rule.spec.action == "deny" {
                "drop"
            } else {
                "accept"
            };
            let source = rule
                .spec
                .source
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            let mut lines = Vec::new();
            for proto in ["tcp", "udp"] {
                if rule.spec.proto != "any" && rule.spec.proto != proto {
                    continue;
                }
                let mut line = String::from("    ");
                if let Some(src) = source {
                    if is_v6(src) {
                        line.push_str(&format!("ip6 saddr {src} "));
                    } else {
                        line.push_str(&format!("ip saddr {src} "));
                    }
                }
                line.push_str(&format!("{proto} dport {} {verb}", rule.spec.port));
                lines.push(line);
            }
            lines
        }

        let (whitelist4, whitelist6): (Vec<String>, Vec<String>) = state
            .whitelist
            .iter()
            .cloned()
            .partition(|entry| !is_v6(entry));
        let (blocked4, blocked6): (Vec<String>, Vec<String>) = state
            .blocked
            .iter()
            .map(|entry| entry.ip.clone())
            .partition(|entry| !is_v6(entry));

        let mut out = String::new();
        out.push_str("# managed-by: RYNXCP\ntable inet rynxcp\ndelete table inet rynxcp\n");
        out.push_str("table inet rynxcp {\n");
        out.push_str(&set("whitelist4", "ipv4_addr", &whitelist4));
        out.push_str(&set("whitelist6", "ipv6_addr", &whitelist6));
        out.push_str(&set("blocked4", "ipv4_addr", &blocked4));
        out.push_str(&set("blocked6", "ipv6_addr", &blocked6));
        out.push_str("  chain input {\n");
        out.push_str("    type filter hook input priority filter; policy drop;\n");
        out.push_str("    ct state established,related accept\n");
        out.push_str("    iif \"lo\" accept\n");
        if !whitelist4.is_empty() {
            out.push_str("    ip saddr @whitelist4 accept\n");
        }
        if !whitelist6.is_empty() {
            out.push_str("    ip6 saddr @whitelist6 accept\n");
        }
        if !blocked4.is_empty() {
            out.push_str("    ip saddr @blocked4 drop\n");
        }
        if !blocked6.is_empty() {
            out.push_str("    ip6 saddr @blocked6 drop\n");
        }
        out.push_str(&format!(
            "    tcp dport {} accept\n",
            self.cfg.firewall_ssh_port
        ));
        for rule in state.rules.iter().filter(|rule| rule.spec.action == "deny") {
            for line in rule_lines(rule) {
                out.push_str(&line);
                out.push('\n');
            }
        }
        for rule in state
            .rules
            .iter()
            .filter(|rule| rule.spec.action == "allow")
        {
            for line in rule_lines(rule) {
                out.push_str(&line);
                out.push('\n');
            }
        }
        out.push_str("    tcp dport { 80, 443 } accept\n");
        if self.cfg.panel_port != 80 && self.cfg.panel_port != 443 {
            out.push_str(&format!("    tcp dport {} accept\n", self.cfg.panel_port));
        }
        out.push_str("    tcp dport 53 accept\n");
        out.push_str("    udp dport 53 accept\n");
        out.push_str("    tcp dport { 25, 110, 143, 465, 587, 993, 995, 4190 } accept\n");
        out.push_str("    tcp dport { 21, 30000-50000 } accept\n");
        out.push_str("    ip protocol icmp accept\n");
        out.push_str("    ip6 nexthdr ipv6-icmp accept\n");
        out.push_str("  }\n}\n");
        out
    }

    pub async fn firewall_apply(&self) -> Result<(), WireError> {
        if !self.cfg.firewall_enabled {
            return Ok(());
        }
        let view = self.firewall_view()?;
        let ruleset = self.render_firewall(&view);
        self.exec.apply_firewall(&ruleset).await.map_err(exec_error)
    }

    async fn firewall_state(&self) -> Result<Response, WireError> {
        let mut state = self.firewall_view()?;
        if let Ok(bans) = self.exec.fail2ban_bans().await {
            for (jail, ip) in bans {
                if state.blocked.iter().any(|entry| entry.ip == ip) {
                    continue;
                }
                state.blocked.push(BlockedIpView {
                    ip,
                    reason: format!("fail2ban:{jail}"),
                    source: "fail2ban".into(),
                    expires_at: None,
                    created_at: now_rfc3339(),
                });
            }
        }
        Ok(Response::Firewall { state })
    }

    async fn firewall_rule_upsert(
        &self,
        spec: FirewallRuleSpec,
        actor: &str,
    ) -> Result<Response, WireError> {
        validate_firewall_rule_spec(&spec).map_err(invalid)?;
        let view = self.state.upsert_firewall_rule(&spec).map_err(internal)?;
        self.firewall_apply().await?;
        self.log(
            actor,
            "firewall.rule.upsert",
            &view.id,
            &format!(
                "{} {} {} source={}",
                spec.action,
                spec.proto,
                spec.port,
                spec.source.unwrap_or_else(|| "*".into())
            ),
        )?;
        self.firewall_state().await
    }

    async fn firewall_rule_delete(&self, id: &str, actor: &str) -> Result<Response, WireError> {
        self.state.delete_firewall_rule(id).map_err(internal)?;
        self.firewall_apply().await?;
        self.log(actor, "firewall.rule.delete", id, "")?;
        self.firewall_state().await
    }

    async fn firewall_block(
        &self,
        ip: &str,
        seconds: u32,
        reason: &str,
        actor: &str,
    ) -> Result<Response, WireError> {
        validate_ban_ip(ip).map_err(invalid)?;
        if self.state.is_whitelisted(ip).map_err(internal)? {
            return Err(WireError::conflict(
                "IP is whitelisted; remove it from the whitelist first",
            ));
        }
        let reason = if reason.trim().is_empty() {
            "manual".to_string()
        } else {
            reason
                .chars()
                .filter(|c| !c.is_control())
                .take(120)
                .collect()
        };
        let source = if reason.contains("brute") {
            "brute-force"
        } else {
            "manual"
        };
        self.state
            .block_ip(ip, &reason, source, seconds)
            .map_err(internal)?;
        self.firewall_apply().await?;
        self.log(
            actor,
            "firewall.block",
            ip,
            &format!("seconds={seconds} reason={reason}"),
        )?;
        self.firewall_state().await
    }

    async fn firewall_unblock(&self, ip: &str, actor: &str) -> Result<Response, WireError> {
        validate_ip_or_cidr(ip).map_err(invalid)?;
        self.state.unblock_ip(ip).map_err(internal)?;
        if let Err(err) = self.exec.fail2ban_unban(ip).await {
            tracing::warn!(ip, error = %err, "fail2ban unban failed");
        }
        self.firewall_apply().await?;
        self.log(actor, "firewall.unblock", ip, "")?;
        self.firewall_state().await
    }

    async fn firewall_whitelist_add(&self, ip: &str, actor: &str) -> Result<Response, WireError> {
        validate_ip_or_cidr(ip).map_err(invalid)?;
        self.state.add_whitelist(ip).map_err(internal)?;
        let _ = self.state.unblock_ip(ip);
        if let Err(err) = self.exec.fail2ban_unban(ip).await {
            tracing::warn!(ip, error = %err, "fail2ban unban failed after whitelist update");
        }
        self.firewall_apply().await?;
        self.log(actor, "firewall.whitelist.add", ip, "")?;
        self.firewall_state().await
    }

    async fn firewall_whitelist_remove(
        &self,
        ip: &str,
        actor: &str,
    ) -> Result<Response, WireError> {
        validate_ip_or_cidr(ip).map_err(invalid)?;
        self.state.remove_whitelist(ip).map_err(internal)?;
        self.firewall_apply().await?;
        self.log(actor, "firewall.whitelist.remove", ip, "")?;
        self.firewall_state().await
    }

    async fn reconcile_all(&self, actor: &str) -> Result<Response, WireError> {
        let mut applied = 0usize;
        let mut failures = 0usize;

        let accounts = self.state.list_accounts().map_err(internal)?;
        for account in &accounts {
            let actual_uid = self
                .exec
                .resolve_user_ids(&account.spec.username)
                .await
                .ok()
                .flatten()
                .map(|(uid, _)| uid)
                .unwrap_or(account.uid);
            if actual_uid != account.uid {
                self.state
                    .upsert_account(&account.spec, actual_uid, &account.home)
                    .map_err(internal)?;
            }
            match self.exec.ensure_account(&account.spec, actual_uid).await {
                Ok(_) => {
                    if self
                        .exec
                        .set_ssh_access(
                            &account.spec.username,
                            account.spec.enabled && account.spec.ssh_enabled,
                        )
                        .await
                        .is_ok()
                    {
                        applied += 1;
                    } else {
                        failures += 1;
                    }
                }
                Err(err) => {
                    failures += 1;
                    tracing::warn!(account = %account.spec.username, error = %err, "reconcile account failed");
                }
            }
            if account.spec.enabled {
                let _ = self.cron_render(&account.spec.username).await;
            } else {
                let _ = self.exec.apply_cron(&account.spec.username, "").await;
            }
        }

        for backup in self.state.list_backups().map_err(internal)? {
            let _ = self
                .exec
                .repair_backup_permissions(Path::new(&backup.path))
                .await;
        }

        for pool in self.state.list_php_pools().map_err(internal)? {
            match self.apply_php_pool(&pool.spec).await {
                Ok(_) => applied += 1,
                Err(err) => {
                    failures += 1;
                    tracing::warn!(pool = %pool.username, error = %err.message, "reconcile php pool failed");
                }
            }
        }

        let account_names: std::collections::HashSet<String> =
            accounts.iter().map(|a| a.spec.username.clone()).collect();
        let enabled_accounts: std::collections::HashMap<String, bool> = accounts
            .iter()
            .map(|a| (a.spec.username.clone(), a.spec.enabled))
            .collect();
        for app in self.state.list_apps().map_err(internal)? {
            if !account_names.contains(&app.spec.username) {
                continue;
            }
            if !enabled_accounts
                .get(&app.spec.username)
                .copied()
                .unwrap_or(false)
            {
                let _ = self.exec.set_unit_running(&app.unit, false).await;
                continue;
            }
            match self.apply_app(&app.spec).await {
                Ok(_) => applied += 1,
                Err(err) => {
                    failures += 1;
                    tracing::warn!(app = %app.id, error = %err.message, "reconcile app failed");
                }
            }
        }

        for website in self.state.list_websites().map_err(internal)? {
            if !enabled_accounts
                .get(&website.spec.username)
                .copied()
                .unwrap_or(false)
            {
                let _ = self.exec.remove_site(&website.spec.domain).await;
                continue;
            }
            match self.apply_website(&website.spec).await {
                Ok(_) => applied += 1,
                Err(err) => {
                    failures += 1;
                    tracing::warn!(domain = %website.spec.domain, error = %err.message, "reconcile website failed");
                }
            }
            if self.cfg.dns_enabled {
                match self
                    .dns_ensure_zone(&website.spec.domain, self.cfg.mail_enabled)
                    .await
                {
                    Ok(_) => {
                        if self.dns_render(&website.spec.domain).await.is_ok() {
                            applied += 1;
                        }
                    }
                    Err(err) => {
                        failures += 1;
                        tracing::warn!(domain = %website.spec.domain, error = %err.message, "reconcile dns failed");
                    }
                }
            }
        }

        if self.cfg.mail_enabled {
            match self.sync_mail_config().await {
                Ok(()) => applied += 1,
                Err(err) => {
                    failures += 1;
                    tracing::warn!(error = %err.message, "reconcile mail configuration failed");
                }
            }
            for mail in self.state.list_mail_domains().map_err(internal)? {
                if !mail.enabled {
                    continue;
                }
                match self.apply_webmail_vhost(&mail.domain).await {
                    Ok(()) => applied += 1,
                    Err(err) => {
                        failures += 1;
                        tracing::warn!(domain = %mail.domain, error = %err.message, "reconcile webmail failed");
                    }
                }
            }
        }

        for ftp in self.state.list_ftp().map_err(internal)? {
            let Some(website) = self.state.get_website(&ftp.domain).map_err(internal)? else {
                continue;
            };
            let Some(account) = self
                .state
                .get_account(&website.spec.username)
                .map_err(internal)?
            else {
                continue;
            };
            if !account.spec.enabled {
                let _ = self.exec.remove_ftp_user(&ftp.login).await;
                continue;
            }
            let ids = if ftp.readonly {
                self.exec
                    .resolve_user_ids(&self.cfg.ftp_readonly_user)
                    .await
            } else {
                self.exec.resolve_user_ids(&account.spec.username).await
            };
            let (uid, gid) = ids.ok().flatten().unwrap_or((account.uid, account.uid));
            let home = account.home.clone();
            match self
                .exec
                .apply_ftp_user(&ftp.login, uid, gid, Path::new(&home), &ftp.password)
                .await
            {
                Ok(_) => {
                    if ftp.home != home {
                        self.state.set_ftp_home(&ftp.id, &home).map_err(internal)?;
                    }
                    applied += 1;
                }
                Err(err) => {
                    failures += 1;
                    tracing::warn!(login = %ftp.login, error = %err, "reconcile ftp failed");
                }
            }
        }

        self.log(
            actor,
            "system.reconcile",
            "all",
            &format!("applied={applied} failures={failures}"),
        )?;
        Ok(Response::Ack {
            message: format!("reconciled {applied} resources ({failures} failures)"),
        })
    }

    fn log(&self, actor: &str, action: &str, target: &str, detail: &str) -> Result<(), WireError> {
        self.audit
            .append(actor, action, target, detail)
            .map(|_| ())
            .map_err(internal)
    }
}

fn internal(err: impl std::fmt::Display) -> WireError {
    WireError::internal(err.to_string())
}

fn invalid(err: impl std::fmt::Display) -> WireError {
    WireError::invalid(err.to_string())
}

fn trim_console_output(mut text: String) -> String {
    text.retain(|c| c == '\n' || c == '\t' || !c.is_control());
    if text.chars().count() > 64_000 {
        text = text.chars().take(64_000).collect();
        text.push_str("\n (truncated)");
    }
    text
}
