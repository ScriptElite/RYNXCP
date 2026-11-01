//! Sandbox executor: renders the exact same artifacts but performs no
//! privileged operation. Used for development and CI.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

use rynx_core::crypto::random_hex;
use rynx_core::paths::{remove_managed, write_managed};
use rynx_core::DaemonConfig;
use rynx_proto::{
    AccountSpec, AppSpec, CertView, CertificateStatus, FileEntry, InstallerApp, InstallerApplySpec,
    MailDomainSpec, MailQueueEntry, PackageUpdate, ProgramInfo, SystemInfo,
};

use super::{
    merge_dkim_table, ExecError, ExecResult, Executor, MailAccountConfig, UnitStatus,
    MAX_FILE_BYTES,
};

fn safe_join(root: &Path, rel: &str) -> ExecResult<PathBuf> {
    safe_join_path(root, Path::new(rel))
}

fn safe_join_path(root: &Path, rel: &Path) -> ExecResult<PathBuf> {
    for component in rel.components() {
        if !matches!(component, std::path::Component::Normal(_)) {
            return Err(ExecError::Io("invalid file path".into()));
        }
    }
    let root_canon = std::fs::canonicalize(root).map_err(|err| ExecError::Io(err.to_string()))?;
    let target = if rel.as_os_str().is_empty() {
        root_canon.clone()
    } else {
        root_canon.join(rel)
    };
    let checked = if target.exists() {
        std::fs::canonicalize(&target).map_err(|err| ExecError::Io(err.to_string()))?
    } else {
        let parent = target
            .parent()
            .ok_or_else(|| ExecError::Io("invalid target path".into()))?;
        let parent = std::fs::canonicalize(parent).map_err(|err| ExecError::Io(err.to_string()))?;
        let name = target
            .file_name()
            .ok_or_else(|| ExecError::Io("invalid target name".into()))?;
        parent.join(name)
    };
    if !checked.starts_with(&root_canon) {
        return Err(ExecError::Io("path escapes the site root".into()));
    }
    Ok(target)
}

pub struct SimExecutor {
    cfg: DaemonConfig,
}

impl SimExecutor {
    pub fn new(cfg: DaemonConfig) -> Self {
        Self { cfg }
    }

    fn users_dir(&self) -> PathBuf {
        self.cfg.state_dir.join("sim-users")
    }

    fn ensure_cert_dir(&self, domain: &str) -> ExecResult<PathBuf> {
        let dir = self.cfg.certs_root.join(domain);
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }
}

fn write_text(path: &Path, content: &str) -> ExecResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, content)?;
    Ok(())
}

#[async_trait]
impl Executor for SimExecutor {
    fn mode(&self) -> &'static str {
        "simulation"
    }

    fn home(&self, username: &str) -> PathBuf {
        self.cfg.home_root.join(username)
    }

    fn apps_dir(&self, username: &str) -> PathBuf {
        self.home(username).join("apps")
    }

    fn working_dir(&self, username: &str, app: &str) -> PathBuf {
        self.apps_dir(username).join(app)
    }

    fn acme_root(&self) -> PathBuf {
        self.cfg.acme_root.clone()
    }

    async fn ensure_account(&self, spec: &AccountSpec, uid: u32) -> ExecResult<()> {
        let home = self.home(&spec.username);
        for dir in [
            home.clone(),
            home.join("logs"),
            home.join("apps"),
            home.join("tmp"),
        ] {
            std::fs::create_dir_all(&dir)?;
        }
        let legacy_public = home.join("public_html");
        if legacy_public.is_dir()
            && std::fs::read_dir(&legacy_public)
                .map(|mut entries| entries.next().is_none())
                .unwrap_or(false)
        {
            let _ = std::fs::remove_dir(&legacy_public);
        }
        std::fs::create_dir_all(self.users_dir())?;
        write_text(
            &self.users_dir().join(format!("uid-{uid}")),
            &format!("{}={uid}", spec.username),
        )?;
        write_text(
            &self.users_dir().join(format!("{}.json", spec.username)),
            &serde_json::to_string_pretty(spec).unwrap_or_default(),
        )?;
        Ok(())
    }

    async fn remove_account(&self, username: &str, purge: bool) -> ExecResult<()> {
        let home = self.home(username);
        if purge && home.exists() {
            std::fs::remove_dir_all(&home)?;
        }
        if let Ok(entries) = std::fs::read_dir(self.users_dir()) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if content.starts_with(&format!("{username}=")) {
                        let _ = std::fs::remove_file(&path);
                    }
                }
                if path.file_name().and_then(|n| n.to_str()) == Some(&format!("{username}.json")) {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
        Ok(())
    }

    async fn set_ssh_access(&self, username: &str, enabled: bool) -> ExecResult<()> {
        if enabled {
            let dir = self.home(username).join(".ssh");
            std::fs::create_dir_all(&dir)?;
            let file = dir.join("authorized_keys");
            if !file.exists() {
                write_text(&file, "")?;
            }
        }
        Ok(())
    }

    async fn ssh_keys(&self, username: &str) -> ExecResult<Vec<String>> {
        let file = self.home(username).join(".ssh/authorized_keys");
        match std::fs::read_to_string(&file) {
            Ok(content) => Ok(content
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .map(str::to_string)
                .collect()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(err) => Err(ExecError::Io(err.to_string())),
        }
    }

    async fn add_ssh_key(&self, username: &str, key: &str) -> ExecResult<()> {
        let mut keys = self.ssh_keys(username).await?;
        if !keys.iter().any(|existing| existing == key) {
            keys.push(key.to_string());
        }
        let dir = self.home(username).join(".ssh");
        std::fs::create_dir_all(&dir)?;
        let mut content = keys.join("\n");
        if !content.is_empty() {
            content.push('\n');
        }
        write_text(&dir.join("authorized_keys"), &content)
    }

    async fn remove_ssh_key(&self, username: &str, key: &str) -> ExecResult<()> {
        let keys: Vec<String> = self
            .ssh_keys(username)
            .await?
            .into_iter()
            .filter(|existing| existing != key)
            .collect();
        let dir = self.home(username).join(".ssh");
        std::fs::create_dir_all(&dir)?;
        let mut content = keys.join("\n");
        if !content.is_empty() {
            content.push('\n');
        }
        write_text(&dir.join("authorized_keys"), &content)
    }

    async fn remove_website_root(&self, username: &str, relative: &str) -> ExecResult<()> {
        let target = self.home(username).join(relative);
        if target.exists() {
            std::fs::remove_dir_all(&target)?;
        }
        Ok(())
    }

    async fn ensure_docroot(&self, username: &str, uid: u32, path: &Path) -> ExecResult<()> {
        let home = self.home(username);
        if !path.starts_with(&home) {
            return Err(ExecError::Unsupported(
                "docroot escapes the account home".into(),
            ));
        }
        std::fs::create_dir_all(path)?;
        let _ = uid;
        Ok(())
    }

    async fn file_list(
        &self,
        username: &str,
        docroot: &str,
        path: &str,
    ) -> ExecResult<Vec<FileEntry>> {
        super::validate_site_root(username, docroot)?;
        super::validate_relative_path(path)?;
        let root = self.home(username).join(docroot);
        let target = safe_join(&root, path)?;
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(&target)? {
            let entry = entry?;
            let meta = std::fs::symlink_metadata(entry.path())?;
            let kind = if meta.file_type().is_dir() {
                "dir"
            } else if meta.file_type().is_file() {
                "file"
            } else if meta.file_type().is_symlink() {
                "symlink"
            } else {
                "other"
            };
            let modified = meta
                .modified()
                .ok()
                .and_then(|value| OffsetDateTime::from(value).format(&Rfc3339).ok());
            entries.push(FileEntry {
                name: entry.file_name().to_string_lossy().to_string(),
                kind: kind.to_string(),
                size: meta.len(),
                modified,
            });
        }
        entries.sort_by(|left, right| {
            (left.kind != "dir")
                .cmp(&(right.kind != "dir"))
                .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
        });
        Ok(entries)
    }

    async fn file_read(&self, username: &str, docroot: &str, path: &str) -> ExecResult<Vec<u8>> {
        super::validate_site_root(username, docroot)?;
        if path.is_empty() {
            return Err(ExecError::Io("a file path is required".into()));
        }
        super::validate_relative_path(path)?;
        let root = self.home(username).join(docroot);
        let target = safe_join(&root, path)?;
        let meta = std::fs::symlink_metadata(&target)?;
        if meta.file_type().is_symlink() {
            return Err(ExecError::Io("symbolic links cannot be edited".into()));
        }
        if !meta.is_file() {
            return Err(ExecError::Io("not a regular file".into()));
        }
        if meta.len() > MAX_FILE_BYTES {
            return Err(ExecError::Io("file is too large".into()));
        }
        Ok(std::fs::read(target)?)
    }

    async fn file_write(
        &self,
        username: &str,
        docroot: &str,
        path: &str,
        data: &[u8],
    ) -> ExecResult<()> {
        super::validate_site_root(username, docroot)?;
        if path.is_empty() {
            return Err(ExecError::Io("a file path is required".into()));
        }
        if data.len() as u64 > MAX_FILE_BYTES {
            return Err(ExecError::Io("file is too large".into()));
        }
        super::validate_relative_path(path)?;
        let root = self.home(username).join(docroot);
        let target = safe_join(&root, path)?;
        if let Ok(meta) = std::fs::symlink_metadata(&target) {
            if meta.file_type().is_symlink() {
                return Err(ExecError::Io("symbolic links cannot be edited".into()));
            }
            if !meta.is_file() {
                return Err(ExecError::Io("not a regular file".into()));
            }
        }
        std::fs::write(target, data)?;
        Ok(())
    }

    async fn file_mkdir(&self, username: &str, docroot: &str, path: &str) -> ExecResult<()> {
        super::validate_site_root(username, docroot)?;
        if path.is_empty() {
            return Err(ExecError::Io("a directory path is required".into()));
        }
        super::validate_relative_path(path)?;
        let root = self.home(username).join(docroot);
        let target = safe_join(&root, path)?;
        std::fs::create_dir(target)?;
        Ok(())
    }

    async fn file_rename(
        &self,
        username: &str,
        docroot: &str,
        path: &str,
        new_name: &str,
    ) -> ExecResult<()> {
        super::validate_site_root(username, docroot)?;
        if path.is_empty() {
            return Err(ExecError::Io("a source path is required".into()));
        }
        super::validate_relative_path(path)?;
        super::validate_file_name(new_name)?;
        let root = self.home(username).join(docroot);
        let source = safe_join(&root, path)?;
        let parent = source
            .parent()
            .ok_or_else(|| ExecError::Io("invalid source path".into()))?;
        let target = parent.join(new_name);
        std::fs::rename(source, target)?;
        Ok(())
    }

    async fn file_delete(
        &self,
        username: &str,
        docroot: &str,
        path: &str,
        recursive: bool,
    ) -> ExecResult<()> {
        super::validate_site_root(username, docroot)?;
        if path.is_empty() {
            return Err(ExecError::Io("refusing to delete the site root".into()));
        }
        super::validate_relative_path(path)?;
        let root = self.home(username).join(docroot);
        let target = safe_join(&root, path)?;
        let meta = std::fs::symlink_metadata(&target)?;
        if meta.is_dir() {
            if recursive {
                std::fs::remove_dir_all(target)?;
            } else {
                std::fs::remove_dir(target)?;
            }
        } else {
            std::fs::remove_file(target)?;
        }
        Ok(())
    }

    async fn ensure_welcome(
        &self,
        username: &str,
        uid: u32,
        docroot: &Path,
        domain: &str,
        locale: &str,
        php: bool,
    ) -> ExecResult<()> {
        let _ = username;
        let _ = uid;
        let html = docroot.join("index.html");
        let php_file = docroot.join("index.php");
        if html.exists() || php_file.exists() {
            return Ok(());
        }
        let path = if php { php_file } else { html };
        std::fs::write(path, rynx_core::templates::welcome_page(locale, domain))?;
        Ok(())
    }

    async fn apply_site(&self, domain: &str, content: &str, enable: bool) -> ExecResult<()> {
        std::fs::create_dir_all(&self.cfg.nginx_sites_dir)?;
        let path = self.cfg.nginx_sites_dir.join(format!("{domain}.conf"));
        write_managed(&self.cfg.nginx_sites_dir, &path, content, 0o644, None)?;
        std::fs::create_dir_all(&self.cfg.nginx_enabled_dir)?;
        let link = self.cfg.nginx_enabled_dir.join(format!("{domain}.conf"));
        if enable {
            write_text(&link, "../sites-available/rynxcp")?;
        } else if link.exists() {
            let _ = std::fs::remove_file(&link);
        }
        Ok(())
    }

    async fn remove_site(&self, domain: &str) -> ExecResult<()> {
        let _ = remove_managed(
            &self.cfg.nginx_sites_dir,
            &self.cfg.nginx_sites_dir.join(format!("{domain}.conf")),
        );
        let link = self.cfg.nginx_enabled_dir.join(format!("{domain}.conf"));
        if link.exists() {
            let _ = std::fs::remove_file(link);
        }
        Ok(())
    }

    async fn apply_php_pool(
        &self,
        username: &str,
        version: &str,
        content: &str,
        enable: bool,
    ) -> ExecResult<()> {
        let dir = self
            .cfg
            .php_fpm_root
            .join(version)
            .join("fpm")
            .join("pool.d");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("rynx-{username}.conf"));
        if enable {
            write_managed(&self.cfg.php_fpm_root, &path, content, 0o644, None)?;
        } else {
            let _ = remove_managed(&self.cfg.php_fpm_root, &path);
        }
        std::fs::create_dir_all(&self.cfg.php_socket_dir)?;
        Ok(())
    }

    async fn remove_php_pool(&self, username: &str, version: &str) -> ExecResult<()> {
        let path = self
            .cfg
            .php_fpm_root
            .join(version)
            .join("fpm")
            .join("pool.d")
            .join(format!("rynx-{username}.conf"));
        let _ = remove_managed(&self.cfg.php_fpm_root, &path);
        Ok(())
    }

    async fn ensure_app_dir(&self, username: &str, uid: u32, dir: &Path) -> ExecResult<()> {
        let home = self.home(username);
        if !dir.starts_with(&home) {
            return Err(ExecError::Unsupported(
                "application directory escapes the account home".into(),
            ));
        }
        std::fs::create_dir_all(dir)?;
        let _ = uid;
        Ok(())
    }

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
    ) -> ExecResult<()> {
        self.ensure_app_dir(&spec.username, uid, working_dir)
            .await?;
        std::fs::create_dir_all(&self.cfg.app_env_dir)?;
        let env_path = self.cfg.app_env_dir.join(env_filename);
        write_managed(&self.cfg.app_env_dir, &env_path, env_content, 0o640, None)?;
        std::fs::create_dir_all(&self.cfg.systemd_dir)?;
        let unit_path = self.cfg.systemd_dir.join(unit);
        write_managed(&self.cfg.systemd_dir, &unit_path, unit_content, 0o644, None)?;
        let enabled_dir = self.cfg.systemd_dir.join("enabled");
        if enable {
            write_text(&enabled_dir.join(unit), "enabled")?;
        } else if enabled_dir.join(unit).exists() {
            let _ = std::fs::remove_file(enabled_dir.join(unit));
        }
        Ok(())
    }

    async fn remove_app(
        &self,
        username: &str,
        unit: &str,
        env_filename: &str,
        working_dir: &Path,
        purge: bool,
    ) -> ExecResult<()> {
        let _ = remove_managed(&self.cfg.systemd_dir, &self.cfg.systemd_dir.join(unit));
        let _ = std::fs::remove_file(self.cfg.systemd_dir.join("enabled").join(unit));
        let _ = remove_managed(
            &self.cfg.app_env_dir,
            &self.cfg.app_env_dir.join(env_filename),
        );
        if purge && working_dir.starts_with(self.home(username)) {
            let _ = std::fs::remove_dir_all(working_dir);
        }
        Ok(())
    }

    async fn installer_apply(
        &self,
        spec: &InstallerApplySpec,
        _archive: Option<&Path>,
    ) -> ExecResult<String> {
        let docroot = self.home(&spec.username).join(&spec.docroot);
        if docroot.exists() {
            std::fs::remove_dir_all(&docroot)?;
        }
        std::fs::create_dir_all(&docroot)?;
        match spec.app {
            InstallerApp::Wordpress => {
                write_managed(
                    &docroot,
                    &docroot.join("index.php"),
                    "<?php // wordpress\n",
                    0o640,
                    None,
                )?;
                write_managed(
                    &docroot,
                    &docroot.join("wp-config.php"),
                    "<?php // wp-config\n",
                    0o640,
                    None,
                )?;
            }
            InstallerApp::Laravel => {
                std::fs::create_dir_all(docroot.join("public"))?;
                write_managed(
                    &docroot,
                    &docroot.join("artisan"),
                    "#!/usr/bin/env php\n",
                    0o640,
                    None,
                )?;
                write_managed(
                    &docroot,
                    &docroot.join(".env"),
                    "APP_ENV=production\n",
                    0o640,
                    None,
                )?;
                write_managed(
                    &docroot,
                    &docroot.join("public/index.php"),
                    "<?php // laravel\n",
                    0o640,
                    None,
                )?;
            }
        }
        Ok(format!("{} installed", spec.app.as_str()))
    }

    async fn issue_cert(
        &self,
        domain: &str,
        domains: &[String],
        _email: &str,
        _webroot: &Path,
        _staging: bool,
    ) -> ExecResult<()> {
        let dir = self.ensure_cert_dir(domain)?;
        write_text(
            &dir.join("fullchain.pem"),
            "-----BEGIN CERTIFICATE-----\nSIMULATION\n-----END CERTIFICATE-----\n",
        )?;
        write_text(
            &dir.join("privkey.pem"),
            "-----BEGIN PRIVATE KEY-----\nSIMULATION\n-----END PRIVATE KEY-----\n",
        )?;
        write_text(&dir.join("domains.txt"), &domains.join("\n"))?;
        Ok(())
    }

    async fn renew_certs(&self, _staging: bool) -> ExecResult<()> {
        if let Ok(entries) = std::fs::read_dir(&self.cfg.certs_root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let chain = path.join("fullchain.pem");
                    if chain.exists() {
                        write_text(
                            &chain,
                            "-----BEGIN CERTIFICATE-----\nSIMULATION RENEWED\n-----END CERTIFICATE-----\n",
                        )?;
                    }
                }
            }
        }
        Ok(())
    }

    async fn remove_cert(&self, domain: &str) -> ExecResult<()> {
        let dir = self.cfg.certs_root.join(domain);
        if dir.exists() {
            std::fs::remove_dir_all(dir)?;
        }
        Ok(())
    }

    async fn cert_info(&self, domain: &str) -> ExecResult<Option<CertView>> {
        let dir = self.cfg.certs_root.join(domain);
        if !dir.join("fullchain.pem").exists() {
            return Ok(None);
        }
        let not_after = (OffsetDateTime::now_utc() + Duration::days(90))
            .format(&Rfc3339)
            .unwrap_or_else(|_| "unknown".into());
        Ok(Some(CertView {
            domain: domain.to_string(),
            issuer: "RYNXCP Simulation CA".into(),
            not_after,
            status: CertificateStatus::Active,
            path: dir.display().to_string(),
        }))
    }

    async fn status_unit(&self, unit: &str) -> ExecResult<UnitStatus> {
        let active = !unit.contains("stopped");
        Ok(UnitStatus {
            active,
            state: if active {
                "active (running)".into()
            } else {
                "inactive (dead)".into()
            },
            pid: if active { 1000 } else { 0 },
            memory_kb: if active { 65_536 } else { 0 },
            cpu_percent: if active { 1.2 } else { 0.0 },
            uptime_secs: if active { 3600 } else { 0 },
        })
    }

    async fn restart_unit(&self, _unit: &str) -> ExecResult<()> {
        Ok(())
    }

    async fn reload_unit(&self, _unit: &str) -> ExecResult<()> {
        Ok(())
    }

    async fn set_unit_running(&self, _unit: &str, _running: bool) -> ExecResult<()> {
        Ok(())
    }

    async fn journal_unit(&self, unit: &str, lines: u32) -> ExecResult<String> {
        let mut output = String::new();
        for index in (1..=lines.min(20)).rev() {
            output.push_str(&format!(
                "2026-01-01T00:00:{:02}Z {}[sim]: health check ok (line {})\n",
                index % 60,
                unit,
                index
            ));
        }
        Ok(output)
    }

    async fn disk_usage(&self) -> ExecResult<String> {
        Ok("Filesystem      Size  Used Avail Use% Mounted on\n/dev/sim1        80G   20G   56G  27% /\n".into())
    }

    async fn nginx_test_text(&self) -> ExecResult<String> {
        Ok("nginx: the configuration file /etc/nginx/nginx.conf syntax is ok (simulation)\nnginx: configuration file test is successful\n".into())
    }

    async fn create_backup(&self, paths: &[String], dest: &Path) -> ExecResult<u64> {
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let manifest = format!(
            "{{\"simulation\":true,\"paths\":{}}}",
            serde_json::to_string(paths).unwrap_or_else(|_| "[]".into())
        );
        std::fs::write(dest, manifest)?;
        Ok(std::fs::metadata(dest)?.len())
    }

    async fn restore_backup(&self, archive: &Path, username: &str, _uid: u32) -> ExecResult<()> {
        let home = self.home(username);
        std::fs::create_dir_all(&home)?;
        let marker = format!("restored from {}", archive.display());
        std::fs::write(home.join(".rynx-restored"), marker)?;
        Ok(())
    }

    async fn repair_backup_permissions(&self, _path: &Path) -> ExecResult<()> {
        Ok(())
    }

    async fn offsite_backup(&self, _path: &Path, _tag: &str) -> ExecResult<bool> {
        Ok(self.cfg.offsite_enabled)
    }

    async fn copy_site_tree(&self, username: &str, source: &str, target: &str) -> ExecResult<()> {
        let source = self.home(username).join(source);
        let target = self.home(username).join(target);
        copy_tree(&source, &target)
    }

    async fn clone_database(&self, _source: &str, _target: &str) -> ExecResult<()> {
        Ok(())
    }

    async fn read_log_tail(&self, path: &Path, lines: u32) -> ExecResult<String> {
        let _ = lines;
        Ok(format!("simulated log for {}", path.display()))
    }

    async fn mail_queue(&self) -> ExecResult<Vec<MailQueueEntry>> {
        Ok(vec![MailQueueEntry {
            id: "SIMULATED01".into(),
            size: 1024,
            arrival: "0".into(),
            sender: "sender@example.com".into(),
            recipients: vec!["recipient@example.com".into()],
            status: "active".into(),
        }])
    }

    async fn mail_queue_action(&self, _action: &str, _id: Option<&str>) -> ExecResult<()> {
        Ok(())
    }

    async fn rewrite_clone_config(
        &self,
        _username: &str,
        _root: &str,
        _old_db: &str,
        _old_password: &str,
        _new_db: &str,
        _new_password: &str,
    ) -> ExecResult<bool> {
        Ok(true)
    }

    async fn apply_cron(&self, username: &str, content: &str) -> ExecResult<()> {
        let dir = self.cfg.state_dir.join("sim-cron");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(username);
        if content.trim().is_empty() {
            let _ = std::fs::remove_file(path);
        } else {
            write_text(&path, content)?;
        }
        Ok(())
    }

    async fn delete_backup_file(&self, path: &Path) -> ExecResult<()> {
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }

    async fn remove_backup_dir(&self, username: &str) -> ExecResult<()> {
        let dir = self.cfg.backup_dir.join(username);
        if dir.exists() {
            let _ = std::fs::remove_dir_all(dir);
        }
        Ok(())
    }

    async fn apply_zone(&self, domain: &str, content: &str) -> ExecResult<()> {
        std::fs::create_dir_all(&self.cfg.bind_zones_dir)?;
        write_managed(
            &self.cfg.bind_zones_dir,
            &self.cfg.bind_zones_dir.join(format!("{domain}.db")),
            content,
            0o644,
            None,
        )?;
        Ok(())
    }

    async fn remove_zone(&self, domain: &str) -> ExecResult<()> {
        let _ = remove_managed(
            &self.cfg.bind_zones_dir,
            &self.cfg.bind_zones_dir.join(format!("{domain}.db")),
        );
        Ok(())
    }

    async fn write_dns_conf(&self, content: &str) -> ExecResult<()> {
        if let Some(parent) = self.cfg.bind_conf_file.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.cfg.bind_conf_file, content)?;
        Ok(())
    }

    async fn generate_dkim_key(&self, domain: &str, selector: &str) -> ExecResult<String> {
        let dir = self.cfg.dkim_key_dir.join(domain);
        std::fs::create_dir_all(&dir)?;
        write_text(
            &dir.join(format!("{selector}.private")),
            "SIMULATED-PRIVATE-KEY\n",
        )?;
        let public =
            "-----BEGIN PUBLIC KEY-----\nU0lNVUxBVEVELVBVQkxJQy1LRVk=\n-----END PUBLIC KEY-----\n";
        write_text(&dir.join(format!("{selector}.public")), public)?;
        Ok(public.to_string())
    }

    async fn remove_dkim_key(&self, domain: &str) -> ExecResult<()> {
        let dir = self.cfg.dkim_key_dir.join(domain);
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
        Ok(())
    }

    async fn hash_mail_password(&self, _password: &str) -> ExecResult<String> {
        Ok(format!("{{SHA512-CRYPT}}sim-{}", random_hex(12)))
    }

    async fn sync_mail(
        &self,
        domains: &[MailDomainSpec],
        accounts: &[MailAccountConfig],
    ) -> ExecResult<()> {
        let root = self.cfg.state_dir.join("sandbox").join("mail");
        let vmail = self.cfg.state_dir.join("sandbox").join("vmail");
        std::fs::create_dir_all(&root)?;
        std::fs::create_dir_all(&vmail)?;
        let mut domain_lines = String::new();
        let mut mailbox_lines = String::new();
        let mut alias_lines = String::new();
        let mut users = String::new();
        let mut conf = String::from("# managed-by: RYNXCP\n");
        for domain in domains.iter().filter(|domain| domain.enabled) {
            domain_lines.push_str(&format!("{} {}\n", domain.domain, domain.domain));
            if let Some(target) = &domain.catch_all {
                alias_lines.push_str(&format!("@{} {}\n", domain.domain, target));
            }
            conf.push_str(&format!(
                "local_name mail.{} {{ ssl_cert = </sandbox/certs/webmail.{}/fullchain.pem\n ssl_key = </sandbox/certs/webmail.{}/privkey.pem\n}}\n",
                domain.domain, domain.domain, domain.domain
            ));
        }
        for account in accounts.iter().filter(|account| account.enabled) {
            let home = vmail.join(&account.domain).join(&account.local_part);
            std::fs::create_dir_all(home.join("Maildir/cur"))?;
            std::fs::create_dir_all(home.join("Maildir/new"))?;
            std::fs::create_dir_all(home.join("Maildir/tmp"))?;
            std::fs::create_dir_all(home.join("sieve"))?;
            let address = format!("{}@{}", account.local_part, account.domain);
            mailbox_lines.push_str(&format!(
                "{} {}/{}/\n",
                address, account.domain, account.local_part
            ));
            for alias in &account.aliases {
                alias_lines.push_str(&format!("{alias} {address}\n"));
            }
            users.push_str(&format!(
                "{}:{}:5000:5000::{}::userdb_quota_rule=*:storage={}M\n",
                address,
                account.password_hash,
                home.display(),
                account.quota_mb
            ));
        }
        write_text(&root.join("domains"), &domain_lines)?;
        write_text(&root.join("mailboxes"), &mailbox_lines)?;
        write_text(&root.join("aliases"), &alias_lines)?;
        write_text(&root.join("users"), &users)?;
        write_text(&root.join("dovecot.conf"), &conf)?;
        write_text(&root.join("sni"), "")?;
        Ok(())
    }

    async fn remove_mailbox(&self, domain: &str, local_part: &str) -> ExecResult<()> {
        let path = self
            .cfg
            .state_dir
            .join("sandbox")
            .join("vmail")
            .join(domain)
            .join(local_part);
        let _ = std::fs::remove_dir_all(path);
        Ok(())
    }

    async fn remove_mail_domain(&self, domain: &str) -> ExecResult<()> {
        let path = self
            .cfg
            .state_dir
            .join("sandbox")
            .join("vmail")
            .join(domain);
        let _ = std::fs::remove_dir_all(path);
        Ok(())
    }

    async fn reload_mail(&self) -> ExecResult<()> {
        Ok(())
    }

    async fn repair_dkim_key_permissions(&self) -> ExecResult<()> {
        Ok(())
    }

    async fn write_dkim_tables(&self, keytable: &str, signingtable: &str) -> ExecResult<()> {
        if let Some(path) = &self.cfg.opendkim_keytable {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, merge_dkim_table(path, keytable))?;
        }
        if let Some(path) = &self.cfg.opendkim_signingtable {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, merge_dkim_table(path, signingtable))?;
        }
        Ok(())
    }

    async fn create_database(&self, database: &str, user: &str, password: &str) -> ExecResult<()> {
        let dir = self.cfg.state_dir.join("sim-databases");
        std::fs::create_dir_all(&dir)?;
        write_text(
            &dir.join(format!("{database}.json")),
            &serde_json::json!({
                "database": database,
                "user": user,
                "password": password,
                "engine": "mariadb",
            })
            .to_string(),
        )?;
        Ok(())
    }

    async fn drop_database(&self, database: &str, _user: &str) -> ExecResult<()> {
        let path = self
            .cfg
            .state_dir
            .join("sim-databases")
            .join(format!("{database}.json"));
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }

    async fn apply_ftp_user(
        &self,
        login: &str,
        uid: u32,
        _gid: u32,
        home: &Path,
        password: &str,
    ) -> ExecResult<()> {
        let dir = self.cfg.state_dir.join("sim-ftp");
        std::fs::create_dir_all(&dir)?;
        write_text(
            &dir.join(format!("{login}.json")),
            &serde_json::json!({
                "login": login,
                "uid": uid,
                "home": home.display().to_string(),
                "password": password,
            })
            .to_string(),
        )?;
        Ok(())
    }

    async fn remove_ftp_user(&self, login: &str) -> ExecResult<()> {
        let path = self
            .cfg
            .state_dir
            .join("sim-ftp")
            .join(format!("{login}.json"));
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }

    async fn apply_ftp_certificate(&self, _domain: &str) -> ExecResult<()> {
        Ok(())
    }

    async fn resolve_user_ids(&self, username: &str) -> ExecResult<Option<(u32, u32)>> {
        if username == self.cfg.ftp_readonly_user {
            Ok(Some((1000, 1000)))
        } else {
            Ok(None)
        }
    }

    async fn apply_firewall(&self, ruleset: &str) -> ExecResult<()> {
        let dir = self.cfg.state_dir.join("sim-firewall");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("ruleset.nft"), ruleset)?;
        Ok(())
    }

    async fn php_versions(&self) -> ExecResult<Vec<String>> {
        Ok(vec!["8.5".into(), "8.3".into()])
    }

    async fn fail2ban_bans(&self) -> ExecResult<Vec<(String, String)>> {
        Ok(Vec::new())
    }

    async fn fail2ban_unban(&self, _ip: &str) -> ExecResult<()> {
        Ok(())
    }

    async fn installed_programs(&self) -> ExecResult<Vec<ProgramInfo>> {
        let rows = [
            ("nginx", "1.26.3", "web", "installed", "reverse proxy"),
            ("php-fpm 8.3", "8.3.14", "runtime", "installed", "FPM pool"),
            ("node", "22.11.0", "runtime", "installed", "systemd"),
            (
                "python3",
                "3.12.7",
                "runtime",
                "installed",
                "gunicorn/uvicorn",
            ),
            ("ruby", "3.3.6", "runtime", "installed", "puma"),
            ("java", "21.0.5", "runtime", "installed", "JAR"),
            ("dotnet", "8.0.11", "runtime", "installed", "ASP.NET"),
            ("go", "1.23.4", "runtime", "installed", "binaries"),
            (
                "mariadb",
                "11.4.4",
                "database",
                "installed",
                "per-domain databases",
            ),
            ("bind9", "9.20.3", "dns", "installed", "authoritative zones"),
            ("certbot", "3.0.1", "security", "installed", "Let's Encrypt"),
            (
                "pure-ftpd",
                "1.0.50",
                "web",
                "installed",
                "FTPS virtual users",
            ),
            ("opendkim", "2.11.0", "mail", "installed", "DKIM signing"),
            (
                "fail2ban",
                "1.1.0",
                "security",
                "installed",
                "brute-force jail",
            ),
            (
                "clamav",
                "1.4.1",
                "security",
                "installed",
                "antivirus engine",
            ),
            (
                "clamav-milter",
                "1.4.1",
                "security",
                "installed",
                "SMTP antivirus",
            ),
            ("spamassassin", "4.0.1", "mail", "installed", "spam scoring"),
            (
                "spamass-milter",
                "0.4.0",
                "mail",
                "installed",
                "SMTP antispam",
            ),
            ("rynxcp", "0.1.0", "panel", "installed", "control plane"),
        ];
        Ok(rows
            .into_iter()
            .map(|(name, version, kind, status, detail)| ProgramInfo {
                name: name.into(),
                version: version.into(),
                kind: kind.into(),
                status: status.into(),
                detail: detail.into(),
                unit: rynx_core::service_unit_for_program(name),
                service_status: if status == "installed"
                    && rynx_core::service_unit_for_program(name).is_some()
                {
                    Some("active".into())
                } else {
                    None
                },
            })
            .collect())
    }

    async fn available_updates(&self) -> ExecResult<Vec<PackageUpdate>> {
        Ok(vec![
            PackageUpdate {
                package: "nginx".into(),
                current_version: "1.26.3-1".into(),
                candidate_version: "1.26.4-1".into(),
                security: true,
            },
            PackageUpdate {
                package: "php8.3-fpm".into(),
                current_version: "8.3.14-1".into(),
                candidate_version: "8.3.15-1".into(),
                security: false,
            },
        ])
    }

    async fn apply_updates(&self) -> ExecResult<String> {
        Ok("simulation: apt-get update && apt-get upgrade completed\n2 packages upgraded\n".into())
    }

    async fn system_info(&self) -> ExecResult<SystemInfo> {
        Ok(SystemInfo {
            hostname: std::env::var("COMPUTERNAME")
                .or_else(|_| std::env::var("HOSTNAME"))
                .unwrap_or_else(|_| "rynx-sim".into()),
            primary_ip: Some("203.0.113.10".into()),
            ssh_port: 22,
            os: format!("{} (simulation)", std::env::consts::OS),
            kernel: "simulation".into(),
            uptime_secs: 0,
            load: [0, 0, 0],
            cpu_count: std::thread::available_parallelism()
                .map(|n| n.get() as u32)
                .unwrap_or(1),
            mem_total_kb: 8 * 1024 * 1024,
            mem_available_kb: 6 * 1024 * 1024,
            disk_total_kb: 80 * 1024 * 1024,
            disk_available_kb: 60 * 1024 * 1024,
            daemon_version: rynx_proto::DAEMON_VERSION.into(),
            mode: "simulation".into(),
        })
    }

    async fn uid_in_use(&self, uid: u32) -> ExecResult<bool> {
        Ok(self.users_dir().join(format!("uid-{uid}")).exists())
    }
}

fn copy_tree(source: &Path, target: &Path) -> ExecResult<()> {
    let meta = std::fs::symlink_metadata(source)?;
    if meta.is_dir() {
        std::fs::create_dir_all(target)?;
        for entry in std::fs::read_dir(source)? {
            let entry = entry?;
            copy_tree(&entry.path(), &target.join(entry.file_name()))?;
        }
        std::fs::set_permissions(target, meta.permissions())?;
    } else if meta.is_file() {
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(source, target)?;
        std::fs::set_permissions(target, meta.permissions())?;
    }
    Ok(())
}
