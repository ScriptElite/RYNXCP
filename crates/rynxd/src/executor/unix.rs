//! Linux executor. Every external command is invoked with an explicit argv,
//! a scrubbed environment and no shell.

use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use async_trait::async_trait;
use base64::Engine as _;
use cap_std::ambient_authority;
use cap_std::fs::{Dir, MetadataExt, OpenOptions as CapOpenOptions};
use nix::unistd::{chown, Gid, Uid, User};
use time::{format_description::well_known::Rfc3339, macros::format_description, OffsetDateTime};
use tokio::io::AsyncWriteExt;

use rynx_core::crypto::random_hex;
use rynx_core::paths::{remove_managed, write_managed};
use rynx_core::DaemonConfig;
use rynx_proto::{
    AccountSpec, AppSpec, CertView, CertificateStatus, FileEntry, InstallerApp, InstallerApplySpec,
    MailDomainSpec, MailQueueEntry, PackageUpdate, ProgramInfo, SystemInfo,
};

use super::{
    merge_dkim_table, validate_file_name, validate_relative_path, validate_site_root, ExecError,
    ExecResult, Executor, MailAccountConfig, UnitStatus, MAX_FILE_BYTES,
};

const SAFE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const VMAIL_ROOT: &str = "/var/vmail";
const POSTFIX_MAIL_DIR: &str = "/etc/postfix/rynxcp";
const DOVECOT_MAIL_DIR: &str = "/etc/dovecot/rynxcp";
const DOVECOT_MAIL_CONF: &str = "/etc/dovecot/conf.d/99-rynxcp.conf";
const MAIL_CERT_DIR: &str = "/etc/ssl/rynxcp/mail";
const MAIL_UID: u32 = 5000;
const MAIL_GID: u32 = 5000;

pub struct RealExecutor {
    cfg: DaemonConfig,
}

impl RealExecutor {
    pub fn new(cfg: DaemonConfig) -> Self {
        Self { cfg }
    }

    fn gid_for(&self, username: &str) -> ExecResult<u32> {
        match User::from_name(username) {
            Ok(Some(user)) => Ok(user.gid.as_raw()),
            Ok(None) => Err(ExecError::MissingAccount(username.to_string())),
            Err(e) => Err(ExecError::Io(e.to_string())),
        }
    }

    fn chown_path(&self, path: &Path, uid: u32, gid: u32) -> ExecResult<()> {
        chown(path, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))
            .map_err(|e| ExecError::Io(format!("chown {}: {e}", path.display())))
    }

    fn make_dir(&self, path: &Path, mode: u32, uid: u32, gid: u32) -> ExecResult<()> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
        self.chown_path(path, uid, gid)?;
        Ok(())
    }

    async fn apply_user_slice(
        &self,
        uid: u32,
        memory_mb: u64,
        cpu_percent: u64,
        process_limit: u64,
    ) -> ExecResult<()> {
        let unit = format!("user-{uid}.slice");
        let path = self.cfg.systemd_dir.join(&unit);
        let mut body = String::from(
            "[Unit]\nDescription=RYNXCP account resource slice\nSlice=user.slice\n\n[Slice]\n",
        );
        if memory_mb > 0 {
            body.push_str(&format!("MemoryMax={memory_mb}M\nMemorySwapMax=0\n"));
        }
        if cpu_percent > 0 {
            body.push_str(&format!("CPUQuota={cpu_percent}%\n"));
        }
        if process_limit > 0 {
            body.push_str(&format!("TasksMax={process_limit}\n"));
        }
        write_managed(&self.cfg.systemd_dir, &path, &body, 0o644, Some((0, 0)))?;
        run("systemctl", &["daemon-reload"]).await?;
        run("systemctl", &["start", &unit]).await?;
        let memory = if memory_mb > 0 {
            format!("{memory_mb}M")
        } else {
            "infinity".to_string()
        };
        let swap = if memory_mb > 0 {
            "0".to_string()
        } else {
            "infinity".to_string()
        };
        let tasks = if process_limit > 0 {
            process_limit.to_string()
        } else {
            "infinity".to_string()
        };
        run(
            "systemctl",
            &[
                "set-property",
                "--runtime",
                &unit,
                &format!("MemoryMax={memory}"),
                &format!("MemorySwapMax={swap}"),
                &format!("TasksMax={tasks}"),
            ],
        )
        .await?;
        if cpu_percent > 0 {
            run(
                "systemctl",
                &[
                    "set-property",
                    "--runtime",
                    &unit,
                    &format!("CPUQuota={cpu_percent}%"),
                ],
            )
            .await?;
        } else {
            let _ = run(
                "systemctl",
                &["set-property", "--runtime", &unit, "CPUQuota="],
            )
            .await;
        }
        Ok(())
    }

    async fn nginx_test(&self) -> ExecResult<()> {
        let args: Vec<String> = self
            .cfg
            .nginx_test_args
            .split_whitespace()
            .map(str::to_string)
            .collect();
        run_owned("nginx", &args).await.map(|_| ())
    }

    async fn reload_service(&self, service: &str) -> ExecResult<()> {
        run("systemctl", &["reload-or-restart", service])
            .await
            .map(|_| ())
    }

    async fn fail2ban_jails(&self) -> ExecResult<Vec<String>> {
        let output = match run("fail2ban-client", &["status"]).await {
            Ok(output) => output,
            Err(_) => return Ok(Vec::new()),
        };
        let Some((_, list)) = output
            .lines()
            .find_map(|line| line.split_once("Jail list:"))
        else {
            return Ok(Vec::new());
        };
        Ok(list
            .split(',')
            .map(str::trim)
            .filter(|jail| !jail.is_empty())
            .map(str::to_string)
            .collect())
    }

    fn php_binary(&self, version: &str) -> String {
        format!("php-fpm{version}")
    }
}

fn php_fpm_unit(version: &str, conf: &Path, uid: u32) -> String {
    format!(
        "[Unit]\n\
         Description=RYNXCP PHP {version} FPM\n\
         After=network.target\n\n\
         [Service]\n\
         Type=simple\n\
         ExecStart=/usr/sbin/php-fpm{version} --nodaemonize --fpm-config {conf}\n\
         Restart=on-failure\n\
         RestartSec=3\n\
         Slice=user-{uid}.slice\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        conf = conf.display()
    )
}

async fn run(program: &str, args: &[&str]) -> ExecResult<String> {
    let output = tokio::process::Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", SAFE_PATH)
        .env("LC_ALL", "C")
        .output()
        .await
        .map_err(|e| ExecError::Command {
            program: program.to_string(),
            args: args.join(" "),
            status: -1,
            stderr: e.to_string(),
        })?;
    if !output.status.success() {
        return Err(ExecError::Command {
            program: program.to_string(),
            args: args.join(" "),
            status: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

async fn run_owned(program: &str, args: &[String]) -> ExecResult<String> {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run(program, &refs).await
}

async fn run_with_env(
    program: &str,
    args: &[String],
    envs: &[(String, String)],
) -> ExecResult<String> {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut command = tokio::process::Command::new(program);
    command
        .args(&refs)
        .env_clear()
        .env("PATH", SAFE_PATH)
        .env("LC_ALL", "C")
        .env("HOME", "/root");
    for (key, value) in envs {
        command.env(key, value);
    }
    let output = command.output().await.map_err(|e| ExecError::Command {
        program: program.to_string(),
        args: args.join(" "),
        status: -1,
        stderr: e.to_string(),
    })?;
    if !output.status.success() {
        return Err(ExecError::Command {
            program: program.to_string(),
            args: args.join(" "),
            status: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

async fn run_with_stdin(program: &str, args: &[&str], input: &str) -> ExecResult<String> {
    let mut child = tokio::process::Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", SAFE_PATH)
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| ExecError::Command {
            program: program.to_string(),
            args: args.join(" "),
            status: -1,
            stderr: e.to_string(),
        })?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input.as_bytes()).await?;
        stdin.flush().await?;
    }
    let output = child.wait_with_output().await?;
    if !output.status.success() {
        return Err(ExecError::Command {
            program: program.to_string(),
            args: args.join(" "),
            status: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Like `run` but returns stdout and stderr on success (nginx prints its
/// configuration check to stderr even when the test passes).
async fn run_combined(program: &str, args: &[String]) -> ExecResult<String> {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = tokio::process::Command::new(program)
        .args(&refs)
        .env_clear()
        .env("PATH", SAFE_PATH)
        .env("LC_ALL", "C")
        .output()
        .await
        .map_err(|e| ExecError::Command {
            program: program.to_string(),
            args: refs.join(" "),
            status: -1,
            stderr: e.to_string(),
        })?;
    let mut combined = String::from_utf8_lossy(&output.stdout).to_string();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    if !output.status.success() {
        return Err(ExecError::Command {
            program: program.to_string(),
            args: refs.join(" "),
            status: output.status.code().unwrap_or(-1),
            stderr: combined,
        });
    }
    Ok(combined)
}

/// Runs an installer command as the hosting account instead of root. The
/// program and every argument are explicit; no shell is involved.
async fn run_as_user(
    username: &str,
    home: &Path,
    cwd: &Path,
    program: &str,
    args: &[String],
) -> ExecResult<String> {
    let runuser = if Path::new("/usr/sbin/runuser").exists() {
        "/usr/sbin/runuser"
    } else {
        "/sbin/runuser"
    };
    let mut argv = vec![
        "-u".to_string(),
        username.to_string(),
        "--".to_string(),
        "/usr/bin/env".to_string(),
        format!("HOME={}", home.display()),
        format!("PATH={SAFE_PATH}"),
        "LC_ALL=C".to_string(),
        format!("COMPOSER_HOME={}", home.join(".composer").display()),
        "COMPOSER_NO_INTERACTION=1".to_string(),
        "COMPOSER_ALLOW_SUPERUSER=0".to_string(),
        program.to_string(),
    ];
    argv.extend(args.iter().cloned());
    let output = tokio::process::Command::new(runuser)
        .args(&argv)
        .current_dir(cwd)
        .env_clear()
        .env("PATH", SAFE_PATH)
        .env("LC_ALL", "C")
        .output()
        .await
        .map_err(|e| ExecError::Command {
            program: program.to_string(),
            args: args.join(" "),
            status: -1,
            stderr: e.to_string(),
        })?;
    if !output.status.success() {
        return Err(ExecError::Command {
            program: program.to_string(),
            args: args.join(" "),
            status: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Removes the installer's dedicated document root so a retry starts clean.
/// The caller has already verified that the path is `<domain>/public_html`.
fn reset_docroot(home: &Path, docroot: &Path, owner: &User) -> ExecResult<()> {
    if !docroot.starts_with(home) {
        return Err(ExecError::InvalidInput(
            "the document root escapes the account home".into(),
        ));
    }
    let _identity = switch_fs_identity(owner.uid.as_raw(), owner.gid.as_raw())?;
    match std::fs::remove_dir_all(docroot) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(ExecError::Io(format!(
            "cannot reset the document root {}: {err}",
            docroot.display()
        ))),
    }
}

/// Grants Nginx (www-data) read/traverse access to a web root without
/// following symlinks. Installer files are created with the daemon umask and
/// the account group, so without this the web server returns 403.
fn grant_web_read(path: &Path, gid: Gid) -> ExecResult<()> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|err| ExecError::Io(format!("cannot inspect {}: {err}", path.display())))?;
    if meta.file_type().is_symlink() {
        return Ok(());
    }
    if meta.is_file() {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if matches!(name, "wp-config.php" | ".env") {
            return Ok(());
        }
    }
    chown(path, None, Some(gid))
        .map_err(|err| ExecError::Io(format!("cannot chgrp {}: {err}", path.display())))?;
    let mut mode = meta.permissions().mode();
    if meta.is_dir() {
        mode |= 0o050;
    } else {
        mode |= 0o040;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|err| ExecError::Io(format!("cannot chmod {}: {err}", path.display())))?;
    if meta.is_dir() {
        let entries = std::fs::read_dir(path)
            .map_err(|err| ExecError::Io(format!("cannot read {}: {err}", path.display())))?;
        for entry in entries {
            let entry = entry
                .map_err(|err| ExecError::Io(format!("cannot read {}: {err}", path.display())))?;
            grant_web_read(&entry.path(), gid)?;
        }
    }
    Ok(())
}

fn write_owned_file(path: &Path, data: &[u8], uid: Uid, gid: Gid) -> ExecResult<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|err| ExecError::Io(format!("cannot write {}: {err}", path.display())))?;
    file.write_all(data)
        .map_err(|err| ExecError::Io(format!("cannot write {}: {err}", path.display())))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640))
        .map_err(|err| ExecError::Io(format!("cannot chmod {}: {err}", path.display())))?;
    chown(path, Some(uid), Some(gid))
        .map_err(|err| ExecError::Io(format!("cannot chown {}: {err}", path.display())))?;
    Ok(())
}

fn read_restic_env(path: &Path) -> ExecResult<Vec<(String, String)>> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path)
        .map_err(|err| ExecError::Io(format!("cannot read {}: {err}", path.display())))?;
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(ExecError::InvalidInput(
            "offsite_env_file must not be readable by other users".into(),
        ));
    }
    let content = std::fs::read_to_string(path)
        .map_err(|err| ExecError::Io(format!("cannot read {}: {err}", path.display())))?;
    let mut envs = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(ExecError::InvalidInput(
                "offsite_env_file contains an invalid line".into(),
            ));
        };
        let key = key.trim();
        let value = value.trim();
        if key.is_empty()
            || !key
                .chars()
                .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
            || value.chars().any(|ch| ch.is_control())
        {
            return Err(ExecError::InvalidInput(
                "offsite_env_file contains an invalid entry".into(),
            ));
        }
        envs.push((key.to_string(), value.to_string()));
    }
    Ok(envs)
}

fn stage_installer_archive(home: &Path, archive: &Path, owner: &User) -> ExecResult<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let data = std::fs::read(archive)
        .map_err(|err| ExecError::Io(format!("cannot read {}: {err}", archive.display())))?;
    let staged = home.join(format!(".rynxcp-installer-{}.archive", random_hex(8)));
    {
        let _identity = switch_fs_identity(owner.uid.as_raw(), owner.gid.as_raw())?;
        std::fs::write(&staged, &data).map_err(|err| {
            ExecError::Io(format!(
                "cannot copy the installer archive to {}: {err}",
                staged.display()
            ))
        })?;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o600))
            .map_err(|err| ExecError::Io(format!("cannot chmod {}: {err}", staged.display())))?;
    }
    Ok(staged)
}

fn php_single(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "\\'")
}

fn env_value(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn wordpress_config(spec: &InstallerApplySpec) -> String {
    format!(
        "<?php\n\
define('DB_NAME', '{db}');\n\
define('DB_USER', '{user}');\n\
define('DB_PASSWORD', '{password}');\n\
define('DB_HOST', '{host}');\n\
define('DB_CHARSET', 'utf8mb4');\n\
define('DB_COLLATE', '');\n\
define('AUTH_KEY', '{auth}');\n\
define('SECURE_AUTH_KEY', '{secure_auth}');\n\
define('LOGGED_IN_KEY', '{logged_in}');\n\
define('NONCE_KEY', '{nonce}');\n\
define('AUTH_SALT', '{auth_salt}');\n\
define('SECURE_AUTH_SALT', '{secure_auth_salt}');\n\
define('LOGGED_IN_SALT', '{logged_in_salt}');\n\
define('NONCE_SALT', '{nonce_salt}');\n\
$table_prefix = 'wp_';\n\
define('WP_DEBUG', false);\n\
if (!defined('ABSPATH')) {{\n    define('ABSPATH', __DIR__ . '/');\n}}\n\
require_once ABSPATH . 'wp-settings.php';\n",
        db = php_single(&spec.database),
        user = php_single(&spec.db_user),
        password = php_single(&spec.db_password),
        host = php_single(&spec.db_host),
        auth = random_hex(64),
        secure_auth = random_hex(64),
        logged_in = random_hex(64),
        nonce = random_hex(64),
        auth_salt = random_hex(64),
        secure_auth_salt = random_hex(64),
        logged_in_salt = random_hex(64),
        nonce_salt = random_hex(64),
    )
}

fn laravel_env(spec: &InstallerApplySpec) -> String {
    let raw = hex::decode(random_hex(32)).unwrap_or_default();
    let key = base64::engine::general_purpose::STANDARD.encode(raw);
    let scheme = if spec.tls { "https" } else { "http" };
    format!(
        "APP_NAME={name}\n\
APP_ENV=production\n\
APP_KEY=base64:{key}\n\
APP_DEBUG=false\n\
APP_URL={scheme}://{domain}\n\
DB_CONNECTION=mysql\n\
DB_HOST={db_host}\n\
DB_PORT=3306\n\
DB_DATABASE={db}\n\
DB_USERNAME={db_user}\n\
DB_PASSWORD={db_password}\n\
SESSION_DRIVER=file\n\
CACHE_STORE=file\n\
QUEUE_CONNECTION=sync\n",
        name = env_value(&spec.site_title),
        key = key,
        domain = spec.domain,
        db_host = spec.db_host,
        db = env_value(&spec.database),
        db_user = env_value(&spec.db_user),
        db_password = env_value(&spec.db_password),
    )
}

/// Dovecot 2.4 split `mail_location` into `mail_driver`/`mail_path`, renamed
/// the SSL settings and removed the `plugin {}` section. Detect the installed
/// version so the generated configuration stays valid on both 2.3 and 2.4.
async fn dovecot_is_v24() -> bool {
    let Ok(output) = run("dovecot", &["--version"]).await else {
        return true;
    };
    let version = output.split_whitespace().next().unwrap_or_default();
    let mut parts = version.split('.');
    let major = parts.next().and_then(|value| value.parse::<u32>().ok());
    let minor = parts.next().and_then(|value| value.parse::<u32>().ok());
    match (major, minor) {
        (Some(major), Some(minor)) => major > 2 || (major == 2 && minor >= 4),
        _ => true,
    }
}

struct SiteRoot {
    dir: Dir,
    #[allow(dead_code)]
    _identity: FsIdentityGuard,
}

#[cfg(target_os = "linux")]
struct FsIdentityGuard {
    old_uid: libc::uid_t,
    old_gid: libc::gid_t,
}

#[cfg(target_os = "linux")]
impl Drop for FsIdentityGuard {
    fn drop(&mut self) {
        unsafe {
            libc::setfsuid(self.old_uid);
            libc::setfsgid(self.old_gid);
        }
    }
}

/// Switches the calling thread to the account's filesystem UID/GID. This makes
/// the file manager obey normal Unix permissions instead of running as root.
/// The guard restores the daemon identity when it is dropped. The caller must
/// not await while the guard is alive.
#[cfg(target_os = "linux")]
fn switch_fs_identity(uid: u32, gid: u32) -> ExecResult<FsIdentityGuard> {
    let old_uid = unsafe { libc::setfsuid(uid as libc::uid_t) } as libc::uid_t;
    let old_gid = unsafe { libc::setfsgid(gid as libc::gid_t) } as libc::gid_t;
    let check_uid = unsafe { libc::setfsuid(uid as libc::uid_t) } as libc::uid_t;
    let check_gid = unsafe { libc::setfsgid(gid as libc::gid_t) } as libc::gid_t;
    if check_uid != uid as libc::uid_t || check_gid != gid as libc::gid_t {
        unsafe {
            libc::setfsuid(old_uid);
            libc::setfsgid(old_gid);
        }
        return Err(ExecError::Io(
            "cannot switch to the account filesystem identity".into(),
        ));
    }
    Ok(FsIdentityGuard { old_uid, old_gid })
}

#[cfg(not(target_os = "linux"))]
struct FsIdentityGuard;

#[cfg(not(target_os = "linux"))]
fn switch_fs_identity(uid: u32, gid: u32) -> ExecResult<FsIdentityGuard> {
    let _ = (uid, gid);
    Ok(FsIdentityGuard)
}

/// Opens the account home as a capability directory. The file manager uses it so
/// the owner can manage everything above the site document root.
fn open_account_root(cfg: &DaemonConfig, username: &str) -> ExecResult<SiteRoot> {
    rynx_core::validate_username(username)
        .map_err(|err| ExecError::InvalidInput(format!("invalid account: {err}")))?;
    let home_root = Dir::open_ambient_dir(&cfg.home_root, ambient_authority())?;
    let home_meta = home_root.symlink_metadata(username)?;
    if home_meta.file_type().is_symlink() || !home_meta.is_dir() {
        return Err(ExecError::Io("the account home is not a directory".into()));
    }
    let identity = switch_fs_identity(home_meta.uid(), home_meta.gid())?;
    let dir = home_root.open_dir(username)?;
    Ok(SiteRoot {
        dir,
        _identity: identity,
    })
}

/// Opens the site document root as a capability directory. The account home and
/// docroot themselves must be real directories, and cap-std confines every
/// subsequent operation to the docroot (no `..` or symlink escapes). On Linux
/// the caller runs with the account's filesystem UID/GID.
fn open_site_root(cfg: &DaemonConfig, username: &str, docroot: &str) -> ExecResult<SiteRoot> {
    validate_site_root(username, docroot)?;
    let home_root = Dir::open_ambient_dir(&cfg.home_root, ambient_authority())?;
    let home_meta = home_root.symlink_metadata(username)?;
    if home_meta.file_type().is_symlink() || !home_meta.is_dir() {
        return Err(ExecError::Io("the account home is not a directory".into()));
    }
    let identity = switch_fs_identity(home_meta.uid(), home_meta.gid())?;
    let account_home = home_root.open_dir(username)?;
    let doc_meta = account_home.symlink_metadata(docroot)?;
    if doc_meta.file_type().is_symlink() || !doc_meta.is_dir() {
        return Err(ExecError::Io(
            "the website document root is not a directory".into(),
        ));
    }
    let dir = account_home.open_dir(docroot)?;
    Ok(SiteRoot {
        dir,
        _identity: identity,
    })
}

/// Opens the account home capability, optionally creating it. Symlinks and
/// non-directories are rejected so later chown/chmod calls cannot be tricked
/// into touching another account.
fn open_account_home(cfg: &DaemonConfig, username: &str, create: bool) -> ExecResult<Dir> {
    let home_root = Dir::open_ambient_dir(&cfg.home_root, ambient_authority())?;
    match home_root.symlink_metadata(username) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(ExecError::InvalidInput(
                    "the account home is not a real directory".into(),
                ));
            }
            Ok(home_root.open_dir(username)?)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound && create => {
            home_root.create_dir(username)?;
            Ok(home_root.open_dir(username)?)
        }
        Err(err) => Err(err.into()),
    }
}

/// Creates/opens each path component below a capability directory, rejecting
/// symlinked or non-directory components. Existing components are re-owned and
/// re-moded to the managed values.
fn ensure_dir_components(
    parent: &Dir,
    relative: &Path,
    mode: u32,
    uid: u32,
    gid: u32,
) -> ExecResult<()> {
    let mut current = parent.try_clone()?;
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(ExecError::InvalidInput(
                "invalid managed directory path".into(),
            ));
        };
        let name = Path::new(name);
        match current.symlink_metadata(name) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_dir() {
                    return Err(ExecError::InvalidInput(format!(
                        "refusing symlinked or non-directory path component '{}'",
                        name.to_string_lossy()
                    )));
                }
                let dir = current.open_dir(name)?;
                set_owner_mode(dir.as_raw_fd(), uid, gid, mode)?;
                current = dir;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                current.create_dir(name)?;
                let dir = current.open_dir(name)?;
                set_owner_mode(dir.as_raw_fd(), uid, gid, mode)?;
                current = dir;
            }
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

fn set_mode(fd: std::os::fd::RawFd, mode: u32) -> ExecResult<()> {
    let rc = unsafe { libc::fchmod(fd, mode as libc::mode_t) };
    if rc == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    #[cfg(target_os = "linux")]
    {
        // cap-std opens directories with O_PATH, where fchmod fails with EBADF.
        if error.raw_os_error() == Some(libc::EBADF) {
            let path = std::ffi::CString::new(format!("/proc/self/fd/{fd}"))
                .map_err(|_| ExecError::Io("invalid descriptor path".into()))?;
            let rc = unsafe { libc::chmod(path.as_ptr(), mode as libc::mode_t) };
            if rc == 0 {
                return Ok(());
            }
            return Err(ExecError::Io(std::io::Error::last_os_error().to_string()));
        }
    }
    Err(ExecError::Io(error.to_string()))
}

#[cfg(target_os = "linux")]
fn set_owner_mode(fd: std::os::fd::RawFd, uid: u32, gid: u32, mode: u32) -> ExecResult<()> {
    // fchown also fails with EBADF on O_PATH descriptors; AT_EMPTY_PATH applies
    // the change to the directory the descriptor refers to.
    let rc = unsafe {
        libc::fchownat(
            fd,
            c"".as_ptr(),
            uid as libc::uid_t,
            gid as libc::gid_t,
            libc::AT_EMPTY_PATH,
        )
    };
    if rc != 0 {
        return Err(ExecError::Io(std::io::Error::last_os_error().to_string()));
    }
    set_mode(fd, mode)
}

#[cfg(not(target_os = "linux"))]
fn set_owner_mode(fd: std::os::fd::RawFd, uid: u32, gid: u32, mode: u32) -> ExecResult<()> {
    let rc = unsafe { libc::fchown(fd, uid as libc::uid_t, gid as libc::gid_t) };
    if rc != 0 {
        return Err(ExecError::Io(std::io::Error::last_os_error().to_string()));
    }
    set_mode(fd, mode)
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
    } else if meta.file_type().is_symlink() {
        let link = std::fs::read_link(source)?;
        if target.exists() || std::fs::symlink_metadata(target).is_ok() {
            let _ = std::fs::remove_file(target);
        }
        std::os::unix::fs::symlink(link, target)?;
    } else if meta.is_file() {
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(source, target)?;
        std::fs::set_permissions(target, meta.permissions())?;
    }
    Ok(())
}

async fn write_ssh_keys(home: &Path, username: &str, keys: &[String]) -> ExecResult<()> {
    let owner = User::from_name(username)
        .map_err(|err| ExecError::Io(err.to_string()))?
        .ok_or_else(|| ExecError::MissingAccount(username.to_string()))?;
    let _identity = switch_fs_identity(owner.uid.as_raw(), owner.gid.as_raw())?;
    let dir = home.join(".ssh");
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    let file = dir.join("authorized_keys");
    let mut content = keys.join("\n");
    if !content.is_empty() {
        content.push('\n');
    }
    std::fs::write(&file, content)?;
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[async_trait]
impl Executor for RealExecutor {
    fn mode(&self) -> &'static str {
        "linux"
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
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let home = self.home(&spec.username);
        let existing = User::from_name(&spec.username).map_err(|e| ExecError::Io(e.to_string()))?;
        if existing.is_none() {
            let uid_s = uid.to_string();
            let home_s = home.display().to_string();
            run(
                "useradd",
                &[
                    "--uid",
                    &uid_s,
                    "--home-dir",
                    &home_s,
                    "--create-home",
                    "--shell",
                    "/usr/sbin/nologin",
                    "--user-group",
                    &spec.username,
                ],
            )
            .await?;
        }

        let gid = self.gid_for(&spec.username)?;
        let account_uid = existing
            .as_ref()
            .map(|user| user.uid.as_raw())
            .unwrap_or(uid);
        let account_home = open_account_home(&self.cfg, &spec.username, true)?;
        let home_s = home.display().to_string();
        if let Ok(meta) = std::fs::symlink_metadata(&home) {
            if meta.uid() != account_uid {
                // Repair homes created for a stale UID (for example after a
                // pre-existing Linux user was adopted by the panel). Do not
                // follow symlinks outside the account home.
                run(
                    "chown",
                    &["-R", "-h", &format!("{account_uid}:{gid}"), &home_s],
                )
                .await?;
            }
        }
        // Nginx (www-data) must traverse the home to reach public_html, but it
        // must not list it. The home is not readable by other accounts.
        let web_gid = User::from_name("www-data")
            .ok()
            .flatten()
            .map(|user| user.gid.as_raw());
        let (home_gid, home_mode) = web_gid.map_or((gid, 0o711), |web| (web, 0o710));
        set_owner_mode(account_home.as_raw_fd(), account_uid, home_gid, home_mode)?;
        for (relative, mode) in [("logs", 0o750), ("apps", 0o750), ("tmp", 0o700)] {
            ensure_dir_components(&account_home, Path::new(relative), mode, account_uid, gid)?;
        }
        // Legacy accounts may still have a shared public_html. Keep it when it
        // contains files; remove it when it is an empty leftover.
        let legacy_public = home.join("public_html");
        if legacy_public.is_dir() {
            let empty = std::fs::read_dir(&legacy_public)
                .map(|mut entries| entries.next().is_none())
                .unwrap_or(false);
            if empty {
                let _ = std::fs::remove_dir(&legacy_public);
            } else if let Some(web_gid) = web_gid {
                if let Ok(public) = account_home.open_dir("public_html") {
                    set_owner_mode(public.as_raw_fd(), account_uid, web_gid, 0o2750)?;
                }
            }
        }

        // PHP sessions are system-managed. Keep them outside the account home
        // so FTP and the file manager cannot read or alter them.
        let sessions_root = Path::new(rynx_core::paths::PHP_SESSION_ROOT);
        if !sessions_root.exists() {
            std::fs::create_dir_all(sessions_root)?;
            std::fs::set_permissions(sessions_root, std::fs::Permissions::from_mode(0o755))?;
        }
        let session_dir = sessions_root.join(&spec.username);
        self.make_dir(&session_dir, 0o700, account_uid, gid)?;
        let old_sessions = home.join(".php/sessions");
        if old_sessions.is_dir() {
            if let Ok(entries) = std::fs::read_dir(&old_sessions) {
                for entry in entries.flatten() {
                    let target = session_dir.join(entry.file_name());
                    if target.exists() {
                        continue;
                    }
                    if std::fs::rename(entry.path(), &target).is_err() {
                        let _ = std::fs::copy(entry.path(), &target);
                    }
                }
            }
        }
        let _ = std::fs::remove_dir_all(home.join(".php"));
        if let Err(err) = self
            .apply_user_slice(
                account_uid,
                spec.memory_mb,
                spec.cpu_percent,
                spec.process_limit,
            )
            .await
        {
            tracing::warn!(
                account = %spec.username,
                error = %err,
                "account resource slice could not be applied"
            );
        }
        Ok(())
    }

    async fn remove_account(&self, username: &str, purge: bool) -> ExecResult<()> {
        let user = User::from_name(username).map_err(|e| ExecError::Io(e.to_string()))?;
        if let Some(user) = &user {
            if purge {
                let _ = run("userdel", &["-r", username]).await;
            } else {
                let _ = run("userdel", &[username]).await;
            }
            let slice = self
                .cfg
                .systemd_dir
                .join(format!("user-{}.slice", user.uid.as_raw()));
            let _ = remove_managed(&self.cfg.systemd_dir, &slice);
            let _ = run("systemctl", &["daemon-reload"]).await;
        }
        if purge {
            let home = self.home(username);
            if home.exists() {
                let _ = std::fs::remove_dir_all(home);
            }
        }
        Ok(())
    }

    async fn set_ssh_access(&self, username: &str, enabled: bool) -> ExecResult<()> {
        let shell = if enabled {
            "/bin/bash"
        } else {
            "/usr/sbin/nologin"
        };
        run("usermod", &["--shell", shell, username]).await?;
        if enabled {
            let home = self.home(username);
            let owner = User::from_name(username)
                .map_err(|err| ExecError::Io(err.to_string()))?
                .ok_or_else(|| ExecError::MissingAccount(username.to_string()))?;
            let _identity = switch_fs_identity(owner.uid.as_raw(), owner.gid.as_raw())?;
            let dir = home.join(".ssh");
            std::fs::create_dir_all(&dir)?;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
            let file = dir.join("authorized_keys");
            if let Ok(existing) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&file)
            {
                drop(existing);
            }
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))?;
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
            Err(err) => Err(ExecError::Io(format!(
                "cannot read {}: {err}",
                file.display()
            ))),
        }
    }

    async fn add_ssh_key(&self, username: &str, key: &str) -> ExecResult<()> {
        self.set_ssh_access(username, true).await?;
        let mut keys = self.ssh_keys(username).await?;
        if keys.iter().any(|existing| existing == key) {
            return Ok(());
        }
        keys.push(key.to_string());
        let home = self.home(username);
        write_ssh_keys(&home, username, &keys).await
    }

    async fn remove_ssh_key(&self, username: &str, key: &str) -> ExecResult<()> {
        let keys: Vec<String> = self
            .ssh_keys(username)
            .await?
            .into_iter()
            .filter(|existing| existing != key)
            .collect();
        let home = self.home(username);
        write_ssh_keys(&home, username, &keys).await
    }

    async fn remove_website_root(&self, username: &str, relative: &str) -> ExecResult<()> {
        validate_relative_path(relative)?;
        if relative.contains('/') {
            return Err(ExecError::InvalidInput(
                "the website root must be a single directory".into(),
            ));
        }
        let home = self.home(username);
        let target = home.join(relative);
        if !target.starts_with(&home) || target == home {
            return Err(ExecError::InvalidInput(
                "the website root escapes the account home".into(),
            ));
        }
        let owner = User::from_name(username)
            .map_err(|err| ExecError::Io(err.to_string()))?
            .ok_or_else(|| ExecError::MissingAccount(username.to_string()))?;
        let _identity = switch_fs_identity(owner.uid.as_raw(), owner.gid.as_raw())?;
        match std::fs::remove_dir_all(&target) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(ExecError::Io(format!(
                "cannot remove {}: {err}",
                target.display()
            ))),
        }
    }

    async fn ensure_docroot(&self, username: &str, uid: u32, path: &Path) -> ExecResult<()> {
        let home = self.home(username);
        if !path.starts_with(&home) {
            return Err(ExecError::Unsupported(
                "docroot escapes the account home".into(),
            ));
        }
        let relative = path
            .strip_prefix(&home)
            .map_err(|_| ExecError::InvalidInput("docroot escapes the account home".into()))?;
        let account_home = open_account_home(&self.cfg, username, false)?;
        let gid = self.gid_for(username)?;
        ensure_dir_components(&account_home, relative, 0o755, uid, gid)?;
        if let Some(web) = User::from_name("www-data").ok().flatten() {
            for docroot in [Path::new("public_html"), relative] {
                if let Ok(dir) = account_home.open_dir(docroot) {
                    set_owner_mode(dir.as_raw_fd(), uid, web.gid.as_raw(), 0o2750)?;
                }
            }
        }
        Ok(())
    }

    async fn file_list(
        &self,
        username: &str,
        _docroot: &str,
        path: &str,
    ) -> ExecResult<Vec<FileEntry>> {
        validate_relative_path(path)?;
        let site = open_account_root(&self.cfg, username)?;
        let read_dir = if path.is_empty() {
            site.dir.entries()?
        } else {
            site.dir.read_dir(path)?
        };
        let mut entries = Vec::new();
        for entry in read_dir {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            let relative = if path.is_empty() {
                PathBuf::from(&name)
            } else {
                Path::new(path).join(&name)
            };
            let meta = site.dir.symlink_metadata(relative.as_path())?;
            let kind = if meta.is_dir() {
                "dir"
            } else if meta.is_file() {
                "file"
            } else if meta.file_type().is_symlink() {
                "symlink"
            } else {
                "other"
            };
            let modified = meta
                .modified()
                .ok()
                .and_then(|value| OffsetDateTime::from(value.into_std()).format(&Rfc3339).ok());
            entries.push(FileEntry {
                name,
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

    async fn file_read(&self, username: &str, _docroot: &str, path: &str) -> ExecResult<Vec<u8>> {
        if path.is_empty() {
            return Err(ExecError::Io("a file path is required".into()));
        }
        validate_relative_path(path)?;
        let site = open_account_root(&self.cfg, username)?;
        let meta = site.dir.symlink_metadata(path)?;
        if meta.file_type().is_symlink() {
            return Err(ExecError::Io("symbolic links cannot be edited".into()));
        }
        if !meta.is_file() {
            return Err(ExecError::Io("not a regular file".into()));
        }
        if meta.len() > MAX_FILE_BYTES {
            return Err(ExecError::Io("file is too large".into()));
        }
        let mut file = site.dir.open(path)?;
        let mut data = Vec::with_capacity(meta.len() as usize);
        file.read_to_end(&mut data)?;
        Ok(data)
    }

    async fn file_write(
        &self,
        username: &str,
        _docroot: &str,
        path: &str,
        data: &[u8],
    ) -> ExecResult<()> {
        if path.is_empty() {
            return Err(ExecError::Io("a file path is required".into()));
        }
        if data.len() as u64 > MAX_FILE_BYTES {
            return Err(ExecError::Io("file is too large".into()));
        }
        validate_relative_path(path)?;
        let site = open_account_root(&self.cfg, username)?;
        let mut existing = false;
        if let Ok(meta) = site.dir.symlink_metadata(path) {
            existing = true;
            if meta.file_type().is_symlink() {
                return Err(ExecError::Io("symbolic links cannot be edited".into()));
            }
            if !meta.is_file() {
                return Err(ExecError::Io("not a regular file".into()));
            }
        }
        let mut options = CapOpenOptions::new();
        options.write(true).create(true).truncate(true);
        let mut file = site.dir.open_with(path, &options)?;
        file.write_all(data)?;
        file.flush()?;
        if !existing {
            // The daemon runs with UMask=0027; make new web files readable by
            // Nginx (www-data) even though the account owns them.
            set_mode(file.as_raw_fd(), 0o644)?;
        }
        Ok(())
    }

    async fn file_mkdir(&self, username: &str, _docroot: &str, path: &str) -> ExecResult<()> {
        if path.is_empty() {
            return Err(ExecError::Io("a directory path is required".into()));
        }
        validate_relative_path(path)?;
        let site = open_account_root(&self.cfg, username)?;
        site.dir.create_dir(path)?;
        let dir = site.dir.open_dir(path)?;
        set_mode(dir.as_raw_fd(), 0o755)?;
        Ok(())
    }

    async fn file_rename(
        &self,
        username: &str,
        _docroot: &str,
        path: &str,
        new_name: &str,
    ) -> ExecResult<()> {
        if path.is_empty() {
            return Err(ExecError::Io("a source path is required".into()));
        }
        validate_relative_path(path)?;
        validate_file_name(new_name)?;
        let site = open_account_root(&self.cfg, username)?;
        let source = Path::new(path);
        let target = source.parent().unwrap_or(Path::new("")).join(new_name);
        site.dir.rename(source, &site.dir, target.as_path())?;
        Ok(())
    }

    async fn file_delete(
        &self,
        username: &str,
        _docroot: &str,
        path: &str,
        recursive: bool,
    ) -> ExecResult<()> {
        if path.is_empty() {
            return Err(ExecError::Io("refusing to delete the account home".into()));
        }
        validate_relative_path(path)?;
        let site = open_account_root(&self.cfg, username)?;
        let meta = site.dir.symlink_metadata(path)?;
        if meta.is_dir() {
            if recursive {
                site.dir.remove_dir_all(path)?;
            } else {
                site.dir.remove_dir(path)?;
            }
        } else {
            site.dir.remove_file(path)?;
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
        let relative = docroot
            .strip_prefix(self.home(username))
            .map_err(|_| ExecError::InvalidInput("welcome path escapes the account home".into()))?;
        let docroot = relative
            .to_str()
            .ok_or_else(|| ExecError::InvalidInput("welcome path is not valid UTF-8".into()))?;
        let site = open_site_root(&self.cfg, username, docroot)?;
        if site.dir.exists("index.html") || site.dir.exists("index.php") {
            return Ok(());
        }
        let name = if php { "index.php" } else { "index.html" };
        let content = rynx_core::templates::welcome_page(locale, domain);
        let mut options = CapOpenOptions::new();
        options.write(true).create(true).truncate(true);
        let mut file = site.dir.open_with(name, &options)?;
        file.write_all(content.as_bytes())?;
        file.flush()?;
        set_mode(file.as_raw_fd(), 0o644)?;
        let _ = uid;
        Ok(())
    }

    async fn apply_site(&self, domain: &str, content: &str, enable: bool) -> ExecResult<()> {
        let filename = format!("{domain}.conf");
        let path = self.cfg.nginx_sites_dir.join(&filename);
        let link = self.cfg.nginx_enabled_dir.join(&filename);
        let previous = std::fs::read_to_string(&path).ok();
        let previous_link = std::fs::symlink_metadata(&link).is_ok();

        write_managed(
            &self.cfg.nginx_sites_dir,
            &path,
            content,
            0o644,
            Some((0, 0)),
        )?;
        std::fs::create_dir_all(&self.cfg.nginx_enabled_dir)?;
        if link.exists() || std::fs::symlink_metadata(&link).is_ok() {
            let _ = std::fs::remove_file(&link);
        }
        if enable {
            std::os::unix::fs::symlink(&path, &link)
                .map_err(|e| ExecError::Io(format!("symlink {}: {e}", link.display())))?;
        }

        if let Err(err) = self.nginx_test().await {
            let _ = std::fs::remove_file(&link);
            match &previous {
                Some(old) => {
                    let _ =
                        write_managed(&self.cfg.nginx_sites_dir, &path, old, 0o644, Some((0, 0)));
                }
                None => {
                    let _ = std::fs::remove_file(&path);
                }
            }
            if previous_link {
                let _ = std::os::unix::fs::symlink(&path, &link);
            }
            return Err(err);
        }
        self.reload_service("nginx").await
    }

    async fn remove_site(&self, domain: &str) -> ExecResult<()> {
        let filename = format!("{domain}.conf");
        let link = self.cfg.nginx_enabled_dir.join(&filename);
        let _ = std::fs::remove_file(&link);
        let _ = remove_managed(
            &self.cfg.nginx_sites_dir,
            &self.cfg.nginx_sites_dir.join(&filename),
        );
        if self.nginx_test().await.is_ok() {
            self.reload_service("nginx").await.ok();
        }
        Ok(())
    }

    async fn apply_php_pool(
        &self,
        username: &str,
        version: &str,
        content: &str,
        _memory_limit_mb: u64,
        _max_children: u16,
        enable: bool,
    ) -> ExecResult<()> {
        let uid = User::from_name(username)
            .map_err(|err| ExecError::Io(err.to_string()))?
            .ok_or_else(|| ExecError::MissingAccount(username.to_string()))?
            .uid
            .as_raw();
        let fpm_dir = self.cfg.php_fpm_root.join(version).join("fpm");
        if !fpm_dir.is_dir() {
            return Err(ExecError::NotFound(format!(
                "PHP {version} FPM is not installed ({})",
                fpm_dir.display()
            )));
        }
        let conf_dir = fpm_dir.join("rynxcp");
        std::fs::create_dir_all(&conf_dir)?;
        std::fs::create_dir_all(&self.cfg.php_socket_dir)?;
        let conf_path = conf_dir.join(format!("rynx-{username}.conf"));
        let unit_name = format!("rynx-php-{username}.service");
        let unit_path = self.cfg.systemd_dir.join(&unit_name);
        let legacy_pool = fpm_dir.join("pool.d").join(format!("rynx-{username}.conf"));
        let legacy_exists = legacy_pool.exists();
        let legacy_removed =
            legacy_exists && remove_managed(&self.cfg.php_fpm_root, &legacy_pool).is_ok();

        if !enable {
            let _ = run("systemctl", &["disable", "--now", &unit_name]).await;
            let _ = remove_managed(&self.cfg.php_fpm_root, &conf_path);
            let _ = remove_managed(&self.cfg.systemd_dir, &unit_path);
            let _ = run("systemctl", &["daemon-reload"]).await;
            if legacy_removed {
                let _ = self.reload_service(&format!("php{version}-fpm")).await;
            }
            return Ok(());
        }

        let conf_changed = std::fs::read_to_string(&conf_path)
            .map(|existing| existing != content)
            .unwrap_or(true);
        let unit_changed = std::fs::read_to_string(&unit_path)
            .map(|existing| existing != php_fpm_unit(version, &conf_path, uid))
            .unwrap_or(true);
        write_managed(
            &self.cfg.php_fpm_root,
            &conf_path,
            content,
            0o644,
            Some((0, 0)),
        )?;
        let unit = php_fpm_unit(version, &conf_path, uid);
        write_managed(
            &self.cfg.systemd_dir,
            &unit_path,
            &unit,
            0o644,
            Some((0, 0)),
        )?;
        let php = self.php_binary(version);
        run(&php, &["-t", "-y", &conf_path.display().to_string()]).await?;
        run("systemctl", &["daemon-reload"]).await?;
        run("systemctl", &["enable", &unit_name]).await?;
        if conf_changed || unit_changed {
            run("systemctl", &["restart", &unit_name]).await?;
        } else if run("systemctl", &["is-active", "--quiet", &unit_name])
            .await
            .is_err()
        {
            run("systemctl", &["start", &unit_name]).await?;
        }
        if legacy_removed {
            let _ = self.reload_service(&format!("php{version}-fpm")).await;
        }
        Ok(())
    }

    async fn remove_php_pool(&self, username: &str, version: &str) -> ExecResult<()> {
        let fpm_dir = self.cfg.php_fpm_root.join(version).join("fpm");
        let conf_path = fpm_dir.join("rynxcp").join(format!("rynx-{username}.conf"));
        let legacy_pool = fpm_dir.join("pool.d").join(format!("rynx-{username}.conf"));
        let unit_name = format!("rynx-php-{username}.service");
        let unit_path = self.cfg.systemd_dir.join(&unit_name);
        let _ = run("systemctl", &["disable", "--now", &unit_name]).await;
        let legacy_exists = legacy_pool.exists();
        let legacy_removed =
            legacy_exists && remove_managed(&self.cfg.php_fpm_root, &legacy_pool).is_ok();
        let _ = remove_managed(&self.cfg.php_fpm_root, &conf_path);
        let _ = remove_managed(&self.cfg.systemd_dir, &unit_path);
        let _ = run("systemctl", &["daemon-reload"]).await;
        if legacy_removed {
            let _ = self.reload_service(&format!("php{version}-fpm")).await;
        }
        Ok(())
    }

    async fn ensure_app_dir(&self, username: &str, uid: u32, dir: &Path) -> ExecResult<()> {
        let home = self.home(username);
        if !dir.starts_with(&home) {
            return Err(ExecError::Unsupported(
                "application directory escapes the account home".into(),
            ));
        }
        let relative = dir.strip_prefix(&home).map_err(|_| {
            ExecError::InvalidInput("application directory escapes the account home".into())
        })?;
        let account_home = open_account_home(&self.cfg, username, false)?;
        let gid = self.gid_for(username)?;
        ensure_dir_components(&account_home, relative, 0o750, uid, gid)
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
        let gid = self.gid_for(&spec.username)?;
        std::fs::create_dir_all(&self.cfg.app_env_dir)?;
        write_managed(
            &self.cfg.app_env_dir,
            &self.cfg.app_env_dir.join(env_filename),
            env_content,
            0o640,
            Some((0, gid)),
        )?;
        write_managed(
            &self.cfg.systemd_dir,
            &self.cfg.systemd_dir.join(unit),
            unit_content,
            0o644,
            Some((0, 0)),
        )?;
        run("systemctl", &["daemon-reload"]).await?;

        if enable {
            run("systemctl", &["enable", unit]).await?;
            if let Err(err) = run("systemctl", &["restart", unit]).await {
                tracing::warn!(unit, error = %err, "application unit failed to start; desired state kept");
            }
        } else if let Err(err) = run("systemctl", &["disable", "--now", unit]).await {
            tracing::warn!(unit, error = %err, "could not disable application unit");
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
        let _ = run("systemctl", &["disable", "--now", unit]).await;
        let _ = remove_managed(&self.cfg.systemd_dir, &self.cfg.systemd_dir.join(unit));
        let _ = remove_managed(
            &self.cfg.app_env_dir,
            &self.cfg.app_env_dir.join(env_filename),
        );
        let _ = run("systemctl", &["daemon-reload"]).await;
        if purge && working_dir.starts_with(self.home(username)) {
            let _ = std::fs::remove_dir_all(working_dir);
        }
        Ok(())
    }

    async fn installer_apply(
        &self,
        spec: &InstallerApplySpec,
        archive: Option<&Path>,
    ) -> ExecResult<String> {
        let home = self.home(&spec.username);
        let docroot = home.join(&spec.docroot);
        let owner = User::from_name(&spec.username)
            .map_err(|err| ExecError::Io(err.to_string()))?
            .ok_or_else(|| ExecError::MissingAccount(spec.username.clone()))?;
        reset_docroot(&home, &docroot, &owner)?;
        self.ensure_docroot(&spec.username, owner.uid.as_raw(), &docroot)
            .await?;
        let php = format!("php{}", spec.php_version);
        let web_gid = User::from_name("www-data")
            .ok()
            .flatten()
            .map(|user| user.gid);

        match spec.app {
            InstallerApp::Wordpress => {
                let archive = archive.ok_or_else(|| {
                    ExecError::InvalidInput("the WordPress archive is missing".into())
                })?;
                // Read the staged archive as root, then write it into the
                // account home with the account's filesystem identity. This
                // works with restricted homes and NFS root-squash.
                let data = std::fs::read(archive).map_err(|err| {
                    ExecError::Io(format!("cannot read {}: {err}", archive.display()))
                })?;
                let staged = home.join(format!(".rynxcp-installer-{}.tar.gz", random_hex(8)));
                {
                    let _identity = switch_fs_identity(owner.uid.as_raw(), owner.gid.as_raw())?;
                    std::fs::write(&staged, &data).map_err(|err| {
                        ExecError::Io(format!(
                            "cannot copy the installer archive to {}: {err}",
                            staged.display()
                        ))
                    })?;
                    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o600))
                        .map_err(|err| {
                            ExecError::Io(format!("cannot chmod {}: {err}", staged.display()))
                        })?;
                }
                let args = vec![
                    "-xzf".to_string(),
                    staged.display().to_string(),
                    "-C".to_string(),
                    docroot.display().to_string(),
                    "--strip-components=1".to_string(),
                    "--no-same-owner".to_string(),
                    "--no-same-permissions".to_string(),
                ];
                let extracted = run_as_user(&spec.username, &home, &docroot, "tar", &args).await;
                if let Ok(_identity) = switch_fs_identity(owner.uid.as_raw(), owner.gid.as_raw()) {
                    let _ = std::fs::remove_file(&staged);
                }
                extracted?;
                let config = wordpress_config(spec);
                write_owned_file(
                    &docroot.join("wp-config.php"),
                    config.as_bytes(),
                    owner.uid,
                    owner.gid,
                )?;
                let args = vec![
                    "/usr/local/bin/wp".to_string(),
                    "core".to_string(),
                    "install".to_string(),
                    format!("--path={}", docroot.display()),
                    format!(
                        "--url={}://{}",
                        if spec.tls { "https" } else { "http" },
                        spec.domain
                    ),
                    format!("--title={}", spec.site_title),
                    format!("--admin_user={}", spec.admin_user),
                    format!("--admin_password={}", spec.admin_password),
                    format!("--admin_email={}", spec.admin_email),
                    "--skip-email".to_string(),
                ];
                run_as_user(&spec.username, &home, &docroot, &php, &args).await?;
                if let Some(gid) = web_gid {
                    grant_web_read(&docroot, gid)?;
                }
            }
            InstallerApp::Laravel => {
                let composer = if Path::new("/usr/bin/composer").exists() {
                    "/usr/bin/composer"
                } else {
                    "/usr/local/bin/composer"
                };
                let args = vec![
                    composer.to_string(),
                    "create-project".to_string(),
                    "laravel/laravel".to_string(),
                    docroot.display().to_string(),
                    "--no-interaction".to_string(),
                    "--prefer-dist".to_string(),
                    "--no-progress".to_string(),
                ];
                run_as_user(&spec.username, &home, &home, &php, &args).await?;
                let env = laravel_env(spec);
                write_owned_file(&docroot.join(".env"), env.as_bytes(), owner.uid, owner.gid)?;
                let args = vec![
                    "artisan".to_string(),
                    "migrate".to_string(),
                    "--force".to_string(),
                ];
                run_as_user(&spec.username, &home, &docroot, &php, &args).await?;
                if let Some(gid) = web_gid {
                    grant_web_read(&docroot.join("public"), gid)?;
                }
            }
            InstallerApp::Joomla => {
                let archive = archive.ok_or_else(|| {
                    ExecError::InvalidInput("the Joomla archive is missing".into())
                })?;
                let staged = stage_installer_archive(&home, archive, &owner)?;
                let args = vec![
                    "-xzf".to_string(),
                    staged.display().to_string(),
                    "-C".to_string(),
                    docroot.display().to_string(),
                    "--no-same-owner".to_string(),
                    "--no-same-permissions".to_string(),
                ];
                let extracted = run_as_user(&spec.username, &home, &docroot, "tar", &args).await;
                let _ = std::fs::remove_file(&staged);
                extracted?;
                let args = vec![
                    "installation/joomla.php".to_string(),
                    "install".to_string(),
                    format!("--site-name={}", spec.site_title),
                    format!("--admin-user={}", spec.site_title),
                    format!("--admin-username={}", spec.admin_user),
                    format!("--admin-password={}", spec.admin_password),
                    format!("--admin-email={}", spec.admin_email),
                    "--db-type=mysqli".to_string(),
                    "--db-host=localhost".to_string(),
                    format!("--db-user={}", spec.db_user),
                    format!("--db-pass={}", spec.db_password),
                    format!("--db-name={}", spec.database),
                    "--db-prefix=rynx_".to_string(),
                    "--db-encryption=0".to_string(),
                    "--no-interaction".to_string(),
                ];
                run_as_user(&spec.username, &home, &docroot, &php, &args).await?;
                if let Some(gid) = web_gid {
                    grant_web_read(&docroot, gid)?;
                }
            }
            InstallerApp::Grav => {
                let archive = archive
                    .ok_or_else(|| ExecError::InvalidInput("the Grav archive is missing".into()))?;
                let staged = stage_installer_archive(&home, archive, &owner)?;
                let unpack = home.join(format!(".rynxcp-unpack-{}", random_hex(8)));
                {
                    let _identity = switch_fs_identity(owner.uid.as_raw(), owner.gid.as_raw())?;
                    std::fs::create_dir_all(&unpack)?;
                }
                let args = vec![
                    "-q".to_string(),
                    staged.display().to_string(),
                    "-d".to_string(),
                    unpack.display().to_string(),
                ];
                let extracted = run_as_user(&spec.username, &home, &home, "unzip", &args).await;
                let _ = std::fs::remove_file(&staged);
                extracted?;
                let source = unpack.join("grav-admin");
                let args = vec![
                    "-a".to_string(),
                    format!("{}/.", source.display()),
                    docroot.display().to_string(),
                ];
                let copied = run_as_user(&spec.username, &home, &home, "cp", &args).await;
                let _ = std::fs::remove_dir_all(&unpack);
                copied?;
                let args = vec![
                    "bin/plugin".to_string(),
                    "login".to_string(),
                    "new-user".to_string(),
                    "-u".to_string(),
                    spec.admin_user.clone(),
                    "-p".to_string(),
                    spec.admin_password.clone(),
                    "-e".to_string(),
                    spec.admin_email.clone(),
                    "-l".to_string(),
                    "en".to_string(),
                    "-P".to_string(),
                    "b".to_string(),
                    "-N".to_string(),
                    spec.site_title.clone(),
                    "-t".to_string(),
                    "Site Administrator".to_string(),
                ];
                run_as_user(&spec.username, &home, &docroot, &php, &args).await?;
                if let Some(gid) = web_gid {
                    grant_web_read(&docroot, gid)?;
                }
            }
            InstallerApp::Mediawiki => {
                let archive = archive.ok_or_else(|| {
                    ExecError::InvalidInput("the MediaWiki archive is missing".into())
                })?;
                let staged = stage_installer_archive(&home, archive, &owner)?;
                let args = vec![
                    "-xzf".to_string(),
                    staged.display().to_string(),
                    "-C".to_string(),
                    docroot.display().to_string(),
                    "--strip-components=1".to_string(),
                    "--no-same-owner".to_string(),
                    "--no-same-permissions".to_string(),
                ];
                let extracted = run_as_user(&spec.username, &home, &docroot, "tar", &args).await;
                let _ = std::fs::remove_file(&staged);
                extracted?;
                let scheme = if spec.tls { "https" } else { "http" };
                let args = vec![
                    "maintenance/run.php".to_string(),
                    "install".to_string(),
                    "--dbtype=mysql".to_string(),
                    "--dbserver=localhost".to_string(),
                    format!("--dbname={}", spec.database),
                    format!("--dbuser={}", spec.db_user),
                    format!("--dbpass={}", spec.db_password),
                    format!("--server={scheme}://{}", spec.domain),
                    "--scriptpath=".to_string(),
                    "--lang=en".to_string(),
                    format!("--pass={}", spec.admin_password),
                    format!("--confpath={}", docroot.display()),
                    spec.site_title.clone(),
                    spec.admin_user.clone(),
                ];
                run_as_user(&spec.username, &home, &docroot, &php, &args).await?;
                if let Some(gid) = web_gid {
                    grant_web_read(&docroot, gid)?;
                }
            }
        }
        Ok(format!("{} installed", spec.app.as_str()))
    }

    async fn issue_cert(
        &self,
        domain: &str,
        domains: &[String],
        email: &str,
        webroot: &Path,
        staging: bool,
    ) -> ExecResult<()> {
        std::fs::create_dir_all(webroot)?;
        let webroot_s = webroot.display().to_string();
        let mut args = vec![
            "certonly".to_string(),
            "--cert-name".into(),
            domain.to_string(),
            "--webroot".into(),
            "-w".into(),
            webroot_s,
        ];
        let mut names = vec![domain.to_string()];
        for name in domains {
            if !names.iter().any(|existing| existing == name) {
                names.push(name.clone());
            }
        }
        for name in &names {
            args.push("-d".into());
            args.push(name.clone());
        }
        args.extend([
            "--non-interactive".into(),
            "--agree-tos".into(),
            "-m".into(),
            email.to_string(),
            "--keep-until-expiring".into(),
            "--expand".into(),
        ]);
        if staging {
            args.push("--staging".into());
        }
        run_owned(&self.cfg.certbot_bin, &args).await?;
        self.reload_service("nginx").await.ok();
        Ok(())
    }

    async fn renew_certs(&self, staging: bool) -> ExecResult<()> {
        let mut args = vec![
            "renew".to_string(),
            "--quiet".into(),
            "--non-interactive".into(),
        ];
        if staging {
            args.push("--staging".into());
        }
        run_owned(&self.cfg.certbot_bin, &args).await?;
        self.reload_service("nginx").await.ok();
        Ok(())
    }

    async fn remove_cert(&self, domain: &str) -> ExecResult<()> {
        let _ = run(
            &self.cfg.certbot_bin,
            &["delete", "--cert-name", domain, "--non-interactive"],
        )
        .await;
        Ok(())
    }

    async fn cert_info(&self, domain: &str) -> ExecResult<Option<CertView>> {
        let dir = self.cfg.certs_root.join(domain);
        let cert_path = dir.join("fullchain.pem");
        if !cert_path.exists() {
            return Ok(None);
        }
        let path_s = cert_path.display().to_string();
        let output = run(
            "openssl",
            &["x509", "-in", &path_s, "-noout", "-enddate", "-issuer"],
        )
        .await?;

        let mut issuer = "unknown".to_string();
        let mut not_after_raw = String::new();
        for line in output.lines() {
            if let Some(value) = line.strip_prefix("issuer=") {
                issuer = value.trim().to_string();
            }
            if let Some(value) = line.strip_prefix("notAfter=") {
                not_after_raw = value.trim().to_string();
            }
        }

        let parsed = parse_openssl_date(&not_after_raw);
        let (not_after, status) = match parsed {
            Some(date) => {
                let days = (date - OffsetDateTime::now_utc()).whole_days();
                let status = if days < 0 {
                    CertificateStatus::Expired
                } else if days < 30 {
                    CertificateStatus::Expiring
                } else {
                    CertificateStatus::Active
                };
                (
                    date.format(&Rfc3339)
                        .unwrap_or_else(|_| not_after_raw.clone()),
                    status,
                )
            }
            None => (not_after_raw, CertificateStatus::Active),
        };

        Ok(Some(CertView {
            domain: domain.to_string(),
            issuer,
            not_after,
            status,
            path: dir.display().to_string(),
        }))
    }

    async fn status_unit(&self, unit: &str) -> ExecResult<UnitStatus> {
        let output = run(
            "systemctl",
            &[
                "show",
                unit,
                "--no-pager",
                "-p",
                "ActiveState",
                "-p",
                "SubState",
                "-p",
                "MainPID",
                "-p",
                "MemoryCurrent",
                "-p",
                "CPUUsageNSec",
                "-p",
                "ActiveEnterTimestampMonotonic",
            ],
        )
        .await?;

        let mut map = std::collections::HashMap::new();
        for line in output.lines() {
            if let Some((key, value)) = line.split_once('=') {
                map.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
        let active_state = map
            .get("ActiveState")
            .cloned()
            .unwrap_or_else(|| "unknown".into());
        let sub_state = map.get("SubState").cloned().unwrap_or_default();
        let pid = map
            .get("MainPID")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);
        let memory_raw = map
            .get("MemoryCurrent")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        let memory_kb = if memory_raw > (1u64 << 60) {
            0
        } else {
            memory_raw / 1024
        };
        let cpu_ns = map
            .get("CPUUsageNSec")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        let active_us = map
            .get("ActiveEnterTimestampMonotonic")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        let boot_secs = std::fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|raw| raw.split_whitespace().next()?.parse::<f64>().ok())
            .unwrap_or(0.0) as u64;
        let started_secs = active_us / 1_000_000;
        let uptime_secs = if started_secs > 0 && active_us > 0 && boot_secs > started_secs {
            boot_secs - started_secs
        } else {
            0
        };
        let cpu_percent = if uptime_secs > 0 {
            ((cpu_ns as f64) / (uptime_secs as f64 * 1_000_000_000.0) * 100.0) as f32
        } else {
            0.0
        };

        Ok(UnitStatus {
            active: active_state == "active",
            state: format!("{active_state} ({sub_state})"),
            pid,
            memory_kb,
            cpu_percent,
            uptime_secs,
        })
    }

    async fn restart_unit(&self, unit: &str) -> ExecResult<()> {
        run("systemctl", &["restart", unit]).await.map(|_| ())
    }

    async fn reload_unit(&self, unit: &str) -> ExecResult<()> {
        run("systemctl", &["reload-or-restart", unit])
            .await
            .map(|_| ())
    }

    async fn set_unit_running(&self, unit: &str, running: bool) -> ExecResult<()> {
        let action = if running { "start" } else { "stop" };
        run("systemctl", &[action, unit]).await.map(|_| ())
    }

    async fn journal_unit(&self, unit: &str, lines: u32) -> ExecResult<String> {
        let lines = lines.clamp(10, 500).to_string();
        run(
            "journalctl",
            &["-u", unit, "-n", &lines, "--no-pager", "--output=short-iso"],
        )
        .await
    }

    async fn disk_usage(&self) -> ExecResult<String> {
        run("df", &["-h"]).await
    }

    async fn nginx_test_text(&self) -> ExecResult<String> {
        let args: Vec<String> = self
            .cfg
            .nginx_test_args
            .split_whitespace()
            .map(str::to_string)
            .collect();
        run_combined("nginx", &args).await
    }

    async fn create_backup(&self, paths: &[String], dest: &Path) -> ExecResult<u64> {
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let dest_s = dest.display().to_string();
        let mut args = vec!["-czf".to_string(), dest_s, "-C".into(), "/".into()];
        for path in paths {
            let relative = path.trim_start_matches('/');
            if !relative.is_empty() {
                args.push(relative.to_string());
            }
        }
        run_owned("tar", &args).await?;
        Ok(std::fs::metadata(dest)?.len())
    }

    async fn restore_backup(&self, archive: &Path, username: &str, uid: u32) -> ExecResult<()> {
        let archive_s = archive.display().to_string();
        let listing = run("tar", &["-tzf", &archive_s]).await?;
        let allowed = [
            format!("home/{username}/"),
            "etc/nginx/sites-available/rynxcp/".to_string(),
            "etc/bind/zones/".to_string(),
            "etc/php/".to_string(),
            "etc/systemd/system/rynxcp-".to_string(),
            "etc/rynxcp/apps/".to_string(),
        ];
        for entry in listing.lines() {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            if entry.starts_with('/') || entry.split('/').any(|part| part == "..") {
                return Err(ExecError::Unsupported(format!(
                    "backup entry escapes its root: {entry}"
                )));
            }
            if !allowed.iter().any(|prefix| entry.starts_with(prefix)) {
                return Err(ExecError::Unsupported(format!(
                    "backup entry is outside managed paths: {entry}"
                )));
            }
        }
        run(
            "tar",
            &[
                "-xzf",
                &archive_s,
                "-C",
                "/",
                "--no-same-owner",
                "--no-same-permissions",
            ],
        )
        .await?;

        let home = self.home(username);
        let gid = self.gid_for(username)?;
        if home.exists() {
            let home_s = home.display().to_string();
            run("chown", &["-R", &format!("{uid}:{gid}"), &home_s]).await?;
        }
        Ok(())
    }

    async fn repair_backup_permissions(&self, path: &Path) -> ExecResult<()> {
        use std::os::unix::fs::PermissionsExt;

        let Some(user) = User::from_name("rynx").ok().flatten() else {
            return Ok(());
        };
        let _ =
            std::fs::set_permissions(&self.cfg.backup_dir, std::fs::Permissions::from_mode(0o755));
        if let Some(parent) = path.parent() {
            let _ = chown(parent, Some(Uid::from_raw(0)), Some(user.gid));
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o750));
        }
        if path.exists() {
            let _ = chown(path, Some(Uid::from_raw(0)), Some(user.gid));
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640))?;
        }
        Ok(())
    }

    async fn offsite_backup(&self, path: &Path, tag: &str) -> ExecResult<bool> {
        if !self.cfg.offsite_enabled {
            return Ok(false);
        }
        let repository = self.cfg.offsite_repository.trim();
        if repository.is_empty() || repository.chars().any(|ch| ch.is_control()) {
            return Err(ExecError::InvalidInput(
                "offsite_repository is required and must be a single value".into(),
            ));
        }
        let password_file = self
            .cfg
            .offsite_password_file
            .as_ref()
            .filter(|path| !path.as_os_str().is_empty())
            .ok_or_else(|| ExecError::InvalidInput("offsite_password_file is required".into()))?;
        let meta = std::fs::metadata(password_file).map_err(|err| {
            ExecError::Io(format!("cannot read {}: {err}", password_file.display()))
        })?;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(ExecError::InvalidInput(
                "offsite_password_file must not be readable by other users".into(),
            ));
        }
        let bin = {
            let value = self.cfg.restic_bin.trim();
            if value.is_empty() {
                "restic"
            } else {
                value
            }
        };
        let mut envs = vec![
            ("RESTIC_REPOSITORY".into(), repository.to_string()),
            (
                "RESTIC_PASSWORD_FILE".into(),
                password_file.display().to_string(),
            ),
        ];
        if let Some(env_file) = self
            .cfg
            .offsite_env_file
            .as_ref()
            .filter(|path| !path.as_os_str().is_empty())
        {
            envs.extend(read_restic_env(env_file)?);
        }
        let mut snapshots = vec!["snapshots".to_string(), "--no-cache".to_string()];
        if run_with_env(bin, &snapshots, &envs).await.is_err() {
            snapshots = vec!["init".to_string()];
            run_with_env(bin, &snapshots, &envs).await?;
        }
        let backup = vec![
            "backup".to_string(),
            path.display().to_string(),
            "--tag".to_string(),
            tag.to_string(),
            "--no-cache".to_string(),
        ];
        run_with_env(bin, &backup, &envs).await?;
        Ok(true)
    }

    async fn copy_site_tree(&self, username: &str, source: &str, target: &str) -> ExecResult<()> {
        validate_relative_path(source)?;
        validate_relative_path(target)?;
        let home = self.home(username);
        let source = home.join(source);
        let target = home.join(target);
        if !source.starts_with(&home) || !target.starts_with(&home) || source == target {
            return Err(ExecError::InvalidInput(
                "clone paths escape the account home".into(),
            ));
        }
        let owner = User::from_name(username)
            .map_err(|err| ExecError::Io(err.to_string()))?
            .ok_or_else(|| ExecError::MissingAccount(username.to_string()))?;
        let _identity = switch_fs_identity(owner.uid.as_raw(), owner.gid.as_raw())?;
        copy_tree(&source, &target)
    }

    async fn clone_database(&self, source: &str, target: &str) -> ExecResult<()> {
        let dump = run(
            "mariadb-dump",
            &[
                "--protocol=socket",
                "-uroot",
                "--single-transaction",
                "--routines",
                "--triggers",
                source,
            ],
        )
        .await?;
        run_with_stdin(
            &self.cfg.mysql_bin,
            &["--protocol=socket", "-uroot", target],
            &dump,
        )
        .await?;
        Ok(())
    }

    async fn rewrite_clone_config(
        &self,
        username: &str,
        root: &str,
        old_db: &str,
        old_password: &str,
        new_db: &str,
        new_password: &str,
    ) -> ExecResult<bool> {
        validate_relative_path(root)?;
        let home = self.home(username);
        let root = home.join(root);
        if !root.starts_with(&home) {
            return Err(ExecError::InvalidInput(
                "clone config escapes the account home".into(),
            ));
        }
        let owner = User::from_name(username)
            .map_err(|err| ExecError::Io(err.to_string()))?
            .ok_or_else(|| ExecError::MissingAccount(username.to_string()))?;
        let _identity = switch_fs_identity(owner.uid.as_raw(), owner.gid.as_raw())?;
        let mut rewritten = false;
        let wordpress = root.join("wp-config.php");
        if wordpress.is_file() {
            let content = std::fs::read_to_string(&wordpress)?;
            let updated = content
                .replace(old_db, new_db)
                .replace(old_password, new_password);
            std::fs::write(&wordpress, updated)?;
            rewritten = true;
        }
        let env = root.join(".env");
        if env.is_file() {
            let content = std::fs::read_to_string(&env)?;
            let mut lines = Vec::new();
            for line in content.lines() {
                if line.starts_with("DB_DATABASE=") {
                    lines.push(format!("DB_DATABASE={new_db}"));
                } else if line.starts_with("DB_USERNAME=") {
                    lines.push(format!("DB_USERNAME={new_db}"));
                } else if line.starts_with("DB_PASSWORD=") {
                    lines.push(format!("DB_PASSWORD={new_password}"));
                } else if line.starts_with("DB_HOST=") {
                    lines.push("DB_HOST=localhost".to_string());
                } else {
                    lines.push(line.to_string());
                }
            }
            std::fs::write(&env, format!("{}\n", lines.join("\n")))?;
            rewritten = true;
        }
        Ok(rewritten)
    }

    async fn read_log_tail(&self, path: &Path, lines: u32) -> ExecResult<String> {
        let mut file = std::fs::File::open(path)?;
        let length = file.metadata()?.len();
        file.seek(SeekFrom::Start(length.saturating_sub(256 * 1024)))?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        let text = String::from_utf8_lossy(&data);
        let all: Vec<&str> = text.lines().collect();
        let limit = lines.clamp(1, 500) as usize;
        let start = all.len().saturating_sub(limit);
        Ok(all[start..].join("\n"))
    }

    async fn mail_queue(&self) -> ExecResult<Vec<MailQueueEntry>> {
        let output = run("postqueue", &["-j"]).await.unwrap_or_default();
        let mut entries = Vec::new();
        for line in output.lines() {
            let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let id = value
                .get("queue_id")
                .and_then(|item| item.as_str())
                .unwrap_or_default();
            if id.is_empty() {
                continue;
            }
            let recipients = value
                .get("recipients")
                .and_then(|item| item.as_array())
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.get("address").and_then(|address| address.as_str()))
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            entries.push(MailQueueEntry {
                id: id.to_string(),
                size: value
                    .get("message_size")
                    .and_then(|item| item.as_u64())
                    .unwrap_or(0),
                arrival: value
                    .get("arrival_time")
                    .and_then(|item| item.as_i64())
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
                sender: value
                    .get("sender")
                    .and_then(|item| item.as_str())
                    .unwrap_or_default()
                    .to_string(),
                recipients,
                status: value
                    .get("queue_name")
                    .and_then(|item| item.as_str())
                    .unwrap_or("active")
                    .to_string(),
            });
        }
        Ok(entries)
    }

    async fn mail_queue_action(&self, action: &str, id: Option<&str>) -> ExecResult<()> {
        match action {
            "flush" => {
                run("postqueue", &["-f"]).await?;
            }
            "delete" => {
                let id = id.unwrap_or_default();
                run("postsuper", &["-d", id]).await?;
            }
            "hold" => {
                let id = id.unwrap_or_default();
                run("postsuper", &["-h", id]).await?;
            }
            "release" => {
                let id = id.unwrap_or_default();
                run("postsuper", &["-H", id]).await?;
            }
            _ => {
                return Err(ExecError::InvalidInput("invalid mail queue action".into()));
            }
        }
        Ok(())
    }

    async fn delete_backup_file(&self, path: &Path) -> ExecResult<()> {
        let root = std::fs::canonicalize(&self.cfg.backup_dir)
            .unwrap_or_else(|_| self.cfg.backup_dir.clone());
        let Ok(target) = std::fs::canonicalize(path) else {
            return Ok(());
        };
        if !target.starts_with(&root) {
            return Err(ExecError::Unsupported(
                "refusing to delete a file outside the backup directory".into(),
            ));
        }
        std::fs::remove_file(target)?;
        Ok(())
    }

    async fn remove_backup_dir(&self, username: &str) -> ExecResult<()> {
        let dir = self.cfg.backup_dir.join(username);
        if dir.starts_with(&self.cfg.backup_dir) && dir.exists() {
            let _ = std::fs::remove_dir_all(dir);
        }
        Ok(())
    }

    async fn apply_cron(&self, username: &str, content: &str) -> ExecResult<()> {
        let dir = Path::new("/etc/cron.d");
        std::fs::create_dir_all(dir)?;
        let path = dir.join(format!("rynxcp-{username}"));
        if content.trim().is_empty() {
            if !path.exists() {
                return Ok(());
            }
            let _ = std::fs::remove_file(&path);
        } else {
            if std::fs::read_to_string(&path).ok().as_deref() == Some(content) {
                return Ok(());
            }
            write_managed(dir, &path, content, 0o644, Some((0, 0)))?;
        }
        let _ = self.reload_unit("cron").await;
        Ok(())
    }

    async fn apply_zone(&self, domain: &str, content: &str) -> ExecResult<()> {
        std::fs::create_dir_all(&self.cfg.bind_zones_dir)?;
        let path = self.cfg.bind_zones_dir.join(format!("{domain}.db"));
        write_managed(
            &self.cfg.bind_zones_dir,
            &path,
            content,
            0o644,
            Some((0, 0)),
        )?;
        let path_s = path.display().to_string();
        let check = vec![domain.to_string(), path_s];
        run_combined(&self.cfg.bind_checkzone_bin, &check).await?;
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
        let base = self
            .cfg
            .bind_conf_file
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("/etc/bind"));
        write_managed(
            &base,
            &self.cfg.bind_conf_file,
            content,
            0o644,
            Some((0, 0)),
        )?;
        self.reload_unit(&self.cfg.bind_reload_unit).await
    }

    async fn generate_dkim_key(&self, domain: &str, selector: &str) -> ExecResult<String> {
        let dir = self.cfg.dkim_key_dir.join(domain);
        std::fs::create_dir_all(&dir)?;
        let private = dir.join(format!("{selector}.private"));
        let public = dir.join(format!("{selector}.public"));
        let private_s = private.display().to_string();
        let public_s = public.display().to_string();

        run(
            "openssl",
            &[
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                &private_s,
            ],
        )
        .await?;
        run(
            "openssl",
            &["rsa", "-in", &private_s, "-pubout", "-out", &public_s],
        )
        .await?;

        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o600))?;
        std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o644))?;
        if let Ok(Some(user)) = User::from_name("opendkim") {
            chown(&private, Some(user.uid), Some(user.gid))
                .map_err(|err| ExecError::Io(err.to_string()))?;
            chown(&public, Some(user.uid), Some(user.gid))
                .map_err(|err| ExecError::Io(err.to_string()))?;
        }
        let pem = std::fs::read_to_string(&public)?;
        Ok(pem)
    }

    async fn remove_dkim_key(&self, domain: &str) -> ExecResult<()> {
        rynx_core::validate_domain(domain)
            .map_err(|err| ExecError::InvalidInput(err.to_string()))?;
        remove_managed(&self.cfg.dkim_key_dir, &self.cfg.dkim_key_dir.join(domain))
            .map_err(|err| ExecError::Io(err.to_string()))
    }

    async fn hash_mail_password(&self, password: &str) -> ExecResult<String> {
        let input = format!("{password}\n{password}\n");
        let hash = run_with_stdin("doveadm", &["pw", "-s", "SHA512-CRYPT"], &input).await?;
        if !hash.starts_with('{') || hash.len() < 20 {
            return Err(ExecError::Io(
                "doveadm did not return a password hash".into(),
            ));
        }
        Ok(hash)
    }

    async fn sync_mail(
        &self,
        domains: &[MailDomainSpec],
        accounts: &[MailAccountConfig],
    ) -> ExecResult<()> {
        use std::os::unix::fs::PermissionsExt;

        let active_domains: Vec<&MailDomainSpec> =
            domains.iter().filter(|domain| domain.enabled).collect();
        let active_accounts: Vec<&MailAccountConfig> = accounts
            .iter()
            .filter(|account| {
                account.enabled
                    && active_domains
                        .iter()
                        .any(|domain| domain.domain == account.domain)
            })
            .collect();

        for account in &active_accounts {
            let domain_dir = PathBuf::from(VMAIL_ROOT).join(&account.domain);
            self.make_dir(&domain_dir, 0o750, MAIL_UID, MAIL_GID)?;
            let home = domain_dir.join(&account.local_part);
            self.make_dir(&home, 0o700, MAIL_UID, MAIL_GID)?;
            for sub in [
                "Maildir",
                "Maildir/cur",
                "Maildir/new",
                "Maildir/tmp",
                "sieve",
            ] {
                self.make_dir(&home.join(sub), 0o700, MAIL_UID, MAIL_GID)?;
            }
        }

        let mut domain_lines = String::new();
        let mut mailbox_lines = String::new();
        let mut alias_lines = String::new();
        let mut sender_lines = String::new();
        for domain in &active_domains {
            domain_lines.push_str(&format!("{} {}\n", domain.domain, domain.domain));
            if let Some(target) = domain
                .catch_all
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                alias_lines.push_str(&format!("@{} {}\n", domain.domain, target));
            }
        }
        for account in &active_accounts {
            let address = format!("{}@{}", account.local_part, account.domain);
            sender_lines.push_str(&format!("{} {}\n", address, address));
            mailbox_lines.push_str(&format!(
                "{} {}/{}/\n",
                address, account.domain, account.local_part
            ));
            for alias in &account.aliases {
                let alias = alias.trim();
                if !alias.is_empty() {
                    alias_lines.push_str(&format!("{alias} {address}\n"));
                    sender_lines.push_str(&format!("{alias} {address}\n"));
                }
            }
            let forwards: Vec<&str> = account
                .forward_to
                .iter()
                .map(String::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty() && *value != address)
                .collect();
            if !forwards.is_empty() {
                let mut targets = vec![address.as_str()];
                targets.extend(forwards);
                alias_lines.push_str(&format!("{} {}\n", address, targets.join(", ")));
            }
        }

        std::fs::create_dir_all(POSTFIX_MAIL_DIR)?;
        std::fs::create_dir_all(DOVECOT_MAIL_DIR)?;
        std::fs::create_dir_all(MAIL_CERT_DIR)?;

        // The Dovecot auth process runs as the dovecot user and must traverse
        // its configuration directory to read the passwd-file.
        let dovecot_dir = PathBuf::from(DOVECOT_MAIL_DIR);
        let mut dovecot_dir_mode = 0o755;
        if let Some(user) = User::from_name("dovecot").ok().flatten() {
            if chown(&dovecot_dir, Some(Uid::from_raw(0)), Some(user.gid)).is_ok() {
                dovecot_dir_mode = 0o750;
            }
        }
        std::fs::set_permissions(
            &dovecot_dir,
            std::fs::Permissions::from_mode(dovecot_dir_mode),
        )?;
        let domains_path = PathBuf::from(POSTFIX_MAIL_DIR).join("domains");
        let mailboxes_path = PathBuf::from(POSTFIX_MAIL_DIR).join("mailboxes");
        let aliases_path = PathBuf::from(POSTFIX_MAIL_DIR).join("aliases");
        let senders_path = PathBuf::from(POSTFIX_MAIL_DIR).join("senders");
        std::fs::write(&domains_path, &domain_lines)?;
        std::fs::write(&mailboxes_path, &mailbox_lines)?;
        std::fs::write(&aliases_path, &alias_lines)?;
        std::fs::write(&senders_path, &sender_lines)?;
        for path in [&domains_path, &mailboxes_path, &aliases_path, &senders_path] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))?;
        }

        let dovecot_v24 = dovecot_is_v24().await;

        let mut users = String::from("# managed-by: RYNXCP\n");
        let mut sni = String::new();
        let mut dovecot = if dovecot_v24 {
            String::from(
                "                 # managed-by: RYNXCP\n\
                 # Dovecot 2.4 configuration.\n\
                 dovecot_config_version = 2.4.0\n\
                 dovecot_storage_version = 2.4.0\n\
                 protocols = imap pop3 lmtp sieve\n\
                 mail_driver = maildir\n\
                 mail_home = /var/vmail/%{user | domain}/%{user | username}\n\
                 mail_path = /var/vmail/%{user | domain}/%{user | username}/Maildir\n\
                 mail_inbox_path = /var/vmail/%{user | domain}/%{user | username}/Maildir\n\
                 mail_uid = 5000\n\
                 mail_gid = 5000\n\
                 first_valid_uid = 5000\n\
                 auth_mechanisms = plain login\n\
                 passdb passwd-file {\n\
                   passwd_file_path = /etc/dovecot/rynxcp/users\n\
                   default_password_scheme = SHA512-CRYPT\n\
                   auth_username_format = %{user}\n\
                 }\n\
                 userdb passwd-file {\n\
                   passwd_file_path = /etc/dovecot/rynxcp/users\n\
                   auth_username_format = %{user}\n\
                 }\n\
                 service auth {\n\
                   unix_listener /var/spool/postfix/private/auth {\n\
                     mode = 0660\n\
                     user = postfix\n\
                     group = postfix\n\
                   }\n\
                 }\n\
                 service lmtp {\n\
                   unix_listener /var/spool/postfix/private/dovecot-lmtp {\n\
                     mode = 0600\n\
                     user = postfix\n\
                     group = postfix\n\
                   }\n\
                 }\n\
                 mail_plugins {\n\
                   quota = yes\n\
                 }\n\
                 protocol lmtp {\n\
                   auth_username_format = %{user}\n\
                   mail_plugins {\n\
                     sieve = yes\n\
                   }\n\
                 }\n\
                 protocol imap {\n\
                   mail_plugins {\n\
                     imap_quota = yes\n\
                   }\n\
                 }\n\
                 quota \"User quota\" {\n\
                 }\n\
                 sieve_script personal {\n\
                   driver = file\n\
                   path = /var/vmail/%{user | domain}/%{user | username}/sieve\n\
                   active_path = /var/vmail/%{user | domain}/%{user | username}/sieve/roundcube.sieve\n\
                 }\n\
                 ssl = required\n\
                 ssl_server_cert_file = /etc/ssl/rynxcp/mail/default.crt\n\
                 ssl_server_key_file = /etc/ssl/rynxcp/mail/default.key\n",
            )
        } else {
            String::from(
                "# managed-by: RYNXCP\n\
                 # Dovecot 2.3 configuration.\n\
                 protocols = imap pop3 lmtp sieve\n\
                 mail_location = maildir:/var/vmail/%d/%n/Maildir\n\
                 mail_uid = 5000\n\
                 mail_gid = 5000\n\
                 first_valid_uid = 5000\n\
                 auth_mechanisms = plain login\n\
                 passdb {\n\
                   driver = passwd-file\n\
                   args = scheme=SHA512-CRYPT username_format=%u /etc/dovecot/rynxcp/users\n\
                 }\n\
                 userdb {\n\
                   driver = passwd-file\n\
                   args = username_format=%u /etc/dovecot/rynxcp/users\n\
                 }\n\
                 service auth {\n\
                   unix_listener /var/spool/postfix/private/auth {\n\
                     mode = 0660\n\
                     user = postfix\n\
                     group = postfix\n\
                   }\n\
                 }\n\
                 service lmtp {\n\
                   unix_listener /var/spool/postfix/private/dovecot-lmtp {\n\
                     mode = 0600\n\
                     user = postfix\n\
                     group = postfix\n\
                   }\n\
                 }\n\
                 protocol lmtp {\n\
                   auth_username_format = %u\n\
                   mail_plugins = $mail_plugins quota sieve\n\
                 }\n\
                 protocol imap { mail_plugins = $mail_plugins quota }\n\
                 protocol pop3 { mail_plugins = $mail_plugins quota }\n\
                 plugin {\n\
                   quota = maildir:User quota\n\
                   sieve = /var/vmail/%d/%n/sieve/roundcube.sieve\n\
                   sieve_dir = /var/vmail/%d/%n/sieve\n\
                 }\n\
                 ssl = required\n\
                 ssl_cert = </etc/ssl/rynxcp/mail/default.crt\n\
                 ssl_key = </etc/ssl/rynxcp/mail/default.key\n",
            )
        };
        for account in &active_accounts {
            let home = format!("{}/{}/{}", VMAIL_ROOT, account.domain, account.local_part);
            if dovecot_v24 {
                users.push_str(&format!(
                    "{}@{}:{}:{}:{}::{}::userdb_quota_storage_size={}M\n",
                    account.local_part,
                    account.domain,
                    account.password_hash,
                    MAIL_UID,
                    MAIL_GID,
                    home,
                    account.quota_mb
                ));
            } else {
                users.push_str(&format!(
                    "{}@{}:{}:{}:{}::{}::userdb_quota_rule=*:storage={}M\n",
                    account.local_part,
                    account.domain,
                    account.password_hash,
                    MAIL_UID,
                    MAIL_GID,
                    home,
                    account.quota_mb
                ));
            }
        }
        for domain in &active_domains {
            let cert_dir = self
                .cfg
                .certs_root
                .join(format!("webmail.{}", domain.domain));
            let chain = cert_dir.join("fullchain.pem");
            let key = cert_dir.join("privkey.pem");
            if !chain.exists() || !key.exists() {
                continue;
            }
            let combined = PathBuf::from(MAIL_CERT_DIR).join(format!("{}.pem", domain.domain));
            let mut pem = std::fs::read(&key)?;
            pem.extend(std::fs::read(&chain)?);
            std::fs::write(&combined, pem)?;
            std::fs::set_permissions(&combined, std::fs::Permissions::from_mode(0o640))?;
            if let Some(user) = User::from_name("postfix").ok().flatten() {
                let _ = chown(&combined, Some(Uid::from_raw(0)), Some(user.gid));
            }
            for prefix in [
                "mail",
                "webmail",
                "imap",
                "smtp",
                "pop",
                "autodiscover",
                "autoconfig",
            ] {
                let name = format!("{prefix}.{}", domain.domain);
                sni.push_str(&format!("{} {}\n", name, combined.display()));
                if dovecot_v24 {
                    dovecot.push_str(&format!(
                        "local_name {name} {{\n  ssl_server_cert_file = {}\n  ssl_server_key_file = {}\n}}\n",
                        chain.display(),
                        key.display()
                    ));
                } else {
                    dovecot.push_str(&format!(
                        "local_name {name} {{\n  ssl_cert = <{}\n  ssl_key = <{}\n}}\n",
                        chain.display(),
                        key.display()
                    ));
                }
            }
        }
        let users_path = PathBuf::from(DOVECOT_MAIL_DIR).join("users");
        std::fs::write(&users_path, users)?;
        std::fs::set_permissions(&users_path, std::fs::Permissions::from_mode(0o640))?;
        let dovecot_owner = User::from_name("dovecot").ok().flatten();
        if let Some(user) = dovecot_owner {
            let _ = chown(&users_path, Some(Uid::from_raw(0)), Some(user.gid));
        }
        std::fs::write(DOVECOT_MAIL_CONF, dovecot)?;
        std::fs::set_permissions(DOVECOT_MAIL_CONF, std::fs::Permissions::from_mode(0o644))?;

        let sni_path = PathBuf::from(POSTFIX_MAIL_DIR).join("sni");
        if sni.is_empty() {
            let default_pem = PathBuf::from(MAIL_CERT_DIR).join("default.pem");
            if default_pem.exists() {
                sni.push_str(&format!("default.invalid {}\n", default_pem.display()));
            }
        }
        std::fs::write(&sni_path, sni)?;
        std::fs::set_permissions(&sni_path, std::fs::Permissions::from_mode(0o640))?;
        if let Some(user) = User::from_name("postfix").ok().flatten() {
            let _ = chown(&sni_path, Some(Uid::from_raw(0)), Some(user.gid));
        }

        for map in [&domains_path, &mailboxes_path, &aliases_path, &senders_path] {
            run("postmap", &[&format!("hash:{}", map.display())]).await?;
        }
        run("postmap", &["-F", &format!("hash:{}", sni_path.display())]).await?;
        run("postfix", &["check"]).await?;
        run("doveconf", &["-n"]).await?;
        self.reload_mail().await
    }

    async fn remove_mailbox(&self, domain: &str, local_part: &str) -> ExecResult<()> {
        let path = PathBuf::from(VMAIL_ROOT).join(domain).join(local_part);
        if !path.starts_with(VMAIL_ROOT) {
            return Err(ExecError::Io("mailbox path escapes vmail root".into()));
        }
        match std::fs::remove_dir_all(&path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(ExecError::Io(err.to_string())),
        }
    }

    async fn remove_mail_domain(&self, domain: &str) -> ExecResult<()> {
        let path = PathBuf::from(VMAIL_ROOT).join(domain);
        if !path.starts_with(VMAIL_ROOT) {
            return Err(ExecError::Io("mail domain path escapes vmail root".into()));
        }
        match std::fs::remove_dir_all(&path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(ExecError::Io(err.to_string())),
        }
    }

    async fn reload_mail(&self) -> ExecResult<()> {
        self.reload_service("postfix").await?;
        self.reload_service("dovecot").await?;
        Ok(())
    }

    async fn repair_dkim_key_permissions(&self) -> ExecResult<()> {
        use std::os::unix::fs::PermissionsExt;

        let root = &self.cfg.dkim_key_dir;
        if !root.is_dir() {
            return Ok(());
        }
        let owner = User::from_name("opendkim").ok().flatten();
        if let Some(user) = &owner {
            let _ = chown(root, Some(user.uid), Some(user.gid));
        }
        let _ = std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o750));
        for entry in std::fs::read_dir(root)? {
            let dir = entry?.path();
            if !std::fs::symlink_metadata(&dir)?.file_type().is_dir() {
                continue;
            }
            if let Some(user) = &owner {
                let _ = chown(&dir, Some(user.uid), Some(user.gid));
            }
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750));
            for entry in std::fs::read_dir(&dir)? {
                let path = entry?.path();
                if !std::fs::symlink_metadata(&path)?.file_type().is_file() {
                    continue;
                }
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default();
                let mode = if name.ends_with(".private") {
                    0o600
                } else if name.ends_with(".public") {
                    0o644
                } else {
                    continue;
                };
                if let Some(user) = &owner {
                    let _ = chown(&path, Some(user.uid), Some(user.gid));
                }
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode));
            }
        }
        Ok(())
    }

    async fn write_dkim_tables(&self, keytable: &str, signingtable: &str) -> ExecResult<()> {
        let owner = User::from_name("opendkim").ok().flatten();
        if let Some(path) = &self.cfg.opendkim_keytable {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, merge_dkim_table(path, keytable))?;
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640));
            if let Some(user) = &owner {
                let _ = chown(path, Some(user.uid), Some(user.gid));
            }
        }
        if let Some(path) = &self.cfg.opendkim_signingtable {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, merge_dkim_table(path, signingtable))?;
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640));
            if let Some(user) = &owner {
                let _ = chown(path, Some(user.uid), Some(user.gid));
            }
        }
        let _ = self.reload_unit("opendkim").await;
        Ok(())
    }

    async fn create_database(&self, database: &str, user: &str, password: &str) -> ExecResult<()> {
        let sql = format!(
            "CREATE DATABASE IF NOT EXISTS `{database}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\
             CREATE USER IF NOT EXISTS '{user}'@'localhost' IDENTIFIED BY '{password}';\
             ALTER USER '{user}'@'localhost' IDENTIFIED BY '{password}';\
             GRANT ALL PRIVILEGES ON `{database}`.* TO '{user}'@'localhost';\
             FLUSH PRIVILEGES;"
        );
        run(
            &self.cfg.mysql_bin,
            &["--protocol=socket", "-uroot", "-e", &sql],
        )
        .await
        .map(|_| ())
    }

    async fn drop_database(&self, database: &str, user: &str) -> ExecResult<()> {
        let sql = format!(
            "DROP DATABASE IF EXISTS `{database}`; DROP USER IF EXISTS '{user}'@'localhost'; FLUSH PRIVILEGES;"
        );
        run(
            &self.cfg.mysql_bin,
            &["--protocol=socket", "-uroot", "-e", &sql],
        )
        .await
        .map(|_| ())
    }

    async fn apply_ftp_user(
        &self,
        login: &str,
        uid: u32,
        gid: u32,
        home: &Path,
        password: &str,
    ) -> ExecResult<()> {
        std::fs::create_dir_all(home)?;
        let passwd_file = self.cfg.pure_passwd.display().to_string();
        let _ = run(
            &self.cfg.pure_pw_bin,
            &["userdel", login, "-f", &passwd_file],
        )
        .await;

        let mut command = tokio::process::Command::new(&self.cfg.pure_pw_bin);
        command
            .args([
                "useradd",
                login,
                "-u",
                &uid.to_string(),
                "-g",
                &gid.to_string(),
                "-d",
                &home.display().to_string(),
                "-f",
                &passwd_file,
            ])
            .env_clear()
            .env("PATH", SAFE_PATH)
            .env("LC_ALL", "C")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|e| ExecError::Command {
            program: self.cfg.pure_pw_bin.clone(),
            args: format!("useradd {login}"),
            status: -1,
            stderr: e.to_string(),
        })?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(password.as_bytes()).await?;
            stdin.write_all(b"\n").await?;
            stdin.write_all(password.as_bytes()).await?;
            stdin.write_all(b"\n").await?;
            stdin.flush().await?;
        }
        let output = child.wait_with_output().await?;
        if !output.status.success() {
            return Err(ExecError::Command {
                program: self.cfg.pure_pw_bin.clone(),
                args: format!("useradd {login}"),
                status: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            });
        }

        let pdb = self.cfg.pure_pdb.display().to_string();
        run_owned(
            &self.cfg.pure_pw_bin,
            &["mkdb".to_string(), pdb, "-f".into(), passwd_file],
        )
        .await?;
        let auth_dir = Path::new("/etc/pure-ftpd/auth");
        std::fs::create_dir_all(auth_dir)?;
        let auth_link = auth_dir.join("10puredb");
        if std::fs::symlink_metadata(&auth_link).is_err() {
            let _ = std::os::unix::fs::symlink("/etc/pure-ftpd/conf/PureDB", &auth_link);
        }
        let _ = self.reload_unit(&self.cfg.pure_ftpd_unit).await;
        Ok(())
    }

    async fn apply_ftp_certificate(&self, domain: &str) -> ExecResult<()> {
        use std::os::unix::fs::PermissionsExt;

        let conf = Path::new("/etc/pure-ftpd/conf");
        if !conf.is_dir() {
            return Ok(());
        }
        let cert_dir = self.cfg.certs_root.join(domain);
        let chain = cert_dir.join("fullchain.pem");
        let key = cert_dir.join("privkey.pem");
        if !chain.exists() || !key.exists() {
            return Ok(());
        }
        let target = Path::new("/etc/ssl/private/pure-ftpd.pem");
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut pem = std::fs::read(&chain)?;
        pem.extend(std::fs::read(&key)?);
        std::fs::write(target, pem)?;
        std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o600))?;
        // The Debian wrapper does not understand CertFile; the compiled-in
        // bundle path above is the only supported location.
        let _ = std::fs::remove_file(conf.join("CertFile"));
        std::fs::write(conf.join("TLS"), "1\n")?;
        self.reload_service("pure-ftpd").await
    }

    async fn remove_ftp_user(&self, login: &str) -> ExecResult<()> {
        let passwd_file = self.cfg.pure_passwd.display().to_string();
        let _ = run(
            &self.cfg.pure_pw_bin,
            &["userdel", login, "-f", &passwd_file],
        )
        .await;
        let pdb = self.cfg.pure_pdb.display().to_string();
        let _ = run_owned(
            &self.cfg.pure_pw_bin,
            &["mkdb".to_string(), pdb, "-f".into(), passwd_file],
        )
        .await;
        Ok(())
    }

    async fn apply_firewall(&self, ruleset: &str) -> ExecResult<()> {
        std::fs::create_dir_all(&self.cfg.state_dir)?;
        let path = self.cfg.state_dir.join("firewall.nft");
        std::fs::write(&path, ruleset)?;
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        let path_s = path.display().to_string();
        run(&self.cfg.nft_bin, &["-f", &path_s]).await.map(|_| ())
    }

    async fn fail2ban_bans(&self) -> ExecResult<Vec<(String, String)>> {
        let mut bans = Vec::new();
        for jail in self.fail2ban_jails().await? {
            let output = match run("fail2ban-client", &["status", jail.as_str()]).await {
                Ok(output) => output,
                Err(_) => continue,
            };
            for line in output.lines() {
                let Some((_, list)) = line.split_once("Banned IP list:") else {
                    continue;
                };
                for ip in list.split_whitespace() {
                    if rynx_core::validate_ip_or_cidr(ip).is_ok() {
                        bans.push((jail.clone(), ip.to_string()));
                    }
                }
            }
        }
        Ok(bans)
    }

    async fn fail2ban_unban(&self, ip: &str) -> ExecResult<()> {
        rynx_core::validate_ip_or_cidr(ip)
            .map_err(|err| ExecError::InvalidInput(format!("invalid IP address: {err}")))?;
        for jail in self.fail2ban_jails().await? {
            let output = match run("fail2ban-client", &["status", jail.as_str()]).await {
                Ok(output) => output,
                Err(_) => continue,
            };
            let banned = output.lines().any(|line| {
                line.split_once("Banned IP list:")
                    .is_some_and(|(_, list)| list.split_whitespace().any(|value| value == ip))
            });
            if banned {
                let _ = run("fail2ban-client", &["set", jail.as_str(), "unbanip", ip]).await;
            }
        }
        Ok(())
    }

    async fn resolve_user_ids(&self, username: &str) -> ExecResult<Option<(u32, u32)>> {
        match User::from_name(username) {
            Ok(Some(user)) => Ok(Some((user.uid.as_raw(), user.gid.as_raw()))),
            Ok(None) => Ok(None),
            Err(e) => Err(ExecError::Io(e.to_string())),
        }
    }

    async fn php_versions(&self) -> ExecResult<Vec<String>> {
        let mut versions = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&self.cfg.php_fpm_root) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.chars().next().is_some_and(|ch| ch.is_ascii_digit())
                    && name.chars().all(|ch| ch.is_ascii_digit() || ch == '.')
                {
                    versions.push(name);
                }
            }
        }
        versions.sort_by(|a, b| b.cmp(a));
        Ok(versions)
    }

    async fn installed_programs(&self) -> ExecResult<Vec<ProgramInfo>> {
        async fn probe(program: &str, args: &[&str]) -> Option<String> {
            run_combined(
                program,
                &args.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            )
            .await
            .ok()
            .and_then(|output| {
                output
                    .lines()
                    .map(str::trim)
                    .find(|line| !line.is_empty())
                    .map(|line| line.to_string())
            })
        }

        async fn package_version(package: &str) -> Option<String> {
            run("dpkg-query", &["-W", "-f=${Version}", package])
                .await
                .ok()
                .map(|version| version.trim().to_string())
                .filter(|version| !version.is_empty())
        }

        async fn probe_or_package(program: &str, package: &str) -> Option<String> {
            match probe(program, &["--version"]).await {
                Some(version) => Some(version),
                None => package_version(package).await,
            }
        }

        let mut out = Vec::new();
        let mut push = |name: &str, kind: &str, version: Option<String>, detail: &str| {
            let installed = version.is_some();
            out.push(ProgramInfo {
                name: name.to_string(),
                version: version.unwrap_or_else(|| "unknown".into()),
                kind: kind.to_string(),
                status: if installed { "installed" } else { "missing" }.into(),
                detail: detail.to_string(),
                unit: rynx_core::service_unit_for_program(name),
                service_status: None,
            });
        };

        push(
            "nginx",
            "web",
            probe("nginx", &["-v"]).await,
            "reverse proxy",
        );
        if let Ok(entries) = std::fs::read_dir(&self.cfg.php_fpm_root) {
            let mut versions: Vec<String> = entries
                .flatten()
                .filter(|entry| entry.path().is_dir())
                .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
                .filter(|name| name.chars().next().is_some_and(|c| c.is_ascii_digit()))
                .collect();
            versions.sort();
            for version in versions {
                let binary = format!("php{version}");
                let found = probe(&binary, &["-v"]).await;
                push(&format!("php{version}"), "runtime", found, "PHP-FPM");
            }
        }
        push(
            "node",
            "runtime",
            probe("node", &["--version"]).await,
            "systemd apps",
        );
        push(
            "python3",
            "runtime",
            probe("python3", &["--version"]).await,
            "gunicorn/uvicorn",
        );
        push(
            "ruby",
            "runtime",
            probe("ruby", &["--version"]).await,
            "puma",
        );
        push(
            "java",
            "runtime",
            probe("java", &["-version"]).await,
            "JAR apps",
        );
        push(
            "dotnet",
            "runtime",
            probe("dotnet", &["--version"]).await,
            "ASP.NET apps",
        );
        push(
            "go",
            "runtime",
            probe("go", &["version"]).await,
            "compiled binaries",
        );
        push(
            "mariadb",
            "database",
            probe("mariadb", &["--version"]).await,
            "per-domain databases",
        );
        push(
            "bind9",
            "dns",
            probe("named", &["-v"]).await,
            "authoritative DNS",
        );
        push(
            "certbot",
            "security",
            probe("certbot", &["--version"]).await,
            "Let's Encrypt",
        );
        push(
            "pure-ftpd",
            "web",
            probe("pure-ftpd", &["-v"]).await,
            "FTPS virtual users",
        );
        push(
            "opendkim",
            "mail",
            probe("opendkim", &["-V"]).await,
            "DKIM signing",
        );
        push(
            "fail2ban",
            "security",
            probe("fail2ban-client", &["--version"]).await,
            "brute-force jail",
        );
        push(
            "clamav",
            "security",
            probe("clamscan", &["--version"]).await,
            "antivirus engine",
        );
        push(
            "clamav-milter",
            "security",
            probe_or_package("clamav-milter", "clamav-milter").await,
            "SMTP antivirus",
        );
        push(
            "spamassassin",
            "mail",
            probe("spamassassin", &["--version"]).await,
            "spam scoring",
        );
        push(
            "spamass-milter",
            "mail",
            probe_or_package("spamass-milter", "spamass-milter").await,
            "SMTP antispam",
        );
        push(
            "rynxcp",
            "panel",
            Some(format!("v{}", rynx_proto::DAEMON_VERSION)),
            "control plane",
        );
        for program in &mut out {
            if let Some(unit) = program.unit.clone() {
                program.service_status = probe(
                    "systemctl",
                    &["show", "-p", "ActiveState", "--value", unit.as_str()],
                )
                .await;
            }
        }
        Ok(out)
    }

    async fn available_updates(&self) -> ExecResult<Vec<PackageUpdate>> {
        let output = run("apt", &["list", "--upgradable"]).await?;
        let mut updates = Vec::new();
        for line in output.lines().skip(1) {
            let line = line.trim();
            if line.is_empty() || !line.contains('/') {
                continue;
            }
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 3 {
                continue;
            }
            let package = fields[0].split('/').next().unwrap_or_default().to_string();
            if package.is_empty() {
                continue;
            }
            let candidate = fields[1].trim_end_matches(',').to_string();
            let current = line
                .split("upgradable from:")
                .nth(1)
                .map(|value| value.trim().trim_end_matches(']').to_string())
                .unwrap_or_default();
            let security = fields[0].contains("security") || line.contains("-security");
            updates.push(PackageUpdate {
                package,
                current_version: current,
                candidate_version: candidate,
                security,
            });
        }
        updates.sort_by(|a, b| a.package.cmp(&b.package));
        Ok(updates)
    }

    async fn apply_updates(&self) -> ExecResult<String> {
        let mut combined = String::new();
        for args in [
            vec!["update"],
            vec![
                "-y",
                "-o",
                "Dpkg::Options::=--force-confdef",
                "-o",
                "Dpkg::Options::=--force-confold",
                "upgrade",
            ],
        ] {
            let output = tokio::process::Command::new("apt-get")
                .args(&args)
                .env_clear()
                .env("PATH", SAFE_PATH)
                .env("LC_ALL", "C")
                .env("DEBIAN_FRONTEND", "noninteractive")
                .output()
                .await
                .map_err(|e| ExecError::Command {
                    program: "apt-get".into(),
                    args: args.join(" "),
                    status: -1,
                    stderr: e.to_string(),
                })?;
            combined.push_str(&String::from_utf8_lossy(&output.stdout));
            combined.push_str(&String::from_utf8_lossy(&output.stderr));
            if !output.status.success() {
                return Err(ExecError::Command {
                    program: "apt-get".into(),
                    args: args.join(" "),
                    status: output.status.code().unwrap_or(-1),
                    stderr: combined,
                });
            }
        }
        Ok(combined)
    }

    async fn system_info(&self) -> ExecResult<SystemInfo> {
        let hostname = read_trim("/proc/sys/kernel/hostname").unwrap_or_else(|| "unknown".into());
        let kernel = read_trim("/proc/sys/kernel/osrelease").unwrap_or_else(|| "unknown".into());
        let os = std::fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|raw| {
                raw.lines()
                    .find(|line| line.starts_with("PRETTY_NAME="))
                    .map(|line| {
                        line.trim_start_matches("PRETTY_NAME=")
                            .trim_matches('"')
                            .to_string()
                    })
            })
            .unwrap_or_else(|| "Linux".into());
        let uptime_secs = std::fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|raw| raw.split_whitespace().next()?.parse::<f64>().ok())
            .unwrap_or(0.0) as u64;
        let load = std::fs::read_to_string("/proc/loadavg")
            .ok()
            .map(|raw| {
                let mut values = [0u32; 3];
                for (idx, part) in raw.split_whitespace().take(3).enumerate() {
                    values[idx] = (part.parse::<f64>().unwrap_or(0.0) * 100.0).round() as u32;
                }
                values
            })
            .unwrap_or([0, 0, 0]);

        let (mem_total_kb, mem_available_kb) = read_meminfo();
        let (disk_total_kb, disk_available_kb) = read_disk().await.unwrap_or((0, 0));

        Ok(SystemInfo {
            hostname,
            primary_ip: self
                .cfg
                .default_ipv4
                .clone()
                .or_else(|| self.cfg.default_ipv6.clone()),
            ssh_port: self.cfg.firewall_ssh_port,
            os,
            kernel,
            uptime_secs,
            load,
            cpu_count: std::thread::available_parallelism()
                .map(|n| n.get() as u32)
                .unwrap_or(1),
            mem_total_kb,
            mem_available_kb,
            disk_total_kb,
            disk_available_kb,
            daemon_version: rynx_proto::DAEMON_VERSION.into(),
            mode: "linux".into(),
        })
    }

    async fn uid_in_use(&self, uid: u32) -> ExecResult<bool> {
        Ok(User::from_uid(Uid::from_raw(uid))
            .map_err(|e| ExecError::Io(e.to_string()))?
            .is_some())
    }
}

fn read_trim(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn read_meminfo() -> (u64, u64) {
    let raw = match std::fs::read_to_string("/proc/meminfo") {
        Ok(raw) => raw,
        Err(_) => return (0, 0),
    };
    let mut total = 0u64;
    let mut available = 0u64;
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total = rest
                .split_whitespace()
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
        }
        if let Some(rest) = line.strip_prefix("MemAvailable:") {
            available = rest
                .split_whitespace()
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
        }
    }
    (total, available)
}

async fn read_disk() -> Option<(u64, u64)> {
    let output = run("df", &["-k", "/"]).await.ok()?;
    let line = output.lines().nth(1)?;
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 4 {
        return None;
    }
    Some((fields[1].parse().ok()?, fields[3].parse().ok()?))
}

fn parse_openssl_date(raw: &str) -> Option<OffsetDateTime> {
    let cleaned = raw.trim().trim_end_matches(" GMT").trim();
    let fmt = format_description!(
        "[month repr:short] [day padding:space] [hour]:[minute]:[second] [year]"
    );
    OffsetDateTime::parse(cleaned, &fmt).ok()
}
