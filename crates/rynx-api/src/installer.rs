//! One-click web application installers.
//!
//! The API downloads and verifies the archive, creates the website and the
//! database through the daemon, and then asks the daemon to extract and
//! configure the application as the hosting account. Jobs run in the
//! background so the HTTP request does not block on composer.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha1::Digest;
use tokio::sync::Mutex;

use rynx_core::crypto::{random_hex, random_password, sha256_hex};
use rynx_proto::{
    DatabaseView, InstallerApp, InstallerApplySpec, Request, Response as DaemonResponse, Runtime,
    TlsMode, WebsiteSpec,
};

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::state::ApiState;

const JOB_TTL: Duration = Duration::from_secs(30 * 60);
const RUNNING_TTL: Duration = Duration::from_secs(2 * 60 * 60);
const MAX_ARCHIVE: usize = 128 * 1024 * 1024;

#[derive(Debug, Clone, Deserialize)]
pub struct InstallRequest {
    pub username: String,
    pub domain: String,
    pub app: String,
    pub php_version: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub admin_user: String,
    #[serde(default)]
    pub admin_email: String,
    #[serde(default)]
    pub admin_password: String,
    #[serde(default = "default_tls")]
    pub tls: bool,
}

fn default_tls() -> bool {
    true
}

#[derive(Debug, Clone, Serialize)]
pub struct InstallerJobView {
    pub id: String,
    pub domain: String,
    pub app: String,
    pub status: String,
    pub message: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub db_user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub db_password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub db_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_password: Option<String>,
}

pub struct InstallerJob {
    pub view: InstallerJobView,
    pub actor: String,
    pub started: Instant,
    pub finished: Option<Instant>,
}

pub type InstallerJobs = Arc<Mutex<HashMap<String, InstallerJob>>>;

pub fn new_store() -> InstallerJobs {
    Arc::new(Mutex::new(HashMap::new()))
}

struct Prepared {
    website: WebsiteSpec,
    app: InstallerApp,
    php_version: String,
    title: String,
    admin_user: String,
    admin_email: String,
    admin_password: Option<String>,
    owner_email: String,
    tls: bool,
}

pub async fn start(
    state: &ApiState,
    request: InstallRequest,
    auth: &AuthUser,
) -> Result<InstallerJobView, ApiError> {
    auth.require_write()?;
    let app = InstallerApp::parse(&request.app)
        .ok_or_else(|| ApiError::BadRequest("unsupported installer application".into()))?;
    let username = request.username.trim().to_string();
    let domain = request.domain.trim().to_ascii_lowercase();
    rynx_core::validate::validate_username(&username)
        .map_err(|err| ApiError::BadRequest(err.to_string()))?;
    rynx_core::validate::validate_domain(&domain)
        .map_err(|err| ApiError::BadRequest(err.to_string()))?;
    rynx_core::validate::validate_php_version(&request.php_version)
        .map_err(|err| ApiError::BadRequest(err.to_string()))?;
    if request.title.trim().len() > 200 || request.title.chars().any(|ch| ch.is_control()) {
        return Err(ApiError::BadRequest("invalid application title".into()));
    }
    crate::scope::ensure_website_upsert(state, auth, &domain, &username).await?;

    let response = state
        .daemon
        .call(Request::WebsiteList, &auth.user.username)
        .await?;
    let DaemonResponse::Websites { websites } = response else {
        return Err(ApiError::internal("unexpected daemon response"));
    };
    if websites
        .iter()
        .any(|website| website.spec.domain.eq_ignore_ascii_case(&domain))
    {
        return Err(ApiError::Conflict(format!(
            "website '{domain}' already exists; the installer only creates new sites"
        )));
    }

    let website = WebsiteSpec {
        domain: domain.clone(),
        username: username.clone(),
        aliases: Vec::new(),
        runtime: Runtime::Php {
            version: request.php_version.clone(),
        },
        app: None,
        // Every domain/subdomain owns its directory with its own public_html.
        docroot: format!("{domain}/public_html"),
        tls: if request.tls {
            TlsMode::LetsEncrypt
        } else {
            TlsMode::Disabled
        },
        enabled: true,
        force_https: request.tls,
        locale: auth.user.locale.clone(),
    };
    crate::limits::check_website(state, &auth.user.username, &website).await?;

    let title = if request.title.trim().is_empty() {
        domain.clone()
    } else {
        request.title.trim().to_string()
    };
    let (admin_user, admin_email, admin_password) = if app.needs_admin() {
        let mut admin_user = request.admin_user.trim().to_string();
        if admin_user.is_empty() {
            admin_user = "admin".into();
        }
        if app == InstallerApp::Grav {
            admin_user = admin_user.to_ascii_lowercase();
        }
        let user_max = if app == InstallerApp::Grav { 16 } else { 60 };
        if admin_user.len() < 3
            || admin_user.len() > user_max
            || !admin_user
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '@'))
        {
            return Err(ApiError::BadRequest(
                "invalid application administrator user".into(),
            ));
        }
        let admin_email = request.admin_email.trim();
        let admin_email = if admin_email.is_empty() {
            auth.user.email.clone()
        } else {
            admin_email.to_string()
        };
        rynx_core::validate::validate_email(&admin_email)
            .map_err(|err| ApiError::BadRequest(err.to_string()))?;
        let generated = if request.admin_password.trim().is_empty() {
            Some(random_password(20))
        } else {
            None
        };
        let password = generated
            .clone()
            .unwrap_or_else(|| request.admin_password.trim().to_string());
        let password_min = if app == InstallerApp::Joomla { 12 } else { 8 };
        if password.len() < password_min
            || password.len() > 128
            || password.chars().any(|ch| ch.is_control())
        {
            return Err(ApiError::BadRequest(format!(
                "the application administrator password must be {password_min}-128 printable characters"
            )));
        }
        (admin_user, admin_email, generated.or(Some(password)))
    } else {
        (String::new(), String::new(), None)
    };

    let prepared = Prepared {
        website,
        app,
        php_version: request.php_version,
        title,
        admin_user,
        admin_email,
        admin_password: admin_password.clone(),
        owner_email: auth.user.email.clone(),
        tls: request.tls,
    };

    let id = random_hex(12);
    let view = InstallerJobView {
        id: id.clone(),
        domain: domain.clone(),
        app: app.as_str().to_string(),
        status: "running".into(),
        message: "queued".into(),
        url: format!(
            "{}://{}",
            if request.tls { "https" } else { "http" },
            domain
        ),
        database: None,
        db_user: None,
        db_password: None,
        db_host: None,
        admin_user: app.needs_admin().then(|| prepared.admin_user.clone()),
        admin_password: app.needs_admin().then(|| admin_password.clone()).flatten(),
    };
    {
        let mut jobs = state.installer_jobs.lock().await;
        prune(&mut jobs);
        let existing = jobs
            .values()
            .find(|job| {
                job.actor == auth.user.username
                    && job.view.domain == domain
                    && job.finished.is_none()
            })
            .map(|job| job.view.clone());
        if let Some(view) = existing {
            return Ok(view);
        }
        jobs.insert(
            id.clone(),
            InstallerJob {
                view: view.clone(),
                actor: auth.user.username.clone(),
                started: Instant::now(),
                finished: None,
            },
        );
    }

    let state = state.clone();
    let actor = auth.user.username.clone();
    tokio::spawn(async move {
        run_job(state, id, prepared, actor).await;
    });
    Ok(view)
}

pub async fn get(state: &ApiState, id: &str, actor: &str) -> Option<InstallerJobView> {
    let mut jobs = state.installer_jobs.lock().await;
    prune(&mut jobs);
    jobs.get(id)
        .filter(|job| job.actor == actor)
        .map(|job| job.view.clone())
}

async fn run_job(state: ApiState, id: String, prepared: Prepared, actor: String) {
    let domain = prepared.website.domain.clone();
    let mut created_website = false;
    let mut database: Option<DatabaseView> = None;
    let mut archive_path: Option<PathBuf> = None;
    let mut failure: Option<String> = None;
    let mut message = String::new();

    set_step(&state, &id, "creating website", "creating the website").await;
    let result = async {
        state
            .daemon
            .call(Request::WebsiteUpsert(prepared.website.clone()), &actor)
            .await
            .map_err(|err| err.to_string())?;
        created_website = true;

        if prepared.app.needs_database() {
            set_step(&state, &id, "creating database", "creating the database").await;
            crate::limits::check_database(&state, &actor, &domain)
                .await
                .map_err(|err| err.to_string())?;
            let response = state
                .daemon
                .call(
                    Request::DatabaseCreate {
                        domain: domain.clone(),
                        name: format!("{}_{}", prepared.app.as_str(), random_hex(2)),
                    },
                    &actor,
                )
                .await
                .map_err(|err| err.to_string())?;
            let DaemonResponse::Database { database: created } = response else {
                return Err("the daemon did not return the created database".to_string());
            };
            database = Some(created);
        }

        let staged = if prepared.app == InstallerApp::Laravel {
            None
        } else {
            set_step(
                &state,
                &id,
                "downloading",
                &format!("downloading {}", prepared.app.as_str()),
            )
            .await;
            let staged = download_archive(&state, prepared.app).await?;
            archive_path = Some(PathBuf::from(&staged.0));
            Some(staged)
        };

        set_step(&state, &id, "installing", "installing the application").await;
        let apply = InstallerApplySpec {
            username: prepared.website.username.clone(),
            domain: domain.clone(),
            app: prepared.app,
            docroot: prepared.website.docroot.clone(),
            php_version: prepared.php_version.clone(),
            tls: prepared.tls,
            database: database
                .as_ref()
                .map(|db| db.username.clone())
                .unwrap_or_default(),
            db_user: database
                .as_ref()
                .map(|db| db.username.clone())
                .unwrap_or_default(),
            db_password: database
                .as_ref()
                .map(|db| db.password.clone())
                .unwrap_or_default(),
            db_host: "localhost".into(),
            site_title: prepared.title.clone(),
            admin_user: prepared.admin_user.clone(),
            admin_email: prepared.admin_email.clone(),
            admin_password: prepared.admin_password.clone().unwrap_or_default(),
            archive_path: staged.as_ref().map(|item| item.0.clone()),
            archive_sha256: staged.as_ref().map(|item| item.2.clone()),
            archive_size: staged.as_ref().map(|item| item.1).unwrap_or(0),
        };
        let response = state
            .daemon
            .call(Request::InstallerApply(apply), &actor)
            .await
            .map_err(|err| err.to_string())?;
        let DaemonResponse::InstallerResult { message: response } = response else {
            return Err("unexpected daemon response".to_string());
        };
        message = response;

        if prepared.app == InstallerApp::Laravel {
            let mut updated = prepared.website.clone();
            updated.docroot = format!("{}/public", prepared.website.docroot);
            // Laravel keeps the project in <domain>/public_html and serves the
            // public/ subdirectory.
            state
                .daemon
                .call(Request::WebsiteUpsert(updated), &actor)
                .await
                .map_err(|err| err.to_string())?;
        }
        // Request TLS only after the installer has finished writing the app.
        // Running the certificate job concurrently re-renders the website and
        // can recreate a welcome page inside the document root.
        if prepared.tls {
            crate::cert_jobs::start(&state, &domain, &prepared.owner_email, false, &actor).await;
        }
        Ok::<(), String>(())
    }
    .await;

    if let Some(path) = &archive_path {
        let _ = std::fs::remove_file(path);
    }

    if let Err(err) = result {
        failure = Some(err);
        if let Some(db) = &database {
            let _ = state
                .daemon
                .call(Request::DatabaseDelete { id: db.id.clone() }, &actor)
                .await;
        }
        if created_website {
            let _ = state
                .daemon
                .call(Request::WebsiteDelete { domain }, &actor)
                .await;
        }
    }

    let mut jobs = state.installer_jobs.lock().await;
    if let Some(job) = jobs.get_mut(&id) {
        job.finished = Some(Instant::now());
        match failure {
            Some(err) => {
                job.view.status = "failed".into();
                job.view.message = err;
                job.view.admin_password = None;
                tracing::warn!(domain = %job.view.domain, error = %job.view.message, "installer job failed");
            }
            None => {
                job.view.status = "succeeded".into();
                job.view.message = message;
                if let Some(db) = database {
                    job.view.database = Some(db.username.clone());
                    job.view.db_user = Some(db.username);
                    job.view.db_password = Some(db.password);
                    job.view.db_host = Some(db.host);
                }
                tracing::info!(domain = %job.view.domain, "installer job succeeded");
            }
        }
    }
}

async fn set_step(state: &ApiState, id: &str, status: &str, message: &str) {
    let mut jobs = state.installer_jobs.lock().await;
    if let Some(job) = jobs.get_mut(id) {
        job.view.status = status.to_string();
        job.view.message = message.to_string();
    }
}

async fn download_archive(
    state: &ApiState,
    app: InstallerApp,
) -> Result<(String, u64, String), String> {
    let (url, expected_sha256, extension) = match app {
        InstallerApp::Wordpress => ("https://wordpress.org/latest.tar.gz", None, "tar.gz"),
        InstallerApp::Joomla => (
            "https://github.com/joomla/joomla-cms/releases/download/6.2.0/Joomla_6.2.0-Stable-Full_Package.tar.gz",
            Some("f7a4c3962c4a8682f5847ea9d47d2848f6eb475109805935c9e19a5c6511829d"),
            "tar.gz",
        ),
        InstallerApp::Grav => (
            "https://github.com/getgrav/grav/releases/download/2.2.21/grav-admin-v2.2.21.zip",
            Some("948f24ae4fe2ab146197148319ed8a7efa9f9ca0159b2efc3373cde110ac9b53"),
            "zip",
        ),
        InstallerApp::Mediawiki => (
            "https://releases.wikimedia.org/mediawiki/1.45/mediawiki-1.45.3.tar.gz",
            Some("5ea8c1f321c9f8dba4d1ac1e4eca1827fb13519d4a2190e239f51432058a4269"),
            "tar.gz",
        ),
        InstallerApp::Laravel => return Err("Laravel does not use an archive".into()),
    };
    let dir = &state.cfg.installer_staging;
    std::fs::create_dir_all(dir).map_err(|err| {
        format!(
            "cannot create the installer staging directory {}: {err}",
            dir.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o750));
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(300))
        .user_agent("RYNXCP installer")
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|err| err.to_string())?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if !response.status().is_success() {
        return Err(format!(
            "{} download failed with HTTP {}",
            app.as_str(),
            response.status()
        ));
    }
    let bytes = response.bytes().await.map_err(|err| err.to_string())?;
    if bytes.is_empty() || bytes.len() > MAX_ARCHIVE {
        return Err(format!("the {} archive has an invalid size", app.as_str()));
    }
    if let Some(expected) = expected_sha256 {
        let actual = sha256_hex(&bytes);
        if actual != expected {
            return Err(format!(
                "the {} archive checksum did not match",
                app.as_str()
            ));
        }
    } else {
        let checksum = client
            .get("https://wordpress.org/latest.tar.gz.sha1")
            .send()
            .await
            .map_err(|err| err.to_string())?
            .text()
            .await
            .map_err(|err| err.to_string())?;
        let expected = checksum
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let actual = format!("{:x}", sha1::Sha1::digest(&bytes));
        if expected.is_empty() || expected != actual {
            return Err("the WordPress archive checksum did not match".into());
        }
    }
    let path = dir.join(format!("{}-{}.{}", app.as_str(), random_hex(12), extension));
    std::fs::write(&path, &bytes).map_err(|err| {
        format!(
            "cannot write the installer archive to {}: {err}",
            path.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok((
        path.display().to_string(),
        bytes.len() as u64,
        sha256_hex(&bytes),
    ))
}

fn prune(jobs: &mut HashMap<String, InstallerJob>) {
    jobs.retain(|_, job| match job.finished {
        Some(finished) => finished.elapsed() < JOB_TTL,
        None => job.started.elapsed() < RUNNING_TTL,
    });
}

pub fn catalog() -> serde_json::Value {
    serde_json::json!({
        "installers": [
            {
                "app": "wordpress",
                "name": "WordPress",
                "description": "Blog and CMS with database, wp-config and admin account",
                "php": true,
                "database": true
            },
            {
                "app": "laravel",
                "name": "Laravel",
                "description": "PHP framework installed with Composer and public/ document root",
                "php": true,
                "database": true
            },
            {
                "app": "joomla",
                "name": "Joomla",
                "description": "Joomla CMS with database, administrator account and CLI installation",
                "php": true,
                "database": true
            },
            {
                "app": "grav",
                "name": "Grav",
                "description": "Flat-file CMS with Admin plugin and no database",
                "php": true,
                "database": false
            },
            {
                "app": "mediawiki",
                "name": "MediaWiki",
                "description": "MediaWiki wiki with database, LocalSettings and administrator account",
                "php": true,
                "database": true
            }
        ]
    })
}
