use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::routing::{any, delete, get, patch, post, put};
use axum::Router;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;

use crate::state::ApiState;

pub mod accounts;
pub mod agent;
pub mod apps;
pub mod audit_route;
pub mod backups;
pub mod certs;
pub mod console;
pub mod cron;
pub mod databases;
pub mod dns;
pub mod files;
pub mod firewall;
pub mod ftp;
pub mod installer;
pub mod mail;
pub mod monitor;
pub mod packages;
pub mod php;
pub mod programs;
pub mod security;
pub mod session;
pub mod ssh;
pub mod system;
pub mod tokens;
pub mod users;
pub mod websites;

async fn api_not_found() -> crate::error::ApiError {
    crate::error::ApiError::NotFound("API endpoint not found".into())
}

pub fn router(state: ApiState) -> Router {
    let protected = Router::new()
        .route("/api/v1/auth/logout", post(session::logout))
        .route("/api/v1/auth/me", get(session::me))
        .route("/api/v1/auth/locale", put(session::set_locale))
        .route(
            "/api/v1/auth/stop-impersonation",
            post(session::stop_impersonation),
        )
        .route("/api/v1/tokens", get(tokens::list).post(tokens::create))
        .route("/api/v1/tokens/{id}", delete(tokens::revoke))
        .route("/api/v1/sessions", get(tokens::sessions))
        .route("/api/v1/sessions/{id}", delete(tokens::revoke_session))
        .route(
            "/api/v1/sessions/revoke-others",
            post(tokens::revoke_other_sessions),
        )
        .route("/api/v1/users", get(users::list).post(users::create))
        .route(
            "/api/v1/users/{username}/impersonate",
            post(session::impersonate),
        )
        .route(
            "/api/v1/users/{username}",
            patch(users::update).delete(users::delete),
        )
        .route(
            "/api/v1/packages",
            get(packages::list).post(packages::create),
        )
        .route("/api/v1/packages/assignments", get(packages::assignments))
        .route("/api/v1/packages/me", get(packages::mine))
        .route(
            "/api/v1/packages/assignments/{account}",
            patch(packages::update_assignment),
        )
        .route(
            "/api/v1/packages/{id}",
            patch(packages::update).delete(packages::delete),
        )
        .route(
            "/api/v1/accounts",
            get(accounts::list).post(accounts::create),
        )
        .route("/api/v1/accounts/{username}", delete(accounts::delete))
        .route(
            "/api/v1/websites",
            get(websites::list).post(websites::create),
        )
        .route(
            "/api/v1/websites/{domain}/clone",
            post(websites::clone_site),
        )
        .route("/api/v1/websites/{domain}", delete(websites::delete))
        .route("/api/v1/files", get(files::list).delete(files::delete))
        .route("/api/v1/files/read", get(files::read))
        .route("/api/v1/files/write", put(files::write))
        .route("/api/v1/files/mkdir", post(files::mkdir))
        .route("/api/v1/files/upload", post(files::upload))
        .route("/api/v1/files/rename", post(files::rename))
        .route("/api/v1/php/versions", get(php::versions))
        .route("/api/v1/php-pools", get(php::list).post(php::create))
        .route("/api/v1/php-pools/{username}", delete(php::delete))
        .route("/api/v1/apps", get(apps::list).post(apps::create))
        .route("/api/v1/apps/{username}/{name}", delete(apps::delete))
        .route("/api/v1/certs", get(certs::list).post(certs::issue))
        .route("/api/v1/certs/jobs", post(certs::start_job))
        .route("/api/v1/certs/jobs/{id}", get(certs::job_status))
        .route("/api/v1/certs/renew", post(certs::renew))
        .route(
            "/api/v1/mail/domains",
            get(mail::list_domains).post(mail::upsert_domain),
        )
        .route("/api/v1/mail/domains/{domain}", delete(mail::delete_domain))
        .route(
            "/api/v1/mail/domains/{domain}/tls",
            post(mail::issue_domain_tls),
        )
        .route(
            "/api/v1/mail/accounts",
            get(mail::list_accounts).post(mail::upsert_account),
        )
        .route("/api/v1/mail/accounts/{id}", delete(mail::delete_account))
        .route("/api/v1/mail/filters", get(mail::filters))
        .route("/api/v1/backups", get(backups::list).post(backups::create))
        .route("/api/v1/backups/{id}", delete(backups::delete))
        .route("/api/v1/backups/{id}/restore", post(backups::restore))
        .route("/api/v1/backups/{id}/download", get(backups::download))
        .route("/api/v1/cron", get(cron::list).post(cron::upsert))
        .route("/api/v1/cron/{id}", delete(cron::delete))
        .route("/api/v1/dns", get(dns::list))
        .route("/api/v1/dns/{domain}", get(dns::zone))
        .route("/api/v1/dns/{domain}/records", post(dns::upsert_record))
        .route(
            "/api/v1/dns/{domain}/records/{id}",
            delete(dns::delete_record),
        )
        .route("/api/v1/dns/{domain}/mail", post(dns::provision_mail))
        .route(
            "/api/v1/databases",
            get(databases::list).post(databases::create),
        )
        .route("/api/v1/databases/{id}", delete(databases::delete))
        .route("/api/v1/ftp", get(ftp::list).post(ftp::create))
        .route("/api/v1/ftp/{id}", delete(ftp::delete))
        .route("/api/v1/firewall", get(firewall::status))
        .route("/api/v1/firewall/rules", post(firewall::upsert_rule))
        .route("/api/v1/firewall/rules/{id}", delete(firewall::delete_rule))
        .route("/api/v1/firewall/block", post(firewall::block))
        .route("/api/v1/firewall/block/{ip}", delete(firewall::unblock))
        .route("/api/v1/firewall/whitelist", post(firewall::whitelist_add))
        .route(
            "/api/v1/firewall/whitelist/{ip}",
            delete(firewall::whitelist_remove),
        )
        .route("/api/v1/monitor/services", get(monitor::services))
        .route("/api/v1/monitor/history", get(monitor::history))
        .route("/api/v1/agent/findings", get(agent::findings))
        .route(
            "/api/v1/agent/findings/{id}/status",
            post(agent::set_status),
        )
        .route("/api/v1/agent/run", post(agent::run))
        .route("/api/v1/agent/provider/test", post(agent::provider_test))
        .route("/api/v1/installer/catalog", get(installer::catalog))
        .route("/api/v1/installer/install", post(installer::install))
        .route("/api/v1/installer/jobs/{id}", get(installer::job_status))
        .route("/api/v1/ssh", get(ssh::status))
        .route(
            "/api/v1/ssh/keys",
            post(ssh::add_key).delete(ssh::remove_key),
        )
        .route("/api/v1/security/auth-events", get(security::events))
        .route("/api/v1/security/stats", get(security::stats))
        .route("/api/v1/console", post(console::run))
        .route("/api/v1/system/programs", get(programs::programs))
        .route(
            "/api/v1/system/programs/{program}/{action}",
            post(programs::control),
        )
        .route("/api/v1/system/updates", get(programs::updates))
        .route("/api/v1/system/updates/apply", post(programs::apply))
        .route("/api/v1/system", get(system::info))
        .route("/api/v1/system/email", get(system::email_status))
        .route("/api/v1/system/email/test", post(system::email_test))
        .route("/api/v1/audit", get(audit_route::list))
        .route("/api/v1/reconcile", post(system::reconcile))
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            crate::auth::require_auth,
        ));

    let public = Router::new()
        .route("/api/v1/auth/login", post(session::login))
        .route("/api/v1/auth/verify-2fa", post(session::verify_two_factor))
        .route(
            "/api/v1/auth/forgot-password",
            post(session::forgot_password),
        )
        .route("/api/v1/auth/reset-password", post(session::reset_password))
        .route("/api/v1/health", get(system::health))
        .route("/api/v1/meta", get(system::meta))
        .route("/api/v1", get(system::meta));

    let index = state.cfg.web_root.join("index.html");
    if !index.exists() {
        tracing::warn!(path = %index.display(), "web root is missing; UI will not be served");
    }
    let serve = ServeDir::new(&state.cfg.web_root).not_found_service(ServeFile::new(index));

    Router::new()
        .merge(public)
        .merge(protected)
        .route("/api/{*rest}", any(api_not_found))
        .fallback_service(serve)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::security::headers,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
