use axum::extract::{Path, State};
use axum::{Extension, Json};
use serde_json::json;

use rynx_proto::{
    CertificateStatus, MailAccountSpec, MailDomainSpec, Request, Response as DaemonResponse,
};

use crate::auth::AuthUser;
use crate::cert_jobs;
use crate::error::ApiError;
use crate::scope;
use crate::state::ApiState;

pub async fn list_domains(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
) -> Result<Json<DaemonResponse>, ApiError> {
    let response = state
        .daemon
        .call(Request::MailDomainList, &auth.user.username)
        .await?;
    let response = match response {
        DaemonResponse::MailDomains { mut domains } => {
            if let Some(account) = auth.scoped_account() {
                domains.retain(|domain| domain.username == account);
            }
            DaemonResponse::MailDomains { domains }
        }
        other => other,
    };
    Ok(Json(response))
}

pub async fn upsert_domain(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Json(spec): Json<MailDomainSpec>,
) -> Result<Json<serde_json::Value>, ApiError> {
    auth.require_write()?;
    rynx_core::validate_mail_domain_spec(&spec)
        .map_err(|err| ApiError::BadRequest(err.to_string()))?;
    scope::ensure_website_upsert(&state, &auth, &spec.domain, &spec.username).await?;
    crate::limits::check_mail_domain(&state, &auth.user.username, &spec).await?;
    let enabled = spec.enabled;
    let domain_name = spec.domain.clone();
    let response = state
        .daemon
        .call(Request::MailDomainUpsert(spec), &auth.user.username)
        .await?;
    let DaemonResponse::MailDomain { domain } = response else {
        return Err(ApiError::Internal(
            "daemon returned an unexpected mail domain response".into(),
        ));
    };
    let wants_tls = enabled
        && matches!(
            domain.tls_status,
            CertificateStatus::Missing | CertificateStatus::Error | CertificateStatus::Expiring
        );
    let job = if wants_tls {
        Some(
            cert_jobs::start_mail_tls(&state, &domain_name, &auth.user.email, &auth.user.username)
                .await,
        )
    } else {
        None
    };
    Ok(Json(json!({ "domain": domain, "cert_job": job })))
}

pub async fn delete_domain(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Path(domain): Path<String>,
) -> Result<Json<DaemonResponse>, ApiError> {
    auth.require_write()?;
    scope::ensure_domain(&state, &auth, &domain).await?;
    let response = state
        .daemon
        .call(Request::MailDomainDelete { domain }, &auth.user.username)
        .await?;
    Ok(Json(response))
}

pub async fn issue_domain_tls(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Path(domain): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    auth.require_write()?;
    scope::ensure_domain(&state, &auth, &domain).await?;
    let job =
        cert_jobs::start_mail_tls(&state, &domain, &auth.user.email, &auth.user.username).await;
    Ok(Json(json!({ "cert_job": job })))
}

pub async fn list_accounts(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
) -> Result<Json<DaemonResponse>, ApiError> {
    let response = state
        .daemon
        .call(Request::MailAccountList, &auth.user.username)
        .await?;
    let response = match response {
        DaemonResponse::MailAccounts { mut accounts } => {
            if let Some(account) = auth.scoped_account() {
                accounts.retain(|mailbox| mailbox.username == account);
            }
            DaemonResponse::MailAccounts { accounts }
        }
        other => other,
    };
    Ok(Json(response))
}

pub async fn upsert_account(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Json(spec): Json<MailAccountSpec>,
) -> Result<Json<DaemonResponse>, ApiError> {
    auth.require_write()?;
    rynx_core::validate_mail_account_spec(&spec)
        .map_err(|err| ApiError::BadRequest(err.to_string()))?;
    scope::ensure_domain(&state, &auth, &spec.domain).await?;
    crate::limits::check_mail_account(&state, &auth.user.username, &spec).await?;
    let response = state
        .daemon
        .call(Request::MailAccountUpsert(spec), &auth.user.username)
        .await?;
    Ok(Json(response))
}

pub async fn filters(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
) -> Result<Json<serde_json::Value>, ApiError> {
    auth.require_admin()?;
    auth.require_global()?;
    let response = state
        .daemon
        .call(Request::Programs, &auth.user.username)
        .await?;
    let DaemonResponse::Programs { programs } = response else {
        return Err(ApiError::Internal(
            "daemon returned an unexpected programs response".into(),
        ));
    };
    const FILTERS: [&str; 4] = ["clamav", "clamav-milter", "spamassassin", "spamass-milter"];
    let programs: Vec<_> = programs
        .into_iter()
        .filter(|program| FILTERS.contains(&program.name.as_str()))
        .collect();
    let response = state
        .daemon
        .call(Request::FilterActivity { limit: 200 }, &auth.user.username)
        .await?;
    let DaemonResponse::FilterActivity { events } = response else {
        return Err(ApiError::Internal(
            "daemon returned an unexpected filter activity response".into(),
        ));
    };
    Ok(Json(json!({ "programs": programs, "events": events })))
}

pub async fn delete_account(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<Json<DaemonResponse>, ApiError> {
    auth.require_write()?;
    let response = state
        .daemon
        .call(Request::MailAccountList, &auth.user.username)
        .await?;
    let DaemonResponse::MailAccounts { accounts } = response else {
        return Err(ApiError::Internal(
            "daemon returned an unexpected mail account response".into(),
        ));
    };
    let account = accounts
        .into_iter()
        .find(|account| account.id == id)
        .ok_or_else(|| ApiError::NotFound("mailbox not found".into()))?;
    auth.ensure_account(&account.username)?;
    let response = state
        .daemon
        .call(Request::MailAccountDelete { id }, &auth.user.username)
        .await?;
    Ok(Json(response))
}

pub async fn queue(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
) -> Result<Json<DaemonResponse>, ApiError> {
    auth.require_admin()?;
    auth.require_global()?;
    let response = state
        .daemon
        .call(Request::MailQueue, &auth.user.username)
        .await?;
    Ok(Json(response))
}

#[derive(serde::Deserialize)]
pub struct QueueAction {
    pub action: String,
    #[serde(default)]
    pub id: Option<String>,
}

pub async fn queue_action(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Json(body): Json<QueueAction>,
) -> Result<Json<DaemonResponse>, ApiError> {
    auth.require_admin()?;
    auth.require_global()?;
    let response = state
        .daemon
        .call(
            Request::MailQueueAction {
                action: body.action,
                id: body.id,
            },
            &auth.user.username,
        )
        .await?;
    Ok(Json(response))
}
