use axum::extract::{Path, Query, State};
use axum::{Extension, Json};
use serde::Deserialize;

use rynx_proto::{Request, Response as DaemonResponse, TlsMode, WebsiteSpec};

use crate::auth::AuthUser;
use crate::cert_jobs;
use crate::error::ApiError;
use crate::scope;
use crate::state::ApiState;

pub async fn list(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
) -> Result<Json<DaemonResponse>, ApiError> {
    let response = state
        .daemon
        .call(Request::WebsiteList, &auth.user.username)
        .await?;
    let response = scope::list_response(&state, &auth, response).await?;
    Ok(Json(response))
}

pub async fn create(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Json(spec): Json<WebsiteSpec>,
) -> Result<Json<serde_json::Value>, ApiError> {
    auth.require_write()?;
    scope::ensure_website_upsert(&state, &auth, &spec.domain, &spec.username).await?;
    crate::limits::check_website(&state, &auth.user.username, &spec).await?;
    let wants_cert = spec.enabled && spec.tls == TlsMode::LetsEncrypt;
    let domain = spec.domain.clone();
    let response = state
        .daemon
        .call(Request::WebsiteUpsert(spec), &auth.user.username)
        .await?;
    let mut body = serde_json::to_value(&response).map_err(ApiError::internal)?;
    if wants_cert {
        let job = cert_jobs::start(
            &state,
            &domain,
            &auth.user.email,
            false,
            &auth.user.username,
        )
        .await;
        if let Some(object) = body.as_object_mut() {
            object.insert(
                "cert_job".into(),
                serde_json::to_value(job).map_err(ApiError::internal)?,
            );
        }
    }
    Ok(Json(body))
}

pub async fn delete(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Path(domain): Path<String>,
) -> Result<Json<DaemonResponse>, ApiError> {
    auth.require_write()?;
    scope::ensure_domain(&state, &auth, &domain).await?;
    let response = state
        .daemon
        .call(Request::WebsiteDelete { domain }, &auth.user.username)
        .await?;
    Ok(Json(response))
}

#[derive(Debug, Deserialize)]
pub struct CloneRequest {
    pub target: String,
    #[serde(default = "default_true")]
    pub with_database: bool,
}

fn default_true() -> bool {
    true
}

pub async fn clone_site(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Path(domain): Path<String>,
    Json(body): Json<CloneRequest>,
) -> Result<Json<DaemonResponse>, ApiError> {
    auth.require_write()?;
    scope::ensure_domain(&state, &auth, &domain).await?;
    let target = body.target.trim().to_ascii_lowercase();
    rynx_core::validate_domain(&target).map_err(|err| ApiError::BadRequest(err.to_string()))?;
    if target.eq_ignore_ascii_case(&domain) {
        return Err(ApiError::BadRequest(
            "the clone target must be a different domain".into(),
        ));
    }
    let source = scope::website_for_domain(&state, &auth.user.username, &domain).await?;
    scope::ensure_website_upsert(&state, &auth, &target, &source.spec.username).await?;
    let mut spec = source.spec.clone();
    spec.domain = target.clone();
    crate::limits::check_website(&state, &auth.user.username, &spec).await?;
    if body.with_database {
        crate::limits::check_database(&state, &auth.user.username, &domain).await?;
    }
    let response = state
        .daemon
        .call(
            Request::WebsiteClone {
                source: domain,
                target,
                with_database: body.with_database,
            },
            &auth.user.username,
        )
        .await?;
    Ok(Json(response))
}

#[derive(Debug, Deserialize)]
pub struct LogsQuery {
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub lines: Option<u32>,
}

pub async fn logs(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Path(domain): Path<String>,
    Query(query): Query<LogsQuery>,
) -> Result<Json<DaemonResponse>, ApiError> {
    scope::ensure_domain(&state, &auth, &domain).await?;
    let kind = query.kind.unwrap_or_else(|| "access".into());
    let lines = query.lines.unwrap_or(200);
    let response = state
        .daemon
        .call(
            Request::WebsiteLogs {
                domain,
                kind,
                lines,
            },
            &auth.user.username,
        )
        .await?;
    Ok(Json(response))
}
