use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::Deserialize;
use tokio_util::io::ReaderStream;

use rynx_proto::{Request, Response as DaemonResponse};

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::scope;
use crate::state::ApiState;

#[derive(Debug, Deserialize)]
pub struct CreateBackup {
    pub username: String,
}

pub async fn list(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
) -> Result<Json<DaemonResponse>, ApiError> {
    let response = state
        .daemon
        .call(Request::BackupList, &auth.user.username)
        .await?;
    let response = scope::list_response(&state, &auth, response).await?;
    Ok(Json(response))
}

pub async fn create(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Json(body): Json<CreateBackup>,
) -> Result<Json<DaemonResponse>, ApiError> {
    auth.require_write()?;
    auth.ensure_account(&body.username)?;
    crate::limits::check_backup(&state, &auth.user.username, &body.username).await?;
    let username = body.username;
    let response = state
        .daemon
        .call(
            Request::BackupCreate {
                username: username.clone(),
            },
            &auth.user.username,
        )
        .await?;
    if let DaemonResponse::Backup { backup } = &response {
        crate::webhooks::dispatch(
            &state,
            "backup.created",
            serde_json::json!({
                "username": username,
                "id": backup.id,
                "size_bytes": backup.size_bytes,
                "path": backup.path,
            }),
        );
    }
    Ok(Json(response))
}

#[derive(Debug, Deserialize)]
pub struct DestinationBody {
    pub kind: String,
    pub repository: String,
    pub password: String,
    pub secret: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

pub async fn destination_get(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Path(account): Path<String>,
) -> Result<Json<DaemonResponse>, ApiError> {
    auth.ensure_account(&account)?;
    let response = state
        .daemon
        .call(
            Request::BackupDestinationGet { username: account },
            &auth.user.username,
        )
        .await?;
    Ok(Json(response))
}

pub async fn destination_put(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Path(account): Path<String>,
    Json(body): Json<DestinationBody>,
) -> Result<Json<DaemonResponse>, ApiError> {
    auth.require_write()?;
    auth.ensure_account(&account)?;
    let response = state
        .daemon
        .call(
            Request::BackupDestinationUpsert(rynx_proto::BackupDestinationSpec {
                username: account.clone(),
                kind: body.kind,
                repository: body.repository,
                password: body.password,
                secret: body.secret,
                enabled: body.enabled,
            }),
            &auth.user.username,
        )
        .await?;
    Ok(Json(response))
}

pub async fn destination_delete(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Path(account): Path<String>,
) -> Result<Json<DaemonResponse>, ApiError> {
    auth.require_write()?;
    auth.ensure_account(&account)?;
    let response = state
        .daemon
        .call(
            Request::BackupDestinationDelete { username: account },
            &auth.user.username,
        )
        .await?;
    Ok(Json(response))
}

pub async fn destination_test(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Path(account): Path<String>,
) -> Result<Json<DaemonResponse>, ApiError> {
    auth.require_write()?;
    auth.ensure_account(&account)?;
    let response = state
        .daemon
        .call(
            Request::BackupDestinationTest { username: account },
            &auth.user.username,
        )
        .await?;
    Ok(Json(response))
}

pub async fn delete(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<Json<DaemonResponse>, ApiError> {
    auth.require_write()?;
    scope::ensure_backup(&state, &auth, &id).await?;
    let response = state
        .daemon
        .call(Request::BackupDelete { id }, &auth.user.username)
        .await?;
    Ok(Json(response))
}

pub async fn download(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    auth.require_write()?;
    scope::ensure_backup(&state, &auth, &id).await?;
    let response = state
        .daemon
        .call(Request::BackupList, &auth.user.username)
        .await?;
    let DaemonResponse::Backups { backups } = response else {
        return Err(ApiError::internal("unexpected daemon response"));
    };
    let backup = backups
        .into_iter()
        .find(|backup| backup.id == id)
        .ok_or_else(|| ApiError::NotFound("backup not found".into()))?;
    let file = tokio::fs::File::open(&backup.path)
        .await
        .map_err(ApiError::internal)?;
    let filename = format!("rynxcp-{}-{}.tar.gz", backup.username, backup.id);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/gzip"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
            .map_err(ApiError::internal)?,
    );
    Ok((headers, Body::from_stream(ReaderStream::new(file))).into_response())
}

pub async fn restore(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<Json<DaemonResponse>, ApiError> {
    auth.require_admin()?;
    auth.require_global()?;
    let response = state
        .daemon
        .call(Request::BackupRestore { id }, &auth.user.username)
        .await?;
    Ok(Json(response))
}
