use axum::extract::State;
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use rynx_proto::{Request, Response as DaemonResponse};

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::state::ApiState;

#[derive(Debug, Deserialize)]
pub struct KeyBody {
    pub key: String,
}

fn account(auth: &AuthUser) -> Result<&str, ApiError> {
    auth.scoped_account().ok_or(ApiError::Forbidden)
}

async fn host(state: &ApiState, actor: &str) -> String {
    if let Ok(DaemonResponse::SystemInfo { info }) =
        state.daemon.call(Request::SystemInfo, actor).await
    {
        if !info.hostname.trim().is_empty() {
            return info.hostname;
        }
    }
    state
        .cfg
        .public_url
        .as_deref()
        .and_then(|url| reqwest::Url::parse(url).ok())
        .and_then(|url| url.host_str().map(str::to_string))
        .unwrap_or_else(|| "localhost".into())
}

pub async fn status(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
) -> Result<Json<Value>, ApiError> {
    let username = account(&auth)?.to_string();
    let keys = match state
        .daemon
        .call(
            Request::SshKeys {
                username: username.clone(),
            },
            &auth.user.username,
        )
        .await?
    {
        DaemonResponse::SshKeys { keys } => keys,
        other => {
            return Err(ApiError::internal(format!(
                "unexpected response: {other:?}"
            )))
        }
    };
    Ok(Json(json!({
        "username": username,
        "host": host(&state, &auth.user.username).await,
        "port": 22,
        "keys": keys,
    })))
}

pub async fn add_key(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Json(body): Json<KeyBody>,
) -> Result<Json<DaemonResponse>, ApiError> {
    auth.require_write()?;
    let username = account(&auth)?.to_string();
    let key = body.key.trim().to_string();
    if key.is_empty() {
        return Err(ApiError::BadRequest(
            "the SSH public key is required".into(),
        ));
    }
    let response = state
        .daemon
        .call(Request::SshKeyAdd { username, key }, &auth.user.username)
        .await?;
    Ok(Json(response))
}

pub async fn remove_key(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Json(body): Json<KeyBody>,
) -> Result<Json<DaemonResponse>, ApiError> {
    auth.require_write()?;
    let username = account(&auth)?.to_string();
    let key = body.key.trim().to_string();
    if key.is_empty() {
        return Err(ApiError::BadRequest(
            "the SSH public key is required".into(),
        ));
    }
    let response = state
        .daemon
        .call(Request::SshKeyDelete { username, key }, &auth.user.username)
        .await?;
    Ok(Json(response))
}
