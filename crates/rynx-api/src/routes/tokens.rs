use axum::extract::{Path, State};
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use rynx_core::crypto::sha256_hex;

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::state::ApiState;

#[derive(Debug, Deserialize)]
pub struct CreateToken {
    #[serde(default)]
    pub name: String,
}

pub async fn list(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
) -> Result<Json<Value>, ApiError> {
    let tokens = state.db.list_api_tokens(&auth.user.id)?;
    Ok(Json(json!({ "tokens": tokens })))
}

pub async fn create(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Json(body): Json<CreateToken>,
) -> Result<Json<Value>, ApiError> {
    let name = if body.name.trim().is_empty() {
        "API token".to_string()
    } else {
        body.name
    };
    let (token, view) = state.db.create_api_token(&auth.user.id, &name)?;
    Ok(Json(json!({ "token": token, "api_token": view })))
}

pub async fn revoke(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let removed = state.db.revoke_api_token(&auth.user.id, &id)?;
    if !removed {
        return Err(ApiError::NotFound("API token not found".into()));
    }
    Ok(Json(json!({ "ok": true })))
}

pub async fn sessions(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
) -> Result<Json<Value>, ApiError> {
    let current = if auth.session_token.is_empty() {
        None
    } else {
        Some(sha256_hex(auth.session_token.as_bytes()))
    };
    let sessions = state.db.list_user_sessions(&auth.user.id)?;
    let items: Vec<Value> = sessions
        .into_iter()
        .map(|session| {
            let current = current.as_deref() == Some(session.id.as_str());
            json!({
                "id": session.id,
                "created_at": session.created_at,
                "last_seen": session.last_seen,
                "ip": session.ip,
                "user_agent": session.user_agent,
                "current": current,
            })
        })
        .collect();
    Ok(Json(json!({ "sessions": items })))
}

pub async fn revoke_session(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let removed = state.db.revoke_user_session(&auth.user.id, &id)?;
    if !removed {
        return Err(ApiError::NotFound("session not found".into()));
    }
    Ok(Json(json!({ "ok": true })))
}

pub async fn revoke_other_sessions(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
) -> Result<Json<Value>, ApiError> {
    if auth.session_token.is_empty() {
        return Err(ApiError::BadRequest(
            "this action requires a panel session".into(),
        ));
    }
    let current = sha256_hex(auth.session_token.as_bytes());
    let removed = state.db.revoke_other_sessions(&auth.user.id, &current)?;
    Ok(Json(json!({ "ok": true, "revoked": removed })))
}
