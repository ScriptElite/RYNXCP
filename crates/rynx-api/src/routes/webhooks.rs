use axum::extract::{Path, State};
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use rynx_core::crypto::random_hex;

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::state::ApiState;
use crate::webhooks;

#[derive(Debug, Deserialize)]
pub struct CreateWebhook {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub events: Vec<String>,
}

pub async fn list(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
) -> Result<Json<Value>, ApiError> {
    let hooks = state.db.list_webhooks(&auth.user.id)?;
    Ok(Json(json!({
        "webhooks": hooks,
        "events": webhooks::EVENTS,
    })))
}

pub async fn create(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Json(body): Json<CreateWebhook>,
) -> Result<Json<Value>, ApiError> {
    let name = body.name.trim();
    if name.is_empty() || name.len() > 100 || name.chars().any(|ch| ch.is_control()) {
        return Err(ApiError::BadRequest("invalid webhook name".into()));
    }
    let (url, _) = webhooks::validate_url(&body.url)
        .await
        .map_err(ApiError::BadRequest)?;
    let events = webhooks::validate_events(&body.events).map_err(ApiError::BadRequest)?;
    let secret = random_hex(32);
    let view = state
        .db
        .create_webhook(&auth.user.id, name, &url, &events, &secret)?;
    Ok(Json(json!({ "webhook": view, "secret": secret })))
}

pub async fn delete(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let removed = state.db.delete_webhook(&auth.user.id, &id)?;
    if !removed {
        return Err(ApiError::NotFound("webhook not found".into()));
    }
    Ok(Json(json!({ "ok": true })))
}
