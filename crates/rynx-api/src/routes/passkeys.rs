use axum::extract::{ConnectInfo, Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::{Extension, Json};
use base64::Engine as _;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;
use webauthn_rs::prelude::{
    CredentialID, Passkey, PublicKeyCredential, RegisterPublicKeyCredential,
};
use webauthn_rs::Webauthn;

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::security::check_origin;
use crate::state::ApiState;
use crate::webauthn::{Authentication, Registration};

#[derive(Debug, Deserialize)]
pub struct BeginRegistration {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct FinishRegistration {
    pub flow: String,
    pub credential: RegisterPublicKeyCredential,
}

#[derive(Debug, Deserialize)]
pub struct LoginBegin {
    pub challenge: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginFinish {
    pub flow: String,
    pub credential: PublicKeyCredential,
}

fn webauthn(state: &ApiState) -> Result<&Webauthn, ApiError> {
    state
        .webauthn
        .as_deref()
        .ok_or_else(|| ApiError::Conflict("passkeys are not available; HTTPS is required".into()))
}

fn credential_key(credential_id: &CredentialID) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(credential_id.as_ref())
}

fn parse_credentials(state: &ApiState, user_id: &str) -> Result<Vec<Passkey>, ApiError> {
    let stored = state.db.list_passkey_credentials(user_id)?;
    Ok(stored
        .into_iter()
        .filter_map(|item| serde_json::from_str::<Passkey>(&item.credential).ok())
        .collect())
}

pub async fn list(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
) -> Result<Json<Value>, ApiError> {
    let passkeys = state.db.list_passkeys(&auth.user.id)?;
    Ok(Json(json!({
        "passkeys": passkeys,
        "enabled": state.webauthn.is_some(),
    })))
}

pub async fn begin_registration(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Json(body): Json<BeginRegistration>,
) -> Result<Json<Value>, ApiError> {
    let webauthn = webauthn(&state)?;
    let name = body.name.trim();
    if name.is_empty() || name.len() > 64 || name.chars().any(|ch| ch.is_control()) {
        return Err(ApiError::BadRequest("invalid passkey name".into()));
    }
    let user_id = Uuid::parse_str(&auth.user.id)
        .map_err(|_| ApiError::internal("invalid user identifier"))?;
    let existing = parse_credentials(&state, &auth.user.id)?;
    let exclude = if existing.is_empty() {
        None
    } else {
        Some(
            existing
                .iter()
                .map(|passkey| passkey.cred_id().clone())
                .collect(),
        )
    };
    let (options, ceremony) = webauthn
        .start_passkey_registration(user_id, &auth.user.username, &auth.user.email, exclude)
        .map_err(|_| ApiError::internal("passkey registration could not be started"))?;
    let flow = state.passkey_flows.start_registration(Registration {
        user_id: auth.user.id.clone(),
        name: name.to_string(),
        state: ceremony,
    });
    Ok(Json(json!({ "flow": flow, "options": options })))
}

pub async fn finish_registration(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Json(body): Json<FinishRegistration>,
) -> Result<Json<Value>, ApiError> {
    let webauthn = webauthn(&state)?;
    let flow = state
        .passkey_flows
        .take_registration(&body.flow)
        .ok_or_else(|| ApiError::BadRequest("invalid or expired passkey flow".into()))?;
    if flow.user_id != auth.user.id {
        return Err(ApiError::Forbidden);
    }
    let passkey = webauthn
        .finish_passkey_registration(&body.credential, &flow.state)
        .map_err(|_| ApiError::BadRequest("passkey registration failed".into()))?;
    let credential = serde_json::to_string(&passkey)
        .map_err(|_| ApiError::internal("passkey could not be stored"))?;
    let view = state.db.create_passkey(
        &auth.user.id,
        &flow.name,
        &credential_key(passkey.cred_id()),
        &credential,
    )?;
    Ok(Json(json!({ "passkey": view })))
}

pub async fn delete(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    if !state.db.delete_passkey(&auth.user.id, &id)? {
        return Err(ApiError::NotFound("passkey not found".into()));
    }
    Ok(Json(json!({ "ok": true })))
}

pub async fn login_begin(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(body): Json<LoginBegin>,
) -> Result<Json<Value>, ApiError> {
    check_origin(&headers, &state.cfg)?;
    let webauthn = webauthn(&state)?;
    let username = state
        .two_factor
        .username(&body.challenge)
        .ok_or_else(|| ApiError::BadRequest("invalid or expired login challenge".into()))?;
    let user = state
        .db
        .find_user(&username)?
        .filter(|user| user.active)
        .ok_or(ApiError::Unauthorized)?;
    let passkeys = parse_credentials(&state, &user.id)?;
    if passkeys.is_empty() {
        return Err(ApiError::Conflict("no passkeys are registered".into()));
    }
    let (options, ceremony) = webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|_| ApiError::internal("passkey login could not be started"))?;
    let flow = state.passkey_flows.start_authentication(Authentication {
        user_id: user.id,
        username: user.username,
        email_challenge: body.challenge,
        state: ceremony,
    });
    Ok(Json(json!({ "flow": flow, "options": options })))
}

pub async fn login_finish(
    State(state): State<ApiState>,
    connect: ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<LoginFinish>,
) -> Result<Response, ApiError> {
    check_origin(&headers, &state.cfg)?;
    let webauthn = webauthn(&state)?;
    let flow = state
        .passkey_flows
        .take_authentication(&body.flow)
        .ok_or_else(|| ApiError::BadRequest("invalid or expired passkey flow".into()))?;
    let result = webauthn
        .finish_passkey_authentication(&body.credential, &flow.state)
        .map_err(|_| {
            record_failure(&state, &flow.username, &headers, &connect);
            ApiError::Unauthorized
        })?;
    let user = state
        .two_factor
        .consume(&flow.email_challenge)
        .map_err(|_| {
            record_failure(&state, &flow.username, &headers, &connect);
            ApiError::Unauthorized
        })?;
    if user.id != flow.user_id {
        return Err(ApiError::Unauthorized);
    }
    let credential_id = credential_key(result.cred_id());
    let stored = state.db.list_passkey_credentials(&user.id)?;
    let Some(stored) = stored
        .into_iter()
        .find(|item| item.credential_id == credential_id)
    else {
        return Err(ApiError::Unauthorized);
    };
    let updated = serde_json::from_str::<Passkey>(&stored.credential)
        .ok()
        .and_then(|mut passkey| {
            let changed = passkey.update_credential(&result)?;
            if changed {
                serde_json::to_string(&passkey).ok()
            } else {
                None
            }
        });
    state
        .db
        .touch_passkey(&user.id, &credential_id, updated.as_deref())?;
    let ip =
        crate::routes::session::client_ip(&headers, Some(&connect), state.cfg.trust_proxy_headers);
    let _ = state.db.record_auth_event(
        &user.username,
        &ip,
        &crate::routes::session::user_agent(&headers),
        "success",
        "passkey",
    );
    crate::routes::session::finish_login(&state, user, &ip, &headers, None)
}

fn record_failure(
    state: &ApiState,
    username: &str,
    headers: &HeaderMap,
    connect: &ConnectInfo<std::net::SocketAddr>,
) {
    let ip =
        crate::routes::session::client_ip(headers, Some(connect), state.cfg.trust_proxy_headers);
    let _ = state.db.record_auth_event(
        username,
        &ip,
        &crate::routes::session::user_agent(headers),
        "failure",
        "passkey",
    );
}
