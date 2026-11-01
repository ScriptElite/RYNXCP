use axum::extract::{Path, State};
use axum::{Extension, Json};
use serde::Deserialize;

use rynx_panel::{Role, UserView};
use rynx_proto::{Request, Response as DaemonResponse};

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::state::ApiState;

/// Returns the hosting account that already uses this email, if any.
async fn account_with_email(
    state: &ApiState,
    email: &str,
    actor: &str,
) -> Result<Option<String>, ApiError> {
    match state.daemon.call(Request::AccountList, actor).await? {
        DaemonResponse::Accounts { accounts } => Ok(accounts
            .into_iter()
            .find(|account| account.spec.email.eq_ignore_ascii_case(email))
            .map(|account| account.spec.username)),
        _ => Ok(None),
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateUser {
    pub username: String,
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub role: Option<Role>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUser {
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub role: Option<Role>,
    #[serde(default)]
    pub active: Option<bool>,
}

pub async fn list(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
) -> Result<Json<Vec<UserView>>, ApiError> {
    auth.require_admin()?;
    auth.require_global()?;
    Ok(Json(state.db.list_users()?))
}

pub async fn create(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Json(body): Json<CreateUser>,
) -> Result<Json<UserView>, ApiError> {
    auth.require_admin()?;
    auth.require_global()?;
    let role = body.role.unwrap_or(Role::Operator);
    if role == Role::Owner && !auth.is_owner() {
        return Err(ApiError::Forbidden);
    }
    let mut user = {
        let _guard = state.identity_lock.lock().await;
        if account_with_email(&state, &body.email, &auth.user.username)
            .await?
            .is_some()
        {
            return Err(ApiError::Conflict(
                "Ese email ya está en uso por una cuenta de hosting.".into(),
            ));
        }
        let policy = rynx_core::PasswordPolicy::new(
            state.cfg.password_min_len,
            state.cfg.password_min_classes,
        );
        state.db.create_user_with_policy(
            &policy,
            &body.username,
            &body.email,
            &body.password,
            role,
        )?
    };
    if user.locale.is_none() {
        if let Some(locale) = auth.user.locale.clone() {
            state.db.set_user_locale(&user.username, Some(&locale))?;
            user.locale = Some(locale);
        }
    }
    if let Err(err) = crate::email::send_credentials(
        &state,
        &user.email,
        &user.username,
        &body.password,
        auth.user.locale.as_deref(),
    )
    .await
    {
        tracing::warn!(
            user = %user.username,
            error = %err,
            "credential email could not be sent"
        );
    }
    Ok(Json(user))
}

pub async fn update(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Path(username): Path<String>,
    Json(body): Json<UpdateUser>,
) -> Result<Json<UserView>, ApiError> {
    auth.require_admin()?;
    auth.require_global()?;
    let _identity_guard = state.identity_lock.lock().await;
    let target = state
        .db
        .find_user(&username)?
        .ok_or_else(|| ApiError::NotFound(format!("user '{username}' not found")))?;

    if target.role == Role::Owner && !auth.is_owner() {
        return Err(ApiError::Forbidden);
    }

    if let Some(role) = body.role {
        if username == auth.user.username {
            return Err(ApiError::BadRequest("cannot change your own role".into()));
        }
        if role == Role::Owner && !auth.is_owner() {
            return Err(ApiError::Forbidden);
        }
        if target.role == Role::Owner && role != Role::Owner && state.db.count_owners()? <= 1 {
            return Err(ApiError::Conflict(
                "cannot remove the last active owner".into(),
            ));
        }
        state.db.set_role(&username, role)?;
    }

    if let Some(active) = body.active {
        if username == auth.user.username && !active {
            return Err(ApiError::BadRequest("cannot deactivate yourself".into()));
        }
        if !active && target.role == Role::Owner && state.db.count_owners()? <= 1 {
            return Err(ApiError::Conflict(
                "cannot deactivate the last active owner".into(),
            ));
        }
        state.db.set_active(&username, active)?;
    }

    if let Some(password) = body.password {
        let policy = rynx_core::PasswordPolicy::new(
            state.cfg.password_min_len,
            state.cfg.password_min_classes,
        );
        state
            .db
            .set_password_with_policy(&policy, &username, &password)?;
    }

    if let Some(email) = &body.email {
        if let Some(account) = account_with_email(&state, email, &auth.user.username).await? {
            if target.account.as_deref() != Some(account.as_str()) {
                return Err(ApiError::Conflict(
                    "Ese email ya está en uso por una cuenta de hosting.".into(),
                ));
            }
        }
    }

    if let Some(email) = body.email {
        state.db.set_email(&username, &email)?;
    }

    let updated = state
        .db
        .find_user(&username)?
        .ok_or_else(|| ApiError::NotFound(format!("user '{username}' not found")))?;
    Ok(Json(updated))
}

pub async fn delete(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Path(username): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    auth.require_admin()?;
    auth.require_global()?;
    if username == auth.user.username {
        return Err(ApiError::BadRequest("cannot delete yourself".into()));
    }
    let target = state
        .db
        .find_user(&username)?
        .ok_or_else(|| ApiError::NotFound(format!("user '{username}' not found")))?;
    if target.role == Role::Owner {
        if !auth.is_owner() {
            return Err(ApiError::Forbidden);
        }
        if state.db.count_owners()? <= 1 {
            return Err(ApiError::Conflict(
                "cannot delete the last active owner".into(),
            ));
        }
    }
    if let Some(account) = target.account.clone() {
        match state
            .daemon
            .call(
                Request::AccountDelete {
                    username: account,
                    purge: true,
                },
                &auth.user.username,
            )
            .await
        {
            Ok(_) | Err(ApiError::NotFound(_)) => {}
            Err(err) => return Err(err),
        }
    }
    state.db.delete_user(&username)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}
