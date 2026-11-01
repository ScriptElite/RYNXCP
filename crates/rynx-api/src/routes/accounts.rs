use axum::extract::{Path, Query, State};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};

use rynx_core::crypto::random_hex;
use rynx_panel::{AccountPackageView, Role, UserView, WEB_BACKENDS};
use rynx_proto::{AccountSpec, AccountView, Request, Response as DaemonResponse};

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::scope;
use crate::state::ApiState;

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct PurgeQuery {
    #[serde(default = "default_true")]
    pub purge: bool,
}

#[derive(Debug, Deserialize)]
pub struct CreateAccount {
    #[serde(flatten)]
    pub spec: AccountSpec,
    /// `None` leaves the linked panel user untouched (used when toggling an
    /// account), `Some(true)` creates it when missing, `Some(false)` disables
    /// its access.
    #[serde(default)]
    pub panel_access: Option<bool>,
    /// Only `viewer` and `operator` are allowed. Defaults to `viewer`.
    #[serde(default)]
    pub panel_role: Option<Role>,
    /// Package assigned to the new account. Limits and templates come from it.
    #[serde(default)]
    pub package_id: Option<String>,
    /// Account-level backend override, preselected from the package.
    #[serde(default)]
    pub web_backend: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateAccountResponse {
    pub account: DaemonResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub panel_user: Option<UserView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub panel_password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<AccountPackageView>,
}

/// The panel treats 0 as unlimited; the daemon needs a concrete quota.
fn package_disk_limit(account_mb: u64) -> u64 {
    if account_mb == 0 {
        rynx_core::MAX_DISK_LIMIT_MB
    } else {
        account_mb.min(rynx_core::MAX_DISK_LIMIT_MB)
    }
}

async fn account_list(state: &ApiState, actor: &str) -> Result<Vec<AccountView>, ApiError> {
    match state.daemon.call(Request::AccountList, actor).await? {
        DaemonResponse::Accounts { accounts } => Ok(accounts),
        _ => Ok(Vec::new()),
    }
}

pub async fn list(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
) -> Result<Json<DaemonResponse>, ApiError> {
    let response = state
        .daemon
        .call(Request::AccountList, &auth.user.username)
        .await?;
    let response = scope::list_response(&state, &auth, response).await?;
    Ok(Json(response))
}

pub async fn create(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Json(body): Json<CreateAccount>,
) -> Result<Json<CreateAccountResponse>, ApiError> {
    auth.require_write()?;
    auth.require_global()?;
    let _identity_guard = state.identity_lock.lock().await;
    let mut spec = body.spec;

    if let Some(role) = body.panel_role {
        if !matches!(role, Role::Viewer | Role::Operator) {
            return Err(ApiError::BadRequest(
                "panel_role must be viewer or operator".into(),
            ));
        }
    }

    let accounts = account_list(&state, &auth.user.username).await?;
    let existing_account = accounts
        .iter()
        .find(|account| account.spec.username == spec.username)
        .cloned();
    let existing_assignment = state.db.get_account_package(&spec.username)?;
    let mut new_assignment: Option<(String, String)> = None;

    if let Some(existing) = existing_assignment.as_ref() {
        if let Some(package_id) = body.package_id.as_deref() {
            if package_id != existing.package_id {
                return Err(ApiError::Conflict(
                    "the package assigned to this account cannot be changed".into(),
                ));
            }
        }
        // Package limits are locked for assigned accounts.
        if let Some(account) = existing_account.as_ref() {
            spec.disk_limit_mb = account.spec.disk_limit_mb;
        } else if let Some(package) = state.db.get_package(&existing.package_id)? {
            spec.disk_limit_mb = package_disk_limit(package.package.account_mb);
        }
    } else if let Some(package_id) = body.package_id.as_deref() {
        let package = state
            .db
            .get_package(package_id)?
            .ok_or_else(|| ApiError::NotFound(format!("package '{package_id}' not found")))?;
        let backend = body
            .web_backend
            .as_deref()
            .unwrap_or(&package.package.web_backend)
            .to_string();
        if !WEB_BACKENDS.contains(&backend.as_str()) {
            return Err(ApiError::BadRequest(format!(
                "invalid web backend '{backend}'"
            )));
        }
        spec.disk_limit_mb = package_disk_limit(package.package.account_mb);
        new_assignment = Some((package_id.to_string(), backend));
    }

    if accounts.iter().any(|account| {
        account.spec.username != spec.username
            && account.spec.email.eq_ignore_ascii_case(&spec.email)
    }) {
        return Err(ApiError::Conflict(
            "Ese email ya está en uso por otra cuenta de hosting.".into(),
        ));
    }

    if let Some(user) = state.db.find_user_by_email(&spec.email)? {
        if user.account.as_deref() != Some(spec.username.as_str()) {
            return Err(ApiError::Conflict(
                "Ese email ya está en uso por un usuario del panel. Usa otro email para la cuenta."
                    .into(),
            ));
        }
    }

    if let Some(user) = state.db.find_user(&spec.username)? {
        if user.account.as_deref() != Some(spec.username.as_str()) {
            return Err(ApiError::Conflict(
                "Ese nombre de usuario ya está en uso por un usuario del panel.".into(),
            ));
        }
    }

    let response = state
        .daemon
        .call(Request::AccountCreate(spec.clone()), &auth.user.username)
        .await?;

    let mut panel_user = state.db.find_user_by_account(&spec.username)?;
    let mut panel_password = None;

    if let Some(user) = panel_user.as_mut() {
        if !user.email.eq_ignore_ascii_case(&spec.email) {
            state.db.set_email(&user.username, &spec.email)?;
            user.email = spec.email.clone();
        }
        let desired_active = match body.panel_access {
            Some(false) => false,
            _ => spec.enabled,
        };
        if user.active != desired_active {
            state.db.set_active(&user.username, desired_active)?;
            user.active = desired_active;
        }
    } else if body.panel_access == Some(true) {
        let policy = rynx_core::PasswordPolicy::new(
            state.cfg.password_min_len,
            state.cfg.password_min_classes,
        );
        let role = body.panel_role.unwrap_or(Role::Viewer);
        // Generated password: 36 chars, four character classes.
        let password = format!("Aa1!{}", random_hex(16));
        let mut user = state.db.create_account_user(
            &policy,
            &spec.username,
            &spec.email,
            &password,
            role,
            &spec.username,
        )?;
        if !spec.enabled {
            state.db.set_active(&user.username, false)?;
            user.active = false;
        }
        if user.locale.is_none() {
            if let Some(locale) = auth.user.locale.clone() {
                state.db.set_user_locale(&user.username, Some(&locale))?;
                user.locale = Some(locale);
            }
        }
        panel_user = Some(user);
        panel_password = Some(password);
    }

    if let (Some(user), Some(password)) = (panel_user.as_ref(), panel_password.as_deref()) {
        if user.active {
            if let Err(err) = crate::email::send_credentials(
                &state,
                &user.email,
                &user.username,
                password,
                auth.user.locale.as_deref(),
            )
            .await
            {
                tracing::warn!(
                    user = %user.username,
                    error = %err,
                    "panel credential email could not be sent"
                );
            }
        }
    }

    let package = if let Some((package_id, backend)) = new_assignment {
        Some(
            state
                .db
                .set_account_package(&spec.username, &package_id, &backend)?,
        )
    } else {
        existing_assignment
    };

    Ok(Json(CreateAccountResponse {
        account: response,
        panel_user,
        panel_password,
        package,
    }))
}

pub async fn delete(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Path(username): Path<String>,
    Query(query): Query<PurgeQuery>,
) -> Result<Json<DaemonResponse>, ApiError> {
    auth.require_write()?;
    auth.require_global()?;
    let response = state
        .daemon
        .call(
            Request::AccountDelete {
                username: username.clone(),
                purge: query.purge,
            },
            &auth.user.username,
        )
        .await?;
    if let Some(user) = state.db.find_user_by_account(&username)? {
        let _ = state.db.delete_user(&user.username);
    }
    state.db.delete_account_package(&username)?;
    Ok(Json(response))
}
