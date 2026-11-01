use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, Method};
use axum::middleware::Next;
use axum::response::Response;

use rynx_core::crypto::constant_time_eq;
use rynx_panel::db::{CSRF_HEADER, SESSION_COOKIE};
use rynx_panel::{Role, UserView};

use crate::error::ApiError;
use crate::state::ApiState;

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user: UserView,
    pub csrf_token: String,
    pub session_token: String,
    pub impersonated_by: Option<String>,
}

impl AuthUser {
    pub fn require_write(&self) -> Result<(), ApiError> {
        if self.user.role.can_write() {
            Ok(())
        } else {
            Err(ApiError::Forbidden)
        }
    }

    pub fn require_admin(&self) -> Result<(), ApiError> {
        if self.user.role.can_manage_users() {
            Ok(())
        } else {
            Err(ApiError::Forbidden)
        }
    }

    pub fn is_owner(&self) -> bool {
        self.user.role == Role::Owner
    }

    /// Hosting account linked to this panel user. Linked users only see and
    /// manage that account's resources.
    pub fn scoped_account(&self) -> Option<&str> {
        self.user.account.as_deref()
    }

    /// Global routes (users, firewall, console, system, ...) are only for
    /// panel users that are not linked to a hosting account.
    pub fn require_global(&self) -> Result<(), ApiError> {
        if self.scoped_account().is_some() {
            return Err(ApiError::Forbidden);
        }
        Ok(())
    }

    /// Rejects access to another account's resources for linked users.
    pub fn ensure_account(&self, account: &str) -> Result<(), ApiError> {
        if let Some(own) = self.scoped_account() {
            if own != account {
                return Err(ApiError::Forbidden);
            }
        }
        Ok(())
    }
}

pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some((key, value)) = part.split_once('=') {
            if key.trim() == name {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

fn is_mutating(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PATCH | Method::PUT | Method::DELETE
    )
}

/// Session + CSRF enforcement for every protected route.
pub async fn require_auth(
    State(state): State<ApiState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if let Some(raw) = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    {
        let user = state
            .db
            .authenticate_api_token(raw.trim())
            .map_err(ApiError::from)?
            .ok_or(ApiError::Unauthorized)?;
        request.extensions_mut().insert(AuthUser {
            user,
            csrf_token: String::new(),
            session_token: String::new(),
            impersonated_by: None,
        });
        return Ok(next.run(request).await);
    }

    let token = cookie_value(request.headers(), SESSION_COOKIE).ok_or(ApiError::Unauthorized)?;
    let session = state
        .db
        .lookup_session(&token, state.cfg.session_idle_secs)
        .map_err(ApiError::from)?
        .ok_or(ApiError::Unauthorized)?;

    if is_mutating(request.method()) {
        let provided = request
            .headers()
            .get(CSRF_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if !constant_time_eq(provided, &session.csrf_token) {
            return Err(ApiError::Forbidden);
        }
    }

    request.extensions_mut().insert(AuthUser {
        user: session.user,
        csrf_token: session.csrf_token,
        session_token: token,
        impersonated_by: session.impersonated_by,
    });
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth_user(account: Option<&str>, role: Role) -> AuthUser {
        AuthUser {
            user: UserView {
                id: "id".into(),
                username: "user".into(),
                email: "user@example.com".into(),
                role,
                active: true,
                created_at: "2026-01-01T00:00:00Z".into(),
                updated_at: "2026-01-01T00:00:00Z".into(),
                account: account.map(str::to_string),
                locale: None,
            },
            csrf_token: "csrf".into(),
            session_token: "session".into(),
            impersonated_by: None,
        }
    }

    #[test]
    fn scoped_users_cannot_escape_their_account() {
        let scoped = auth_user(Some("acme"), Role::Operator);
        assert!(scoped.ensure_account("acme").is_ok());
        assert!(scoped.ensure_account("other").is_err());
        assert!(scoped.require_global().is_err());

        let global = auth_user(None, Role::Admin);
        assert!(global.ensure_account("other").is_ok());
        assert!(global.require_global().is_ok());
    }
}
