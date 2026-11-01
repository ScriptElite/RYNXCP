use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use axum::extract::{ConnectInfo, Path, State};
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;

use rynx_panel::db::SESSION_COOKIE;
use rynx_panel::UserView;

use crate::auth::AuthUser;
use crate::authlog;
use crate::error::ApiError;
use crate::security::check_origin;
use crate::state::ApiState;
use crate::two_factor::VerifyError;

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyTwoFactorRequest {
    pub challenge: String,
    pub code: String,
}

#[derive(Debug, Serialize)]
pub struct TwoFactorResponse {
    pub two_factor_required: bool,
    pub challenge: String,
    pub email: String,
    pub expires_in: u64,
}

#[derive(Debug, Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub user: UserView,
    pub csrf_token: String,
    pub expires_at: i64,
    pub impersonated_by: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MeResponse {
    pub user: UserView,
    pub csrf_token: String,
    pub impersonated_by: Option<String>,
    #[serde(default)]
    pub ssh_enabled: bool,
}

pub async fn login(
    State(state): State<ApiState>,
    connect: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> Result<Response, ApiError> {
    check_origin(&headers, &state.cfg)?;

    if body.username.is_empty()
        || body.username.len() > 64
        || body.password.is_empty()
        || body.password.len() > 256
    {
        return Err(ApiError::BadRequest("invalid credentials".into()));
    }

    let ip = client_ip(&headers, Some(&connect), state.cfg.trust_proxy_headers);
    let identity = format!("u:{}|{}", body.username, ip);
    let ip_key = format!("ip:{ip}");
    let keys = [identity.as_str(), ip_key.as_str()];

    if state.limiter.retry_after(&keys).is_some() {
        let _ = state.db.record_auth_event(
            &body.username,
            &ip,
            &user_agent(&headers),
            "blocked",
            "rate_limited",
        );
        authlog::log(
            &state.cfg.auth_log,
            "login_blocked",
            &body.username,
            &ip,
            &user_agent(&headers),
            None,
        );
        let daemon = state.daemon.clone();
        let ban_ip = ip.clone();
        tokio::spawn(async move {
            let _ = daemon
                .call(
                    rynx_proto::Request::FirewallBlock {
                        ip: ban_ip,
                        seconds: 3600,
                        reason: "brute-force".into(),
                    },
                    "security",
                )
                .await;
        });
        return Err(ApiError::RateLimited);
    }

    let user = match state.db.authenticate(&body.username, &body.password)? {
        Some(user) => user,
        None => {
            state.limiter.record_failure(&keys);
            let _ = state.db.record_auth_event(
                &body.username,
                &ip,
                &user_agent(&headers),
                "failure",
                "invalid_credentials",
            );
            authlog::log(
                &state.cfg.auth_log,
                "login_failed",
                &body.username,
                &ip,
                &user_agent(&headers),
                None,
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
            return Err(ApiError::Unauthorized);
        }
    };
    state.limiter.reset(&identity);
    start_two_factor(&state, user, &ip, &headers).await
}

fn masked_email(email: &str) -> String {
    let Some((local, domain)) = email.split_once('@') else {
        return "***".into();
    };
    let first = local.chars().next().unwrap_or('*');
    format!("{first}***@{domain}")
}

async fn start_two_factor(
    state: &ApiState,
    user: UserView,
    ip: &str,
    headers: &HeaderMap,
) -> Result<Response, ApiError> {
    if state.mailer.is_none() {
        #[cfg(windows)]
        {
            tracing::warn!(
                user = %user.username,
                "SMTP is disabled; skipping two-factor authentication in Windows development mode"
            );
            let _ = state.db.record_auth_event(
                &user.username,
                ip,
                &user_agent(headers),
                "success",
                "two_factor_disabled_development",
            );
            return finish_login(state, user, ip, headers, None);
        }
        #[cfg(not(windows))]
        {
            return Err(ApiError::internal(
                "two-factor email delivery is not configured",
            ));
        }
    }
    let (challenge, code) = state.two_factor.issue(user.clone());
    if let Err(err) = crate::email::send_login_code(
        state,
        &user.email,
        &user.username,
        &code,
        user.locale.as_deref(),
    )
    .await
    {
        state.two_factor.cancel(&challenge);
        tracing::warn!(user = %user.username, error = %err, "two-factor email could not be sent");
        let _ = state.db.record_auth_event(
            &user.username,
            ip,
            &user_agent(headers),
            "failure",
            "two_factor_delivery",
        );
        return Err(ApiError::internal(
            "the verification code could not be sent by email",
        ));
    }
    let _ = state.db.record_auth_event(
        &user.username,
        ip,
        &user_agent(headers),
        "pending",
        "two_factor_required",
    );
    authlog::log(
        &state.cfg.auth_log,
        "login_2fa_required",
        &user.username,
        ip,
        &user_agent(headers),
        None,
    );
    Ok(Json(TwoFactorResponse {
        two_factor_required: true,
        challenge,
        email: masked_email(&user.email),
        expires_in: 600,
    })
    .into_response())
}

pub async fn verify_two_factor(
    State(state): State<ApiState>,
    connect: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<VerifyTwoFactorRequest>,
) -> Result<Response, ApiError> {
    check_origin(&headers, &state.cfg)?;
    let code = body.code.trim();
    if body.challenge.len() != 64 || code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return Err(ApiError::BadRequest(
            "invalid or expired verification challenge".into(),
        ));
    }
    let ip = client_ip(&headers, Some(&connect), state.cfg.trust_proxy_headers);
    let attempted_user = state
        .two_factor
        .username(&body.challenge)
        .unwrap_or_else(|| "two-factor".into());
    match state.two_factor.verify(&body.challenge, code) {
        Ok(user) => {
            let Some(user) = state.db.find_user(&user.username)? else {
                return Err(ApiError::Unauthorized);
            };
            if !user.active {
                return Err(ApiError::Forbidden);
            }
            let _ = state.db.record_auth_event(
                &user.username,
                &ip,
                &user_agent(&headers),
                "success",
                "two_factor",
            );
            authlog::log(
                &state.cfg.auth_log,
                "login_success",
                &user.username,
                &ip,
                &user_agent(&headers),
                None,
            );
            finish_login(&state, user, &ip, &headers, None)
        }
        Err(VerifyError::Invalid | VerifyError::TooManyAttempts) => {
            let _ = state.db.record_auth_event(
                &attempted_user,
                &ip,
                &user_agent(&headers),
                "failure",
                "invalid_2fa",
            );
            authlog::log(
                &state.cfg.auth_log,
                "login_2fa_failed",
                &attempted_user,
                &ip,
                &user_agent(&headers),
                None,
            );
            Err(ApiError::Unauthorized)
        }
        Err(VerifyError::Expired | VerifyError::NotFound) => Err(ApiError::BadRequest(
            "the verification code expired; sign in again".into(),
        )),
    }
}

/// Public password-reset request. The response is always generic to avoid
/// disclosing whether an email belongs to an active panel user.
pub async fn forgot_password(
    State(state): State<ApiState>,
    connect: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<ForgotPasswordRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_origin(&headers, &state.cfg)?;
    let ip = client_ip(&headers, Some(&connect), state.cfg.trust_proxy_headers);
    let key = format!("forgot|{ip}");
    if state.reset_limiter.retry_after(&[&key]).is_some() {
        return Err(ApiError::RateLimited);
    }
    state.reset_limiter.record_failure(&[&key]);

    let email = body.email.trim().to_ascii_lowercase();
    if email.len() <= 254 && rynx_core::validate_email(&email).is_ok() {
        if let Some((token, user)) = state.db.create_password_reset(&email, 3600)? {
            if state.mailer.is_some() {
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(err) = crate::email::send_password_reset(
                        &state,
                        &user.email,
                        &user.username,
                        &token,
                        user.locale.as_deref(),
                    )
                    .await
                    {
                        tracing::warn!(
                            user = %user.username,
                            error = %err,
                            "password reset email could not be sent"
                        );
                    }
                });
            } else {
                tracing::warn!(
                    user = %user.username,
                    "password reset requested but SMTP is disabled"
                );
            }
        }
    }

    Ok(Json(serde_json::json!({ "ok": true })))
}

pub async fn reset_password(
    State(state): State<ApiState>,
    connect: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<ResetPasswordRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_origin(&headers, &state.cfg)?;
    let ip = client_ip(&headers, Some(&connect), state.cfg.trust_proxy_headers);
    let key = format!("reset|{ip}");
    if state.reset_limiter.retry_after(&[&key]).is_some() {
        return Err(ApiError::RateLimited);
    }
    state.reset_limiter.record_failure(&[&key]);

    if body.token.len() != 64 || body.password.is_empty() || body.password.len() > 256 {
        return Err(ApiError::BadRequest(
            "invalid or expired reset token".into(),
        ));
    }
    let policy =
        rynx_core::PasswordPolicy::new(state.cfg.password_min_len, state.cfg.password_min_classes);
    let Some(username) = state
        .db
        .consume_password_reset(&policy, &body.token, &body.password)?
    else {
        return Err(ApiError::BadRequest(
            "invalid or expired reset token".into(),
        ));
    };

    state.reset_limiter.reset(&key);
    let _ = state.db.record_auth_event(
        &username,
        &ip,
        &user_agent(&headers),
        "success",
        "password_reset",
    );
    authlog::log(
        &state.cfg.auth_log,
        "password_reset",
        &username,
        &ip,
        &user_agent(&headers),
        None,
    );
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Admin-only impersonation. Creates a dedicated session for the target user
/// and records the original actor, so it can be stopped safely.
pub async fn impersonate(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    connect: ConnectInfo<SocketAddr>,
    Path(username): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    auth.require_admin()?;
    auth.require_global()?;
    check_origin(&headers, &state.cfg)?;
    if username == auth.user.username {
        return Err(ApiError::BadRequest(
            "you are already logged in as this user".into(),
        ));
    }
    let target = state
        .db
        .find_user(&username)?
        .ok_or_else(|| ApiError::NotFound(format!("user '{username}' not found")))?;
    if !target.active {
        return Err(ApiError::Conflict("target user is disabled".into()));
    }
    if target.role == rynx_panel::Role::Owner && !auth.is_owner() {
        return Err(ApiError::Forbidden);
    }

    let ip = client_ip(&headers, Some(&connect), state.cfg.trust_proxy_headers);
    let _ = state.db.record_auth_event(
        &target.username,
        &ip,
        &user_agent(&headers),
        "impersonation",
        &format!("by:{}", auth.user.username),
    );
    authlog::log(
        &state.cfg.auth_log,
        "impersonation_start",
        &target.username,
        &ip,
        &user_agent(&headers),
        Some(&auth.user.username),
    );
    finish_login(&state, target, &ip, &headers, Some(&auth.user.username))
}

pub async fn stop_impersonation(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    connect: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let Some(actor_name) = auth.impersonated_by.clone() else {
        return Err(ApiError::BadRequest("not impersonating anyone".into()));
    };
    let actor = state
        .db
        .find_user(&actor_name)?
        .ok_or(ApiError::Forbidden)?;
    if !actor.active || !actor.role.can_manage_users() {
        return Err(ApiError::Forbidden);
    }
    let _ = state.db.delete_session(&auth.session_token);
    let ip = client_ip(&headers, Some(&connect), state.cfg.trust_proxy_headers);
    let _ = state.db.record_auth_event(
        &actor.username,
        &ip,
        &user_agent(&headers),
        "success",
        "stop_impersonation",
    );
    authlog::log(
        &state.cfg.auth_log,
        "impersonation_stop",
        &actor.username,
        &ip,
        &user_agent(&headers),
        Some(&auth.user.username),
    );
    finish_login(&state, actor, &ip, &headers, None)
}

fn finish_login(
    state: &ApiState,
    user: UserView,
    ip: &str,
    headers: &HeaderMap,
    impersonated_by: Option<&str>,
) -> Result<Response, ApiError> {
    let ttl = state.cfg.session_ttl_secs;
    let session =
        state
            .db
            .create_session(&user.id, ttl, ip, &user_agent(headers), impersonated_by)?;
    let cookie = session_cookie(&session.token, ttl, state.cfg.secure_cookies);
    let mut response = Json(SessionResponse {
        user,
        csrf_token: session.csrf_token,
        expires_at: session.expires_at,
        impersonated_by: impersonated_by.map(str::to_string),
    })
    .into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).map_err(ApiError::internal)?,
    );
    Ok(response)
}

#[derive(Debug, Deserialize)]
pub struct LocaleRequest {
    pub locale: String,
}

pub async fn set_locale(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
    Json(body): Json<LocaleRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let locale = body.locale.trim();
    rynx_core::validate_locale(locale).map_err(|err| ApiError::BadRequest(err.to_string()))?;
    state
        .db
        .set_user_locale(&auth.user.username, Some(locale))?;
    Ok(Json(serde_json::json!({ "ok": true, "locale": locale })))
}

pub async fn logout(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
) -> Result<Response, ApiError> {
    state.db.delete_session(&auth.session_token)?;
    let mut response = Json(json!({ "ok": true })).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&clear_cookie(state.cfg.secure_cookies))
            .map_err(ApiError::internal)?,
    );
    Ok(response)
}

pub async fn me(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthUser>,
) -> Json<MeResponse> {
    let ssh_enabled = match auth.user.account.as_deref() {
        Some(account) => match state
            .daemon
            .call(rynx_proto::Request::AccountList, &auth.user.username)
            .await
        {
            Ok(rynx_proto::Response::Accounts { accounts }) => accounts.iter().any(|item| {
                item.spec.username == account && item.spec.enabled && item.spec.ssh_enabled
            }),
            _ => false,
        },
        None => false,
    };
    Json(MeResponse {
        user: auth.user,
        csrf_token: auth.csrf_token,
        impersonated_by: auth.impersonated_by,
        ssh_enabled,
    })
}

fn user_agent(headers: &HeaderMap) -> String {
    headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .chars()
        .take(200)
        .collect()
}

fn session_cookie(token: &str, ttl_secs: i64, secure: bool) -> String {
    let mut cookie = format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
        ttl_secs.max(60)
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

fn clear_cookie(secure: bool) -> String {
    let mut cookie = format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

fn parse_ip(value: &str) -> Option<String> {
    value
        .trim()
        .trim_matches('"')
        .parse::<IpAddr>()
        .ok()
        .map(|ip| ip.to_string())
}

fn client_ip(
    headers: &HeaderMap,
    connect: Option<&ConnectInfo<SocketAddr>>,
    trust_proxy: bool,
) -> String {
    if trust_proxy {
        // Nginx overwrites X-Real-IP with $remote_addr. Never trust the
        // client-controlled prefix of X-Forwarded-For.
        if let Some(value) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            if let Some(ip) = parse_ip(value) {
                return ip;
            }
        }
        if let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(last) = value.rsplit(',').next() {
                if let Some(ip) = parse_ip(last) {
                    return ip;
                }
            }
        }
    }
    connect
        .map(|info| info.0.ip().to_string())
        .unwrap_or_else(|| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn proxy_ip_uses_real_ip_and_last_forwarded_value() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", HeaderValue::from_static("203.0.113.9"));
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.7, 203.0.113.9"),
        );
        assert_eq!(client_ip(&headers, None, true), "203.0.113.9");
    }

    #[test]
    fn proxy_ip_rejects_non_ip_values() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", HeaderValue::from_static("evil"));
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("1.2.3.4, not-an-ip"),
        );
        assert_eq!(client_ip(&headers, None, true), "unknown");
    }
}
