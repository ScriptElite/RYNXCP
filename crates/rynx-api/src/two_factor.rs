//! Short-lived email verification challenges used by the login flow.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::Rng;
use rynx_core::crypto::{constant_time_eq, random_hex, sha256_hex};
use rynx_panel::UserView;

const CODE_TTL_SECS: u64 = 600;
const MAX_ATTEMPTS: u8 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    NotFound,
    Expired,
    Invalid,
    TooManyAttempts,
}

struct Challenge {
    user: UserView,
    code_hash: String,
    expires_at: u64,
    attempts: u8,
}

#[derive(Default)]
pub struct TwoFactor {
    challenges: Mutex<HashMap<String, Challenge>>,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

impl TwoFactor {
    /// Creates a new challenge and returns `(challenge_token, code)`.
    /// Only the most recent challenge for a user remains valid.
    pub fn issue(&self, user: UserView) -> (String, String) {
        let code = format!("{:06}", rand::thread_rng().gen_range(0..1_000_000));
        let token = random_hex(32);
        let now = now_secs();
        let challenge = Challenge {
            code_hash: sha256_hex(code.as_bytes()),
            user,
            expires_at: now + CODE_TTL_SECS,
            attempts: 0,
        };
        if let Ok(mut challenges) = self.challenges.lock() {
            challenges.retain(|_, pending| {
                pending.expires_at > now && pending.user.username != challenge.user.username
            });
            challenges.insert(token.clone(), challenge);
        }
        (token, code)
    }

    pub fn cancel(&self, token: &str) {
        if let Ok(mut challenges) = self.challenges.lock() {
            challenges.remove(token);
        }
    }

    pub fn username(&self, token: &str) -> Option<String> {
        self.challenges.lock().ok().and_then(|challenges| {
            challenges
                .get(token)
                .map(|challenge| challenge.user.username.clone())
        })
    }

    pub fn consume(&self, token: &str) -> Result<UserView, VerifyError> {
        let Ok(mut challenges) = self.challenges.lock() else {
            return Err(VerifyError::NotFound);
        };
        let now = now_secs();
        let Some(challenge) = challenges.get(token) else {
            return Err(VerifyError::NotFound);
        };
        if challenge.expires_at <= now {
            challenges.remove(token);
            return Err(VerifyError::Expired);
        }
        let user = challenge.user.clone();
        challenges.remove(token);
        Ok(user)
    }

    pub fn verify(&self, token: &str, code: &str) -> Result<UserView, VerifyError> {
        let Ok(mut challenges) = self.challenges.lock() else {
            return Err(VerifyError::NotFound);
        };
        let now = now_secs();
        let Some(challenge) = challenges.get_mut(token) else {
            return Err(VerifyError::NotFound);
        };
        if challenge.expires_at <= now {
            challenges.remove(token);
            return Err(VerifyError::Expired);
        }
        if !constant_time_eq(&challenge.code_hash, &sha256_hex(code.as_bytes())) {
            challenge.attempts = challenge.attempts.saturating_add(1);
            if challenge.attempts >= MAX_ATTEMPTS {
                challenges.remove(token);
                return Err(VerifyError::TooManyAttempts);
            }
            return Err(VerifyError::Invalid);
        }
        let user = challenge.user.clone();
        challenges.remove(token);
        Ok(user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rynx_panel::Role;

    fn user() -> UserView {
        UserView {
            id: "u1".into(),
            username: "admin".into(),
            email: "admin@example.com".into(),
            role: Role::Owner,
            active: true,
            created_at: "now".into(),
            updated_at: "now".into(),
            account: None,
            locale: None,
        }
    }

    #[test]
    fn verifies_once() {
        let otp = TwoFactor::default();
        let (token, code) = otp.issue(user());
        assert!(matches!(
            otp.verify(&token, "000000"),
            Err(VerifyError::Invalid)
        ));
        assert_eq!(otp.verify(&token, &code).unwrap().username, "admin");
        assert!(matches!(
            otp.verify(&token, &code),
            Err(VerifyError::NotFound)
        ));
    }

    #[test]
    fn consumed_challenge_is_single_use() {
        let otp = TwoFactor::default();
        let (token, _) = otp.issue(user());
        assert_eq!(otp.consume(&token).unwrap().username, "admin");
        assert!(matches!(otp.consume(&token), Err(VerifyError::NotFound)));
    }

    #[test]
    fn replaces_previous_challenge() {
        let otp = TwoFactor::default();
        let (first, _) = otp.issue(user());
        let (second, code) = otp.issue(user());
        assert!(matches!(otp.verify(&first, ""), Err(VerifyError::NotFound)));
        assert!(otp.verify(&second, &code).is_ok());
    }
}
