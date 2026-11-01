use rynx_core::ApiConfig;

#[cfg(unix)]
use std::collections::HashMap;
#[cfg(unix)]
use std::net::IpAddr;
#[cfg(unix)]
use std::sync::Arc;
#[cfg(unix)]
use std::sync::Mutex;
#[cfg(unix)]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use rynx_core::crypto::random_hex;
#[cfg(unix)]
use webauthn_rs::prelude::{
    PasskeyAuthentication, PasskeyRegistration, Url, Webauthn, WebauthnBuilder,
};

#[cfg(unix)]
pub type WebauthnClient = Webauthn;
#[cfg(not(unix))]
pub type WebauthnClient = std::convert::Infallible;

#[cfg(unix)]
const FLOW_TTL_SECS: u64 = 300;

#[cfg(unix)]
pub struct Registration {
    pub user_id: String,
    pub name: String,
    pub state: PasskeyRegistration,
}

#[cfg(unix)]
pub struct Authentication {
    pub user_id: String,
    pub username: String,
    pub email_challenge: String,
    pub state: PasskeyAuthentication,
}

#[cfg(unix)]
enum Flow {
    Registration {
        flow: Registration,
        expires_at: u64,
    },
    Authentication {
        flow: Authentication,
        expires_at: u64,
    },
}

#[cfg(unix)]
#[derive(Default)]
pub struct PasskeyFlows {
    flows: Mutex<HashMap<String, Flow>>,
}

#[cfg(not(unix))]
#[derive(Default)]
pub struct PasskeyFlows;

#[cfg(unix)]
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(unix)]
impl PasskeyFlows {
    fn insert(&self, flow: Flow) -> String {
        let token = random_hex(32);
        let now = now_secs();
        if let Ok(mut flows) = self.flows.lock() {
            flows.retain(|_, flow| match flow {
                Flow::Registration { expires_at, .. } => *expires_at > now,
                Flow::Authentication { expires_at, .. } => *expires_at > now,
            });
            flows.insert(token.clone(), flow);
        }
        token
    }

    pub fn start_registration(&self, flow: Registration) -> String {
        self.insert(Flow::Registration {
            flow,
            expires_at: now_secs() + FLOW_TTL_SECS,
        })
    }

    pub fn start_authentication(&self, flow: Authentication) -> String {
        self.insert(Flow::Authentication {
            flow,
            expires_at: now_secs() + FLOW_TTL_SECS,
        })
    }

    pub fn take_registration(&self, token: &str) -> Option<Registration> {
        let now = now_secs();
        let mut flows = self.flows.lock().ok()?;
        match flows.remove(token)? {
            Flow::Registration { flow, expires_at } if expires_at > now => Some(flow),
            _ => None,
        }
    }

    pub fn take_authentication(&self, token: &str) -> Option<Authentication> {
        let now = now_secs();
        let mut flows = self.flows.lock().ok()?;
        match flows.remove(token)? {
            Flow::Authentication { flow, expires_at } if expires_at > now => Some(flow),
            _ => None,
        }
    }
}

#[cfg(unix)]
pub fn build(cfg: &ApiConfig) -> Option<Arc<Webauthn>> {
    let origin = Url::parse(cfg.public_url.as_deref()?).ok()?;
    if origin.scheme() != "https" {
        return None;
    }
    let host = origin.host_str()?;
    if host.parse::<IpAddr>().is_ok() {
        return None;
    }
    let builder = WebauthnBuilder::new(host, &origin).ok()?;
    builder.rp_name("RYNXCP").build().ok().map(Arc::new)
}

#[cfg(not(unix))]
pub fn build(_cfg: &ApiConfig) -> Option<std::sync::Arc<WebauthnClient>> {
    None
}
