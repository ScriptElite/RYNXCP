use std::sync::Arc;

use rynx_core::ApiConfig;
use rynx_panel::PanelDb;

use crate::cert_jobs::CertJobs;
use crate::daemon::DaemonClient;
use crate::email::Mailer;
use crate::installer::InstallerJobs;
use crate::ratelimit::LoginLimiter;
use crate::two_factor::TwoFactor;
use crate::webauthn::{PasskeyFlows, WebauthnClient};

#[derive(Clone)]
pub struct ApiState {
    pub cfg: Arc<ApiConfig>,
    pub db: Arc<PanelDb>,
    pub daemon: Arc<DaemonClient>,
    pub limiter: Arc<LoginLimiter>,
    pub reset_limiter: Arc<LoginLimiter>,
    pub cert_jobs: CertJobs,
    pub installer_jobs: InstallerJobs,
    pub mailer: Option<Arc<Mailer>>,
    pub two_factor: Arc<TwoFactor>,
    pub webauthn: Option<Arc<WebauthnClient>>,
    pub passkey_flows: Arc<PasskeyFlows>,
    pub agent_lock: Arc<tokio::sync::Mutex<()>>,
    /// Serializes panel-user and hosting-account creation so email and
    /// username uniqueness checks cannot race across the two databases.
    pub identity_lock: Arc<tokio::sync::Mutex<()>>,
}
