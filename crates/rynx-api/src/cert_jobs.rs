use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::Mutex;

use rynx_core::crypto::random_hex;
use rynx_proto::{CertView, Request, Response};

use crate::state::ApiState;

const JOB_TTL: Duration = Duration::from_secs(15 * 60);
const RUNNING_TTL: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, Clone, Serialize)]
pub struct CertJobView {
    pub id: String,
    pub domain: String,
    pub status: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<CertView>,
}

pub struct CertJob {
    pub view: CertJobView,
    pub actor: String,
    pub started: Instant,
    pub finished: Option<Instant>,
}

pub type CertJobs = Arc<Mutex<HashMap<String, CertJob>>>;

pub fn new_store() -> CertJobs {
    Arc::new(Mutex::new(HashMap::new()))
}

pub async fn start(
    state: &ApiState,
    domain: &str,
    email: &str,
    staging: bool,
    actor: &str,
) -> CertJobView {
    let request = Request::CertIssue {
        domain: domain.to_string(),
        email: email.to_string(),
        staging,
    };
    spawn(state, domain, actor, request, "requesting certificate").await
}

pub async fn start_mail_tls(
    state: &ApiState,
    domain: &str,
    email: &str,
    actor: &str,
) -> CertJobView {
    let webmail = format!("webmail.{domain}");
    let request = Request::MailTls {
        domain: domain.to_string(),
        email: email.to_string(),
    };
    spawn(
        state,
        &webmail,
        actor,
        request,
        "requesting webmail certificate",
    )
    .await
}

/// Issue a certificate in the foreground so callers such as the one-click
/// installer can finish only after Nginx has the certificate installed.
pub async fn issue_now(
    state: &ApiState,
    domain: &str,
    email: &str,
    staging: bool,
    actor: &str,
) -> Result<CertView, String> {
    let request = Request::CertIssue {
        domain: domain.to_string(),
        email: email.to_string(),
        staging,
    };
    let result = state.daemon.call(request, actor).await;
    match result {
        Ok(Response::Cert { cert }) => {
            crate::webhooks::dispatch(
                state,
                "certificate.issued",
                serde_json::json!({ "domain": domain, "message": "certificate issued" }),
            );
            Ok(cert)
        }
        Ok(_) => Err("daemon returned an unexpected certificate response".into()),
        Err(err) => {
            crate::webhooks::dispatch(
                state,
                "certificate.failed",
                serde_json::json!({ "domain": domain, "message": err.to_string() }),
            );
            Err(err.to_string())
        }
    }
}

async fn spawn(
    state: &ApiState,
    domain: &str,
    actor: &str,
    request: Request,
    message: &str,
) -> CertJobView {
    let id = random_hex(12);
    let view = CertJobView {
        id: id.clone(),
        domain: domain.to_string(),
        status: "running".into(),
        message: message.into(),
        certificate: None,
    };
    {
        let mut jobs = state.cert_jobs.lock().await;
        prune(&mut jobs);
        let existing = jobs
            .values()
            .find(|job| job.actor == actor && job.view.domain == domain && job.finished.is_none())
            .map(|job| job.view.clone());
        if let Some(view) = existing {
            return view;
        }
        jobs.insert(
            id.clone(),
            CertJob {
                view: view.clone(),
                actor: actor.to_string(),
                started: Instant::now(),
                finished: None,
            },
        );
    }

    let jobs = state.cert_jobs.clone();
    let daemon = state.daemon.clone();
    let mailer = state.mailer.clone();
    let alert_to = state.cfg.smtp_alert_to.clone();
    let alert_locale = alert_to
        .as_deref()
        .and_then(|to| state.db.find_user_by_email(to).ok().flatten())
        .and_then(|user| user.locale);
    let actor = actor.to_string();
    let webhook_state = state.clone();
    tokio::spawn(async move {
        let result = daemon.call(request, &actor).await;
        let outcome = {
            let mut jobs = jobs.lock().await;
            let Some(job) = jobs.get_mut(&id) else {
                return;
            };
            match result {
                Ok(Response::Cert { cert }) => {
                    job.view.status = "succeeded".into();
                    job.view.message = "certificate issued".into();
                    job.view.certificate = Some(cert);
                }
                Ok(_) => {
                    job.view.status = "failed".into();
                    job.view.message = "daemon returned an unexpected response".into();
                }
                Err(err) => {
                    job.view.status = "failed".into();
                    job.view.message = err.to_string();
                }
            }
            job.finished = Some(Instant::now());
            (
                job.view.status.clone(),
                job.view.domain.clone(),
                job.view.message.clone(),
            )
        };

        crate::webhooks::dispatch(
            &webhook_state,
            if outcome.0 == "failed" {
                "certificate.failed"
            } else {
                "certificate.issued"
            },
            serde_json::json!({
                "domain": outcome.1,
                "message": outcome.2,
            }),
        );

        if outcome.0 == "failed" {
            tracing::warn!(
                domain = %outcome.1,
                error = %outcome.2,
                "certificate job failed"
            );
            if let (Some(mailer), Some(to)) = (mailer, alert_to) {
                let (subject, body) = crate::email::certificate_failure_text(
                    alert_locale.as_deref(),
                    &outcome.1,
                    &outcome.2,
                );
                if let Err(err) = mailer.send(&to, &subject, &body).await {
                    tracing::warn!(
                        domain = %outcome.1,
                        error = %err,
                        "certificate alert email could not be sent"
                    );
                }
            }
        } else {
            tracing::info!(domain = %outcome.1, "certificate job succeeded");
        }
    });
    view
}

pub async fn get(state: &ApiState, id: &str, actor: &str) -> Option<CertJobView> {
    let mut jobs = state.cert_jobs.lock().await;
    prune(&mut jobs);
    jobs.get(id)
        .filter(|job| job.actor == actor)
        .map(|job| job.view.clone())
}

fn prune(jobs: &mut HashMap<String, CertJob>) {
    jobs.retain(|_, job| match job.finished {
        Some(finished) => finished.elapsed() < JOB_TTL,
        None => job.started.elapsed() < RUNNING_TTL,
    });
}
