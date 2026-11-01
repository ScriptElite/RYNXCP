//! Deterministic system analyzer.
//!
//! The agent only reads state through the daemon and the panel database. It
//! stores findings, deduplicates them by fingerprint, optionally enriches them
//! with a local or external LLM and emails new or escalating high/critical
//! findings. It never executes remediation.

pub mod collect;
pub mod messages;
pub mod provider;
pub mod redact;
pub mod rules;

use std::time::Duration;

use rynx_core::crypto::{now_rfc3339, now_unix, random_hex};
use rynx_panel::{AgentFinding, AgentRun, Role};

use crate::state::ApiState;

/// Locale used for deterministic findings and alert emails. It follows the
/// most recently active owner/administrator, then the owner or first
/// administrator, and finally Spanish.
pub(crate) fn agent_locale(state: &ApiState) -> String {
    if let Ok(Some(locale)) = state.db.latest_admin_locale() {
        if !locale.is_empty() {
            return locale;
        }
    }
    let Ok(users) = state.db.list_users() else {
        return "es".to_string();
    };
    users
        .iter()
        .find(|user| user.role == Role::Owner)
        .or_else(|| users.iter().find(|user| user.role == Role::Admin))
        .and_then(|user| user.locale.clone())
        .unwrap_or_else(|| "es".to_string())
}

pub struct RunSummary {
    pub run: AgentRun,
    pub new_findings: usize,
    pub total_findings: usize,
    pub notified: usize,
}

/// Runs one analysis under the shared agent lock. `locale` overrides the
/// detected administrator language, so a manual run answers in the language of
/// the administrator who triggered it.
pub async fn run_once(state: &ApiState, locale: Option<String>) -> Result<RunSummary, String> {
    let _guard = state.agent_lock.lock().await;
    let started_at = now_rfc3339();
    let locale = locale
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| agent_locale(state));
    let snapshot = collect::collect(state, state.cfg.agent.max_events).await;
    if snapshot.system.is_none() && snapshot.services.is_empty() && snapshot.programs.is_empty() {
        let run = AgentRun {
            id: random_hex(8),
            started_at: started_at.clone(),
            finished_at: now_rfc3339(),
            status: "error".into(),
            findings: 0,
            error: "daemon unavailable".into(),
            model: "rules".into(),
            summary: String::new(),
        };
        if let Err(err) = state.db.record_agent_run(&run) {
            tracing::warn!(error = %err, "agent run could not be recorded");
        }
        return Err("daemon unavailable".into());
    }

    let mut findings = rules::evaluate(&snapshot, &locale);
    let enhancement = provider::enhance(state, &snapshot, &findings, &locale)
        .await
        .unwrap_or_else(|err| {
            tracing::warn!(
                error = %err,
                "local agent provider unavailable; continuing with rules"
            );
            provider::Enhancement::default()
        });
    findings.extend(enhancement.findings);
    let model = if enhancement.model.is_empty() {
        "rules".to_string()
    } else {
        enhancement.model
    };
    let summary = enhancement.summary;
    let run_started_unix = now_unix();
    let mut new_findings = 0usize;
    let mut alerts: Vec<AgentFinding> = Vec::new();
    for finding in &findings {
        match state.db.upsert_agent_finding(finding) {
            Ok((stored, is_new, escalated, reopened)) => {
                if is_new {
                    new_findings += 1;
                }
                if (is_new || escalated || reopened)
                    && matches!(stored.severity.as_str(), "critical" | "high")
                {
                    alerts.push(stored);
                }
            }
            Err(err) => tracing::warn!(error = %err, "agent finding could not be stored"),
        }
    }
    match state.db.resolve_stale_agent_findings(run_started_unix) {
        Ok(resolved) if resolved > 0 => {
            tracing::info!(
                resolved,
                "agent resolved findings that are no longer present"
            )
        }
        Ok(_) => {}
        Err(err) => tracing::warn!(error = %err, "stale agent findings could not be resolved"),
    }

    let run = AgentRun {
        id: random_hex(8),
        started_at,
        finished_at: now_rfc3339(),
        status: "ok".into(),
        findings: findings.len() as i64,
        error: String::new(),
        model,
        summary,
    };
    if let Err(err) = state.db.record_agent_run(&run) {
        tracing::warn!(error = %err, "agent run could not be recorded");
    }
    if !alerts.is_empty() {
        crate::webhooks::dispatch(
            state,
            "agent.alert",
            serde_json::json!({
                "findings": alerts
                    .iter()
                    .map(|finding| serde_json::json!({
                        "severity": finding.severity,
                        "category": finding.category,
                        "title": finding.title,
                        "summary": finding.summary,
                    }))
                    .collect::<Vec<_>>(),
            }),
        );
    }
    let notified = notify(state, &alerts, &locale).await;

    Ok(RunSummary {
        run,
        new_findings,
        total_findings: findings.len(),
        notified,
    })
}

/// Starts the background scheduler. Disabled when `agent.enabled = false`.
pub fn spawn(state: ApiState) {
    if !state.cfg.agent.enabled {
        tracing::info!("agent disabled by configuration");
        return;
    }
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(20)).await;
        loop {
            match run_once(&state, None).await {
                Ok(summary) => tracing::info!(
                    findings = summary.total_findings,
                    new = summary.new_findings,
                    notified = summary.notified,
                    "agent analysis completed"
                ),
                Err(err) => tracing::warn!(error = %err, "agent analysis failed"),
            }
            let secs = state.cfg.agent.interval_secs.clamp(60, 86_400);
            tokio::time::sleep(Duration::from_secs(secs)).await;
        }
    });
}

async fn notify(state: &ApiState, findings: &[AgentFinding], locale: &str) -> usize {
    if findings.is_empty() {
        return 0;
    }
    if !state.cfg.agent.email_alerts {
        tracing::info!(
            findings = findings.len(),
            "agent alert skipped: email_alerts is disabled"
        );
        return 0;
    }
    let Some(to) = state.cfg.smtp_alert_to.as_deref() else {
        tracing::warn!(
            findings = findings.len(),
            "agent alert skipped: smtp_alert_to is not configured"
        );
        return 0;
    };
    let Some(mailer) = state.mailer.as_ref() else {
        tracing::warn!(
            findings = findings.len(),
            "agent alert skipped: SMTP is not configured"
        );
        return 0;
    };
    let (recommendation_label, severity_label) = messages::email_labels(locale);
    let subject = messages::email_subject(locale, findings.len());
    let body = findings
        .iter()
        .take(20)
        .map(|finding| {
            format!(
                "{}: {}\n{} [{}]\n{}\n{}: {}\n",
                severity_label,
                finding.severity.to_uppercase(),
                finding.title,
                finding.category,
                finding.summary,
                recommendation_label,
                finding.recommendation
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    match mailer.send(to, &subject, &body).await {
        Ok(()) => findings.len(),
        Err(err) => {
            tracing::warn!(error = %err, "agent alert email could not be sent");
            0
        }
    }
}
