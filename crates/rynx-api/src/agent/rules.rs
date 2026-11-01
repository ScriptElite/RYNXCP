//! Deterministic rules. These run without an LLM and never touch the system.

use serde_json::json;

use rynx_core::crypto::sha256_hex;
use rynx_panel::AgentFindingInput;
use rynx_proto::CertificateStatus;

use super::collect::Snapshot;
use super::messages;

const FILTER_PROGRAMS: [&str; 4] = ["clamav", "clamav-milter", "spamassassin", "spamass-milter"];

struct RuleFinding {
    rule: &'static str,
    target: String,
    code: &'static str,
    params: serde_json::Value,
    severity: &'static str,
    category: &'static str,
    title: String,
    summary: String,
    evidence: Vec<String>,
    recommendation: &'static str,
}

impl RuleFinding {
    fn into_input(self, locale: &str) -> AgentFindingInput {
        let mut title = self.title;
        let mut summary = self.summary;
        let mut recommendation = self.recommendation.to_string();
        if locale != "es" {
            if let Some(text) = messages::localized(locale, self.code, &self.params) {
                title = text.title;
                summary = text.summary;
                recommendation = text.recommendation;
            }
        }
        let fingerprint = sha256_hex(format!("{}:{}", self.rule, self.target));
        AgentFindingInput {
            fingerprint,
            severity: self.severity.to_string(),
            category: self.category.to_string(),
            title,
            summary,
            evidence: self.evidence,
            recommendation,
            source: "rules".to_string(),
        }
    }
}

pub fn evaluate(snapshot: &Snapshot, locale: &str) -> Vec<AgentFindingInput> {
    let mut out: Vec<RuleFinding> = Vec::new();
    auth_rules(snapshot, &mut out);
    service_rules(snapshot, &mut out);
    filter_program_rules(snapshot, &mut out);
    filter_activity_rules(snapshot, &mut out);
    update_rules(snapshot, &mut out);
    resource_rules(snapshot, &mut out);
    certificate_rules(snapshot, &mut out);
    firewall_rules(snapshot, &mut out);
    out.into_iter()
        .map(|finding| finding.into_input(locale))
        .collect()
}

fn auth_rules(snapshot: &Snapshot, out: &mut Vec<RuleFinding>) {
    let stats = &snapshot.auth_stats;
    if stats.failures >= 20 {
        let severity = if stats.failures >= 100 {
            "critical"
        } else {
            "high"
        };
        out.push(RuleFinding {
            rule: "auth-failures",
            target: "panel".into(),
            code: "auth-failures",
            params: json!({ "failures": stats.failures, "unique_ips": stats.unique_ips }),
            severity,
            category: "security",
            title: "Intentos de acceso fallidos elevados".into(),
            summary: format!(
                "{} fallos de autenticación en las últimas 24 horas.",
                stats.failures
            ),
            evidence: vec![
                format!("fallos={}", stats.failures),
                format!("IPs únicas={}", stats.unique_ips),
            ],
            recommendation:
                "Revisa la vista Seguridad, bloquea las IPs sospechosas y comprueba fail2ban.",
        });
    }
    if stats.blocked >= 10 {
        out.push(RuleFinding {
            rule: "auth-blocked",
            target: "panel".into(),
            code: "auth-blocked",
            params: json!({ "blocked": stats.blocked }),
            severity: "medium",
            category: "security",
            title: "Bloqueos de autenticación".into(),
            summary: format!(
                "{} inicios de sesión bloqueados en las últimas 24 horas.",
                stats.blocked
            ),
            evidence: vec![format!("bloqueos={}", stats.blocked)],
            recommendation:
                "Comprueba si los bloqueos vienen de fuerza bruta o de usuarios legítimos.",
        });
    }
}

fn service_rules(snapshot: &Snapshot, out: &mut Vec<RuleFinding>) {
    for service in &snapshot.services {
        if !matches!(service.status.as_str(), "failed" | "inactive") {
            continue;
        }
        out.push(
            RuleFinding {
                rule: "service-failed",
                target: service.unit.clone(),
                code: "service-failed",
                params: json!({
                    "name": service.name,
                    "unit": service.unit,
                    "status": service.status
                }),
                severity: "high",
                category: "reliability",
                title: format!("Servicio caído: {}", service.name),
                summary: format!(
                    "La unidad {} no está funcionando correctamente (estado: {}) y puede afectar al hosting.",
                    service.unit, service.status
                ),
                evidence: vec![
                    format!("servicio={}", service.name),
                    format!("unidad={}", service.unit),
                    format!("estado={}", service.status),
                ],
                recommendation: "Revisa el estado del servicio y su journal; reinícialo desde Programas si procede.",
            }
        );
    }
}

fn filter_program_rules(snapshot: &Snapshot, out: &mut Vec<RuleFinding>) {
    let missing: Vec<&str> = snapshot
        .programs
        .iter()
        .filter(|program| {
            FILTER_PROGRAMS.contains(&program.name.as_str()) && program.status != "installed"
        })
        .map(|program| program.name.as_str())
        .collect();
    if !missing.is_empty() {
        out.push(RuleFinding {
            rule: "mail-filter-missing",
            target: "mail-filters".into(),
            code: "mail-filter-missing",
            params: json!({ "missing": missing.join(", ") }),
            severity: "high",
            category: "security",
            title: "Filtros de correo incompletos".into(),
            summary: format!(
                "Faltan componentes de antivirus/antispam: {}.",
                missing.join(", ")
            ),
            evidence: missing
                .iter()
                .map(|name| format!("ausente={name}"))
                .collect(),
            recommendation: "Reinstala el stack de correo con el instalador o desde Programas.",
        });
    }

    for program in &snapshot.programs {
        if program.status != "installed" || !FILTER_PROGRAMS.contains(&program.name.as_str()) {
            continue;
        }
        let Some(status) = program.service_status.as_deref() else {
            continue;
        };
        if matches!(status, "active" | "activating") {
            continue;
        }
        out.push(RuleFinding {
            rule: "mail-filter-inactive",
            target: program.name.clone(),
            code: "mail-filter-inactive",
            params: json!({ "name": program.name, "status": status }),
            severity: "high",
            category: "reliability",
            title: format!("Filtro de correo detenido: {}", program.name),
            summary: format!(
                "{} está instalado pero su unidad reporta '{}'.",
                program.name, status
            ),
            evidence: vec![
                format!("programa={}", program.name),
                format!("estado={status}"),
                format!("unidad={}", program.unit.clone().unwrap_or_default()),
            ],
            recommendation:
                "Reinicia el componente desde la vista Antivirus y antispam o desde Programas.",
        });
    }
}

fn filter_activity_rules(snapshot: &Snapshot, out: &mut Vec<RuleFinding>) {
    let mut alerts = snapshot
        .filter_events
        .iter()
        .filter(|event| event.kind == "antivirus" && event.severity == "alert");
    for event in alerts.by_ref().take(10) {
        out.push(
            RuleFinding {
                rule: "antivirus-detection",
                target: format!("{}:{}", event.service, event.message),
                code: "antivirus-detection",
                params: json!({
                    "service": event.service,
                    "message": event.message,
                    "at": event.at
                }),
                severity: "high",
                category: "security",
                title: format!("Detección de malware en {}", event.service),
                summary: event.message.clone(),
                evidence: vec![format!("fecha={}", event.at), format!("unidad={}", event.service)],
                recommendation: "Aísla el fichero, revisa el buzón o cuenta afectada y ejecuta un análisis completo.",
            }
        );
    }

    let spam = snapshot
        .filter_events
        .iter()
        .filter(|event| {
            event.kind == "antispam" && matches!(event.severity.as_str(), "warn" | "alert")
        })
        .count();
    if spam >= 50 {
        let severity = if spam >= 200 { "high" } else { "medium" };
        out.push(
            RuleFinding {
                rule: "antispam-volume",
                target: "mail".into(),
                code: "antispam-volume",
                params: json!({ "spam": spam }),
                severity,
                category: "security",
                title: "Volumen alto de spam reciente".into(),
                summary: format!("{spam} mensajes marcados o rechazados por SpamAssassin en el journal reciente."),
                evidence: vec![format!("eventos={spam}")],
                recommendation: "Revisa las reglas de SpamAssassin, el volumen de correo y si hay una campaña de spam en curso.",
            }
        );
    }
}

fn update_rules(snapshot: &Snapshot, out: &mut Vec<RuleFinding>) {
    let security: Vec<_> = snapshot
        .updates
        .iter()
        .filter(|update| update.security)
        .collect();
    if security.is_empty() {
        return;
    }
    let severity = if security.len() >= 10 {
        "high"
    } else {
        "medium"
    };
    out.push(RuleFinding {
        rule: "security-updates",
        target: "apt".into(),
        code: "security-updates",
        params: json!({ "count": security.len() }),
        severity,
        category: "maintenance",
        title: "Actualizaciones de seguridad pendientes".into(),
        summary: format!(
            "{} actualizaciones marcadas como de seguridad están pendientes.",
            security.len()
        ),
        evidence: security
            .iter()
            .take(10)
            .map(|update| {
                format!(
                    "{} {} -> {}",
                    update.package, update.current_version, update.candidate_version
                )
            })
            .collect(),
        recommendation:
            "Aplica las actualizaciones desde Programas durante una ventana de mantenimiento.",
    });
}

fn resource_rules(snapshot: &Snapshot, out: &mut Vec<RuleFinding>) {
    let Some(system) = &snapshot.system else {
        return;
    };
    if system.disk_total_kb > 0 {
        let used = system
            .disk_total_kb
            .saturating_sub(system.disk_available_kb);
        let percent = used as f64 / system.disk_total_kb as f64 * 100.0;
        if percent >= 80.0 {
            let severity = if percent >= 90.0 { "high" } else { "medium" };
            out.push(
                RuleFinding {
                    rule: "disk-usage",
                    target: "node".into(),
                    code: "disk-usage",
                    params: json!({ "percent": format!("{percent:.1}") }),
                    severity,
                    category: "reliability",
                    title: "Uso de disco elevado".into(),
                    summary: format!("El disco está al {percent:.1}% y puede llenarse."),
                    evidence: vec![
                        format!("total_kb={}", system.disk_total_kb),
                        format!("disponible_kb={}", system.disk_available_kb),
                    ],
                    recommendation: "Revisa backups, logs y cuentas con más consumo antes de que el disco se llene.",
                }
            );
        }
    }
    if system.mem_total_kb > 0 {
        let used = system.mem_total_kb.saturating_sub(system.mem_available_kb);
        let percent = used as f64 / system.mem_total_kb as f64 * 100.0;
        if percent >= 85.0 {
            let severity = if percent >= 95.0 { "high" } else { "medium" };
            out.push(
                RuleFinding {
                    rule: "memory-usage",
                    target: "node".into(),
                    code: "memory-usage",
                    params: json!({ "percent": format!("{percent:.1}") }),
                    severity,
                    category: "reliability",
                    title: "Memoria usada elevada".into(),
                    summary: format!("La memoria está al {percent:.1}% de uso."),
                    evidence: vec![
                        format!("total_kb={}", system.mem_total_kb),
                        format!("disponible_kb={}", system.mem_available_kb),
                    ],
                    recommendation: "Revisa procesos, contenedores y límites de aplicaciones antes de que el OOM killer actúe.",
                }
            );
        }
    }
    let cpus = system.cpu_count.max(1) as f64;
    let load1 = system.load.first().copied().unwrap_or(0) as f64 / 100.0;
    let per_cpu = load1 / cpus;
    if per_cpu >= 2.0 {
        let severity = if per_cpu >= 4.0 { "high" } else { "medium" };
        out.push(RuleFinding {
            rule: "load-average",
            target: "node".into(),
            code: "load-average",
            params: json!({ "per_cpu": format!("{per_cpu:.2}") }),
            severity,
            category: "reliability",
            title: "Carga del sistema elevada".into(),
            summary: format!("Load 1m por CPU: {per_cpu:.2}."),
            evidence: vec![
                format!("load1={load1:.2}"),
                format!("cpus={}", system.cpu_count),
            ],
            recommendation:
                "Identifica los procesos que consumen CPU y revisa las aplicaciones gestionadas.",
        });
    }
}

fn certificate_rules(snapshot: &Snapshot, out: &mut Vec<RuleFinding>) {
    let mut emitted = 0;
    for cert in &snapshot.certs {
        let (severity, label, code) = match cert.status {
            CertificateStatus::Expired => ("high", "vencido", "certificate-expired"),
            CertificateStatus::Expiring => ("medium", "por vencer", "certificate-expiring"),
            _ => continue,
        };
        out.push(RuleFinding {
            rule: "certificate",
            target: cert.domain.clone(),
            code,
            params: json!({ "domain": cert.domain, "not_after": cert.not_after }),
            severity,
            category: "security",
            title: format!("Certificado {label}: {}", cert.domain),
            summary: format!(
                "El certificado de {} está {} (vence {}).",
                cert.domain, label, cert.not_after
            ),
            evidence: vec![
                format!("dominio={}", cert.domain),
                format!("emisor={}", cert.issuer),
                format!("vence={}", cert.not_after),
            ],
            recommendation:
                "Renueva el certificado desde la vista Certificados o vuelve a publicar el sitio.",
        });
        emitted += 1;
        if emitted >= 10 {
            break;
        }
    }
}

fn firewall_rules(snapshot: &Snapshot, out: &mut Vec<RuleFinding>) {
    let Some(firewall) = &snapshot.firewall else {
        return;
    };
    let blocked = firewall.blocked.len();
    if blocked >= 200 {
        out.push(RuleFinding {
            rule: "firewall-blocks",
            target: "firewall".into(),
            code: "firewall-blocks",
            params: json!({ "blocked": blocked }),
            severity: "medium",
            category: "security",
            title: "Muchas IPs bloqueadas".into(),
            summary: format!("{blocked} direcciones IP están bloqueadas ahora mismo."),
            evidence: vec![format!("bloqueadas={blocked}")],
            recommendation:
                "Comprueba si hay un ataque distribuido y revisa las reglas de fail2ban.",
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rynx_panel::AuthStats;
    use rynx_proto::{
        CertView, CertificateStatus, FilterEvent, PackageUpdate, ProgramInfo, ServiceStat,
        SystemInfo,
    };

    fn base_snapshot() -> Snapshot {
        Snapshot {
            system: Some(SystemInfo {
                hostname: "node".into(),
                primary_ip: None,
                ssh_port: 22,
                os: "Debian".into(),
                kernel: "6.1".into(),
                uptime_secs: 100,
                load: [10, 10, 10],
                cpu_count: 4,
                mem_total_kb: 8_000_000,
                mem_available_kb: 6_000_000,
                disk_total_kb: 100_000_000,
                disk_available_kb: 70_000_000,
                daemon_version: "0.1.0".into(),
                mode: "simulation".into(),
            }),
            auth_stats: AuthStats::default(),
            ..Snapshot::default()
        }
    }

    #[test]
    fn reports_security_updates() {
        let mut snapshot = base_snapshot();
        snapshot.updates.push(PackageUpdate {
            package: "nginx".into(),
            current_version: "1.0".into(),
            candidate_version: "1.1".into(),
            security: true,
        });
        let findings = evaluate(&snapshot, "es");
        assert!(findings
            .iter()
            .any(|finding| finding.title.contains("seguridad")));
        assert!(findings.iter().any(|finding| finding.severity == "medium"));
    }

    #[test]
    fn reports_antivirus_alert() {
        let mut snapshot = base_snapshot();
        snapshot.filter_events.push(FilterEvent {
            at: "2026-01-01T00:00:00Z".into(),
            kind: "antivirus".into(),
            service: "clamav-milter".into(),
            severity: "alert".into(),
            message: "Eicar FOUND".into(),
        });
        let findings = evaluate(&snapshot, "es");
        assert!(findings.iter().any(|finding| {
            finding.category == "security"
                && finding.severity == "high"
                && finding.title.contains("malware")
        }));
    }

    #[test]
    fn reports_inactive_core_service() {
        let mut snapshot = base_snapshot();
        snapshot.services.push(ServiceStat {
            name: "mariadb".into(),
            kind: "database".into(),
            status: "inactive".into(),
            pid: 0,
            memory_kb: 0,
            cpu_percent: 0.0,
            uptime_secs: 0,
            unit: "mariadb".into(),
        });
        let findings = evaluate(&snapshot, "es");
        assert!(findings
            .iter()
            .any(|finding| { finding.severity == "high" && finding.title.contains("mariadb") }));
    }

    #[test]
    fn reports_auth_failures_and_missing_filters() {
        let mut snapshot = base_snapshot();
        snapshot.auth_stats.failures = 120;
        snapshot.programs.push(ProgramInfo {
            name: "spamass-milter".into(),
            version: "unknown".into(),
            kind: "mail".into(),
            status: "missing".into(),
            detail: "SMTP antispam".into(),
            unit: Some("spamass-milter".into()),
            service_status: Some("active".into()),
        });
        let findings = evaluate(&snapshot, "es");
        assert!(findings
            .iter()
            .any(|finding| finding.severity == "critical"));
        assert!(findings.iter().any(|finding| finding.severity == "high"));
    }

    #[test]
    fn reports_expired_certificate() {
        let mut snapshot = base_snapshot();
        snapshot.certs.push(CertView {
            domain: "example.com".into(),
            issuer: "test".into(),
            not_after: "2020-01-01".into(),
            status: CertificateStatus::Expired,
            path: "/etc/cert".into(),
        });
        let findings = evaluate(&snapshot, "es");
        assert!(findings
            .iter()
            .any(|finding| finding.title.contains("Certificado")));
    }

    #[test]
    fn findings_are_deterministic() {
        let snapshot = base_snapshot();
        let first = evaluate(&snapshot, "es");
        let second = evaluate(&snapshot, "es");
        assert_eq!(first.len(), second.len());
        for (left, right) in first.iter().zip(second.iter()) {
            assert_eq!(left.fingerprint, right.fingerprint);
        }
    }
}
