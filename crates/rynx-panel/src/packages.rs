use serde::{Deserialize, Serialize};

use crate::db::PanelError;

/// Upper bound for every package limit. Zero means "unlimited".
pub const MAX_LIMIT: u64 = 1000;
pub const MIN_BACKUPS: u64 = 1;
pub const MAX_BACKUPS: u64 = 3;
pub const MAX_NAMESERVERS: usize = 16;
pub const MAX_MEMORY_MB: u64 = 1_048_576;
pub const MAX_CPU_PERCENT: u64 = 100_000;
pub const MAX_PROCESSES: u64 = 100_000;

pub const WEB_BACKENDS: &[&str] = &[
    "static", "php", "node", "python", "ruby", "java", "dotnet", "go",
];
pub const NGINX_TEMPLATES: &[&str] = &["caching", "hosting", "suspended"];
pub const DNS_TEMPLATES: &[&str] = &["child-ns", "no-mail", "gmail", "office365", "zoho"];

/// Editable package (hosting plan) fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageInput {
    pub name: String,
    pub account_mb: u64,
    pub bandwidth_mb: u64,
    pub backups: u64,
    pub incremental_backup: bool,
    pub web_domains: u64,
    pub web_aliases: u64,
    pub web_backend: String,
    pub nginx_template: String,
    pub dns_template: String,
    pub dns_zones: u64,
    pub dns_records: u64,
    pub nameservers: Vec<String>,
    pub mail_domains: u64,
    pub mail_accounts: u64,
    pub mail_rate_limit: u64,
    pub databases: u64,
    pub system_databases: u64,
    #[serde(default)]
    pub ftp_accounts: u64,
    /// Aggregate cgroup memory limit for the account, in MB. Zero is unlimited.
    #[serde(default)]
    pub memory_mb: u64,
    /// Aggregate cgroup CPU limit for the account, in percent. Zero is unlimited.
    #[serde(default)]
    pub cpu_percent: u64,
    /// Aggregate task/process limit for the account. Zero is unlimited.
    #[serde(default)]
    pub process_limit: u64,
}

/// Stored package plus its identity and timestamps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageView {
    pub id: String,
    pub is_default: bool,
    #[serde(flatten)]
    pub package: PackageInput,
    pub created_at: String,
    pub updated_at: String,
}

/// Package assigned to a hosting account, with the account-level backend override.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountPackageView {
    pub account: String,
    pub package_id: String,
    pub package_name: String,
    pub web_backend: String,
}

/// The seeded, editable package used as the installation default.
pub fn default_package() -> PackageInput {
    PackageInput {
        name: "Por defecto".into(),
        account_mb: 0,
        bandwidth_mb: 0,
        backups: MAX_BACKUPS,
        incremental_backup: false,
        web_domains: 0,
        web_aliases: 0,
        web_backend: "php".into(),
        nginx_template: "hosting".into(),
        dns_template: "child-ns".into(),
        dns_zones: 0,
        dns_records: 0,
        nameservers: vec!["ns1.example.tld".into(), "ns2.example.tld".into()],
        mail_domains: 0,
        mail_accounts: 0,
        mail_rate_limit: 200,
        databases: 0,
        system_databases: 0,
        ftp_accounts: 0,
        memory_mb: 0,
        cpu_percent: 0,
        process_limit: 0,
    }
}

/// Validates and normalizes a package before it is stored.
pub fn normalize_and_validate(mut input: PackageInput) -> Result<PackageInput, PanelError> {
    input.name = input.name.trim().to_string();
    if input.name.is_empty() {
        return Err(PanelError::Validation(
            "the package name is required".into(),
        ));
    }
    if input.name.chars().count() > 80 {
        return Err(PanelError::Validation(
            "the package name must be 80 characters or fewer".into(),
        ));
    }

    for (field, value) in [
        ("account_mb", input.account_mb),
        ("bandwidth_mb", input.bandwidth_mb),
        ("web_domains", input.web_domains),
        ("web_aliases", input.web_aliases),
        ("dns_zones", input.dns_zones),
        ("dns_records", input.dns_records),
        ("mail_domains", input.mail_domains),
        ("mail_accounts", input.mail_accounts),
        ("mail_rate_limit", input.mail_rate_limit),
        ("databases", input.databases),
        ("system_databases", input.system_databases),
        ("ftp_accounts", input.ftp_accounts),
    ] {
        if value > MAX_LIMIT {
            return Err(PanelError::Validation(format!(
                "{field} must be between 0 and {MAX_LIMIT}"
            )));
        }
    }
    if input.memory_mb > MAX_MEMORY_MB {
        return Err(PanelError::Validation(format!(
            "memory_mb must be between 0 and {MAX_MEMORY_MB}"
        )));
    }
    if input.cpu_percent > MAX_CPU_PERCENT {
        return Err(PanelError::Validation(format!(
            "cpu_percent must be between 0 and {MAX_CPU_PERCENT}"
        )));
    }
    if input.process_limit > MAX_PROCESSES {
        return Err(PanelError::Validation(format!(
            "process_limit must be between 0 and {MAX_PROCESSES}"
        )));
    }
    if !(MIN_BACKUPS..=MAX_BACKUPS).contains(&input.backups) {
        return Err(PanelError::Validation(format!(
            "backups must be between {MIN_BACKUPS} and {MAX_BACKUPS}"
        )));
    }

    input.web_backend = input.web_backend.trim().to_string();
    if !WEB_BACKENDS.contains(&input.web_backend.as_str()) {
        return Err(PanelError::Validation(format!(
            "invalid web backend '{}'",
            input.web_backend
        )));
    }
    input.nginx_template = input.nginx_template.trim().to_string();
    if !NGINX_TEMPLATES.contains(&input.nginx_template.as_str()) {
        return Err(PanelError::Validation(format!(
            "invalid nginx template '{}'",
            input.nginx_template
        )));
    }
    input.dns_template = input.dns_template.trim().to_string();
    if !DNS_TEMPLATES.contains(&input.dns_template.as_str()) {
        return Err(PanelError::Validation(format!(
            "invalid DNS template '{}'",
            input.dns_template
        )));
    }

    input.nameservers = input
        .nameservers
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect();
    if input.nameservers.is_empty() {
        return Err(PanelError::Validation(
            "at least one nameserver is required".into(),
        ));
    }
    if input.nameservers.len() > MAX_NAMESERVERS {
        return Err(PanelError::Validation(format!(
            "at most {MAX_NAMESERVERS} nameservers are allowed"
        )));
    }
    for nameserver in &input.nameservers {
        rynx_core::validate_domain(nameserver).map_err(|err| {
            PanelError::Validation(format!("invalid nameserver '{nameserver}': {err}"))
        })?;
    }
    let mut seen = std::collections::HashSet::new();
    input.nameservers.retain(|value| seen.insert(value.clone()));

    Ok(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> PackageInput {
        default_package()
    }

    #[test]
    fn accepts_zero_as_unlimited_and_normalizes() {
        let mut input = valid();
        input.name = "  Starter  ".into();
        input.account_mb = 0;
        input.nameservers = vec![
            "NS1.Example.TLD".into(),
            "ns1.example.tld".into(),
            "".into(),
        ];
        let input = normalize_and_validate(input).unwrap();
        assert_eq!(input.name, "Starter");
        assert_eq!(input.account_mb, 0);
        assert_eq!(input.nameservers, vec!["ns1.example.tld"]);
    }

    #[test]
    fn rejects_out_of_range_and_unknown_values() {
        let mut input = valid();
        input.account_mb = 1001;
        assert!(matches!(
            normalize_and_validate(input),
            Err(PanelError::Validation(_))
        ));

        let mut input = valid();
        input.backups = 4;
        assert!(matches!(
            normalize_and_validate(input),
            Err(PanelError::Validation(_))
        ));

        let mut input = valid();
        input.web_backend = "perl".into();
        assert!(matches!(
            normalize_and_validate(input),
            Err(PanelError::Validation(_))
        ));

        let mut input = valid();
        input.nameservers = vec!["not a domain".into()];
        assert!(matches!(
            normalize_and_validate(input),
            Err(PanelError::Validation(_))
        ));
    }
}
