//! Strict validation of everything that reaches the privileged daemon.
//!
//! Validation happens at the trust boundary (API) and is repeated by the
//! daemon before any system mutation. The daemon never interpolates values
//! into a shell; every command is executed with an explicit argv.

use once_cell::sync::Lazy;
use regex::Regex;

use crate::{CoreError, CoreResult};
use rynx_proto::{
    AccountSpec, AppSpec, CronSpec, MailAccountSpec, MailDomainSpec, PhpPoolSpec, Runtime,
    WebsiteSpec,
};

static USERNAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-z][a-z0-9_]{2,23}$").unwrap());
static DOMAIN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$").unwrap());
static APP_NAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-z][a-z0-9-]{1,31}$").unwrap());
static VERSION_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[0-9]{1,2}(\.[0-9]{1,3}){0,2}$").unwrap());
static EMAIL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$").unwrap()
});
static MAIL_LOCAL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$").unwrap());
static ENV_KEY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$").unwrap());
static COMMAND_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$").unwrap());

pub const SUPPORTED_PHP: &[&str] = &["8.1", "8.2", "8.3", "8.4", "8.5"];

const RESERVED_USERNAMES: &[&str] = &[
    "root",
    "admin",
    "administrator",
    "www-data",
    "nginx",
    "mysql",
    "postgres",
    "rynx",
    "rynxd",
    "rynxcp",
    "systemd",
    "daemon",
    "bin",
    "sys",
    "nobody",
    "mail",
    "ftp",
    "sshd",
    "system",
    "operator",
    "support",
    "apache",
    "redis",
    "docker",
    "lxd",
    "git",
];

fn invalid(msg: impl Into<String>) -> CoreError {
    CoreError::Validation(msg.into())
}

pub fn validate_username(value: &str) -> CoreResult<()> {
    if !USERNAME_RE.is_match(value) {
        return Err(invalid(
            "username must match ^[a-z][a-z0-9_]{2,23}$ (lowercase, 3-24 chars)",
        ));
    }
    if RESERVED_USERNAMES.contains(&value) {
        return Err(invalid("username is reserved"));
    }
    Ok(())
}

/// Panel logins are a separate namespace from Linux accounts, so system names
/// such as `admin` are allowed here while still enforcing a strict shape.
pub fn validate_panel_username(value: &str) -> CoreResult<()> {
    if !USERNAME_RE.is_match(value) {
        return Err(invalid(
            "panel username must match ^[a-z][a-z0-9_]{2,23}$ (lowercase, 3-24 chars)",
        ));
    }
    Ok(())
}

pub fn validate_domain(value: &str) -> CoreResult<()> {
    if value.is_empty() || value.len() > 253 {
        return Err(invalid("domain length is invalid"));
    }
    if value != value.to_ascii_lowercase() {
        return Err(invalid("domain must be lowercase"));
    }
    if value.ends_with('.') || value.contains("..") || value.contains('*') {
        return Err(invalid("domain contains invalid characters"));
    }
    if !DOMAIN_RE.is_match(value) {
        return Err(invalid("domain is not a valid fully qualified hostname"));
    }
    let tld = value.rsplit('.').next().unwrap_or_default();
    if tld.len() < 2 {
        return Err(invalid("domain TLD is too short"));
    }
    Ok(())
}

pub fn validate_email(value: &str) -> CoreResult<()> {
    if value.len() > 254 || !EMAIL_RE.is_match(value) {
        return Err(invalid("email address is invalid"));
    }
    Ok(())
}

pub fn validate_app_name(value: &str) -> CoreResult<()> {
    if !APP_NAME_RE.is_match(value) {
        return Err(invalid(
            "application name must match ^[a-z][a-z0-9-]{1,31}$",
        ));
    }
    Ok(())
}

pub fn validate_php_version(value: &str) -> CoreResult<()> {
    if !SUPPORTED_PHP.contains(&value) {
        return Err(invalid(format!(
            "unsupported PHP version; allowed: {}",
            SUPPORTED_PHP.join(", ")
        )));
    }
    Ok(())
}

pub fn validate_runtime_version(value: &str) -> CoreResult<()> {
    if value.len() > 16 || !VERSION_RE.is_match(value) {
        return Err(invalid("runtime version must look like 22 or 3.12.1"));
    }
    Ok(())
}

pub fn validate_port(port: u16) -> CoreResult<()> {
    if port < 1024 {
        return Err(invalid("application port must be >= 1024"));
    }
    Ok(())
}

/// Relative path rooted inside an account home. Used for docroots and
/// entrypoints. Rejects absolute paths, traversal and platform separators.
pub fn validate_relative_path(value: &str, field: &str) -> CoreResult<()> {
    if value.is_empty() || value.len() > 200 {
        return Err(invalid(format!("{field} length is invalid")));
    }
    if value.starts_with('/') || value.starts_with('\\') {
        return Err(invalid(format!("{field} must be relative")));
    }
    if value.contains('\\') || value.contains('\0') || value.contains(':') {
        return Err(invalid(format!("{field} contains forbidden characters")));
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(invalid(format!("{field} contains control characters")));
    }
    for segment in value.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(invalid(format!("{field} contains an invalid path segment")));
        }
        if segment.len() > 100 {
            return Err(invalid(format!("{field} segment is too long")));
        }
    }
    Ok(())
}

pub fn validate_docroot(value: &str) -> CoreResult<()> {
    validate_relative_path(value, "docroot")?;
    let first = value.split('/').next().unwrap_or_default();
    if first.starts_with('.') || matches!(first, "apps" | "logs" | "tmp" | "Maildir" | "sieve") {
        return Err(invalid(
            "docroot must not point at an internal account directory",
        ));
    }
    Ok(())
}

pub const MAX_DISK_LIMIT_MB: u64 = 10_485_760;

pub fn validate_disk_limit(mb: u64) -> CoreResult<()> {
    if !(1..=MAX_DISK_LIMIT_MB).contains(&mb) {
        return Err(invalid(format!(
            "disk_limit_mb must be between 1 and {MAX_DISK_LIMIT_MB}"
        )));
    }
    Ok(())
}

pub fn validate_command(engine: &str, command: &str) -> CoreResult<()> {
    let allow: &[&str] = match engine {
        "node" => &["node", "nodejs"],
        "python" => &["python3", "gunicorn", "uvicorn"],
        "ruby" => &["ruby", "bundle", "puma", "rackup"],
        "java" => &["java"],
        "dotnet" => &["dotnet"],
        "go" => {
            validate_relative_path(command, "command")?;
            return Ok(());
        }
        _ => return Err(invalid("runtime does not accept an application command")),
    };
    if !allow.contains(&command) {
        return Err(invalid(format!(
            "command '{command}' is not allowed for {engine}; allowed: {}",
            allow.join(", ")
        )));
    }
    Ok(())
}

pub fn validate_args(args: &[String]) -> CoreResult<()> {
    if args.len() > 32 {
        return Err(invalid("too many application arguments"));
    }
    let mut total = 0usize;
    for arg in args {
        if arg.len() > 512 {
            return Err(invalid("application argument is too long"));
        }
        if arg.contains('\0') || arg.contains('\n') || arg.contains('\r') {
            return Err(invalid(
                "application argument contains forbidden characters",
            ));
        }
        total += arg.len();
    }
    if total > 4096 {
        return Err(invalid("application arguments are too large"));
    }
    Ok(())
}

pub fn validate_env(env: &std::collections::BTreeMap<String, String>) -> CoreResult<()> {
    if env.len() > 64 {
        return Err(invalid("too many environment variables"));
    }
    for (key, value) in env {
        if !ENV_KEY_RE.is_match(key) {
            return Err(invalid(format!("invalid environment variable name: {key}")));
        }
        if key.starts_with("LD_") || key == "PATH" || key == "IFS" {
            return Err(invalid(format!("environment variable {key} is reserved")));
        }
        if value.len() > 4096 {
            return Err(invalid(format!("environment variable {key} is too long")));
        }
        if value.contains('\0') || value.contains('\n') || value.contains('\r') {
            return Err(invalid(format!(
                "environment variable {key} contains a newline"
            )));
        }
    }
    Ok(())
}

pub fn validate_runtime(runtime: &Runtime) -> CoreResult<()> {
    match runtime {
        Runtime::Static | Runtime::Go => Ok(()),
        Runtime::Php { version } => validate_php_version(version),
        Runtime::Node { version }
        | Runtime::Python { version }
        | Runtime::Ruby { version }
        | Runtime::Java { version }
        | Runtime::Dotnet { version } => validate_runtime_version(version),
    }
}

pub fn validate_account_spec(spec: &AccountSpec) -> CoreResult<()> {
    validate_username(&spec.username)?;
    validate_email(&spec.email)?;
    validate_disk_limit(spec.disk_limit_mb)?;
    if spec.memory_mb > 1_048_576 {
        return Err(invalid("memory_mb must be between 0 and 1048576"));
    }
    if spec.cpu_percent > 100_000 {
        return Err(invalid("cpu_percent must be between 0 and 100000"));
    }
    if spec.process_limit > 100_000 {
        return Err(invalid("process_limit must be between 0 and 100000"));
    }
    if let Some(version) = &spec.php_version {
        validate_php_version(version)?;
    }
    Ok(())
}

pub const SUPPORTED_LOCALES: &[&str] =
    &["es", "en", "pt", "fr", "ar", "ru", "zh", "ja", "it", "de"];

pub fn validate_locale(locale: &str) -> CoreResult<()> {
    if !SUPPORTED_LOCALES.contains(&locale) {
        return Err(invalid("unsupported locale"));
    }
    Ok(())
}

pub fn validate_website_spec(spec: &WebsiteSpec) -> CoreResult<()> {
    validate_domain(&spec.domain)?;
    validate_username(&spec.username)?;
    validate_docroot(&spec.docroot)?;
    validate_runtime(&spec.runtime)?;
    if let Some(locale) = &spec.locale {
        validate_locale(locale)?;
    }

    if spec.aliases.len() > 20 {
        return Err(invalid("too many domain aliases"));
    }
    for alias in &spec.aliases {
        validate_domain(alias)?;
        if alias == &spec.domain {
            return Err(invalid("alias duplicates the primary domain"));
        }
    }

    match &spec.runtime {
        Runtime::Static => {
            if spec.app.is_some() {
                return Err(invalid("static websites cannot reference an application"));
            }
        }
        Runtime::Php { .. } => {
            if spec.app.is_some() {
                return Err(invalid("PHP websites cannot reference an application"));
            }
            if spec.tls == rynx_proto::TlsMode::LetsEncrypt && spec.aliases.is_empty() {
                // allowed, but ACME needs the primary domain only
            }
        }
        _ => {
            let app = spec
                .app
                .as_deref()
                .ok_or_else(|| invalid("managed runtime requires an application name"))?;
            validate_app_name(app)?;
        }
    }
    Ok(())
}

pub fn validate_mail_domain_spec(spec: &MailDomainSpec) -> CoreResult<()> {
    validate_domain(&spec.domain)?;
    validate_username(&spec.username)?;
    if let Some(target) = &spec.catch_all {
        if !target.trim().is_empty() {
            validate_email(target)?;
        }
    }
    Ok(())
}

pub fn validate_mail_account_spec(spec: &MailAccountSpec) -> CoreResult<()> {
    validate_domain(&spec.domain)?;
    if !MAIL_LOCAL_RE.is_match(&spec.local_part) {
        return Err(invalid(
            "mailbox name must be lowercase and match ^[a-z0-9][a-z0-9._-]{0,62}$",
        ));
    }
    if spec.local_part.contains("..") {
        return Err(invalid("mailbox name contains an invalid dot sequence"));
    }
    if let Some(id) = &spec.id {
        if id.len() < 8
            || id.len() > 64
            || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(invalid("mailbox id is invalid"));
        }
    }
    if !(64..=1_048_576).contains(&spec.quota_mb) {
        return Err(invalid("mailbox quota must be between 64 and 1048576 MB"));
    }
    if let Some(password) = &spec.password {
        validate_mail_password(password)?;
    } else if spec.id.is_none() {
        return Err(invalid("a password is required for a new mailbox"));
    }
    if spec.aliases.len() > 50 || spec.forward_to.len() > 50 {
        return Err(invalid("too many aliases or forwarding targets"));
    }
    for alias in &spec.aliases {
        validate_email(alias)?;
        let Some((_, domain)) = alias.rsplit_once('@') else {
            return Err(invalid("alias address is invalid"));
        };
        if domain != spec.domain {
            return Err(invalid("aliases must belong to the mailbox domain"));
        }
    }
    for target in &spec.forward_to {
        validate_email(target)?;
    }
    Ok(())
}

pub fn validate_mail_password(password: &str) -> CoreResult<()> {
    if !(12..=128).contains(&password.len()) {
        return Err(invalid(
            "mailbox password must be between 12 and 128 characters",
        ));
    }
    if password.chars().any(|c| c.is_control()) {
        return Err(invalid("mailbox password contains control characters"));
    }
    let classes = [
        password.chars().any(|c| c.is_ascii_lowercase()),
        password.chars().any(|c| c.is_ascii_uppercase()),
        password.chars().any(|c| c.is_ascii_digit()),
        password.chars().any(|c| !c.is_ascii_alphanumeric()),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if classes < 3 {
        return Err(invalid(
            "mailbox password must combine at least 3 character classes",
        ));
    }
    Ok(())
}

pub fn validate_php_pool_spec(spec: &PhpPoolSpec) -> CoreResult<()> {
    validate_username(&spec.username)?;
    validate_php_version(&spec.version)?;
    if !(1..=64).contains(&spec.max_children) {
        return Err(invalid("max_children must be between 1 and 64"));
    }
    if !(16..=2048).contains(&spec.memory_limit_mb) {
        return Err(invalid("memory_limit_mb must be between 16 and 2048"));
    }
    if !(1..=4096).contains(&spec.upload_max_mb) {
        return Err(invalid("upload_max_mb must be between 1 and 4096"));
    }
    Ok(())
}

pub fn validate_app_spec(spec: &AppSpec) -> CoreResult<()> {
    validate_username(&spec.username)?;
    validate_app_name(&spec.name)?;
    validate_runtime(&spec.runtime)?;
    if !spec.runtime.supports_app() {
        return Err(invalid(
            "application runtime must be one of node, python, ruby, java, dotnet or go",
        ));
    }
    validate_port(spec.port)?;
    validate_relative_path(&spec.entrypoint, "entrypoint")?;
    if !COMMAND_RE.is_match(&spec.command) {
        return Err(invalid("application command is malformed"));
    }
    validate_command(spec.runtime.engine(), &spec.command)?;
    validate_args(&spec.args)?;
    validate_env(&spec.env)?;
    Ok(())
}

pub fn validate_dns_name(name: &str) -> CoreResult<()> {
    if name.is_empty() || name.len() > 100 {
        return Err(invalid("DNS record name length is invalid"));
    }
    if name == "@" || name == "*" {
        return Ok(());
    }
    if name != name.to_ascii_lowercase() {
        return Err(invalid("DNS record name must be lowercase"));
    }
    if name.starts_with('.') || name.ends_with('.') || name.contains("..") {
        return Err(invalid("DNS record name has an invalid dot sequence"));
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(invalid("DNS label length is invalid"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(invalid("DNS label cannot start or end with a hyphen"));
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
        {
            return Err(invalid("DNS label contains forbidden characters"));
        }
    }
    Ok(())
}

pub fn validate_dns_type(rtype: &str) -> CoreResult<()> {
    const ALLOWED: &[&str] = &["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA"];
    if !ALLOWED.contains(&rtype) {
        return Err(invalid(format!(
            "DNS record type must be one of {}",
            ALLOWED.join(", ")
        )));
    }
    Ok(())
}

pub fn validate_dns_value(rtype: &str, value: &str, priority: Option<u16>) -> CoreResult<()> {
    if value.is_empty() || value.len() > 2048 {
        return Err(invalid("DNS record value length is invalid"));
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(invalid("DNS record value contains control characters"));
    }
    match rtype {
        "A" => {
            if value.parse::<std::net::Ipv4Addr>().is_err() {
                return Err(invalid("A record value must be an IPv4 address"));
            }
        }
        "AAAA" => {
            if value.parse::<std::net::Ipv6Addr>().is_err() {
                return Err(invalid("AAAA record value must be an IPv6 address"));
            }
        }
        "CNAME" | "NS" => validate_domain(value)?,
        "MX" => {
            validate_domain(value)?;
            if priority.is_none() {
                return Err(invalid("MX records require a priority"));
            }
        }
        "TXT" => {
            if value.len() > 2048 {
                return Err(invalid("TXT record is too long"));
            }
        }
        "SRV" => {
            let parts: Vec<&str> = value.split_whitespace().collect();
            if parts.len() != 4
                || parts[0].parse::<u16>().is_err()
                || parts[1].parse::<u16>().is_err()
                || parts[2].parse::<u16>().is_err()
                || validate_domain(parts[3]).is_err()
            {
                return Err(invalid("SRV value must be 'priority weight port target'"));
            }
        }
        "CAA" => {
            let parts: Vec<&str> = value.split_whitespace().collect();
            if parts.len() < 3
                || parts[0].parse::<u8>().is_err()
                || !matches!(parts[1], "issue" | "issuewild" | "iodef")
            {
                return Err(invalid("CAA value must be 'flags tag \"value\"'"));
            }
        }
        _ => return Err(invalid("unsupported DNS record type")),
    }
    Ok(())
}

pub fn validate_dns_record_spec(spec: &rynx_proto::DnsRecordSpec) -> CoreResult<()> {
    validate_domain(&spec.domain)?;
    validate_dns_name(&spec.name)?;
    validate_dns_type(&spec.rtype)?;
    if !(60..=86400).contains(&spec.ttl) {
        return Err(invalid("DNS TTL must be between 60 and 86400"));
    }
    validate_dns_value(&spec.rtype, &spec.value, spec.priority)?;
    Ok(())
}

/// Short user-provided database name; the account prefix is added later.
pub fn validate_database_name(value: &str) -> CoreResult<()> {
    if value.is_empty()
        || value.len() > 32
        || !value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        || !value
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    {
        return Err(invalid(
            "database name must be 1-32 chars, start with a letter or digit and contain only a-z, 0-9 or _",
        ));
    }
    Ok(())
}

/// Validate a five-field cron schedule using numeric/operator characters.
pub fn validate_cron_schedule(value: &str) -> CoreResult<()> {
    let fields: Vec<&str> = value.split_whitespace().collect();
    if fields.len() != 5 || value.len() > 128 {
        return Err(invalid(
            "cron schedule must contain exactly five fields (minute hour day month weekday)",
        ));
    }
    for field in fields {
        if !field
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '*' | '/' | ',' | '-'))
        {
            return Err(invalid(
                "cron schedule fields only accept digits and * / , -",
            ));
        }
    }
    Ok(())
}

/// Validate a cron command. Commands run as the account's own Unix user.
pub fn validate_cron_command(value: &str) -> CoreResult<()> {
    if value.trim().is_empty() || value.len() > 1024 {
        return Err(invalid(
            "cron command must be between 1 and 1024 characters",
        ));
    }
    if value.chars().any(|c| matches!(c, '\n' | '\r' | '\0' | '%')) {
        return Err(invalid(
            "cron command cannot contain newlines, NUL or the % character",
        ));
    }
    Ok(())
}

pub fn validate_cron_spec(spec: &CronSpec) -> CoreResult<()> {
    validate_username(&spec.username)?;
    validate_cron_schedule(&spec.schedule)?;
    validate_cron_command(&spec.command)?;
    if let Some(id) = &spec.id {
        if id.len() < 8
            || id.len() > 64
            || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(invalid("cron job id is invalid"));
        }
    }
    Ok(())
}

/// Deterministic, collision-resistant MariaDB identifier for a domain.
pub fn db_identifier(domain: &str) -> String {
    let mut out = String::from("rynx_");
    let mut last_underscore = false;
    for ch in domain.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_underscore = false;
        } else if !last_underscore {
            out.push('_');
            last_underscore = true;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    if out.len() > 32 {
        out.truncate(32);
    }
    while out.ends_with('_') {
        out.pop();
    }
    out
}

pub fn validate_ftp_spec(spec: &rynx_proto::FtpSpec) -> CoreResult<()> {
    validate_domain(&spec.domain)?;
    validate_panel_username(&spec.username)?;
    if let Some(password) = &spec.password {
        if password.len() < 12 || password.len() > 128 {
            return Err(invalid(
                "FTP password must be between 12 and 128 characters",
            ));
        }
        if password.chars().any(|c| c.is_control()) {
            return Err(invalid("FTP password contains control characters"));
        }
    }
    Ok(())
}

pub fn validate_ip_or_cidr(value: &str) -> CoreResult<()> {
    let value = value.trim();
    if value.is_empty() || value.len() > 64 {
        return Err(invalid("IP address length is invalid"));
    }
    if let Some((ip, prefix)) = value.split_once('/') {
        let addr: std::net::IpAddr = ip
            .parse()
            .map_err(|_| invalid("invalid IP address in CIDR"))?;
        let prefix: u8 = prefix.parse().map_err(|_| invalid("invalid CIDR prefix"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(invalid("CIDR prefix is out of range"));
        }
    } else {
        value
            .parse::<std::net::IpAddr>()
            .map_err(|_| invalid("invalid IP address"))?;
    }
    Ok(())
}

pub fn validate_ban_ip(value: &str) -> CoreResult<()> {
    validate_ip_or_cidr(value)?;
    if let Some((ip, prefix)) = value.split_once('/') {
        let addr: std::net::IpAddr = ip.parse().map_err(|_| invalid("invalid IP address"))?;
        let prefix: u8 = prefix.parse().map_err(|_| invalid("invalid CIDR prefix"))?;
        if addr.is_loopback() || addr.is_unspecified() {
            return Err(invalid("refusing to ban loopback or unspecified networks"));
        }
        let too_wide = if addr.is_ipv4() {
            prefix < 8
        } else {
            prefix < 16
        };
        if too_wide {
            return Err(invalid("refusing to ban an excessively wide network"));
        }
        return Ok(());
    }
    let ip: std::net::IpAddr = value.parse().map_err(|_| invalid("invalid IP address"))?;
    if ip.is_loopback() || ip.is_unspecified() {
        return Err(invalid("refusing to ban loopback or unspecified addresses"));
    }
    Ok(())
}

pub fn validate_firewall_rule_spec(spec: &rynx_proto::FirewallRuleSpec) -> CoreResult<()> {
    if !matches!(spec.action.as_str(), "allow" | "deny") {
        return Err(invalid("firewall action must be allow or deny"));
    }
    if !matches!(spec.proto.as_str(), "tcp" | "udp" | "any") {
        return Err(invalid("firewall protocol must be tcp, udp or any"));
    }
    if spec.port == 0 {
        return Err(invalid("firewall port must be between 1 and 65535"));
    }
    if let Some(source) = &spec.source {
        if !source.trim().is_empty() {
            validate_ip_or_cidr(source)?;
        }
    }
    if spec.comment.len() > 120 || spec.comment.chars().any(|c| c.is_control()) {
        return Err(invalid("firewall comment is invalid"));
    }
    Ok(())
}

/// Metadata keys accepted by managed application units.
pub fn unit_name(username: &str, app: &str) -> String {
    format!("rynxcp-{username}-{app}.service")
}

pub fn php_pool_name(username: &str) -> String {
    format!("rynx-{username}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames_are_strict() {
        assert!(validate_username("acme").is_ok());
        assert!(validate_username("a_b_c").is_ok());
        assert!(validate_username("Root").is_err());
        assert!(validate_username("root").is_err());
        assert!(validate_username("ab").is_err());
        assert!(validate_username("has space").is_err());
        assert!(validate_username("admin123").is_ok());
    }

    #[test]
    fn domains_reject_traversal_and_ips() {
        assert!(validate_domain("example.com").is_ok());
        assert!(validate_domain("sub.example.co.uk").is_ok());
        assert!(validate_domain("Example.com").is_err());
        assert!(validate_domain("example.com.").is_err());
        assert!(validate_domain("127.0.0.1").is_err());
        assert!(validate_domain("-bad.com").is_err());
        assert!(validate_domain("example..com").is_err());
    }

    #[test]
    fn paths_cannot_escape() {
        assert!(validate_docroot("public_html").is_ok());
        assert!(validate_docroot("public/app").is_ok());
        assert!(validate_docroot("../etc").is_err());
        assert!(validate_docroot("/etc").is_err());
        assert!(validate_docroot("a\\b").is_err());
        assert!(validate_docroot("a//b").is_err());
        assert!(validate_docroot("c:evil").is_err());
        assert!(validate_docroot(".php/sessions").is_err());
        assert!(validate_docroot("apps").is_err());
        assert!(validate_docroot("logs").is_err());
        assert!(validate_docroot("tmp").is_err());
    }

    #[test]
    fn commands_are_allowlisted() {
        assert!(validate_command("node", "node").is_ok());
        assert!(validate_command("node", "bash").is_err());
        assert!(validate_command("python", "gunicorn").is_ok());
        assert!(validate_command("python", "sh").is_err());
        assert!(validate_command("go", "bin/server").is_ok());
        assert!(validate_command("go", "../server").is_err());
        assert!(validate_command("php", "php").is_err());
    }

    #[test]
    fn env_is_restricted() {
        let mut env = std::collections::BTreeMap::new();
        env.insert("APP_KEY".into(), "value".into());
        assert!(validate_env(&env).is_ok());
        env.insert("LD_PRELOAD".into(), "/tmp/x.so".into());
        assert!(validate_env(&env).is_err());
        env.insert("BAD-KEY".into(), "x".into());
        assert!(validate_env(&env).is_err());
    }
}
