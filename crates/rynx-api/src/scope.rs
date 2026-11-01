//! Per-account scoping for panel users linked to a hosting account.

use std::collections::HashSet;

use rynx_proto::{Request, Response as DaemonResponse};

use crate::{auth::AuthUser, error::ApiError, state::ApiState};

/// Domains owned by the account. Used to scope resources that only carry a
/// domain (databases, FTP, DNS, certificates).
pub async fn account_domains(
    state: &ApiState,
    actor: &str,
    account: &str,
) -> Result<HashSet<String>, ApiError> {
    let response = state.daemon.call(Request::WebsiteList, actor).await?;
    let mut domains = HashSet::new();
    if let DaemonResponse::Websites { websites } = response {
        for website in websites {
            if website.spec.username == account {
                domains.insert(website.spec.domain);
            }
        }
    }
    Ok(domains)
}

fn filter(response: DaemonResponse, account: &str, domains: &HashSet<String>) -> DaemonResponse {
    match response {
        DaemonResponse::Accounts { mut accounts } => {
            accounts.retain(|item| item.spec.username == account);
            DaemonResponse::Accounts { accounts }
        }
        DaemonResponse::Websites { mut websites } => {
            websites.retain(|item| item.spec.username == account);
            DaemonResponse::Websites { websites }
        }
        DaemonResponse::Apps { mut apps } => {
            apps.retain(|item| item.spec.username == account);
            DaemonResponse::Apps { apps }
        }
        DaemonResponse::PhpPools { mut pools } => {
            pools.retain(|item| item.spec.username == account);
            DaemonResponse::PhpPools { pools }
        }
        DaemonResponse::Backups { mut backups } => {
            backups.retain(|item| item.username == account);
            DaemonResponse::Backups { backups }
        }
        DaemonResponse::CronJobs { mut jobs } => {
            jobs.retain(|item| item.username == account);
            DaemonResponse::CronJobs { jobs }
        }
        DaemonResponse::Databases { mut databases } => {
            databases.retain(|item| domains.contains(&item.domain));
            DaemonResponse::Databases { databases }
        }
        DaemonResponse::Ftps { accounts: mut ftps } => {
            ftps.retain(|item| domains.contains(&item.domain));
            DaemonResponse::Ftps { accounts: ftps }
        }
        DaemonResponse::DnsZones { mut zones } => {
            zones.retain(|item| domains.contains(&item.domain));
            DaemonResponse::DnsZones { zones }
        }
        DaemonResponse::Certs { mut certs } => {
            certs.retain(|item| domains.contains(&item.domain));
            DaemonResponse::Certs { certs }
        }
        other => other,
    }
}

/// Filter a list response for a linked panel user. Global users receive the
/// unmodified response.
pub async fn list_response(
    state: &ApiState,
    auth: &AuthUser,
    response: DaemonResponse,
) -> Result<DaemonResponse, ApiError> {
    if let Some(account) = auth.scoped_account() {
        let domains = account_domains(state, &auth.user.username, account).await?;
        Ok(filter(response, account, &domains))
    } else {
        Ok(response)
    }
}

/// Return the website record for a domain, including its owning account.
pub async fn website_for_domain(
    state: &ApiState,
    actor: &str,
    domain: &str,
) -> Result<rynx_proto::WebsiteView, ApiError> {
    let response = state.daemon.call(Request::WebsiteList, actor).await?;
    let DaemonResponse::Websites { websites } = response else {
        return Err(ApiError::internal("unexpected daemon response"));
    };
    websites
        .into_iter()
        .find(|website| website.spec.domain.eq_ignore_ascii_case(domain))
        .ok_or_else(|| ApiError::NotFound(format!("website '{domain}' not found")))
}

/// Ensure a domain belongs to the linked account (no-op for global users).
pub async fn ensure_domain(
    state: &ApiState,
    auth: &AuthUser,
    domain: &str,
) -> Result<(), ApiError> {
    if let Some(account) = auth.scoped_account() {
        let domains = account_domains(state, &auth.user.username, account).await?;
        if !domains.contains(domain) {
            return Err(ApiError::Forbidden);
        }
    }
    Ok(())
}

/// A linked user may create new websites only for their account and may not
/// take over an existing domain owned by another account.
pub async fn ensure_website_upsert(
    state: &ApiState,
    auth: &AuthUser,
    domain: &str,
    username: &str,
) -> Result<(), ApiError> {
    if let Some(account) = auth.scoped_account() {
        if username != account {
            return Err(ApiError::Forbidden);
        }
        let response = state
            .daemon
            .call(Request::WebsiteList, &auth.user.username)
            .await?;
        if let DaemonResponse::Websites { websites } = response {
            if let Some(existing) = websites
                .into_iter()
                .find(|item| item.spec.domain.eq_ignore_ascii_case(domain))
            {
                if existing.spec.username != account {
                    return Err(ApiError::Forbidden);
                }
            }
        }
    }
    Ok(())
}

/// Ensure a backup belongs to the linked account.
pub async fn ensure_backup(state: &ApiState, auth: &AuthUser, id: &str) -> Result<(), ApiError> {
    if let Some(account) = auth.scoped_account() {
        let response = state
            .daemon
            .call(Request::BackupList, &auth.user.username)
            .await?;
        let allowed = matches!(
            response,
            DaemonResponse::Backups { backups }
                if backups.iter().any(|item| item.id == id && item.username == account)
        );
        if !allowed {
            return Err(ApiError::Forbidden);
        }
    }
    Ok(())
}

/// Ensure a database belongs to the linked account.
pub async fn ensure_database(state: &ApiState, auth: &AuthUser, id: &str) -> Result<(), ApiError> {
    if let Some(account) = auth.scoped_account() {
        let domains = account_domains(state, &auth.user.username, account).await?;
        let response = state
            .daemon
            .call(Request::DatabaseList, &auth.user.username)
            .await?;
        let allowed = matches!(
            response,
            DaemonResponse::Databases { databases }
                if databases
                    .iter()
                    .any(|item| item.id == id && domains.contains(&item.domain))
        );
        if !allowed {
            return Err(ApiError::Forbidden);
        }
    }
    Ok(())
}

/// Ensure an FTP user belongs to the linked account.
pub async fn ensure_ftp(state: &ApiState, auth: &AuthUser, id: &str) -> Result<(), ApiError> {
    if let Some(account) = auth.scoped_account() {
        let domains = account_domains(state, &auth.user.username, account).await?;
        let response = state
            .daemon
            .call(Request::FtpList, &auth.user.username)
            .await?;
        let allowed = matches!(
            response,
            DaemonResponse::Ftps { accounts }
                if accounts
                    .iter()
                    .any(|item| item.id == id && domains.contains(&item.domain))
        );
        if !allowed {
            return Err(ApiError::Forbidden);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rynx_proto::{AccountSpec, AccountView};

    fn account(username: &str) -> AccountView {
        AccountView {
            id: username.into(),
            spec: AccountSpec {
                username: username.into(),
                email: format!("{username}@example.com"),
                disk_limit_mb: 1024,
                memory_mb: 0,
                cpu_percent: 0,
                process_limit: 0,
                php_version: None,
                enabled: true,
                ssh_enabled: false,
            },
            uid: 2000,
            home: format!("/home/{username}"),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn filters_account_lists() {
        let response = DaemonResponse::Accounts {
            accounts: vec![account("acme"), account("other")],
        };
        let filtered = filter(response, "acme", &HashSet::new());
        match filtered {
            DaemonResponse::Accounts { accounts } => {
                assert_eq!(accounts.len(), 1);
                assert_eq!(accounts[0].spec.username, "acme");
            }
            _ => panic!("unexpected response"),
        }
    }
}
