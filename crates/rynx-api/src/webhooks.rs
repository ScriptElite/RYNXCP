use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hmac::{Hmac, Mac};
use reqwest::Url;
use serde_json::{json, Value};
use sha2::Sha256;

use crate::state::ApiState;

pub const EVENTS: [&str; 5] = [
    "agent.alert",
    "certificate.issued",
    "certificate.failed",
    "backup.created",
    "website.cloned",
];

type HmacSha256 = Hmac<Sha256>;

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_v4(ip),
        IpAddr::V6(ip) => is_public_v6(ip),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.octets()[0] == 0
        || (ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]))
        || (ip.octets()[0] == 198 && matches!(ip.octets()[1], 18 | 19)))
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (ip.segments()[0] & 0xfe00) == 0xfc00
        || (ip.segments()[0] & 0xffc0) == 0xfe80)
}

pub async fn validate_url(raw: &str) -> Result<(String, IpAddr), String> {
    let url = Url::parse(raw.trim()).map_err(|_| "invalid webhook URL".to_string())?;
    if url.scheme() != "https" {
        return Err("webhook URLs must use HTTPS".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("webhook URLs cannot embed credentials".into());
    }
    let host = url
        .host_str()
        .ok_or_else(|| "invalid webhook host".to_string())?;
    let port = url.port_or_known_default().unwrap_or(443);
    let addresses: Vec<IpAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| "webhook host does not resolve".to_string())?
        .map(|item| item.ip())
        .collect();
    if addresses.is_empty() {
        return Err("webhook host does not resolve".into());
    }
    if addresses.iter().any(|ip| !is_public_ip(*ip)) {
        return Err("webhook host must resolve to a public address".into());
    }
    Ok((url.to_string(), addresses[0]))
}

pub fn validate_events(events: &[String]) -> Result<Vec<String>, String> {
    if events.is_empty() {
        return Err("at least one webhook event is required".into());
    }
    let mut out = Vec::new();
    for event in events {
        let event = event.trim();
        if !EVENTS.contains(&event) {
            return Err(format!("unsupported webhook event '{event}'"));
        }
        if !out.iter().any(|item| item == event) {
            out.push(event.to_string());
        }
    }
    Ok(out)
}

pub fn dispatch(state: &ApiState, event: &str, data: Value) {
    let targets = match state.db.webhooks_for_event(event) {
        Ok(targets) => targets,
        Err(err) => {
            tracing::warn!(error = %err, "webhook targets could not be loaded");
            return;
        }
    };
    if targets.is_empty() {
        return;
    }
    let body = json!({
        "event": event,
        "at": rynx_core::crypto::now_rfc3339(),
        "data": data,
    });
    let payload = match serde_json::to_vec(&body) {
        Ok(payload) => payload,
        Err(_) => return,
    };
    for target in targets {
        let payload = payload.clone();
        let event = event.to_string();
        tokio::spawn(async move {
            if let Err(err) = deliver(&target.url, &target.secret, &event, &payload).await {
                tracing::warn!(event = %event, error = %err, "webhook delivery failed");
            }
        });
    }
}

async fn deliver(url: &str, secret: &str, event: &str, payload: &[u8]) -> Result<(), String> {
    let (url, address) = validate_url(url).await?;
    let parsed = Url::parse(&url).map_err(|_| "invalid webhook URL".to_string())?;
    let host = parsed
        .host_str()
        .map(str::to_string)
        .ok_or_else(|| "invalid webhook URL".to_string())?;
    let port = parsed.port_or_known_default().unwrap_or(443);
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| "invalid webhook secret".to_string())?;
    mac.update(payload);
    let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .resolve(&host, std::net::SocketAddr::new(address, port))
        .build()
        .map_err(|err| err.to_string())?;
    let response = client
        .post(url)
        .header("content-type", "application/json")
        .header("x-rynx-event", event)
        .header("x-rynx-signature", signature)
        .body(payload.to_vec())
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if !response.status().is_success() {
        return Err(format!("webhook returned {}", response.status()));
    }
    Ok(())
}
