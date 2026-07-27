use std::{
    cmp::Ordering,
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use reqwest::{Client, Method, StatusCode, Url};
use tokio::{net::lookup_host, time::timeout};
use url::Host;

use crate::target_validation;

const MAXIMUM_ANSWERS: usize = 32;
const MAXIMUM_REDIRECT_HOPS: usize = 5;
const DNS_RESOLVE_MILLIS: u64 = 2_000;
const REQUEST_BODY_BYTES: usize = 65_536;
const RESPONSE_BODY_BYTES: usize = 65_536;
const WHOLE_OPERATION_MILLIS: u64 = 5_000;

pub(crate) async fn post_json(
    url: String,
    payload: Vec<u8>,
    allowlist: &[String],
) -> Result<StatusCode, String> {
    if payload.len() > REQUEST_BODY_BYTES {
        return Err(format!("request body exceeds {REQUEST_BODY_BYTES} bytes"));
    }
    let canonical = target_validation::validate_target(&url, allowlist)?;
    let url = Url::parse(&canonical).map_err(|error| format!("invalid callback URL: {error}"))?;
    let operation = send_bounded(url, payload, allowlist);
    timeout(Duration::from_millis(WHOLE_OPERATION_MILLIS), operation)
        .await
        .map_err(|_| format!("operation exceeded {WHOLE_OPERATION_MILLIS} ms"))?
}

async fn send_bounded(
    mut url: Url,
    mut payload: Vec<u8>,
    allowlist: &[String],
) -> Result<StatusCode, String> {
    let mut method = Method::POST;
    let mut send_content_type = true;
    let mut seen = HashSet::from([url.to_string()]);
    let mut redirect_hops = 0;

    loop {
        let client = pinned_client(&url, Duration::from_millis(WHOLE_OPERATION_MILLIS)).await?;
        let mut request = client.request(method.clone(), url.clone());
        if send_content_type {
            request = request.header(reqwest::header::CONTENT_TYPE, "application/json");
        }
        if !payload.is_empty() {
            request = request.body(payload.clone());
        }
        let mut response = request
            .send()
            .await
            .map_err(|error| format!("request failed: {error}"))?;
        let status = response.status();
        if is_manual_redirect(status) {
            if redirect_hops >= MAXIMUM_REDIRECT_HOPS {
                return Err(format!(
                    "redirect count exceeds {MAXIMUM_REDIRECT_HOPS} hops"
                ));
            }
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .ok_or_else(|| "redirect response is missing Location".to_string())?
                .to_str()
                .map_err(|_| "redirect Location is not valid text".to_string())?;
            let candidate = url
                .join(location)
                .map_err(|error| format!("invalid redirect Location: {error}"))?;
            let canonical = target_validation::validate_target(candidate.as_str(), allowlist)
                .map_err(|error| format!("redirect target rejected: {error}"))?;
            let next = Url::parse(&canonical)
                .map_err(|error| format!("invalid normalized redirect: {error}"))?;
            if url.scheme() == "https" && next.scheme() == "http" {
                return Err("HTTPS-to-HTTP redirect downgrade is forbidden".to_string());
            }
            if !seen.insert(next.to_string()) {
                return Err("redirect loop detected".to_string());
            }
            if status == StatusCode::SEE_OTHER {
                method = Method::GET;
                payload.clear();
                send_content_type = false;
            }
            url = next;
            redirect_hops += 1;
            continue;
        }

        let mut response_bytes = 0usize;
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    response_bytes = response_bytes.saturating_add(chunk.len());
                    if response_bytes > RESPONSE_BODY_BYTES {
                        return Err(format!("response body exceeds {RESPONSE_BODY_BYTES} bytes"));
                    }
                }
                Ok(None) => return Ok(status),
                Err(error) => return Err(format!("response read failed: {error}")),
            }
        }
    }
}

async fn pinned_client(url: &Url, operation_timeout: Duration) -> Result<Client, String> {
    let host = url
        .host()
        .ok_or_else(|| "normalized target has no host".to_string())?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "normalized target has no effective port".to_string())?;
    let addresses = match host {
        Host::Ipv4(address) => vec![IpAddr::V4(address)],
        Host::Ipv6(address) => vec![IpAddr::V6(address)],
        Host::Domain(domain) => resolve_complete(domain, port).await?,
    };
    let selected = validate_answers(addresses)?;
    let host_name = url
        .host_str()
        .ok_or_else(|| "normalized target has no hostname".to_string())?;
    Client::builder()
        .timeout(operation_timeout)
        .connect_timeout(operation_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .resolve(host_name, SocketAddr::new(selected, port))
        .build()
        .map_err(|error| format!("pinned client init: {error}"))
}

async fn resolve_complete(host: &str, port: u16) -> Result<Vec<IpAddr>, String> {
    let lookup = timeout(
        Duration::from_millis(DNS_RESOLVE_MILLIS),
        lookup_host((host, port)),
    )
    .await
    .map_err(|_| format!("DNS resolution exceeded {DNS_RESOLVE_MILLIS} ms"))?
    .map_err(|error| format!("DNS resolution failed: {error}"))?;
    let addresses: Vec<IpAddr> = lookup.map(|address| address.ip()).collect();
    if addresses.len() > MAXIMUM_ANSWERS {
        return Err(format!(
            "DNS answer set exceeds {MAXIMUM_ANSWERS} addresses"
        ));
    }
    Ok(addresses)
}

fn validate_answers(addresses: Vec<IpAddr>) -> Result<IpAddr, String> {
    if addresses.is_empty() {
        return Err("DNS answer set is empty".to_string());
    }
    if addresses.len() > MAXIMUM_ANSWERS {
        return Err(format!(
            "DNS answer set exceeds {MAXIMUM_ANSWERS} addresses"
        ));
    }
    if addresses
        .iter()
        .copied()
        .any(|address| !target_validation::is_public_ip(address))
    {
        return Err("DNS answer set contains a non-public address".to_string());
    }
    let mut unique: Vec<IpAddr> = addresses
        .into_iter()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    unique.sort_by(compare_addresses);
    unique
        .into_iter()
        .next()
        .ok_or_else(|| "DNS answer set is empty".to_string())
}

fn compare_addresses(left: &IpAddr, right: &IpAddr) -> Ordering {
    match (left, right) {
        (IpAddr::V4(left), IpAddr::V4(right)) => left.octets().cmp(&right.octets()),
        (IpAddr::V6(left), IpAddr::V6(right)) => left.octets().cmp(&right.octets()),
        (IpAddr::V4(_), IpAddr::V6(_)) => Ordering::Less,
        (IpAddr::V6(_), IpAddr::V4(_)) => Ordering::Greater,
    }
}

fn is_manual_redirect(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_the_complete_set_and_selects_deterministically() {
        let selected = validate_answers(vec![
            "2606:4700:4700::1111".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
        ])
        .unwrap();
        assert_eq!(selected, "1.1.1.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn mixed_public_and_non_public_answers_reject_as_a_unit() {
        let result = validate_answers(vec![
            "8.8.8.8".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
        ]);
        assert_eq!(
            result.unwrap_err(),
            "DNS answer set contains a non-public address"
        );
    }

    #[test]
    fn empty_oversized_and_non_contract_redirects_reject() {
        assert_eq!(
            validate_answers(Vec::new()).unwrap_err(),
            "DNS answer set is empty"
        );
        let addresses = (0..=MAXIMUM_ANSWERS)
            .map(|index| IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, index as u8)))
            .collect();
        assert!(
            validate_answers(addresses)
                .unwrap_err()
                .contains("exceeds 32 addresses")
        );
        assert!(!is_manual_redirect(StatusCode::MULTIPLE_CHOICES));
        assert_eq!(MAXIMUM_REDIRECT_HOPS, 5);
    }
}
