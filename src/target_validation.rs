use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde_json::Value;
use url::{Host, Url};

const FIXTURE: &str = include_str!("../contracts/rooted-path-target-validation-v1.fixture.json");
const SCHEMA: &str = include_str!("../contracts/rooted-path-target-validation-v1.schema.json");

#[derive(Clone, Debug, Eq, PartialEq)]
struct AllowedTarget {
    scheme: String,
    host: String,
    port: u16,
    path: String,
    canonical: String,
}

pub(crate) fn validate_embedded_contract() -> Result<(), String> {
    let fixture: Value =
        serde_json::from_str(FIXTURE).map_err(|error| format!("contract fixture: {error}"))?;
    let _: Value =
        serde_json::from_str(SCHEMA).map_err(|error| format!("contract schema: {error}"))?;
    if fixture["contract"] != "clavenar.rooted-path-target-validation/v1"
        || fixture.pointer("/targets/credentialsAllowed") != Some(&Value::Bool(false))
        || fixture.pointer("/targets/fragmentsAllowed") != Some(&Value::Bool(false))
        || fixture.pointer("/targets/redirects") != Some(&Value::String("disabled".to_string()))
    {
        return Err("embedded rooted path/target contract is weakened".to_string());
    }
    Ok(())
}

pub(crate) fn normalize_allowlist_strings(entries: &[String]) -> Result<Vec<String>, String> {
    parse_allowlist(entries).map(|rules| rules.into_iter().map(|rule| rule.canonical).collect())
}

pub(crate) fn validate_target(raw: &str, entries: &[String]) -> Result<String, String> {
    let allowlist = parse_allowlist(entries)?;
    if allowlist.is_empty() {
        return Err("empty allowlist denies all targets".to_string());
    }
    let normalized = normalize(raw, false)?;
    if !allowlist.iter().any(|allowed| {
        allowed.scheme == normalized.scheme
            && allowed.host == normalized.host
            && allowed.port == normalized.port
            && path_matches(&allowed.path, &normalized.path)
    }) {
        return Err("normalized target is outside the configured allowlist".to_string());
    }
    Ok(normalized.canonical)
}

fn parse_allowlist(entries: &[String]) -> Result<Vec<AllowedTarget>, String> {
    entries
        .iter()
        .map(|entry| {
            let normalized = normalize(entry, true)?;
            Ok(AllowedTarget {
                scheme: normalized.scheme,
                host: normalized.host,
                port: normalized.port,
                path: normalized.path,
                canonical: normalized.canonical,
            })
        })
        .collect()
}

struct NormalizedTarget {
    scheme: String,
    host: String,
    port: u16,
    path: String,
    canonical: String,
}

fn normalize(raw: &str, allowlist_entry: bool) -> Result<NormalizedTarget, String> {
    validate_percent_encoding(raw)?;
    let mut url = Url::parse(raw).map_err(|error| format!("invalid URL: {error}"))?;
    let scheme = url.scheme().to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https") {
        return Err("only http and https schemes are allowed".to_string());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("URL credentials are forbidden".to_string());
    }
    if url.fragment().is_some() {
        return Err("URL fragments are forbidden".to_string());
    }
    if allowlist_entry && url.query().is_some() {
        return Err("allowlist entries cannot contain a query".to_string());
    }
    let host = normalize_host(
        url.host()
            .ok_or_else(|| "URL host is required".to_string())?,
    )?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "URL effective port is required".to_string())?;
    let path = normalize_path(url.path());
    url.set_host(Some(&host))
        .map_err(|_| "normalized URL host is invalid".to_string())?;
    if allowlist_entry {
        url.set_path(&path);
    }
    let canonical = url.to_string();
    Ok(NormalizedTarget {
        scheme,
        host,
        port,
        path,
        canonical,
    })
}

fn normalize_host(host: Host<&str>) -> Result<String, String> {
    match host {
        Host::Domain(domain) => {
            let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
            if normalized.is_empty()
                || !normalized.contains('.')
                || normalized == "localhost"
                || normalized.ends_with(".localhost")
                || normalized.ends_with(".local")
                || normalized.ends_with(".internal")
                || normalized.ends_with(".home.arpa")
            {
                return Err("local-use or single-label host is forbidden".to_string());
            }
            Ok(normalized)
        }
        Host::Ipv4(address) => {
            if is_public_ipv4(address) {
                Ok(address.to_string())
            } else {
                Err("non-public IPv4 target is forbidden".to_string())
            }
        }
        Host::Ipv6(address) => {
            if is_public_ipv6(address) {
                Ok(address.to_string())
            } else {
                Err("non-public IPv6 target is forbidden".to_string())
            }
        }
    }
}

fn normalize_path(path: &str) -> String {
    if path == "/" {
        return "/".to_string();
    }
    path.trim_end_matches('/').to_string()
}

fn path_matches(allowed: &str, requested: &str) -> bool {
    allowed == "/"
        || requested == allowed
        || requested
            .strip_prefix(allowed)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn validate_percent_encoding(raw: &str) -> Result<(), String> {
    let bytes = raw.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return Err("invalid percent encoding".to_string());
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    Ok(())
}

pub(crate) fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }
    let segments = address.segments();
    let first = segments[0];
    let ipv4_compatible = segments[..6] == [0, 0, 0, 0, 0, 0];
    let global_unicast = (first & 0xe000) == 0x2000;
    let documentation = first == 0x2001 && segments[1] == 0x0db8;
    let benchmarking = first == 0x2001 && segments[1] == 0x0002;
    let teredo = first == 0x2001 && segments[1] == 0;
    let orchid = first == 0x2001 && (segments[1] & 0xffe0) == 0x0020;
    global_unicast
        && !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_multicast()
        && !ipv4_compatible
        && !documentation
        && !benchmarking
        && !teredo
        && !orchid
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowlist() -> Vec<String> {
        normalize_allowlist_strings(&["https://callback.example.com/hil".to_string()]).unwrap()
    }

    #[test]
    fn embedded_contract_is_exact_and_strict() {
        validate_embedded_contract().unwrap();
    }

    #[test]
    fn matches_normalized_origin_and_segment_boundary() {
        let rules = allowlist();
        assert!(validate_target("HTTPS://CALLBACK.EXAMPLE.COM:443/hil", &rules).is_ok());
        assert!(validate_target("https://callback.example.com/hil/result?q=1", &rules).is_ok());
        assert!(validate_target("https://callback.example.com/hil-evil", &rules).is_err());
        assert!(validate_target("https://callback.example.com.evil/hil", &rules).is_err());
        assert!(validate_target("http://callback.example.com/hil", &rules).is_err());
    }

    #[test]
    fn rejects_userinfo_fragments_encoded_local_ips_and_local_names() {
        let rules = allowlist();
        for target in [
            "https://user@callback.example.com/hil",
            "https://callback.example.com/hil#fragment",
            "http://localhost/hil",
            "http://service/hil",
            "http://127.0.0.1/hil",
            "http://2130706433/hil",
            "http://0x7f000001/hil",
            "http://169.254.169.254/latest/meta-data",
            "http://[::1]/hil",
        ] {
            assert!(
                validate_target(target, &rules).is_err(),
                "{target} was accepted"
            );
        }
    }

    #[test]
    fn invalid_allowlist_entries_fail_startup_normalization() {
        for entry in [
            "https://user@example.com/",
            "https://localhost/",
            "https://example.com/path?query=1",
            "file:///tmp/callback",
        ] {
            assert!(
                normalize_allowlist_strings(&[entry.to_string()]).is_err(),
                "{entry} was accepted"
            );
        }
    }

    #[test]
    fn dns_answer_classifier_rejects_every_non_public_class() {
        for address in [
            "0.0.0.0",
            "10.1.2.3",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "203.0.113.1",
            "224.0.0.1",
            "::",
            "::1",
            "2001:db8::1",
            "fc00::1",
            "fe80::1",
            "ff00::1",
        ] {
            let address = address.parse().unwrap();
            assert!(!is_public_ip(address), "{address} was accepted");
        }
        assert!(is_public_ip("8.8.8.8".parse().unwrap()));
        assert!(is_public_ip("2606:4700:4700::1111".parse().unwrap()));
    }
}
