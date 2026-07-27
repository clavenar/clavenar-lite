//! Fail-closed validation for internet-hosted Clavenar Lite templates.
//!
//! The developer profile intentionally keeps the one-command local posture.
//! Hosted templates must opt into this validator explicitly and cannot start
//! with anonymous, ephemeral, unbounded, or adapter-incompatible settings.

use std::{
    path::{Component, Path},
    str::FromStr,
    time::Duration,
};

use crate::upstream_adapter::UpstreamAdapter;

pub const MINIMUM_TOKEN_BYTES: usize = 32;
pub const MINIMUM_RATE_LIMIT_QPS: f64 = 0.1;
pub const MAXIMUM_RATE_LIMIT_QPS: f64 = 100.0;
pub const MINIMUM_RATE_LIMIT_BURST: u32 = 1;
pub const MAXIMUM_RATE_LIMIT_BURST: u32 = 200;
pub const MAXIMUM_UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DeploymentProfile {
    #[default]
    Developer,
    Hosted,
}

impl FromStr for DeploymentProfile {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "developer" => Ok(Self::Developer),
            "hosted" => Ok(Self::Hosted),
            other => Err(format!(
                "unknown deployment profile {other:?}; expected developer or hosted"
            )),
        }
    }
}

#[derive(Debug)]
pub struct HostedSafetyConfig<'a> {
    pub profile: DeploymentProfile,
    pub agent_token: Option<&'a str>,
    pub agents: Option<&'a str>,
    pub decide_token: Option<&'a str>,
    pub deciders: Option<&'a str>,
    pub enforce_mode: bool,
    pub verbose_verdicts: bool,
    pub rate_limit_qps: Option<f64>,
    pub rate_limit_burst: Option<u32>,
    pub ledger_path: &'a str,
    pub upstream_url: &'a str,
    pub upstream_adapter: UpstreamAdapter,
    pub upstream_timeout: Duration,
}

pub fn validate(config: &HostedSafetyConfig<'_>) -> Result<(), String> {
    if config.profile == DeploymentProfile::Developer {
        return Ok(());
    }
    crate::hosted_safety_contract::validate_embedded_contract()?;

    let agent_tokens =
        configured_tokens("agent authentication", config.agent_token, config.agents)?;
    let operator_tokens = configured_tokens(
        "operator authentication",
        config.decide_token,
        config.deciders,
    )?;
    for agent in &agent_tokens {
        for operator in &operator_tokens {
            if constant_time_eq(agent.as_bytes(), operator.as_bytes()) {
                return Err(
                    "hosted profile requires disjoint agent and operator credentials".to_string(),
                );
            }
        }
    }

    if !config.enforce_mode {
        return Err("hosted profile requires enforce mode".to_string());
    }
    if config.verbose_verdicts {
        return Err("hosted profile forbids verbose verdicts".to_string());
    }

    let qps = config
        .rate_limit_qps
        .ok_or_else(|| "hosted profile requires a rate-limit QPS".to_string())?;
    if !qps.is_finite() || !(MINIMUM_RATE_LIMIT_QPS..=MAXIMUM_RATE_LIMIT_QPS).contains(&qps) {
        return Err(format!(
            "hosted rate-limit QPS must be within {MINIMUM_RATE_LIMIT_QPS}..={MAXIMUM_RATE_LIMIT_QPS}"
        ));
    }
    let burst = config
        .rate_limit_burst
        .ok_or_else(|| "hosted profile requires an explicit rate-limit burst".to_string())?;
    if !(MINIMUM_RATE_LIMIT_BURST..=MAXIMUM_RATE_LIMIT_BURST).contains(&burst) {
        return Err(format!(
            "hosted rate-limit burst must be within {MINIMUM_RATE_LIMIT_BURST}..={MAXIMUM_RATE_LIMIT_BURST}"
        ));
    }

    validate_ledger_path(config.ledger_path)?;
    validate_upstream(config.upstream_url)?;
    if config.upstream_adapter != UpstreamAdapter::McpJsonRpcV1 {
        return Err("hosted profile requires upstream adapter mcp-jsonrpc-v1".to_string());
    }
    if config.upstream_timeout.is_zero() || config.upstream_timeout > MAXIMUM_UPSTREAM_TIMEOUT {
        return Err("hosted upstream timeout must be within 1 ms..=30000 ms".to_string());
    }
    Ok(())
}

fn configured_tokens<'a>(
    purpose: &str,
    single: Option<&'a str>,
    registry: Option<&'a str>,
) -> Result<Vec<&'a str>, String> {
    match (single, registry) {
        (Some(_), Some(_)) => Err(format!(
            "hosted profile requires exactly one {purpose} source"
        )),
        (None, None) => Err(format!("hosted profile requires {purpose}")),
        (Some(token), None) => {
            let token = checked_token(purpose, token)?;
            Ok(vec![token])
        }
        (None, Some(spec)) => {
            let mut tokens = Vec::new();
            for raw in spec.split(',') {
                let entry = raw.trim();
                if entry.is_empty() {
                    return Err(format!("{purpose} registry contains an empty entry"));
                }
                let (_, token) = entry
                    .split_once(':')
                    .ok_or_else(|| format!("{purpose} registry entry is missing ':' separator"))?;
                tokens.push(checked_token(purpose, token.trim())?);
            }
            if tokens.is_empty() {
                return Err(format!("{purpose} registry is empty"));
            }
            Ok(tokens)
        }
    }
}

fn checked_token<'a>(purpose: &str, token: &'a str) -> Result<&'a str, String> {
    let token = token.trim();
    if token.len() < MINIMUM_TOKEN_BYTES {
        return Err(format!(
            "hosted {purpose} tokens must be at least {MINIMUM_TOKEN_BYTES} bytes"
        ));
    }
    Ok(token)
}

fn validate_ledger_path(raw: &str) -> Result<(), String> {
    let path = Path::new(raw);
    if !path.is_absolute()
        || raw == ":memory:"
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(
            "hosted ledger must be an absolute normalized file path beneath /data".to_string(),
        );
    }
    if !path.starts_with("/data") || path == Path::new("/data") {
        return Err("hosted ledger must be a file beneath the /data mount".to_string());
    }
    Ok(())
}

fn validate_upstream(raw: &str) -> Result<(), String> {
    let url = reqwest::Url::parse(raw)
        .map_err(|error| format!("invalid hosted upstream URL: {error}"))?;
    if url.scheme() != "https" {
        return Err("hosted upstream URL must use HTTPS".to_string());
    }
    if url.username() != "" || url.password().is_some() || url.fragment().is_some() {
        return Err("hosted upstream URL must not contain credentials or a fragment".to_string());
    }
    let host = url
        .host_str()
        .ok_or_else(|| "hosted upstream URL has no host".to_string())?
        .to_ascii_lowercase();
    if host == "localhost"
        || host == "example.com"
        || host.ends_with(".example")
        || host.ends_with(".invalid")
        || host.ends_with(".test")
    {
        return Err("hosted upstream URL uses a placeholder host".to_string());
    }
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for index in 0..left.len() {
        difference |= left[index] ^ right[index];
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const AGENT: &str = "agent-token-0123456789abcdef0123456789abcdef";
    const OPERATOR: &str = "operator-token-0123456789abcdef0123456789abcdef";

    fn hosted() -> HostedSafetyConfig<'static> {
        HostedSafetyConfig {
            profile: DeploymentProfile::Hosted,
            agent_token: Some(AGENT),
            agents: None,
            decide_token: Some(OPERATOR),
            deciders: None,
            enforce_mode: true,
            verbose_verdicts: false,
            rate_limit_qps: Some(10.0),
            rate_limit_burst: Some(20),
            ledger_path: "/data/clavenar-lite.db",
            upstream_url: "https://mcp.vendor.net/rpc",
            upstream_adapter: UpstreamAdapter::McpJsonRpcV1,
            upstream_timeout: Duration::from_secs(30),
        }
    }

    #[test]
    fn accepts_the_complete_hosted_profile() {
        assert_eq!(validate(&hosted()), Ok(()));
    }

    #[test]
    fn developer_profile_keeps_local_defaults() {
        let mut config = hosted();
        config.profile = DeploymentProfile::Developer;
        config.agent_token = None;
        config.decide_token = None;
        config.rate_limit_qps = None;
        config.rate_limit_burst = None;
        config.ledger_path = ":memory:";
        config.upstream_url = "http://localhost:9000/mcp";
        config.upstream_adapter = UpstreamAdapter::RawJson;
        config.upstream_timeout = Duration::from_secs(120);
        assert_eq!(validate(&config), Ok(()));
    }

    #[test]
    fn rejects_missing_ambiguous_short_and_overlapping_credentials() {
        let mut config = hosted();
        config.agent_token = None;
        assert!(
            validate(&config)
                .unwrap_err()
                .contains("agent authentication")
        );

        config = hosted();
        config.agents = Some("tenant/agent:another-agent-token-0123456789abcdef0123456789");
        assert!(
            validate(&config)
                .unwrap_err()
                .contains("exactly one agent authentication")
        );

        config = hosted();
        config.agent_token = Some("short");
        assert!(validate(&config).unwrap_err().contains("at least 32 bytes"));

        config = hosted();
        config.decide_token = Some(AGENT);
        assert!(validate(&config).unwrap_err().contains("disjoint"));
    }

    #[test]
    fn rejects_unsafe_posture_and_unbounded_rates() {
        let mut config = hosted();
        config.enforce_mode = false;
        assert!(validate(&config).unwrap_err().contains("enforce mode"));

        config = hosted();
        config.verbose_verdicts = true;
        assert!(validate(&config).unwrap_err().contains("verbose verdicts"));

        for qps in [0.0, 100.1, f64::NAN] {
            config = hosted();
            config.rate_limit_qps = Some(qps);
            assert!(validate(&config).unwrap_err().contains("QPS"));
        }
        config = hosted();
        config.rate_limit_burst = Some(201);
        assert!(validate(&config).unwrap_err().contains("burst"));
    }

    #[test]
    fn rejects_ephemeral_state_and_incompatible_upstreams() {
        for ledger in [":memory:", "relative.db", "/tmp/lite.db", "/data"] {
            let mut config = hosted();
            config.ledger_path = ledger;
            assert!(validate(&config).unwrap_err().contains("ledger"));
        }

        for upstream in [
            "http://mcp.vendor.test/rpc",
            "https://replace-me.invalid/mcp",
            "https://user:pass@mcp.vendor.test/rpc",
        ] {
            let mut config = hosted();
            config.upstream_url = upstream;
            assert!(validate(&config).unwrap_err().contains("upstream"));
        }

        let mut config = hosted();
        config.upstream_adapter = UpstreamAdapter::RawJson;
        assert!(validate(&config).unwrap_err().contains("mcp-jsonrpc-v1"));

        config = hosted();
        config.upstream_timeout = Duration::from_secs(31);
        assert!(validate(&config).unwrap_err().contains("timeout"));
    }
}
