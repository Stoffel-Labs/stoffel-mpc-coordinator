//! Environment configuration for the opt-in browser WSS endpoints.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::{fmt, path::PathBuf};
use stoffel_mpc_coordinator_shared::{
    browser_capability::BrowserCapabilityVerifier, browser_rpc::BrowserOriginAllowlist,
    CoordinatorError,
};

pub const DEFAULT_BROWSER_REPLAY_CAPACITY: usize = 4096;
const DEFAULT_ISSUER: &str = "stoffel-browser-capability";
const DEFAULT_AUDIENCE: &str = "stoffel-mpc";
const DEFAULT_CLOCK_SKEW_SECONDS: u64 = 30;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrowserRpcConfig {
    pub verifying_key: [u8; 32],
    pub allowed_origin: String,
    pub tls_cert_path: PathBuf,
    pub tls_key_path: PathBuf,
    pub coordinator_port: u16,
    pub node_port_offset: u16,
    pub replay_capacity: usize,
    pub issuer: String,
    pub audience: String,
    pub clock_skew_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrowserRpcConfigError(String);

impl fmt::Display for BrowserRpcConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BrowserRpcConfigError {}

impl BrowserRpcConfig {
    /// Read browser RPC configuration. No other browser variables are read unless
    /// `STOFFEL_BROWSER_RPC_ENABLED` is exactly `1`.
    pub fn from_env() -> Result<Option<Self>, BrowserRpcConfigError> {
        Self::parse(|name| std::env::var(name).ok())
    }

    /// Pure configuration parser, suitable for callers and tests backed by a map.
    pub fn parse(
        get: impl Fn(&str) -> Option<String>,
    ) -> Result<Option<Self>, BrowserRpcConfigError> {
        if get("STOFFEL_BROWSER_RPC_ENABLED").as_deref() != Some("1") {
            return Ok(None);
        }

        let required = |name: &str| {
            get(name).filter(|value| !value.is_empty()).ok_or_else(|| {
                BrowserRpcConfigError(format!("missing required browser RPC variable {name}"))
            })
        };

        let key = URL_SAFE_NO_PAD
            .decode(required("STOFFEL_BROWSER_RPC_VERIFYING_KEY")?)
            .map_err(|_| {
                BrowserRpcConfigError("invalid base64url browser RPC verifying key".into())
            })?;
        let verifying_key: [u8; 32] = key.try_into().map_err(|_| {
            BrowserRpcConfigError("browser RPC verifying key must be exactly 32 bytes".into())
        })?;

        let allowed_origin = required("STOFFEL_BROWSER_RPC_ALLOWED_ORIGIN")?;
        validate_origin(&allowed_origin)?;

        let coordinator_port: u16 = parse_number(
            "STOFFEL_BROWSER_RPC_COORDINATOR_PORT",
            required("STOFFEL_BROWSER_RPC_COORDINATOR_PORT")?,
        )?;
        if coordinator_port == 0 {
            return Err(BrowserRpcConfigError(
                "browser RPC coordinator port must be non-zero".into(),
            ));
        }
        let node_port_offset: u16 = parse_number(
            "STOFFEL_BROWSER_RPC_NODE_PORT_OFFSET",
            required("STOFFEL_BROWSER_RPC_NODE_PORT_OFFSET")?,
        )?;
        if node_port_offset == 0 {
            return Err(BrowserRpcConfigError(
                "browser RPC node port offset must be non-zero".into(),
            ));
        }
        let replay_capacity: usize = match get("STOFFEL_BROWSER_RPC_REPLAY_CAPACITY") {
            Some(value) => parse_number("STOFFEL_BROWSER_RPC_REPLAY_CAPACITY", value)?,
            None => DEFAULT_BROWSER_REPLAY_CAPACITY,
        };
        if replay_capacity == 0 {
            return Err(BrowserRpcConfigError(
                "browser RPC replay capacity must be non-zero".into(),
            ));
        }

        Ok(Some(Self {
            verifying_key,
            allowed_origin,
            tls_cert_path: required("STOFFEL_BROWSER_RPC_TLS_CERT_PATH")?.into(),
            tls_key_path: required("STOFFEL_BROWSER_RPC_TLS_KEY_PATH")?.into(),
            coordinator_port,
            node_port_offset,
            replay_capacity,
            issuer: get("STOFFEL_BROWSER_RPC_ISSUER")
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| DEFAULT_ISSUER.into()),
            audience: get("STOFFEL_BROWSER_RPC_AUDIENCE")
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| DEFAULT_AUDIENCE.into()),
            clock_skew_seconds: match get("STOFFEL_BROWSER_RPC_CLOCK_SKEW_SECONDS") {
                Some(value) => parse_number("STOFFEL_BROWSER_RPC_CLOCK_SKEW_SECONDS", value)?,
                None => DEFAULT_CLOCK_SKEW_SECONDS,
            },
        }))
    }

    pub fn node_port(&self, native_port: u16) -> Result<u16, BrowserRpcConfigError> {
        native_port
            .checked_add(self.node_port_offset)
            .ok_or_else(|| {
                BrowserRpcConfigError(format!(
                    "browser RPC node port overflows: {native_port} + {}",
                    self.node_port_offset
                ))
            })
    }

    pub fn verifier(&self) -> Result<BrowserCapabilityVerifier, CoordinatorError> {
        BrowserCapabilityVerifier::new(
            &self.issuer,
            self.verifying_key,
            &self.audience,
            self.clock_skew_seconds,
        )
        .map_err(|error| CoordinatorError::JSONError(format!("browser RPC verifier: {error}")))
    }

    pub fn origin_allowlist(&self) -> Result<BrowserOriginAllowlist, CoordinatorError> {
        BrowserOriginAllowlist::new([&self.allowed_origin]).map_err(|error| {
            CoordinatorError::JSONError(format!("invalid browser RPC origin header: {error}"))
        })
    }

    pub fn tls_material(&self) -> Result<(Vec<u8>, Vec<u8>), CoordinatorError> {
        let cert = std::fs::read(&self.tls_cert_path).map_err(|error| {
            CoordinatorError::TlsConfigError(format!(
                "failed to read browser RPC certificate {}: {error}",
                self.tls_cert_path.display()
            ))
        })?;
        let key = std::fs::read(&self.tls_key_path).map_err(|error| {
            CoordinatorError::TlsConfigError(format!(
                "failed to read browser RPC private key {}: {error}",
                self.tls_key_path.display()
            ))
        })?;
        Ok((cert, key))
    }
}

fn parse_number<T: std::str::FromStr>(
    name: &str,
    value: String,
) -> Result<T, BrowserRpcConfigError> {
    value
        .parse()
        .map_err(|_| BrowserRpcConfigError(format!("invalid numeric browser RPC variable {name}")))
}

fn validate_origin(origin: &str) -> Result<(), BrowserRpcConfigError> {
    if origin.contains('*') {
        return Err(BrowserRpcConfigError(
            "browser RPC origin must not contain a wildcard".into(),
        ));
    }
    let parsed = url::Url::parse(origin).map_err(|_| {
        BrowserRpcConfigError("browser RPC origin is not a valid URL origin".into())
    })?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.origin().ascii_serialization() != origin
    {
        return Err(BrowserRpcConfigError(
            "browser RPC origin must be an exact http(s) origin without path, credentials, query, fragment, or wildcard".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn parse(values: &[(&str, &str)]) -> Result<Option<BrowserRpcConfig>, BrowserRpcConfigError> {
        let values = values
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect::<HashMap<_, _>>();
        BrowserRpcConfig::parse(|name| values.get(name).cloned())
    }

    fn valid() -> Vec<(&'static str, &'static str)> {
        vec![
            ("STOFFEL_BROWSER_RPC_ENABLED", "1"),
            (
                "STOFFEL_BROWSER_RPC_VERIFYING_KEY",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ),
            ("STOFFEL_BROWSER_RPC_ALLOWED_ORIGIN", "https://app.example"),
            ("STOFFEL_BROWSER_RPC_TLS_CERT_PATH", "/tls/server.der"),
            ("STOFFEL_BROWSER_RPC_TLS_KEY_PATH", "/tls/server.key.der"),
            ("STOFFEL_BROWSER_RPC_COORDINATOR_PORT", "3443"),
            ("STOFFEL_BROWSER_RPC_NODE_PORT_OFFSET", "1000"),
        ]
    }

    #[test]
    fn disabled_by_default_does_not_require_other_values() {
        assert_eq!(parse(&[]).unwrap(), None);
        assert_eq!(
            parse(&[("STOFFEL_BROWSER_RPC_ENABLED", "0")]).unwrap(),
            None
        );
    }

    #[test]
    fn rejects_malformed_values_and_wildcard_origins() {
        let mut values = valid();
        values[1].1 = "not-base64!";
        assert!(parse(&values).is_err());

        let mut values = valid();
        values[2].1 = "https://*.example";
        assert!(parse(&values).unwrap_err().to_string().contains("wildcard"));

        let mut values = valid();
        values[5].1 = "0";
        assert!(parse(&values).is_err());
    }

    #[test]
    fn derives_node_ports_with_checked_addition() {
        let config = parse(&valid()).unwrap().unwrap();
        assert_eq!(config.node_port(4100).unwrap(), 5100);
        assert!(config.node_port(65000).is_err());
        assert_eq!(config.replay_capacity, DEFAULT_BROWSER_REPLAY_CAPACITY);
    }
}
