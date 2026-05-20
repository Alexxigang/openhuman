#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorsHeadersDecision {
    pub allow_origin: Option<String>,
    pub vary_on_origin: bool,
}

pub fn parse_allowed_origins_env(value: Option<&str>) -> Vec<String> {
    value
        .into_iter()
        .flat_map(|raw| raw.split(','))
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

pub fn cors_headers_for_origin(
    origin: Option<&str>,
    extra_allowed_origins: &[String],
) -> CorsHeadersDecision {
    let Some(origin) = origin.map(str::trim).filter(|origin| !origin.is_empty()) else {
        return CorsHeadersDecision {
            allow_origin: None,
            vary_on_origin: false,
        };
    };

    let allow_origin = if is_default_allowed_origin(origin)
        || extra_allowed_origins.iter().any(|candidate| candidate == origin)
    {
        Some(origin.to_string())
    } else {
        None
    };

    CorsHeadersDecision {
        allow_origin,
        vary_on_origin: true,
    }
}

fn is_default_allowed_origin(origin: &str) -> bool {
    matches!(
        origin,
        "tauri://localhost" | "http://tauri.localhost" | "https://tauri.localhost"
    ) || is_loopback_dev_origin(origin)
}

fn is_loopback_dev_origin(origin: &str) -> bool {
    let Some((scheme, authority)) = origin.split_once("://") else {
        return false;
    };

    if scheme != "http" || authority.is_empty() || authority.contains('/') {
        return false;
    }

    match authority {
        host if host.starts_with("localhost:") => has_valid_port(&host["localhost:".len()..]),
        host if host.starts_with("127.0.0.1:") => has_valid_port(&host["127.0.0.1:".len()..]),
        host if host.starts_with("[::1]:") => has_valid_port(&host["[::1]:".len()..]),
        _ => false,
    }
}

fn has_valid_port(port: &str) -> bool {
    port.parse::<u16>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::{cors_headers_for_origin, parse_allowed_origins_env};

    #[test]
    fn allows_tauri_origin() {
        let decision = cors_headers_for_origin(Some("tauri://localhost"), &[]);
        assert_eq!(decision.allow_origin.as_deref(), Some("tauri://localhost"));
        assert!(decision.vary_on_origin);
    }

    #[test]
    fn allows_loopback_dev_origin() {
        let decision = cors_headers_for_origin(Some("http://127.0.0.1:1420"), &[]);
        assert_eq!(decision.allow_origin.as_deref(), Some("http://127.0.0.1:1420"));
        assert!(decision.vary_on_origin);
    }

    #[test]
    fn rejects_non_allowlisted_origin() {
        let decision = cors_headers_for_origin(Some("https://evil.example"), &[]);
        assert!(decision.allow_origin.is_none());
        assert!(decision.vary_on_origin);
    }

    #[test]
    fn parses_env_override_entries() {
        let parsed = parse_allowed_origins_env(Some(" https://debug.example , http://localhost:3000 "));
        assert_eq!(parsed, vec!["https://debug.example", "http://localhost:3000"]);
    }
}
