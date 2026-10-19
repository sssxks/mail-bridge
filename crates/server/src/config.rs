use mail_bridge_auth::{AuthConfig, validate_oauth_redirect};
use mail_bridge_core::{Error, Result, safe};
use std::{path::PathBuf, sync::Arc};
use zeroize::Zeroizing;

/// Process configuration DTO parsed at startup; mailbox accounts are persistent runtime data.
/// Authorization construction parses its public origin and callback policy before use.
#[derive(Clone)]
pub struct Settings {
    /// Independent owner credential, separate from mailbox credentials.
    pub owner_password: Arc<Zeroizing<Box<str>>>,
    /// Configured public HTTPS origin.
    pub public_url: Box<str>,
    /// Explicit callback allowlist; registration must match its policy.
    pub redirects: Box<[Box<str>]>,
    /// Directory containing the sole SQLite state file.
    pub data_dir: PathBuf,
    /// Local socket address used by the HTTP listener.
    pub bind: std::net::SocketAddr,
}

impl Settings {
    /// Load the configured private owner credential from its file or environment boundary.
    fn secret(name: &str) -> Result<String> {
        if let Some(path) = std::env::var_os(format!("{name}_FILE")) {
            let bytes = std::fs::read(path).map_err(safe)?;
            if bytes.len() > 1024 {
                return Err(Error::Rejected("Secret file too large"));
            }
            return String::from_utf8(bytes)
                .map(|value| value.trim_end_matches(['\r', '\n']).to_owned())
                .map_err(safe);
        }
        std::env::var(name).map_err(|_| {
            Error::Rejected("Set the required private server credential or its _FILE path")
        })
    }
    /// Parse process configuration before constructing authorization, storage or network services.
    pub fn from_env() -> Result<Self> {
        let owner_password = Self::secret("MAIL_BRIDGE_OWNER_PASSWORD")?;
        if owner_password.len() < 32
            || owner_password.len() > 256
            || !owner_password.is_ascii()
            || owner_password.contains(['\r', '\n', '\0'])
        {
            return Err(Error::Rejected(
                "Owner password must be 32–256 ASCII characters",
            ));
        }
        let public_url = std::env::var("MAIL_BRIDGE_PUBLIC_URL")
            .map_err(|_| Error::Rejected("Set MAIL_BRIDGE_PUBLIC_URL to an HTTPS origin"))?;
        let url = url::Url::parse(&public_url).map_err(safe)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(Error::Rejected(
                "Public URL must be an HTTPS origin without a path or credentials",
            ));
        }
        let redirects: Box<[Box<str>]> = serde_json::from_str(
            &std::env::var("MAIL_BRIDGE_OAUTH_REDIRECT_URIS").unwrap_or_else(|_| {
                "[\"https://chatgpt.com/connector_platform_oauth_redirect\"]".into()
            }),
        )
        .map_err(safe)?;
        if redirects.is_empty() || redirects.len() > 10 {
            return Err(Error::Rejected("Set exact OAuth redirect URI allowlist"));
        }
        for redirect in &redirects {
            validate_oauth_redirect(redirect)?;
        }
        Ok(Self {
            owner_password: Arc::new(Zeroizing::new(owner_password.into_boxed_str())),
            public_url: url.origin().ascii_serialization().into(),
            redirects,
            data_dir: std::env::var_os("MAIL_BRIDGE_DATA_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("./data")),
            bind: std::env::var("MAIL_BRIDGE_BIND")
                .unwrap_or_else(|_| "127.0.0.1:18765".into())
                .parse()
                .map_err(safe)?,
        })
    }
}

impl Settings {
    /// Extract authorization policy from process configuration.
    pub fn auth_config(&self) -> AuthConfig {
        AuthConfig {
            public_url: self.public_url.clone(),
            redirects: self.redirects.clone(),
            owner_password: self.owner_password.clone(),
        }
    }
}
