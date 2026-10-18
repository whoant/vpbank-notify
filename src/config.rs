use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Public Firebase web configuration embedded in VPBank's page script.
#[derive(Clone, Serialize, Deserialize)]
pub struct PublicConfig {
    pub app_id: String,
    pub project_id: String,
    pub api_key: String,
    pub sender_id: String,
}

impl PublicConfig {
    pub fn parse_script(script: &str) -> Result<Self> {
        let start = script
            .find("firebase.initializeApp(")
            .context("Public Firebase configuration not found")?;
        let script = &script[start..];
        let field = |name: &str| -> Result<String> {
            let pattern = Regex::new(&format!(
                r#"\b{}\s*:\s*["']([^"']+)["']"#,
                regex::escape(name)
            ))?;
            pattern
                .captures(script)
                .and_then(|c| c.get(1))
                .map(|v| v.as_str().to_owned())
                .context("Public Firebase configuration is incomplete")
        };
        let config = Self {
            app_id: field("appId")?,
            project_id: field("projectId")?,
            api_key: field("apiKey")?,
            sender_id: field("messagingSenderId")?,
        };
        if !Regex::new(r"^1:[0-9]+:(web|android):[a-zA-Z0-9]+$")?.is_match(&config.app_id)
            || !Regex::new(r"^[a-z0-9][a-z0-9-]{1,99}$")?.is_match(&config.project_id)
            || !Regex::new(r"^[a-zA-Z0-9_-]+$")?.is_match(&config.api_key)
            || !Regex::new(r"^[0-9]+$")?.is_match(&config.sender_id)
            || config.app_id.split(':').nth(1) != Some(config.sender_id.as_str())
        {
            bail!("Public Firebase configuration has an unexpected format");
        }
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn extracts_public_configuration_and_rejects_missing_fields() {
        let config = PublicConfig::parse_script(r#"firebase.initializeApp({apiKey:"synthetic-public",projectId:"synthetic-project",appId:"1:123:web:abc",messagingSenderId:"123"});"#).unwrap();
        assert_eq!(config.sender_id, "123");
        assert_eq!(config.app_id, "1:123:web:abc");
        assert!(PublicConfig::parse_script("not a firebase app").is_err());
    }
}
