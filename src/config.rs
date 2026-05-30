//! Config file model. Mirrors the original SNI-Spoofing `config.json` shape so
//! the two ecosystems feel familiar, with an added optional `strategy` per
//! listener and an optional `sni` used by `tune`.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Listener {
    /// Local address to accept connections on, e.g. "127.0.0.1:40443".
    pub listen: String,
    /// Upstream server "ip:port". Must be an IP, not a hostname.
    pub connect: String,
    /// SNI used when auto-tuning this listener (often the upstream's real host).
    #[serde(default)]
    pub sni: Option<String>,
    /// Chosen strategy name. If absent, a safe default is used.
    #[serde(default)]
    pub strategy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub listeners: Vec<Listener>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let cfg: Config = serde_json::from_str(&text)
            .with_context(|| format!("parsing config {}", path.display()))?;
        Ok(cfg)
    }

    #[allow(dead_code)] // public API: used by callers that persist tuned configs
    pub fn save(&self, path: &Path) -> Result<()> {
        let text = serde_json::to_string_pretty(self)?;
        fs::write(path, text).with_context(|| format!("writing config {}", path.display()))?;
        Ok(())
    }
}
