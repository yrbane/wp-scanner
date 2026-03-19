/// WordPress.org API client with built-in response caching.
///
/// Avoids duplicate HTTP requests when the same plugin appears across
/// multiple WordPress installations on the same server.

use crate::config;
use std::collections::HashMap;

pub struct WpApi {
    /// Cache: slug → Option<latest_version>.
    plugin_cache: HashMap<String, Option<String>>,
    /// Cached latest WP core version.
    wp_latest: Option<String>,
    /// Whether we already attempted the WP core version fetch.
    fetched_wp: bool,
}

impl WpApi {
    pub fn new() -> Self {
        Self {
            plugin_cache: HashMap::new(),
            wp_latest: None,
            fetched_wp: false,
        }
    }

    /// Returns the latest WordPress core version from api.wordpress.org.
    pub fn latest_wp_version(&mut self) -> Option<String> {
        if !self.fetched_wp {
            self.wp_latest = Self::fetch_wp_version();
            self.fetched_wp = true;
        }
        self.wp_latest.clone()
    }

    /// Returns the latest version of a plugin from api.wordpress.org.
    /// Results are cached per slug for the lifetime of this WpApi instance.
    pub fn latest_plugin_version(&mut self, slug: &str) -> Option<String> {
        if !self.plugin_cache.contains_key(slug) {
            let version = Self::fetch_plugin_version(slug);
            self.plugin_cache.insert(slug.to_string(), version);
        }
        self.plugin_cache.get(slug).cloned().flatten()
    }

    /// Fetch the current WordPress core version from the JSON API.
    fn fetch_wp_version() -> Option<String> {
        let resp = ureq::get(config::WP_VERSION_API)
            .set("User-Agent", config::USER_AGENT)
            .call()
            .ok()?;
        let json: serde_json::Value = resp.into_json().ok()?;
        // The 1.7 API returns offers[0].current for the latest stable version.
        json["offers"][0]["current"]
            .as_str()
            .or_else(|| json["offers"][0]["version"].as_str())
            .map(String::from)
    }

    /// Fetch the latest version of a single plugin.
    fn fetch_plugin_version(slug: &str) -> Option<String> {
        let url = format!("{}{}", config::WP_PLUGIN_API, slug);
        let resp = ureq::get(&url)
            .set("User-Agent", config::USER_AGENT)
            .call()
            .ok()?;
        let json: serde_json::Value = resp.into_json().ok()?;
        json["version"].as_str().map(String::from)
    }
}
