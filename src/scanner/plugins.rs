/// Scan wp-content/plugins/ and extract metadata from each plugin's
/// main PHP file header, then check versions against wordpress.org.

use crate::models::WpPlugin;
use crate::wordpress_api::WpApi;
use regex::Regex;
use std::fs;
use std::path::Path;

/// Scan all plugins in the given WordPress installation.
pub fn scan_plugins(wp_root: &Path, api: &mut WpApi) -> Vec<WpPlugin> {
    let plugin_dir = wp_root.join("wp-content/plugins");
    if !plugin_dir.is_dir() {
        return Vec::new();
    }

    let mut entries: Vec<_> = fs::read_dir(&plugin_dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().is_dir())
        .collect();
    entries.sort_by_key(|e| e.file_name());

    let mut plugins = Vec::new();

    for entry in entries {
        let slug = entry.file_name().to_string_lossy().to_string();
        let init_file = entry.path().join(format!("{}.php", slug));
        if !init_file.is_file() {
            continue;
        }

        // Read only the first 8 KB for the metadata header.
        let data = match fs::read_to_string(&init_file) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let data = &data[..data.len().min(8192)];
        let metas = extract_plugin_metas(data);

        let name = metas
            .iter()
            .find(|(k, _)| k == "Plugin Name")
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| slug.clone());

        let installed_version = metas
            .iter()
            .find(|(k, _)| k == "Version")
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| "?".to_string());

        let latest_version = api.latest_plugin_version(&slug);

        plugins.push(WpPlugin {
            slug,
            name,
            installed_version,
            latest_version,
        });
    }

    plugins
}

/// Parse the first `/* ... */` comment block for WordPress-style metadata.
/// Returns a list of (key, value) pairs preserving insertion order.
pub fn extract_plugin_metas(data: &str) -> Vec<(String, String)> {
    let re_block = Regex::new(r"/\*([\s\S]+?)\*/").unwrap();
    let re_meta = Regex::new(r"(?mi)^[ \t/*#@]*([a-zA-Z0-9 ]+):(.*)$").unwrap();

    let mut metas = Vec::new();
    if let Some(block_match) = re_block.captures(data) {
        let block = &block_match[1];
        for cap in re_meta.captures_iter(block) {
            metas.push((cap[1].trim().to_string(), cap[2].trim().to_string()));
        }
    }
    metas
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_metas_standard() {
        let php = r#"<?php
/*
 * Plugin Name: Akismet Anti-spam
 * Version: 5.3.1
 * Author: Automattic
 * Description: Used by millions.
 */
?>"#;
        let metas = extract_plugin_metas(php);
        assert!(metas.iter().any(|(k, v)| k == "Plugin Name" && v == "Akismet Anti-spam"));
        assert!(metas.iter().any(|(k, v)| k == "Version" && v == "5.3.1"));
        assert!(metas.iter().any(|(k, v)| k == "Author" && v == "Automattic"));
    }

    #[test]
    fn test_extract_metas_no_block() {
        let php = "<?php echo 'hello'; ?>";
        let metas = extract_plugin_metas(php);
        assert!(metas.is_empty());
    }

    #[test]
    fn test_extract_metas_minimal() {
        let php = "<?php\n/* Plugin Name: Foo\nVersion: 1.0 */\n";
        let metas = extract_plugin_metas(php);
        assert!(metas.iter().any(|(k, v)| k == "Plugin Name" && v == "Foo"));
        assert!(metas.iter().any(|(k, v)| k == "Version" && v == "1.0"));
    }
}
