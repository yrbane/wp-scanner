/// Discover WordPress installations by parsing nginx site configurations.
///
/// Improvement over the original PHP implementation: extracts ALL `root`
/// directives from ALL `server` blocks in each config file (the PHP version
/// only returned the first one).

use crate::config;
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};

/// Find WordPress installations served by nginx.
/// Returns deduplicated, sorted list of paths containing wp-config.php.
pub fn find_wordpress_sites(
    site_filter: Option<&str>,
    explicit_path: Option<&Path>,
) -> Vec<PathBuf> {
    // If an explicit path was given, bypass nginx discovery entirely.
    if let Some(path) = explicit_path {
        if path.join("wp-config.php").is_file() {
            return vec![path.to_path_buf()];
        }
        eprintln!(
            "Warning: {} does not contain wp-config.php",
            path.display()
        );
        return Vec::new();
    }

    let doc_roots = list_nginx_doc_roots();

    let mut wp_sites: Vec<PathBuf> = doc_roots
        .into_iter()
        .filter(|root| root.join("wp-config.php").is_file())
        .filter(|root| {
            site_filter
                .map(|f| root.to_string_lossy().contains(f))
                .unwrap_or(true)
        })
        .collect();

    wp_sites.sort();
    wp_sites.dedup();
    wp_sites
}

/// Parse every nginx config file and extract all document root paths.
fn list_nginx_doc_roots() -> Vec<PathBuf> {
    let entries = match fs::read_dir(config::NGINX_SITES_DIR) {
        Ok(e) => e,
        Err(_) => {
            eprintln!("Warning: cannot read {}", config::NGINX_SITES_DIR);
            return Vec::new();
        }
    };

    let re_root = Regex::new(r"(?m)^\s*root\s+([^;]+);").unwrap();
    let mut roots = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();

        // Skip non-files, backup files, and editor swap files.
        if !path.is_file() {
            continue;
        }
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        if name.ends_with(".save")
            || name.ends_with(".bak")
            || name.ends_with('~')
            || name.starts_with('.')
        {
            continue;
        }

        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Strip comments before extracting roots.
        let cleaned: String = content
            .lines()
            .map(|line| {
                if let Some(pos) = line.find('#') {
                    &line[..pos]
                } else {
                    line
                }
            })
            .collect::<Vec<_>>()
            .join("\n");

        for cap in re_root.captures_iter(&cleaned) {
            let root_str = cap[1].trim();
            let root_path = PathBuf::from(root_str);
            if root_path.is_dir() && !roots.contains(&root_path) {
                roots.push(root_path);
            }
        }
    }

    roots.sort();
    roots
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Helper: create a fake WP installation in a temp dir.
    fn create_fake_wp(base: &Path) {
        fs::create_dir_all(base.join("wp-includes")).unwrap();
        fs::write(base.join("wp-config.php"), "<?php // config").unwrap();
        fs::write(
            base.join("wp-includes/version.php"),
            "<?php\n$wp_version = '6.4.1';\n",
        )
        .unwrap();
    }

    #[test]
    fn test_explicit_path_with_wp() {
        let tmp = TempDir::new().unwrap();
        create_fake_wp(tmp.path());
        let sites = find_wordpress_sites(None, Some(tmp.path()));
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0], tmp.path());
    }

    #[test]
    fn test_explicit_path_without_wp() {
        let tmp = TempDir::new().unwrap();
        let sites = find_wordpress_sites(None, Some(tmp.path()));
        assert!(sites.is_empty());
    }

    #[test]
    fn test_site_filter_with_explicit_path() {
        // When --path is given, --site filter is ignored (explicit path takes precedence).
        let tmp = TempDir::new().unwrap();
        create_fake_wp(tmp.path());
        let sites = find_wordpress_sites(Some("nonexistent"), Some(tmp.path()));
        assert_eq!(sites.len(), 1, "explicit path bypasses site filter");
    }
}
