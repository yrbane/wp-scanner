/// Extract WordPress core version from wp-includes/version.php via regex.
///
/// This deliberately reads the file as plain text — it does NOT execute any
/// PHP code. This is critical for safety when scanning potentially
/// compromised WordPress installations.

use regex::Regex;
use std::fs;
use std::path::Path;

/// Extract the WordPress version string from `wp-includes/version.php`.
/// Returns None if the file is missing or the version cannot be parsed.
pub fn extract_wp_version(wp_root: &Path) -> Option<String> {
    let version_file = wp_root.join("wp-includes/version.php");
    let data = fs::read_to_string(&version_file).ok()?;
    // Only read first 8 KB (the version is always near the top).
    let data = &data[..data.len().min(8192)];
    let re = Regex::new(r#"(?m)^\$wp_version\s*=\s*'([0-9.]+)'"#).unwrap();
    re.captures(data).map(|c| c[1].to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_extract_version_standard() {
        let tmp = TempDir::new().unwrap();
        let inc = tmp.path().join("wp-includes");
        fs::create_dir(&inc).unwrap();
        fs::write(
            inc.join("version.php"),
            "<?php\n$wp_version = '6.4.1';\n$wp_db_version = 56657;\n",
        )
        .unwrap();
        assert_eq!(
            extract_wp_version(tmp.path()),
            Some("6.4.1".to_string())
        );
    }

    #[test]
    fn test_extract_version_with_spaces() {
        let tmp = TempDir::new().unwrap();
        let inc = tmp.path().join("wp-includes");
        fs::create_dir(&inc).unwrap();
        fs::write(
            inc.join("version.php"),
            "<?php\n$wp_version  =  '5.9';\n",
        )
        .unwrap();
        assert_eq!(
            extract_wp_version(tmp.path()),
            Some("5.9".to_string())
        );
    }

    #[test]
    fn test_missing_version_file() {
        let tmp = TempDir::new().unwrap();
        assert_eq!(extract_wp_version(tmp.path()), None);
    }

    #[test]
    fn test_malformed_version_file() {
        let tmp = TempDir::new().unwrap();
        let inc = tmp.path().join("wp-includes");
        fs::create_dir(&inc).unwrap();
        fs::write(inc.join("version.php"), "<?php\n// no version here\n").unwrap();
        assert_eq!(extract_wp_version(tmp.path()), None);
    }
}
