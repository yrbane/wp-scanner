/// Scan for potential backdoors and malicious code in WordPress installations.
///
/// Patterns are loaded from an external JSON file if available
/// (~/.config/wp-scanner/patterns.json), with built-in defaults as fallback.
/// File scanning is parallelized with rayon for performance.

use crate::config;
use crate::models::{BackdoorFinding, Severity};
use rayon::prelude::*;
use regex::Regex;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

// ---------------------------------------------------------------------------
// Pattern definitions — JSON-serializable
// ---------------------------------------------------------------------------

/// JSON pattern database structure (matches patterns.json on the website).
#[derive(Debug, Deserialize)]
pub struct PatternDatabase {
    pub version: String,
    #[serde(default)]
    pub updated: String,
    #[serde(default = "default_safe_dirs")]
    pub uploads_safe_dirs: Vec<String>,
    pub patterns: Vec<JsonPattern>,
}

#[derive(Debug, Deserialize)]
pub struct JsonPattern {
    pub name: String,
    pub pattern: String,
    pub severity: String,
    #[serde(default)]
    pub description: String,
}

fn default_safe_dirs() -> Vec<String> {
    vec![
        "cache".to_string(),
        "wflogs".to_string(),
        "wp-file-manager-pro".to_string(),
    ]
}

/// Pre-compiled pattern ready for matching.
struct CompiledPattern {
    name: String,
    regex: Regex,
    severity: Severity,
}

/// Built-in patterns used when no external JSON file is available.
const BUILTIN_PATTERNS_JSON: &str = include_str!("../../builtin_patterns.json");

// ---------------------------------------------------------------------------
// BackdoorScanner
// ---------------------------------------------------------------------------

/// Scanner with pre-compiled regex patterns for detecting PHP backdoors.
pub struct BackdoorScanner {
    patterns: Vec<CompiledPattern>,
    uploads_safe_dirs: Vec<String>,
}

impl BackdoorScanner {
    /// Load patterns from the local JSON file, or fall back to built-in defaults.
    pub fn new() -> Self {
        let db = Self::load_database();
        let uploads_safe_dirs = db.uploads_safe_dirs;

        let patterns = db
            .patterns
            .iter()
            .filter_map(|p| {
                Regex::new(&p.pattern).ok().map(|regex| CompiledPattern {
                    name: p.name.clone(),
                    regex,
                    severity: parse_severity(&p.severity),
                })
            })
            .collect();

        Self {
            patterns,
            uploads_safe_dirs,
        }
    }

    /// Load pattern database: try local file first, then built-in.
    fn load_database() -> PatternDatabase {
        let local_path = config::patterns_local_path();

        // 1. Try local file (~/.config/wp-scanner/patterns.json).
        if local_path.is_file() {
            if let Ok(data) = fs::read_to_string(&local_path) {
                if let Ok(db) = serde_json::from_str::<PatternDatabase>(&data) {
                    eprintln!(
                        "Patterns: loaded v{} ({}) from {}",
                        db.version,
                        db.updated,
                        local_path.display()
                    );
                    return db;
                }
                eprintln!(
                    "Warning: failed to parse {}, using built-in patterns",
                    local_path.display()
                );
            }
        }

        // 2. Fall back to built-in patterns.
        serde_json::from_str(BUILTIN_PATTERNS_JSON)
            .expect("Built-in patterns JSON is invalid — this is a bug")
    }

    /// Scan an entire WordPress installation for potential backdoors.
    pub fn scan(&self, wp_root: &Path) -> Vec<BackdoorFinding> {
        let mut findings = Vec::new();

        // 1. Check for PHP files in wp-content/uploads/ (always suspicious).
        findings.extend(self.check_uploads_php(wp_root));

        // 2. Check for hidden PHP dotfiles.
        findings.extend(self.check_hidden_php(wp_root));

        // 3. Collect PHP files to scan.
        let php_files: Vec<PathBuf> = WalkDir::new(wp_root)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file() && is_php_file(e.path()))
            .map(|e| e.path().to_path_buf())
            .collect();

        // 4. Scan files in parallel against all patterns.
        let pattern_findings: Vec<BackdoorFinding> = php_files
            .par_iter()
            .flat_map(|file| self.scan_file(file, wp_root))
            .collect();

        findings.extend(pattern_findings);
        findings
    }

    /// Scan a single PHP file against all patterns.
    fn scan_file(&self, file: &Path, wp_root: &Path) -> Vec<BackdoorFinding> {
        let content = match fs::read_to_string(file) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        let mut findings = Vec::new();

        // Skip WP core directories for warning/info patterns.
        let relative = file.strip_prefix(wp_root).unwrap_or(file);
        let is_core = relative.starts_with("wp-includes") || relative.starts_with("wp-admin");

        // Check for obfuscated long lines (>1000 chars with suspicious keywords).
        for (i, line) in content.lines().enumerate() {
            if line.len() > 1000
                && (line.contains("eval")
                    || line.contains("base64")
                    || line.contains("gzinflate"))
            {
                findings.push(BackdoorFinding {
                    file: file.to_path_buf(),
                    line: i + 1,
                    pattern_name: "obfuscated_long_line".to_string(),
                    severity: Severity::Critical,
                    snippet: truncate(line.trim(), 120),
                });
            }
        }

        // Match against compiled patterns.
        for pattern in &self.patterns {
            if is_core && pattern.severity != Severity::Critical {
                continue;
            }

            for (i, line) in content.lines().enumerate() {
                if pattern.regex.is_match(line) {
                    findings.push(BackdoorFinding {
                        file: file.to_path_buf(),
                        line: i + 1,
                        pattern_name: pattern.name.clone(),
                        severity: pattern.severity.clone(),
                        snippet: truncate(line.trim(), 120),
                    });
                }
            }
        }

        findings
    }

    /// Detect PHP files in wp-content/uploads/.
    fn check_uploads_php(&self, wp_root: &Path) -> Vec<BackdoorFinding> {
        let uploads = wp_root.join("wp-content/uploads");
        if !uploads.is_dir() {
            return Vec::new();
        }

        let safe_dirs = &self.uploads_safe_dirs;

        WalkDir::new(&uploads)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file() && is_php_file(e.path()))
            .filter(|e| {
                let rel = e.path().strip_prefix(&uploads).unwrap_or(e.path());
                !safe_dirs.iter().any(|safe| rel.starts_with(safe.as_str()))
            })
            .map(|e| BackdoorFinding {
                file: e.path().to_path_buf(),
                line: 0,
                pattern_name: "php_in_uploads".to_string(),
                severity: Severity::Critical,
                snippet: "PHP file found in uploads directory".to_string(),
            })
            .collect()
    }

    /// Detect hidden PHP files (dotfiles with .php extension).
    fn check_hidden_php(&self, wp_root: &Path) -> Vec<BackdoorFinding> {
        WalkDir::new(wp_root)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                if !e.path().is_file() {
                    return false;
                }
                let name = e.file_name().to_string_lossy();
                name.starts_with('.') && is_php_file(e.path())
            })
            .map(|e| BackdoorFinding {
                file: e.path().to_path_buf(),
                line: 0,
                pattern_name: "hidden_php_file".to_string(),
                severity: Severity::Warning,
                snippet: "Hidden PHP file (dotfile)".to_string(),
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Update command
// ---------------------------------------------------------------------------

/// Download the latest patterns from the remote server and save locally.
pub fn update_patterns() -> anyhow::Result<()> {
    eprintln!("Downloading patterns from {} ...", config::PATTERNS_URL);

    let resp = ureq::get(config::PATTERNS_URL)
        .set("User-Agent", config::USER_AGENT)
        .call()
        .map_err(|e| anyhow::anyhow!("Failed to download patterns: {}", e))?;

    let body = resp.into_string()?;

    // Validate JSON before saving.
    let db: PatternDatabase = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("Invalid patterns JSON: {}", e))?;

    // Create config directory if needed.
    let local_path = config::patterns_local_path();
    if let Some(parent) = local_path.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(&local_path, &body)?;

    eprintln!(
        "Updated to v{} ({}) — {} patterns saved to {}",
        db.version,
        db.updated,
        db.patterns.len(),
        local_path.display()
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "warning" => Severity::Warning,
        _ => Severity::Info,
    }
}

fn is_php_file(path: &Path) -> bool {
    path.extension()
        .map(|ext| {
            let ext = ext.to_string_lossy().to_lowercase();
            ext == "php" || ext == "php5" || ext == "phtml" || ext == "pht"
        })
        .unwrap_or(false)
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn scanner() -> BackdoorScanner {
        BackdoorScanner::new()
    }

    #[test]
    fn test_detect_eval_base64() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("evil.php");
        fs::write(&file, "<?php eval(base64_decode('dGVzdA==')); ?>").unwrap();

        let findings = scanner().scan_file(&file, tmp.path());
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.pattern_name == "eval_base64"));
    }

    #[test]
    fn test_detect_eval_gzinflate() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("evil2.php");
        fs::write(&file, "<?php eval(gzinflate(base64_decode('test'))); ?>").unwrap();

        let findings = scanner().scan_file(&file, tmp.path());
        assert!(findings.iter().any(|f| f.pattern_name == "eval_gzinflate"));
    }

    #[test]
    fn test_clean_file_no_findings() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("clean.php");
        fs::write(&file, "<?php echo 'Hello World'; ?>").unwrap();

        let findings = scanner().scan_file(&file, tmp.path());
        assert!(findings.is_empty());
    }

    #[test]
    fn test_php_in_uploads() {
        let tmp = TempDir::new().unwrap();
        let uploads = tmp.path().join("wp-content/uploads/2024");
        fs::create_dir_all(&uploads).unwrap();
        fs::write(
            uploads.join("backdoor.php"),
            "<?php system($_GET['cmd']); ?>",
        )
        .unwrap();

        let findings = scanner().check_uploads_php(tmp.path());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pattern_name, "php_in_uploads");
    }

    #[test]
    fn test_php_in_uploads_safe_cache_excluded() {
        let tmp = TempDir::new().unwrap();
        let cache_dir = tmp.path().join("wp-content/uploads/cache/wpml/twig");
        fs::create_dir_all(&cache_dir).unwrap();
        fs::write(cache_dir.join("compiled.php"), "<?php // twig cache ?>").unwrap();

        let findings = scanner().check_uploads_php(tmp.path());
        assert!(findings.is_empty(), "Cache PHP files should be excluded");
    }

    #[test]
    fn test_hidden_php_file() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join(".hidden.php"), "<?php ?>").unwrap();

        let findings = scanner().check_hidden_php(tmp.path());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pattern_name, "hidden_php_file");
    }

    #[test]
    fn test_obfuscated_long_line() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("obfuscated.php");
        let long_line = format!("<?php eval(base64_decode('{}'));", "A".repeat(1500));
        fs::write(&file, long_line).unwrap();

        let findings = scanner().scan_file(&file, tmp.path());
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_name == "obfuscated_long_line"),
            "Should detect obfuscated long lines"
        );
    }

    #[test]
    fn test_core_files_skip_warning_patterns() {
        let tmp = TempDir::new().unwrap();
        let core = tmp.path().join("wp-includes");
        fs::create_dir(&core).unwrap();
        let file = core.join("class-wp.php");
        fs::write(&file, "<?php system('ls'); ?>").unwrap();

        let findings = scanner().scan_file(&file, tmp.path());
        assert!(
            !findings.iter().any(|f| f.pattern_name == "system_call"),
            "Warning patterns should be skipped in wp-includes/"
        );
    }

    #[test]
    fn test_is_php_file() {
        assert!(is_php_file(Path::new("test.php")));
        assert!(is_php_file(Path::new("test.PHP")));
        assert!(is_php_file(Path::new("test.php5")));
        assert!(is_php_file(Path::new("test.phtml")));
        assert!(!is_php_file(Path::new("test.txt")));
        assert!(!is_php_file(Path::new("test.js")));
    }

    #[test]
    fn test_parse_severity() {
        assert_eq!(parse_severity("critical"), Severity::Critical);
        assert_eq!(parse_severity("CRITICAL"), Severity::Critical);
        assert_eq!(parse_severity("warning"), Severity::Warning);
        assert_eq!(parse_severity("info"), Severity::Info);
        assert_eq!(parse_severity("unknown"), Severity::Info);
    }

    #[test]
    fn test_builtin_patterns_valid() {
        let db: PatternDatabase = serde_json::from_str(BUILTIN_PATTERNS_JSON).unwrap();
        assert!(!db.patterns.is_empty(), "Built-in patterns should not be empty");
        // Verify all patterns compile as valid regex.
        for p in &db.patterns {
            assert!(
                Regex::new(&p.pattern).is_ok(),
                "Pattern '{}' has invalid regex: {}",
                p.name,
                p.pattern
            );
        }
    }
}
