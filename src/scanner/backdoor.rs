/// Scan for potential backdoors and malicious code in WordPress installations.
///
/// Uses pre-compiled regex patterns organized by severity level.
/// File scanning is parallelized with rayon for performance.
/// Special handling for wp-content/uploads/ (PHP files should never be there).

use crate::models::{BackdoorFinding, Severity};
use rayon::prelude::*;
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

// ---------------------------------------------------------------------------
// Pattern definitions
// ---------------------------------------------------------------------------

struct PatternDef {
    name: &'static str,
    pattern: &'static str,
    severity: Severity,
}

/// Pre-compiled pattern ready for matching.
struct CompiledPattern {
    name: String,
    regex: Regex,
    severity: Severity,
}

/// Backdoor detection patterns ordered by severity.
const PATTERN_DEFS: &[PatternDef] = &[
    // ── Critical: almost certainly malicious ──────────────────────────────
    PatternDef {
        name: "eval_base64",
        pattern: r"eval\s*\(\s*base64_decode\s*\(",
        severity: Severity::Critical,
    },
    PatternDef {
        name: "eval_gzinflate",
        pattern: r"eval\s*\(\s*gzinflate\s*\(",
        severity: Severity::Critical,
    },
    PatternDef {
        name: "eval_gzuncompress",
        pattern: r"eval\s*\(\s*gzuncompress\s*\(",
        severity: Severity::Critical,
    },
    PatternDef {
        name: "eval_str_rot13",
        pattern: r"eval\s*\(\s*str_rot13\s*\(",
        severity: Severity::Critical,
    },
    PatternDef {
        name: "assert_base64",
        pattern: r"assert\s*\(\s*base64_decode\s*\(",
        severity: Severity::Critical,
    },
    PatternDef {
        name: "preg_replace_eval",
        pattern: r#"preg_replace\s*\(\s*['"]/.+/[a-z]*e"#,
        severity: Severity::Critical,
    },
    PatternDef {
        name: "webshell_signature",
        pattern: r"(?i)(c99shell|r57shell|WSO\s+\d|b374k|FilesMan|WebShell)",
        severity: Severity::Critical,
    },
    PatternDef {
        name: "suppressed_superglobal_exec",
        pattern: r"@\$_(GET|POST|REQUEST|COOKIE)\s*\[",
        severity: Severity::Critical,
    },
    PatternDef {
        name: "create_function_user_input",
        pattern: r"create_function\s*\(.*\$_(GET|POST|REQUEST)",
        severity: Severity::Critical,
    },
    // ── Warning: suspicious, needs investigation ─────────────────────────
    PatternDef {
        name: "shell_exec",
        pattern: r"\bshell_exec\s*\(",
        severity: Severity::Warning,
    },
    PatternDef {
        name: "system_call",
        pattern: r"\bsystem\s*\(",
        severity: Severity::Warning,
    },
    PatternDef {
        name: "passthru_call",
        pattern: r"\bpassthru\s*\(",
        severity: Severity::Warning,
    },
    PatternDef {
        name: "exec_call",
        pattern: r"\bexec\s*\(",
        severity: Severity::Warning,
    },
    PatternDef {
        name: "popen_call",
        pattern: r"\bpopen\s*\(",
        severity: Severity::Warning,
    },
    PatternDef {
        name: "proc_open_call",
        pattern: r"\bproc_open\s*\(",
        severity: Severity::Warning,
    },
    PatternDef {
        name: "file_put_contents_user_input",
        pattern: r"file_put_contents\s*\(.*\$_(GET|POST|REQUEST)",
        severity: Severity::Warning,
    },
    PatternDef {
        name: "base64_decode_user_input",
        pattern: r"base64_decode\s*\(.*\$_(GET|POST|REQUEST|COOKIE)",
        severity: Severity::Warning,
    },
    PatternDef {
        name: "hex_obfuscation",
        pattern: r"(\\x[0-9a-fA-F]{2}){10,}",
        severity: Severity::Warning,
    },
    PatternDef {
        name: "chr_obfuscation",
        pattern: r"(chr\s*\(\s*\d+\s*\)\s*\.?\s*){10,}",
        severity: Severity::Warning,
    },
    // ── Info: worth noting ───────────────────────────────────────────────
    PatternDef {
        name: "eval_variable",
        pattern: r"\beval\s*\(\s*\$",
        severity: Severity::Info,
    },
];

/// Known safe subdirectories inside wp-content/uploads/ that may legitimately
/// contain PHP files (caches, logging plugins, etc.).
const UPLOADS_SAFE_DIRS: &[&str] = &["cache", "wflogs", "wp-file-manager-pro"];

// ---------------------------------------------------------------------------
// BackdoorScanner
// ---------------------------------------------------------------------------

/// Scanner with pre-compiled regex patterns for detecting PHP backdoors.
pub struct BackdoorScanner {
    patterns: Vec<CompiledPattern>,
}

impl BackdoorScanner {
    /// Compile all patterns once — reuse across multiple site scans.
    pub fn new() -> Self {
        let patterns = PATTERN_DEFS
            .iter()
            .filter_map(|def| {
                Regex::new(def.pattern).ok().map(|regex| CompiledPattern {
                    name: def.name.to_string(),
                    regex,
                    severity: def.severity.clone(),
                })
            })
            .collect();
        Self { patterns }
    }

    /// Scan an entire WordPress installation for potential backdoors.
    pub fn scan(&self, wp_root: &Path) -> Vec<BackdoorFinding> {
        let mut findings = Vec::new();

        // 1. Check for PHP files in wp-content/uploads/ (always suspicious).
        findings.extend(self.check_uploads_php(wp_root));

        // 2. Check for hidden PHP dotfiles.
        findings.extend(self.check_hidden_php(wp_root));

        // 3. Collect PHP files to scan (focus on wp-content/).
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

        // Skip WP core directories for warning/info patterns (they contain
        // legitimate uses of system(), exec(), etc.).
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
            // In WP core files, only report Critical patterns.
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

    /// Detect PHP files in wp-content/uploads/ (they should not be there,
    /// unless in known safe cache directories).
    fn check_uploads_php(&self, wp_root: &Path) -> Vec<BackdoorFinding> {
        let uploads = wp_root.join("wp-content/uploads");
        if !uploads.is_dir() {
            return Vec::new();
        }

        WalkDir::new(&uploads)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file() && is_php_file(e.path()))
            .filter(|e| {
                // Skip known safe cache directories.
                let rel = e
                    .path()
                    .strip_prefix(&uploads)
                    .unwrap_or(e.path());
                !UPLOADS_SAFE_DIRS
                    .iter()
                    .any(|safe| rel.starts_with(safe))
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
// Helpers
// ---------------------------------------------------------------------------

/// Check if a file path has a PHP-related extension.
fn is_php_file(path: &Path) -> bool {
    path.extension()
        .map(|ext| {
            let ext = ext.to_string_lossy().to_lowercase();
            ext == "php" || ext == "php5" || ext == "phtml" || ext == "pht"
        })
        .unwrap_or(false)
}

/// Truncate a string to `max_len` characters, appending "..." if truncated.
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
        // system() in wp-includes should not be flagged as Warning.
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
}
