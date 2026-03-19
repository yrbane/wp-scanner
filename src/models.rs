/// Core data structures shared across all modules.

use serde::Serialize;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    Warning,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::Warning => write!(f, "WARNING"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

// ---------------------------------------------------------------------------
// WordPress site
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct WpSite {
    pub path: PathBuf,
    /// WordPress core version extracted from version.php (None if unreadable).
    pub version: Option<String>,
    /// Unix owner of the site root directory.
    pub owner: String,
    /// Unix group of the site root directory.
    pub group: String,
    /// Octal permission string (e.g. "0750").
    pub permissions: String,
}

impl WpSite {
    /// Returns true when the installed version differs from `latest`.
    pub fn is_wp_outdated(&self, latest: &str) -> bool {
        self.version.as_ref().map(|v| v != latest).unwrap_or(true)
    }
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct WpPlugin {
    pub slug: String,
    pub name: String,
    pub installed_version: String,
    /// Latest version from wordpress.org (None = not found on the directory).
    pub latest_version: Option<String>,
}

impl WpPlugin {
    pub fn is_outdated(&self) -> bool {
        self.latest_version
            .as_ref()
            .map(|v| v != &self.installed_version)
            .unwrap_or(false)
    }

    pub fn is_unknown(&self) -> bool {
        self.latest_version.is_none()
    }
}

// ---------------------------------------------------------------------------
// Permission issue
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct PermIssue {
    pub path: PathBuf,
    pub issue: String,
    pub severity: Severity,
    pub fix_command: Option<String>,
}

// ---------------------------------------------------------------------------
// Backdoor finding
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct BackdoorFinding {
    pub file: PathBuf,
    pub line: usize,
    pub pattern_name: String,
    pub severity: Severity,
    /// Truncated snippet of the matching line.
    pub snippet: String,
}

// ---------------------------------------------------------------------------
// Site report — aggregates all scan results for one WP installation.
//
// Option semantics:
//   None       → section was NOT scanned (e.g. running `versions` only)
//   Some([])   → scanned, no findings
//   Some([..]) → scanned, findings present
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct SiteReport {
    pub site: WpSite,
    /// Latest WP core version (set when version check is relevant).
    pub latest_wp_version: Option<String>,
    pub plugins: Option<Vec<WpPlugin>>,
    pub perm_issues: Option<Vec<PermIssue>>,
    /// Shell commands to fix permission issues.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub perm_fix_commands: Vec<String>,
    pub backdoor_findings: Option<Vec<BackdoorFinding>>,
}
