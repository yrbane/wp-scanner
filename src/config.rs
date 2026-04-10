/// Centralized configuration constants.

/// Path to nginx site configuration files.
pub const NGINX_SITES_DIR: &str = "/etc/nginx/sites-available";

/// WordPress.org API endpoint for core version checks (JSON format).
pub const WP_VERSION_API: &str = "https://api.wordpress.org/core/version-check/1.7/";

/// WordPress.org API endpoint for plugin information.
pub const WP_PLUGIN_API: &str =
    "https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&slug=";

/// User-Agent string sent with API requests.
pub const USER_AGENT: &str = "wp-scanner/1.0";

/// URL for the remote patterns database.
pub const PATTERNS_URL: &str = "https://wp-scanner.gie.im/patterns.json";

/// Local patterns file path (~/.config/wp-scanner/patterns.json).
pub fn patterns_local_path() -> std::path::PathBuf {
    let config_dir = std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/tmp"))
        .join(".config/wp-scanner");
    config_dir.join("patterns.json")
}

/// SMTP environment variable names for email delivery.
pub const SMTP_HOST_VAR: &str = "SMTP_HOST";
pub const SMTP_PORT_VAR: &str = "SMTP_PORT";
pub const SMTP_USER_VAR: &str = "SMTP_USER";
pub const SMTP_PASS_VAR: &str = "SMTP_PASS";
pub const SMTP_FROM_VAR: &str = "SMTP_FROM";
