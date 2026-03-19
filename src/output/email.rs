/// Email delivery — auto-detects local sendmail or falls back to remote SMTP.
///
/// Priority:
///   1. If SMTP_HOST env var is set → use remote SMTP transport
///   2. If /usr/sbin/sendmail exists → use local sendmail (postfix)
///   3. Error with helpful message

use crate::cli::OutputFormat;
use crate::config;
use anyhow::{Context, Result};
use lettre::message::header::ContentType;
use lettre::{Message, Transport};
use regex::Regex;
use std::path::Path;

/// Send the formatted report by email.
pub fn send_email(to: &str, content: &str, format: &OutputFormat) -> Result<()> {
    // Build the "from" address.
    let from = resolve_from_address();

    // Strip ANSI escape codes for non-HTML formats.
    let body = if matches!(format, OutputFormat::Console) {
        strip_ansi_codes(content)
    } else {
        content.to_string()
    };

    let ct = if matches!(format, OutputFormat::Html) {
        ContentType::TEXT_HTML
    } else {
        ContentType::TEXT_PLAIN
    };

    let email = Message::builder()
        .from(from.parse().context("Invalid sender address")?)
        .to(to.parse().context("Invalid recipient address")?)
        .subject("WP Scanner Report")
        .header(ct)
        .body(body)
        .context("Failed to build email")?;

    // Choose transport: SMTP if configured, otherwise local sendmail.
    if std::env::var(config::SMTP_HOST_VAR).is_ok() {
        send_via_smtp(email)?;
    } else if Path::new("/usr/sbin/sendmail").exists() {
        send_via_sendmail(email)?;
    } else {
        anyhow::bail!(
            "No email transport available.\n\
             Either install postfix/sendmail locally,\n\
             or set SMTP_HOST, SMTP_USER, SMTP_PASS env vars."
        );
    }

    eprintln!("Report sent to {}", to);
    Ok(())
}

/// Send using local sendmail binary (postfix).
fn send_via_sendmail(email: Message) -> Result<()> {
    // Use the absolute path — /usr/sbin is often not in the user's PATH.
    let transport = lettre::SendmailTransport::new_with_command("/usr/sbin/sendmail");
    transport
        .send(&email)
        .context("Failed to send via sendmail")?;
    Ok(())
}

/// Send using remote SMTP with TLS.
fn send_via_smtp(email: Message) -> Result<()> {
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::SmtpTransport;

    let host = std::env::var(config::SMTP_HOST_VAR).context("SMTP_HOST not set")?;
    let port: u16 = std::env::var(config::SMTP_PORT_VAR)
        .unwrap_or_else(|_| "587".to_string())
        .parse()
        .context("Invalid SMTP_PORT")?;
    let user = std::env::var(config::SMTP_USER_VAR).context("SMTP_USER not set")?;
    let pass = std::env::var(config::SMTP_PASS_VAR).context("SMTP_PASS not set")?;

    let creds = Credentials::new(user, pass);
    let transport = SmtpTransport::relay(&host)
        .context("Failed to create SMTP transport")?
        .port(port)
        .credentials(creds)
        .build();

    transport
        .send(&email)
        .context("Failed to send via SMTP")?;
    Ok(())
}

/// Determine the sender email address.
fn resolve_from_address() -> String {
    // 1. Explicit SMTP_FROM env var
    if let Ok(from) = std::env::var(config::SMTP_FROM_VAR) {
        return from;
    }
    // 2. SMTP_USER (if using remote SMTP)
    if let Ok(user) = std::env::var(config::SMTP_USER_VAR) {
        return user;
    }
    // 3. Auto-detect from system user + hostname
    let user = std::env::var("USER").unwrap_or_else(|_| "wp-scanner".to_string());
    let hostname = std::fs::read_to_string("/etc/hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_else(|_| "localhost".to_string());
    format!("{}@{}", user, hostname)
}

/// Remove ANSI escape sequences from a string.
fn strip_ansi_codes(s: &str) -> String {
    let re = Regex::new(r"\x1b\[[0-9;]*[a-zA-Z]").unwrap();
    re.replace_all(s, "").into_owned()
}
