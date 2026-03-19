/// Colored terminal output formatter — pretty-printed with Unicode box-drawing.

use super::OutputFormatter;
use crate::models::*;
use colored::*;

pub struct ConsoleFormatter;

// ── Reusable formatting helpers ─────────────────────────────────────────────

const W: usize = 80;

/// Section header with dotted line: ┄┄┄ Title ┄┄┄┄┄┄┄┄┄┄┄┄┄┄
fn section(title: &str) -> String {
    let label = format!("┄┄┄ {} ", title);
    let rest = W.saturating_sub(label.len() + 2);
    format!("\n  {}{}\n", label.bold(), "┄".repeat(rest).dimmed())
}

/// Thick separator line.
fn separator() -> String {
    format!("  {}\n", "━".repeat(W).dimmed())
}

/// Format a site header box for report view.
fn site_box(site: &WpSite) -> String {
    let ver = site.version.as_deref().unwrap_or("unknown");
    let mut out = String::new();
    out += &format!("\n{}", separator());
    out += &format!(
        "  {}  {}\n",
        "📦".to_string(),
        site.path.display().to_string().bold().cyan()
    );
    out += &format!(
        "  WordPress {}  {}  Owner: {}  {}  Group: {}  {}  Perms: {}\n",
        ver.bold(),
        "│".dimmed(),
        site.owner.yellow(),
        "│".dimmed(),
        site.group,
        "│".dimmed(),
        site.permissions
    );
    out += &separator();
    out
}

// ── OutputFormatter implementation ──────────────────────────────────────────

impl OutputFormatter for ConsoleFormatter {
    fn format_list(&self, sites: &[WpSite]) -> String {
        let mut out = String::new();
        for site in sites {
            let ver = site.version.as_deref().unwrap_or("?");
            let ver_pad = format!("{:<10}", ver);
            out += &format!(
                "  {}  {}\n",
                ver_pad.dimmed(),
                site.path.display()
            );
        }
        out += &format!(
            "\n  {}\n",
            format!("{} site(s) found", sites.len()).dimmed()
        );
        out
    }

    fn format_versions(&self, sites: &[WpSite], latest_wp: &str) -> String {
        let mut out = String::new();

        out += &format!(
            "\n  Latest WordPress version: {}\n\n",
            latest_wp.green().bold()
        );

        // Column headers
        out += &format!(
            "  {:<10} {:<16} {:<16} {:<6} {}\n",
            "VERSION".dimmed(),
            "OWNER".dimmed(),
            "GROUP".dimmed(),
            "PERMS".dimmed(),
            "PATH".dimmed()
        );
        out += &format!("  {}\n", "─".repeat(W).dimmed());

        let mut ok_count = 0usize;
        let mut outdated_count = 0usize;

        for site in sites {
            let ver = site.version.as_deref().unwrap_or("?");
            let is_outdated = site.is_wp_outdated(latest_wp);

            let ver_display = format!("{:<10}", ver);
            let ver_colored = if is_outdated {
                ver_display.red().bold().to_string()
            } else {
                ver_display.green().to_string()
            };

            let status = if is_outdated {
                outdated_count += 1;
                "⚠ OUTDATED".red().bold().to_string()
            } else {
                ok_count += 1;
                "✓ OK".green().to_string()
            };

            out += &format!(
                "  {} {:<16} {:<16} {:<6} {}  {}\n",
                ver_colored,
                site.owner,
                site.group,
                site.permissions,
                site.path.display(),
                status
            );
        }

        // Summary
        out += &format!("  {}\n", "─".repeat(W).dimmed());
        out += &format!(
            "  {} site(s)  {}  {}  {}\n\n",
            sites.len().to_string().bold(),
            "│".dimmed(),
            format!("{} up-to-date", ok_count).green(),
            format!("{} outdated", outdated_count).red()
        );

        out
    }

    fn format_report(&self, reports: &[SiteReport]) -> String {
        let mut out = String::new();

        for report in reports {
            let ver = report.site.version.as_deref().unwrap_or("unknown");

            // ── Site header ──────────────────────────────────────────
            out += &site_box(&report.site);

            // ── Version check ────────────────────────────────────────
            if let Some(latest) = &report.latest_wp_version {
                if report.site.is_wp_outdated(latest) {
                    out += &format!(
                        "\n  {} WordPress {} {} {} {}\n",
                        "⚠".red().bold(),
                        ver.red().bold(),
                        "→".dimmed(),
                        latest.green().bold(),
                        "available".green()
                    );
                    out += &format!(
                        "  {} {}\n",
                        "→".dimmed(),
                        format!(
                            "wp core update --path=\"{}\"",
                            report.site.path.display()
                        )
                        .yellow()
                    );
                } else {
                    out += &format!(
                        "\n  {} WordPress {} {}\n",
                        "✓".green().bold(),
                        ver.green().bold(),
                        "up-to-date".green()
                    );
                }
            }

            // ── Plugins ──────────────────────────────────────────────
            if let Some(plugins) = &report.plugins {
                out += &section("Plugins");

                if plugins.is_empty() {
                    out += &format!("  {} {}\n", "—".dimmed(), "No plugins found".dimmed());
                } else {
                    out += &format!(
                        "  {:<35} {:<15} {:<15} {}\n",
                        "PLUGIN".dimmed(),
                        "INSTALLED".dimmed(),
                        "LATEST".dimmed(),
                        "STATUS".dimmed()
                    );
                    out += &format!("  {}\n", "─".repeat(W - 2).dimmed());

                    let mut outdated_slugs = Vec::new();
                    for plugin in plugins {
                        let name_pad = format!("{:<35}", plugin.name);
                        let ver_pad = format!("{:<15}", plugin.installed_version);
                        let latest_pad = format!(
                            "{:<15}",
                            plugin.latest_version.as_deref().unwrap_or("—")
                        );

                        if plugin.is_outdated() {
                            outdated_slugs.push(plugin.slug.clone());
                            out += &format!(
                                "  {} {} {} {}\n",
                                name_pad.red(),
                                ver_pad.red(),
                                latest_pad,
                                "⚠ OUTDATED".red().bold()
                            );
                        } else if plugin.is_unknown() {
                            out += &format!(
                                "  {} {} {} {}\n",
                                name_pad, ver_pad, latest_pad,
                                "? unknown".yellow()
                            );
                        } else {
                            out += &format!(
                                "  {} {} {} {}\n",
                                name_pad, ver_pad, latest_pad,
                                "✓ OK".green()
                            );
                        }
                    }

                    // Summary line
                    let ok = plugins.iter().filter(|p| !p.is_outdated() && !p.is_unknown()).count();
                    let outdated = outdated_slugs.len();
                    let unknown = plugins.iter().filter(|p| p.is_unknown()).count();
                    out += &format!("  {}\n", "─".repeat(W - 2).dimmed());
                    out += &format!(
                        "  {} plugin(s): {} {}, {} {}, {} {}\n",
                        plugins.len().to_string().bold(),
                        ok.to_string().green(), "OK".green(),
                        outdated.to_string().red(), "outdated".red(),
                        unknown.to_string().yellow(), "unknown".yellow()
                    );

                    if !outdated_slugs.is_empty() {
                        out += &format!(
                            "\n  {} {}\n",
                            "→".dimmed(),
                            format!(
                                "wp plugin update {} --path=\"{}\"",
                                outdated_slugs.join(" "),
                                report.site.path.display()
                            )
                            .yellow()
                        );
                    }
                }
            }

            // ── Permissions ──────────────────────────────────────────
            if let Some(issues) = &report.perm_issues {
                out += &section("Permissions");

                if issues.is_empty() {
                    out += &format!("  {} {}\n", "✓".green().bold(), "No issues found".green());
                } else {
                    for issue in issues {
                        let (icon, msg) = match issue.severity {
                            Severity::Critical => (
                                "✗".red().bold().to_string(),
                                format!("{}: {}", "CRITICAL".red().bold(), issue.issue),
                            ),
                            Severity::Warning => (
                                "!".yellow().bold().to_string(),
                                format!("{}: {}", "WARNING".yellow(), issue.issue),
                            ),
                            Severity::Info => (
                                "i".blue().to_string(),
                                format!("{}: {}", "INFO".blue(), issue.issue),
                            ),
                        };
                        out += &format!(
                            "  {} {}  {}\n",
                            icon,
                            msg,
                            issue.path.display().to_string().dimmed()
                        );
                    }

                    if !report.perm_fix_commands.is_empty() {
                        out += &format!("\n  {}\n", "Fix commands:".bold());
                        for cmd in &report.perm_fix_commands {
                            out += &format!("  {} {}\n", "→".dimmed(), cmd.yellow());
                        }
                    }
                }
            }

            // ── Backdoor scan ────────────────────────────────────────
            if let Some(findings) = &report.backdoor_findings {
                out += &section("Backdoor Scan");

                if findings.is_empty() {
                    out += &format!(
                        "  {} {}\n",
                        "✓".green().bold(),
                        "No suspicious files found".green()
                    );
                } else {
                    let crit = findings.iter().filter(|f| f.severity == Severity::Critical).count();
                    let warn = findings.iter().filter(|f| f.severity == Severity::Warning).count();
                    let info = findings.iter().filter(|f| f.severity == Severity::Info).count();

                    out += &format!(
                        "  {} {} finding(s): {} {}, {} {}, {} {}\n\n",
                        "⚠".red().bold(),
                        findings.len().to_string().bold(),
                        crit.to_string().red().bold(), "critical".red(),
                        warn.to_string().yellow(), "warning".yellow(),
                        info.to_string().blue(), "info".blue()
                    );

                    for finding in findings {
                        let (icon, tag) = match finding.severity {
                            Severity::Critical => (
                                "✗".red().bold().to_string(),
                                finding.pattern_name.red().bold().to_string(),
                            ),
                            Severity::Warning => (
                                "!".yellow().bold().to_string(),
                                finding.pattern_name.yellow().to_string(),
                            ),
                            Severity::Info => (
                                "i".blue().to_string(),
                                finding.pattern_name.blue().to_string(),
                            ),
                        };
                        let loc = if finding.line > 0 {
                            format!("{}:{}", finding.file.display(), finding.line)
                        } else {
                            format!("{}", finding.file.display())
                        };
                        out += &format!("  {} {}  {}\n", icon, tag, loc.dimmed());
                        out += &format!("    {}\n", finding.snippet.dimmed());
                    }
                }
            }

            out += "\n";
        }

        out
    }
}
