/// Markdown output formatter — generates tables and headings.

use crate::models::*;
use super::OutputFormatter;

pub struct MarkdownFormatter;

impl OutputFormatter for MarkdownFormatter {
    fn format_list(&self, sites: &[WpSite]) -> String {
        let mut out = String::from("# WordPress Installations\n\n");
        for site in sites {
            out += &format!("- `{}`\n", site.path.display());
        }
        out
    }

    fn format_versions(&self, sites: &[WpSite], latest_wp: &str) -> String {
        let mut out = format!("# WordPress Versions\n\nLatest: **{}**\n\n", latest_wp);
        out += "| Version | Owner | Group | Perms | Path | Status |\n";
        out += "|---------|-------|-------|-------|------|--------|\n";

        for site in sites {
            let ver = site.version.as_deref().unwrap_or("?");
            let status = if site.is_wp_outdated(latest_wp) {
                "⚠️ OUTDATED"
            } else {
                "✅ OK"
            };
            out += &format!(
                "| {} | {} | {} | {} | `{}` | {} |\n",
                ver,
                site.owner,
                site.group,
                site.permissions,
                site.path.display(),
                status
            );
        }
        out
    }

    fn format_report(&self, reports: &[SiteReport]) -> String {
        let mut out = String::from("# WP Scanner Report\n\n");

        for report in reports {
            let ver = report.site.version.as_deref().unwrap_or("unknown");
            out += &format!(
                "## {} (WordPress {})\n\n",
                report.site.path.display(),
                ver
            );
            out += &format!(
                "- **Owner:** {} | **Group:** {} | **Permissions:** {}\n\n",
                report.site.owner, report.site.group, report.site.permissions
            );

            // Version check
            if let Some(latest) = &report.latest_wp_version {
                if report.site.is_wp_outdated(latest) {
                    out += &format!(
                        "⚠️ **WordPress outdated:** {} → {}\n\n",
                        ver, latest
                    );
                    out += &format!(
                        "```bash\nwp core update --path=\"{}\"\n```\n\n",
                        report.site.path.display()
                    );
                } else {
                    out += "✅ WordPress is up-to-date\n\n";
                }
            }

            // Plugins
            if let Some(plugins) = &report.plugins {
                out += "### Plugins\n\n";
                if plugins.is_empty() {
                    out += "No plugins found.\n\n";
                } else {
                    out += "| Plugin | Installed | Latest | Status |\n";
                    out += "|--------|-----------|--------|--------|\n";

                    let mut outdated_slugs = Vec::new();
                    for p in plugins {
                        let latest = p.latest_version.as_deref().unwrap_or("—");
                        let status = if p.is_outdated() {
                            outdated_slugs.push(p.slug.as_str());
                            "⚠️ OUTDATED"
                        } else if p.is_unknown() {
                            "❓ Unknown"
                        } else {
                            "✅ OK"
                        };
                        out += &format!(
                            "| {} | {} | {} | {} |\n",
                            p.name, p.installed_version, latest, status
                        );
                    }
                    out += "\n";

                    if !outdated_slugs.is_empty() {
                        out += "**Update command:**\n\n";
                        out += &format!(
                            "```bash\nwp plugin update {} --path=\"{}\"\n```\n\n",
                            outdated_slugs.join(" "),
                            report.site.path.display()
                        );
                    }
                }
            }

            // Permissions
            if let Some(issues) = &report.perm_issues {
                out += "### Permissions\n\n";
                if issues.is_empty() {
                    out += "✅ No issues found.\n\n";
                } else {
                    for issue in issues {
                        let icon = match issue.severity {
                            Severity::Critical => "🔴",
                            Severity::Warning => "🟡",
                            Severity::Info => "🔵",
                        };
                        out += &format!(
                            "- {} **{}** — `{}`\n",
                            icon,
                            issue.issue,
                            issue.path.display()
                        );
                    }
                    out += "\n";

                    if !report.perm_fix_commands.is_empty() {
                        out += "**Fix commands:**\n\n```bash\n";
                        for cmd in &report.perm_fix_commands {
                            out += &format!("{}\n", cmd);
                        }
                        out += "```\n\n";
                    }
                }
            }

            // Backdoors
            if let Some(findings) = &report.backdoor_findings {
                out += "### Backdoor Scan\n\n";
                if findings.is_empty() {
                    out += "✅ No suspicious files found.\n\n";
                } else {
                    out += &format!("⚠️ **{} finding(s)**\n\n", findings.len());
                    out += "| Severity | Pattern | File | Line | Snippet |\n";
                    out += "|----------|---------|------|------|---------|\n";
                    for f in findings {
                        let sev = match f.severity {
                            Severity::Critical => "🔴 CRITICAL",
                            Severity::Warning => "🟡 WARNING",
                            Severity::Info => "🔵 INFO",
                        };
                        let loc = if f.line > 0 {
                            f.line.to_string()
                        } else {
                            "—".to_string()
                        };
                        // Escape pipe chars in snippet for markdown table.
                        let snippet = f.snippet.replace('|', "\\|");
                        out += &format!(
                            "| {} | {} | `{}` | {} | `{}` |\n",
                            sev,
                            f.pattern_name,
                            f.file.display(),
                            loc,
                            snippet
                        );
                    }
                    out += "\n";
                }
            }

            out += "---\n\n";
        }

        out
    }
}
