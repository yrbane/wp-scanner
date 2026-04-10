/// wp-scanner — WordPress security scanner & monitoring tool.
///
/// Discovers WordPress installations via nginx configs and runs security
/// checks: version, plugins, permissions, backdoor detection.
/// Outputs to console (colored), JSON, Markdown, or HTML.

mod cli;
mod config;
mod models;
mod output;
mod scanner;
mod wordpress_api;

use anyhow::Result;
use clap::Parser;

use cli::{Cli, Commands};
use models::*;
use scanner::{backdoor, backdoor::BackdoorScanner, discovery, permissions, plugins, version};
use wordpress_api::WpApi;

fn main() -> Result<()> {
    let cli = Cli::parse();

    // ── Handle update command early (no site discovery needed) ──────────
    if matches!(&cli.command, Commands::Update) {
        return backdoor::update_patterns();
    }

    let formatter = output::create_formatter(&cli.format);
    let mut api = WpApi::new();

    // ── Discover WordPress sites ────────────────────────────────────────
    let site_paths = discovery::find_wordpress_sites(
        cli.site.as_deref(),
        cli.path.as_deref(),
    );

    if site_paths.is_empty() {
        eprintln!("No WordPress installations found.");
        return Ok(());
    }

    // ── Build site info ─────────────────────────────────────────────────
    let sites: Vec<WpSite> = site_paths
        .iter()
        .map(|path| {
            let (owner, group, perms) = permissions::get_file_info(path);
            WpSite {
                path: path.clone(),
                version: version::extract_wp_version(path),
                owner,
                group,
                permissions: perms,
            }
        })
        .collect();

    // ── Execute command ─────────────────────────────────────────────────
    let result = match &cli.command {
        Commands::List => formatter.format_list(&sites),

        Commands::Versions => {
            let latest = api
                .latest_wp_version()
                .unwrap_or_else(|| "unknown".to_string());
            formatter.format_versions(&sites, &latest)
        }

        Commands::Plugins => {
            let reports = build_reports(&sites, |site| SiteReport {
                site: site.clone(),
                latest_wp_version: None,
                plugins: Some(plugins::scan_plugins(&site.path, &mut api)),
                perm_issues: None,
                perm_fix_commands: Vec::new(),
                backdoor_findings: None,
            });
            formatter.format_report(&reports)
        }

        Commands::Permissions => {
            let reports = build_reports(&sites, |site| {
                let issues = permissions::scan_permissions(site);
                let fix_cmds = permissions::build_fix_commands(site, &issues);
                SiteReport {
                    site: site.clone(),
                    latest_wp_version: None,
                    plugins: None,
                    perm_issues: Some(issues),
                    perm_fix_commands: fix_cmds,
                    backdoor_findings: None,
                }
            });
            formatter.format_report(&reports)
        }

        Commands::Backdoor => {
            let bd_scanner = BackdoorScanner::new();
            let reports = build_reports(&sites, |site| SiteReport {
                site: site.clone(),
                latest_wp_version: None,
                plugins: None,
                perm_issues: None,
                perm_fix_commands: Vec::new(),
                backdoor_findings: Some(bd_scanner.scan(&site.path)),
            });
            formatter.format_report(&reports)
        }

        Commands::Update => unreachable!("handled above"),

        Commands::Report => {
            let latest_wp = api.latest_wp_version();
            let bd_scanner = BackdoorScanner::new();
            let reports = build_reports(&sites, |site| {
                let perm_issues = permissions::scan_permissions(site);
                let fix_cmds = permissions::build_fix_commands(site, &perm_issues);
                SiteReport {
                    site: site.clone(),
                    latest_wp_version: latest_wp.clone(),
                    plugins: Some(plugins::scan_plugins(&site.path, &mut api)),
                    perm_issues: Some(perm_issues),
                    perm_fix_commands: fix_cmds,
                    backdoor_findings: Some(bd_scanner.scan(&site.path)),
                }
            });
            formatter.format_report(&reports)
        }
    };

    // ── Output ──────────────────────────────────────────────────────────
    print!("{}", result);

    // ── Send email if requested ─────────────────────────────────────────
    if let Some(addr) = &cli.mail {
        output::email::send_email(addr, &result, &cli.format)?;
    }

    Ok(())
}

/// Helper: build a SiteReport for each site using the given closure.
fn build_reports<F>(sites: &[WpSite], mut f: F) -> Vec<SiteReport>
where
    F: FnMut(&WpSite) -> SiteReport,
{
    sites.iter().map(|site| f(site)).collect()
}
