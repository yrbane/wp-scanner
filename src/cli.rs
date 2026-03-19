/// Command-line interface definition (clap derive).

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// ASCII art banner displayed in --help.
const BANNER: &str = "\x1b[36m\
 █░█░█ █▀█   █▀ █▀▀ ▄▀█ █▄░█ █▄░█ █▀▀ █▀█\n\
 ▀▄▀▄▀ █▀▀   ▄█ █▄▄ █▀█ █░▀█ █░▀█ ██▄ █▀▄\
\x1b[0m";

/// Examples and email info shown after --help.
const AFTER_HELP: &str = "\x1b[33mEMAIL:\x1b[0m\n\
  If postfix/sendmail is available locally, \x1b[32m--mail works out of the box\x1b[0m.\n\
  Otherwise, set SMTP_HOST, SMTP_USER, SMTP_PASS env vars for remote SMTP.\n\n\
\x1b[33mEXAMPLES:\x1b[0m\n\
  \x1b[2m$\x1b[0m wp-scanner \x1b[36mlist\x1b[0m\n\
  \x1b[2m$\x1b[0m wp-scanner \x1b[36mversions\x1b[0m\n\
  \x1b[2m$\x1b[0m wp-scanner \x1b[36mplugins\x1b[0m --site olikalari\n\
  \x1b[2m$\x1b[0m wp-scanner \x1b[36mpermissions\x1b[0m --format json\n\
  \x1b[2m$\x1b[0m wp-scanner \x1b[36mbackdoor\x1b[0m --site lafourniliere\n\
  \x1b[2m$\x1b[0m wp-scanner \x1b[36mreport\x1b[0m --format html --mail admin@example.com\n\
  \x1b[2m$\x1b[0m wp-scanner \x1b[36mreport\x1b[0m --format html > report.html";

#[derive(Parser)]
#[command(
    name = "wp-scanner",
    version,
    about = "\x1b[2mWordPress Security Scanner & Monitoring Tool\x1b[0m",
    before_help = BANNER,
    after_help = AFTER_HELP,
    help_template = "\
{before-help}
 {name} \x1b[33m{version}\x1b[0m

{about}

\x1b[33mUSAGE:\x1b[0m {usage}

\x1b[33mCOMMANDS:\x1b[0m
{subcommands}

\x1b[33mOPTIONS:\x1b[0m
{options}

{after-help}
"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Output format [console|json|md|html]
    #[arg(long, short, default_value = "console", global = true)]
    pub format: OutputFormat,

    /// Email the report to this address
    #[arg(long, global = true)]
    pub mail: Option<String>,

    /// Filter discovered sites by path (substring match)
    #[arg(long, global = true)]
    pub site: Option<String>,

    /// Scan a specific WordPress directory (bypasses nginx discovery)
    #[arg(long, global = true)]
    pub path: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// List all WordPress installations found via nginx
    List,
    /// Check WordPress core versions against latest release
    Versions,
    /// Scan installed plugins and check for updates
    Plugins,
    /// Audit file permissions and ownership
    Permissions,
    /// Scan for potential backdoors and malicious code
    Backdoor,
    /// Generate a comprehensive security report (all checks)
    Report,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum OutputFormat {
    Console,
    Json,
    Md,
    Html,
}
