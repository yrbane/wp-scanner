```
 █░█░█ █▀█   █▀ █▀▀ ▄▀█ █▄░█ █▄░█ █▀▀ █▀█
 ▀▄▀▄▀ █▀▀   ▄█ █▄▄ █▀█ █░▀█ █░▀█ ██▄ █▀▄
```

# WP Scanner

**WordPress Security Scanner & Monitoring Tool** — a fast, single-binary CLI written in Rust.

Discovers WordPress installations served by nginx, then audits versions, plugins, file permissions, and scans for backdoors — all **without executing any PHP code**, making it safe to run even on compromised servers.

---

## Features

| Command | Description |
|---------|-------------|
| `list` | List all WordPress installations found via nginx configs |
| `versions` | Check WordPress core versions against the latest release |
| `plugins` | Scan installed plugins and check for updates via wordpress.org API |
| `permissions` | Audit file permissions and ownership (world-writable, www-data, etc.) |
| `backdoor` | Scan for potential backdoors and malicious PHP code |
| `report` | Generate a comprehensive security report (all checks combined) |

### Highlights

- **Safe** — extracts WP versions and plugin metadata via regex, never `include`/`require`
- **Fast** — parallel file scanning with [rayon](https://github.com/rayon-rs/rayon) (~2s per site for backdoor scans)
- **Smart** — caches wordpress.org API responses (1 call per plugin slug, even across 30+ sites)
- **Multi-root nginx** — correctly handles configs with multiple `server` blocks (fixes a bug in the original PHP implementation it replaces)
- **4 output formats** — `console` (colored), `json`, `md`, `html` (standalone dark-themed page)
- **Email** — auto-detects local sendmail/postfix; falls back to remote SMTP
- **Single binary** — no runtime dependencies, no PHP, no Python

---

## Installation

### From source

```bash
# Install Rust (if needed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
git clone https://github.com/yrbane/wp-scanner.git
cd wp-scanner
cargo build --release

# Install
cp target/release/wp-scanner ~/.local/bin/
```

### Requirements

- Linux (uses `libc` for uid/gid resolution)
- Read access to `/etc/nginx/sites-available/` (for auto-discovery)
- Read access to WordPress installation directories

---

## Usage

```bash
# List all WordPress sites
wp-scanner list

# Check versions
wp-scanner versions

# Scan plugins for a specific site
wp-scanner plugins --site myblog

# Audit permissions (JSON output)
wp-scanner permissions --format json

# Backdoor scan
wp-scanner backdoor --site myshop

# Full report as HTML, emailed
wp-scanner report --format html --mail admin@example.com

# Full report saved to file
wp-scanner report --format html > report.html

# Scan a specific directory (bypass nginx discovery)
wp-scanner report --path /var/www/my-wordpress
```

### Global options

| Option | Description |
|--------|-------------|
| `-f, --format <FORMAT>` | Output format: `console` (default), `json`, `md`, `html` |
| `--mail <EMAIL>` | Email the report to this address |
| `--site <FILTER>` | Filter discovered sites by path (substring match) |
| `--path <DIR>` | Scan a specific WordPress directory (bypass nginx discovery) |

---

## Output examples

### `wp-scanner versions`

```
  Latest WordPress version: 6.9.4

  VERSION    OWNER            GROUP            PERMS  PATH
  ────────────────────────────────────────────────────────────────────────────────
  6.3        alice            www-data         0750   /var/www/myblog/www           ⚠ OUTDATED
  6.9.4      bob              www-data         0750   /var/www/myshop/www           ✓ OK
  ────────────────────────────────────────────────────────────────────────────────
  12 site(s)  │  5 up-to-date  7 outdated
```

### `wp-scanner permissions`

```
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  📦  /var/www/myshop/www
  WordPress 6.9.4  │  Owner: deploy  │  Group: deploy  │  Perms: 0777
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ┄┄┄ Permissions ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄
  ✗ CRITICAL: directory is world-writable
  ! WARNING: wp-config.php is world-readable

  Fix commands:
  → sudo chown deploy.www-data "/var/www/myshop/www" -R
  → sudo chmod 750 "/var/www/myshop/www" -R
```

### `wp-scanner report --format html`

Generates a standalone HTML page with a dark theme, color-coded tables, and copy-pastable fix commands.

---

## Backdoor scanner

Detects ~20 patterns organized by severity:

### Critical (almost certainly malicious)

- `eval(base64_decode(…))`, `eval(gzinflate(…))`, `eval(str_rot13(…))`
- `assert(base64_decode(…))`
- `preg_replace` with `/e` modifier (code execution)
- Known webshell signatures (c99, r57, WSO, b374k, FilesMan)
- PHP files in `wp-content/uploads/` (with safe cache dir exclusions)
- Obfuscated long lines (>1000 chars with eval/base64)
- `create_function()` with superglobal input
- `@$_GET[`/`@$_POST[` suppressed superglobal execution

### Warning (suspicious, needs investigation)

- `system()`, `exec()`, `passthru()`, `shell_exec()`, `popen()`, `proc_open()`
- `file_put_contents()` with `$_GET`/`$_POST`/`$_REQUEST`
- `base64_decode()` with superglobal input
- Hex obfuscation (`\x` sequences) and `chr()` obfuscation chains
- Hidden PHP dotfiles

### Smart filtering

- **WP core directories** (`wp-includes/`, `wp-admin/`) are only checked for Critical patterns (they contain legitimate uses of `exec()` etc.)
- **Known cache directories** in uploads (`cache/`, `wflogs/`, `wp-file-manager-pro/`) are excluded from the PHP-in-uploads check

---

## Email

`--mail` auto-detects the best transport:

1. **Local sendmail/postfix** — if `/usr/sbin/sendmail` exists, it just works. No configuration needed.
2. **Remote SMTP** — if `SMTP_HOST` env var is set, uses SMTP with TLS.

### SMTP environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SMTP_HOST` | Yes | SMTP server hostname |
| `SMTP_PORT` | No | SMTP port (default: 587) |
| `SMTP_USER` | Yes | SMTP username |
| `SMTP_PASS` | Yes | SMTP password |
| `SMTP_FROM` | No | Sender address (defaults to `SMTP_USER`) |

When using `--format html` with `--mail`, the email is sent as HTML with the dark-themed report rendered directly in the email client.

---

## Project structure

```
src/
├── main.rs               Entry point, command dispatch
├── cli.rs                 CLI definition (clap derive)
├── config.rs              Constants (paths, API URLs, env vars)
├── models.rs              Data structures (WpSite, WpPlugin, SiteReport, …)
├── wordpress_api.rs       WordPress.org API client with caching
├── scanner/
│   ├── discovery.rs       Find WP sites via nginx configs
│   ├── version.rs         Extract WP version via regex
│   ├── plugins.rs         Plugin metadata extraction + API check
│   ├── permissions.rs     Unix permission auditing + fix commands
│   └── backdoor.rs        Backdoor pattern detection (rayon parallel)
└── output/
    ├── mod.rs             OutputFormatter trait + factory
    ├── console.rs         Colored terminal output
    ├── json.rs            JSON (serde)
    ├── markdown.rs        Markdown tables
    ├── html.rs            Standalone HTML page (dark theme)
    └── email.rs           Email delivery (sendmail / SMTP)
```

### Design principles

- **SOLID** — `OutputFormatter` trait (Open/Closed), single-responsibility modules, dependency inversion via traits
- **DRY** — shared `WpApi` cache, reusable `SiteReport` structure, `build_reports()` helper
- **Safe** — no PHP execution, no shell injection, regex-only extraction
- **Tested** — 25 unit tests covering version extraction, plugin metadata parsing, backdoor detection, permission checks

---

## Tests

```bash
cargo test
```

```
test result: ok. 25 passed; 0 failed; 0 ignored
```

---

## License

MIT

---

*Built with Rust 🦀*
