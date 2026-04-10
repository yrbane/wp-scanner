```
 █░█░█ █▀█   █▀ █▀▀ ▄▀█ █▄░█ █▄░█ █▀▀ █▀█
 ▀▄▀▄▀ █▀▀   ▄█ █▄▄ █▀█ █░▀█ █░▀█ ██▄ █▀▄
```

# WP Scanner

**WordPress Security Scanner & Monitoring Tool** — a fast, single-binary CLI written in Rust.

Discovers WordPress installations served by nginx, then audits versions, plugins, file permissions, and scans for backdoors — all **without executing any PHP code**, making it safe to run even on compromised servers.

**[Documentation & Pattern Database](https://yrbane.github.io/wp-scanner/)**

---

## Features

| Command | Description |
|---------|-------------|
| `list` | List all WordPress installations found via nginx configs |
| `versions` | Check WordPress core versions against the latest release |
| `plugins` | Scan installed plugins and check for updates via wordpress.org API |
| `permissions` | Audit file permissions and ownership (world-writable, www-data, etc.) |
| `backdoor` | Scan for potential backdoors and malicious PHP code (38 patterns) |
| `report` | Generate a comprehensive security report (all checks combined) |
| `update` | Download the latest backdoor patterns from the remote database |

### Highlights

- **Safe** — extracts WP versions and plugin metadata via regex, never `include`/`require`
- **Fast** — parallel file scanning with [rayon](https://github.com/rayon-rs/rayon) (~2s per site for backdoor scans)
- **Smart** — caches wordpress.org API responses (1 call per plugin slug, even across 30+ sites)
- **Multi-root nginx** — correctly handles configs with multiple `server` blocks
- **4 output formats** — `console` (colored), `json`, `md`, `html` (standalone dark-themed page)
- **Email** — auto-detects local sendmail/postfix; falls back to remote SMTP
- **Updatable patterns** — backdoor patterns stored in external JSON, updated without rebuilding
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

# Update backdoor patterns
wp-scanner update
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

Detects **38 patterns** organized by severity:

### Critical

| Pattern | Description |
|---------|-------------|
| `eval_base64` | `eval(base64_decode())` — classic obfuscation |
| `eval_gzinflate` | `eval(gzinflate())` — compressed code execution |
| `eval_str_rot13` | `eval(str_rot13())` — ROT13 obfuscation |
| `assert_base64` | `assert(base64_decode())` — alternative to eval |
| `assert_string` | `assert()` with superglobal input |
| `preg_replace_eval` | `preg_replace` with `/e` modifier |
| `webshell_signature` | c99, r57, WSO, b374k, FilesMan, AnonymousFox, AlfaShell |
| `suppressed_superglobal` | `@$_GET[` / `@$_POST[` suppressed access |
| `create_function_input` | `create_function()` with user input |
| `include_remote_url` | `include/require` with `http://` URL |
| `include_user_input` | `include/require` with `$_GET`/`$_POST` |
| `call_user_func_input` | `call_user_func()` with superglobal |
| `unserialize_user_input` | `unserialize()` — PHP object injection |
| `extract_superglobal` | `extract($_GET)` — variable overwrite |
| `ini_set_url_include` | Enabling `allow_url_include` at runtime |
| `variable_function_call` | `$_GET['func']()` — dynamic call |
| `php_in_uploads` | PHP files in `wp-content/uploads/` |
| `obfuscated_long_line` | Lines >1000 chars with eval/base64 |

### Warning

| Pattern | Description |
|---------|-------------|
| `shell_exec` / `system_call` / `exec_call` / `passthru_call` | Shell command execution |
| `popen_call` / `proc_open_call` | Process opening |
| `file_put_contents` | File write with user input |
| `move_uploaded_file` | User-controlled upload destination |
| `file_get_contents` | SSRF / local file read with user input |
| `fsockopen_call` | Raw socket connection (C2 callback) |
| `curl_exec_user_input` | SSRF / data exfiltration |
| `chmod_777` | Setting world-writable permissions |
| `mail_header_injection` | `mail()` with user input |
| `dl_extension_load` | Dynamic PHP extension loading |
| `hex_obfuscation` | `\x` hex sequences (10+ consecutive) |
| `chr_obfuscation` | `chr()` chain (10+ calls) |
| `base64_decode_input` | `base64_decode()` with superglobal |
| `hidden_php_file` | Hidden dotfiles with `.php` extension |

### Info

| Pattern | Description |
|---------|-------------|
| `eval_variable` | `eval($var)` — may be legitimate |
| `error_reporting_off` | `error_reporting(0)` — error suppression |
| `set_time_limit_zero` | `set_time_limit(0)` — unlimited execution |
| `disable_functions_check` | `ini_get('disable_functions')` — recon |

### Smart filtering

- **WP core directories** (`wp-includes/`, `wp-admin/`) are only checked for Critical patterns
- **Known cache directories** in uploads (`cache/`, `wflogs/`, `wp-file-manager-pro/`, `wc-logs/`) are excluded from the PHP-in-uploads check

### Updating patterns

Patterns are stored in an external JSON file and can be updated without rebuilding:

```bash
wp-scanner update
# Downloads latest patterns from https://wp-scanner.gie.im/patterns.json
# Saves to ~/.config/wp-scanner/patterns.json
```

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

website/                   Landing page (wp-scanner.gie.im)
├── index.html             Lunar Aurora + geo3d background
├── patterns.json          Pattern database (served for `wp-scanner update`)
└── css/                   Assets (aurora.min.css, geo3d.js)

builtin_patterns.json      Fallback patterns compiled into the binary
.github/workflows/         Auto-deploy website to GitHub Pages on push
```

### Design principles

- **SOLID** — `OutputFormatter` trait (Open/Closed), single-responsibility modules, dependency inversion via traits
- **DRY** — shared `WpApi` cache, reusable `SiteReport` structure, `build_reports()` helper
- **Safe** — no PHP execution, no shell injection, regex-only extraction
- **Tested** — 27 unit tests covering all scanner modules

---

## Tests

```bash
cargo test
```

```
test result: ok. 27 passed; 0 failed; 0 ignored
```

---

## License

MIT

---

*Built with Rust 🦀*
