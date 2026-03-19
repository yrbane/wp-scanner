/// Audit file permissions and ownership for a WordPress installation.
///
/// Checks replicate the logic from the original Symfony `wp:perm` command:
/// world-writable directories, www-data ownership, missing uploads dir, etc.

use crate::models::{PermIssue, Severity, WpSite};
use std::ffi::CStr;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Run all permission checks on a WordPress site.
pub fn scan_permissions(site: &WpSite) -> Vec<PermIssue> {
    let wp_root = &site.path;
    let mut issues = Vec::new();

    // 1. Root directory checks.
    let perm = parse_octal_perms(&site.permissions);
    check_world_writable(wp_root, perm, &mut issues);
    check_owner_www_data(wp_root, &site.owner, &mut issues);
    check_group_writable_www_data(wp_root, &site.group, perm, &mut issues);

    // 2. wp-content directory.
    let wp_content = wp_root.join("wp-content");
    if wp_content.is_dir() {
        check_directory_world_writable(&wp_content, &mut issues);
    }

    // 3. uploads directory existence.
    let uploads = wp_root.join("wp-content/uploads");
    if !uploads.is_dir() {
        issues.push(PermIssue {
            path: uploads.clone(),
            issue: "uploads directory does not exist".to_string(),
            severity: Severity::Warning,
            fix_command: Some(format!("sudo mkdir -p \"{}\"", uploads.display())),
        });
    }

    // 4. wp-config.php world-readable check.
    let wp_config = wp_root.join("wp-config.php");
    if wp_config.is_file() {
        if let Ok(meta) = fs::metadata(&wp_config) {
            let mode = meta.mode() & 0o777;
            if mode & 0o004 != 0 {
                issues.push(PermIssue {
                    path: wp_config,
                    issue: "wp-config.php is world-readable".to_string(),
                    severity: Severity::Warning,
                    fix_command: Some(format!(
                        "sudo chmod 640 \"{}/wp-config.php\"",
                        wp_root.display()
                    )),
                });
            }
        }
    }

    // 5. Forum directory (legacy check from the original PHP code).
    let forum = wp_root.join("forum");
    if forum.is_dir() {
        check_directory_world_writable(&forum, &mut issues);
    }

    issues
}

/// Build fix commands for a site with permission issues.
/// These match the original Symfony command output format.
pub fn build_fix_commands(site: &WpSite, issues: &[PermIssue]) -> Vec<String> {
    if issues.is_empty() {
        return Vec::new();
    }

    let wp_root = &site.path;
    let owner = if site.owner == "www-data" {
        std::env::var("USER").unwrap_or_else(|_| "root".to_string())
    } else {
        site.owner.clone()
    };

    let mut cmds = vec![
        format!(
            "sudo chown {}.www-data \"{}\" -R",
            owner,
            wp_root.display()
        ),
        format!("sudo chmod 750 \"{}\" -R", wp_root.display()),
        format!(
            "sudo chown {}.www-data \"{}/wp-content/\" -R",
            owner,
            wp_root.display()
        ),
        format!("sudo chmod 770 \"{}/wp-content/\" -R", wp_root.display()),
    ];

    let forum = wp_root.join("forum");
    if forum.is_dir() {
        cmds.push(format!("sudo chmod 750 \"{}\" -R", forum.display()));
        cmds.push(format!(
            "sudo chmod 770 \"{}/storage/\" -R",
            forum.display()
        ));
        cmds.push(format!(
            "sudo chmod 770 \"{}/assets/\" -R",
            forum.display()
        ));
    }

    cmds
}

/// Read file metadata and return (owner_name, group_name, octal_permissions).
pub fn get_file_info(path: &Path) -> (String, String, String) {
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return ("?".into(), "?".into(), "0000".into()),
    };

    let uid = meta.uid();
    let gid = meta.gid();
    let mode = meta.mode() & 0o7777;

    let owner = uid_to_name(uid);
    let group = gid_to_name(gid);
    let perms = format!("{:04o}", mode);

    (owner, group, perms)
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn parse_octal_perms(s: &str) -> u32 {
    u32::from_str_radix(s, 8).unwrap_or(0)
}

fn check_world_writable(path: &Path, perm: u32, issues: &mut Vec<PermIssue>) {
    if perm & 0o002 != 0 {
        issues.push(PermIssue {
            path: path.to_path_buf(),
            issue: "directory is world-writable".to_string(),
            severity: Severity::Critical,
            fix_command: Some(format!("sudo chmod o-w \"{}\" -R", path.display())),
        });
    }
}

fn check_owner_www_data(path: &Path, owner: &str, issues: &mut Vec<PermIssue>) {
    if owner == "www-data" {
        issues.push(PermIssue {
            path: path.to_path_buf(),
            issue: "directory is owned by www-data".to_string(),
            severity: Severity::Critical,
            fix_command: None,
        });
    }
}

fn check_group_writable_www_data(
    path: &Path,
    group: &str,
    perm: u32,
    issues: &mut Vec<PermIssue>,
) {
    if group == "www-data" && perm & 0o020 != 0 {
        issues.push(PermIssue {
            path: path.to_path_buf(),
            issue: "directory is group-writable by www-data".to_string(),
            severity: Severity::Warning,
            fix_command: None,
        });
    }
}

fn check_directory_world_writable(dir: &Path, issues: &mut Vec<PermIssue>) {
    if let Ok(meta) = fs::metadata(dir) {
        let mode = meta.mode() & 0o777;
        if mode & 0o002 != 0 {
            issues.push(PermIssue {
                path: dir.to_path_buf(),
                issue: format!("{} is world-writable", dir.display()),
                severity: Severity::Critical,
                fix_command: Some(format!("sudo chmod o-w \"{}\" -R", dir.display())),
            });
        }
    }
}

fn uid_to_name(uid: u32) -> String {
    unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            return uid.to_string();
        }
        CStr::from_ptr((*pw).pw_name)
            .to_string_lossy()
            .into_owned()
    }
}

fn gid_to_name(gid: u32) -> String {
    unsafe {
        let gr = libc::getgrgid(gid);
        if gr.is_null() {
            return gid.to_string();
        }
        CStr::from_ptr((*gr).gr_name)
            .to_string_lossy()
            .into_owned()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_octal_perms() {
        assert_eq!(parse_octal_perms("0750"), 0o750);
        assert_eq!(parse_octal_perms("0777"), 0o777);
        assert_eq!(parse_octal_perms("invalid"), 0);
    }

    #[test]
    fn test_world_writable_detected() {
        let mut issues = Vec::new();
        check_world_writable(Path::new("/tmp/test"), 0o777, &mut issues);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].severity, Severity::Critical);
    }

    #[test]
    fn test_not_world_writable() {
        let mut issues = Vec::new();
        check_world_writable(Path::new("/tmp/test"), 0o750, &mut issues);
        assert!(issues.is_empty());
    }

    #[test]
    fn test_owner_www_data() {
        let mut issues = Vec::new();
        check_owner_www_data(Path::new("/tmp/test"), "www-data", &mut issues);
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn test_owner_not_www_data() {
        let mut issues = Vec::new();
        check_owner_www_data(Path::new("/tmp/test"), "seb", &mut issues);
        assert!(issues.is_empty());
    }

    #[test]
    fn test_build_fix_commands_empty_issues() {
        let site = WpSite {
            path: "/tmp/test".into(),
            version: None,
            owner: "seb".into(),
            group: "www-data".into(),
            permissions: "0750".into(),
        };
        assert!(build_fix_commands(&site, &[]).is_empty());
    }
}
