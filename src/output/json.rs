/// JSON output formatter — leverages serde Serialize derives on all models.

use crate::models::*;
use super::OutputFormatter;

pub struct JsonFormatter;

impl OutputFormatter for JsonFormatter {
    fn format_list(&self, sites: &[WpSite]) -> String {
        serde_json::to_string_pretty(sites).unwrap_or_else(|_| "[]".to_string())
    }

    fn format_versions(&self, sites: &[WpSite], latest_wp: &str) -> String {
        let data = serde_json::json!({
            "latest_wp_version": latest_wp,
            "sites": sites,
        });
        serde_json::to_string_pretty(&data).unwrap_or_else(|_| "{}".to_string())
    }

    fn format_report(&self, reports: &[SiteReport]) -> String {
        serde_json::to_string_pretty(reports).unwrap_or_else(|_| "[]".to_string())
    }
}
