/// Output formatting — trait-based polymorphism (Open/Closed Principle).
///
/// Each format implements `OutputFormatter`. Adding a new format only requires
/// a new struct + impl, with zero changes to existing code.

pub mod console;
pub mod email;
pub mod html;
pub mod json;
pub mod markdown;

use crate::cli::OutputFormat;
use crate::models::{SiteReport, WpSite};

/// Trait for formatting scan results into a displayable string.
pub trait OutputFormatter {
    /// Format a simple list of discovered WordPress sites.
    fn format_list(&self, sites: &[WpSite]) -> String;

    /// Format version comparison for all sites.
    fn format_versions(&self, sites: &[WpSite], latest_wp: &str) -> String;

    /// Format a full or partial report (plugins, permissions, backdoors).
    /// Which sections appear depends on which Option fields are Some.
    fn format_report(&self, reports: &[SiteReport]) -> String;
}

/// Factory: create the appropriate formatter for the requested output format.
pub fn create_formatter(format: &OutputFormat) -> Box<dyn OutputFormatter> {
    match format {
        OutputFormat::Console => Box::new(console::ConsoleFormatter),
        OutputFormat::Json => Box::new(json::JsonFormatter),
        OutputFormat::Md => Box::new(markdown::MarkdownFormatter),
        OutputFormat::Html => Box::new(html::HtmlFormatter),
    }
}
