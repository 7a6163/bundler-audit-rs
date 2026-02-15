use std::io::Write;

use crate::advisory::Criticality;
use crate::scanner::Report;

// ANSI color codes
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

/// Label column width (right-aligned).
const LABEL_WIDTH: usize = 12;

/// Print the scan report as human-readable text.
pub fn print_text(
    report: &Report,
    output: &mut dyn Write,
    verbose: bool,
    quiet: bool,
    use_color: bool,
) {
    let total_sources = report.insecure_sources.len();
    let total_gems = report.unpatched_gems.len();

    for (i, source) in report.insecure_sources.iter().enumerate() {
        if use_color {
            writeln!(
                output,
                "{}{}Insecure Source URI found:{} {}",
                YELLOW, BOLD, RESET, source.source
            )
            .ok();
        } else {
            writeln!(output, "Insecure Source URI found: {}", source.source).ok();
        }

        if i < total_sources - 1 || !report.unpatched_gems.is_empty() {
            writeln!(output).ok();
        }
    }

    for (i, vuln) in report.unpatched_gems.iter().enumerate() {
        print_advisory(output, vuln, verbose, use_color);
        if i < total_gems - 1 {
            if use_color {
                writeln!(output, "{}{}{}", DIM, "─".repeat(40), RESET).ok();
            } else {
                writeln!(output, "{}", "─".repeat(40)).ok();
            }
            writeln!(output).ok();
        }
    }

    if report.vulnerable() {
        // Summary line
        let mut parts = Vec::new();
        if total_sources > 0 {
            parts.push(format!(
                "{} insecure source{}",
                total_sources,
                if total_sources == 1 { "" } else { "s" }
            ));
        }
        if total_gems > 0 {
            parts.push(format!(
                "{} unpatched gem{}",
                total_gems,
                if total_gems == 1 { "" } else { "s" }
            ));
        }
        let summary = parts.join(", ");

        writeln!(output).ok();
        if use_color {
            writeln!(
                output,
                "{}{}Vulnerabilities found!{} ({})",
                RED, BOLD, RESET, summary
            )
            .ok();
        } else {
            writeln!(output, "Vulnerabilities found! ({})", summary).ok();
        }
    } else if !quiet {
        if use_color {
            writeln!(output, "{}{}No vulnerabilities found{}", GREEN, BOLD, RESET).ok();
        } else {
            writeln!(output, "No vulnerabilities found").ok();
        }
    }

    // Show warning counts if any errors occurred
    if report.version_parse_errors > 0 || report.advisory_load_errors > 0 {
        let mut warnings = Vec::new();
        if report.version_parse_errors > 0 {
            warnings.push(format!(
                "{} version parse error{}",
                report.version_parse_errors,
                if report.version_parse_errors == 1 {
                    ""
                } else {
                    "s"
                }
            ));
        }
        if report.advisory_load_errors > 0 {
            warnings.push(format!(
                "{} advisory load error{}",
                report.advisory_load_errors,
                if report.advisory_load_errors == 1 {
                    ""
                } else {
                    "s"
                }
            ));
        }
        let msg = format!("Warnings: {}", warnings.join(", "));
        if use_color {
            writeln!(output, "{}{}{}{}", YELLOW, BOLD, msg, RESET).ok();
        } else {
            writeln!(output, "{}", msg).ok();
        }
    }
}

fn print_advisory(
    output: &mut dyn Write,
    vuln: &crate::scanner::UnpatchedGem,
    verbose: bool,
    use_color: bool,
) {
    let adv = &vuln.advisory;

    label_value(output, "Name", &vuln.name, use_color);
    label_value(output, "Version", &vuln.version, use_color);

    if let Some(cve_id) = adv.cve_id() {
        label_value(output, "CVE", &cve_id, use_color);
    }

    if let Some(ghsa_id) = adv.ghsa_id() {
        label_value(output, "GHSA", &ghsa_id, use_color);
    }

    // Criticality
    let crit_str = match adv.criticality() {
        Some(Criticality::None) => "None",
        Some(Criticality::Low) => "Low",
        Some(Criticality::Medium) => "Medium",
        Some(Criticality::High) => "High",
        Some(Criticality::Critical) => "Critical",
        None => "Unknown",
    };

    if use_color {
        let colored_value = match adv.criticality() {
            Some(Criticality::High) => format!("{}{}{}{}", RED, BOLD, crit_str, RESET),
            Some(Criticality::Critical) => format!("{}{}{}{}", RED, BOLD, crit_str, RESET),
            Some(Criticality::Medium) => format!("{}{}{}", YELLOW, crit_str, RESET),
            _ => crit_str.to_string(),
        };
        writeln!(
            output,
            "{}{:>width$}:{} {}",
            CYAN,
            "Criticality",
            RESET,
            colored_value,
            width = LABEL_WIDTH
        )
        .ok();
    } else {
        writeln!(
            output,
            "{:>width$}: {}",
            "Criticality",
            crit_str,
            width = LABEL_WIDTH
        )
        .ok();
    }

    if let Some(url) = &adv.url {
        label_value(output, "URL", url, use_color);
    }

    if verbose {
        if let Some(desc) = &adv.description {
            if use_color {
                writeln!(
                    output,
                    "{}{:>width$}:{}",
                    CYAN,
                    "Description",
                    RESET,
                    width = LABEL_WIDTH
                )
                .ok();
            } else {
                writeln!(output, "{:>width$}:", "Description", width = LABEL_WIDTH).ok();
            }
            for line in desc.lines() {
                writeln!(output, "{:>width$}  {}", "", line, width = LABEL_WIDTH).ok();
            }
        }
    } else if let Some(title) = &adv.title {
        label_value(output, "Title", title, use_color);
    }

    // Solution
    if !adv.patched_versions.is_empty() {
        let versions: Vec<String> = adv
            .patched_versions
            .iter()
            .map(|v| format!("'{}'", v))
            .collect();
        if use_color {
            writeln!(
                output,
                "{}{:>width$}:{} upgrade to {}",
                CYAN,
                "Solution",
                RESET,
                versions.join(", "),
                width = LABEL_WIDTH
            )
            .ok();
        } else {
            writeln!(
                output,
                "{:>width$}: upgrade to {}",
                "Solution",
                versions.join(", "),
                width = LABEL_WIDTH
            )
            .ok();
        }
    } else if use_color {
        writeln!(
            output,
            "{}{:>width$}:{} {}{}remove or disable this gem until a patch is available!{}",
            CYAN,
            "Solution",
            RESET,
            RED,
            BOLD,
            RESET,
            width = LABEL_WIDTH
        )
        .ok();
    } else {
        writeln!(
            output,
            "{:>width$}: remove or disable this gem until a patch is available!",
            "Solution",
            width = LABEL_WIDTH
        )
        .ok();
    }

    writeln!(output).ok();
}

fn label_value(output: &mut dyn Write, label: &str, value: &str, use_color: bool) {
    if use_color {
        writeln!(
            output,
            "{}{:>width$}:{} {}",
            CYAN,
            label,
            RESET,
            value,
            width = LABEL_WIDTH
        )
        .ok();
    } else {
        writeln!(output, "{:>width$}: {}", label, value, width = LABEL_WIDTH).ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisory::Advisory;
    use crate::scanner::{InsecureSource, Report, UnpatchedGem};
    use std::path::Path;

    fn make_report_with_insecure_source() -> Report {
        Report {
            insecure_sources: vec![InsecureSource {
                source: "http://rubygems.org/".to_string(),
            }],
            unpatched_gems: vec![],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        }
    }

    fn make_report_with_vuln() -> Report {
        let yaml = "---\ngem: test\ncve: 2020-1234\nghsa: aaaa-bbbb-cccc\nurl: https://example.com/\ntitle: Test advisory\ncvss_v3: 9.8\npatched_versions:\n  - \">= 1.0.0\"\n";
        let advisory = Advisory::from_yaml(yaml, Path::new("CVE-2020-1234.yml")).unwrap();
        Report {
            insecure_sources: vec![],
            unpatched_gems: vec![UnpatchedGem {
                name: "test".to_string(),
                version: "0.5.0".to_string(),
                advisory,
            }],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        }
    }

    #[test]
    fn text_output_no_vulnerabilities() {
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, false);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("No vulnerabilities found"));
    }

    #[test]
    fn text_output_quiet_suppresses_no_vulns() {
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, true, false);
        let output = String::from_utf8(buf).unwrap();
        assert!(!output.contains("No vulnerabilities found"));
    }

    #[test]
    fn text_output_insecure_source() {
        let report = make_report_with_insecure_source();
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, false);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Insecure Source URI found: http://rubygems.org/"));
        assert!(output.contains("Vulnerabilities found!"));
    }

    #[test]
    fn text_output_unpatched_gem() {
        let report = make_report_with_vuln();
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, false);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Name"));
        assert!(output.contains("test"));
        assert!(output.contains("Version"));
        assert!(output.contains("0.5.0"));
        assert!(output.contains("CVE-2020-1234"));
        assert!(output.contains("GHSA-aaaa-bbbb-cccc"));
        assert!(output.contains("Critical"));
        assert!(output.contains("upgrade to '>= 1.0.0'"));
    }

    #[test]
    fn text_output_verbose_shows_description() {
        let yaml = "---\ngem: test\ncve: 2020-1234\ntitle: Test\ndescription: |\n  Detailed description here.\ncvss_v3: 5.0\npatched_versions:\n  - \">= 1.0\"\n";
        let advisory = Advisory::from_yaml(yaml, Path::new("CVE-2020-1234.yml")).unwrap();
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![UnpatchedGem {
                name: "test".to_string(),
                version: "0.5.0".to_string(),
                advisory,
            }],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, true, false, false);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Description"));
        assert!(output.contains("Detailed description here."));
        assert!(!output.contains("Title"));
    }

    #[test]
    fn text_output_no_color() {
        let report = make_report_with_vuln();
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, false);
        let output = String::from_utf8(buf).unwrap();
        assert!(!output.contains("\x1b["));
    }
}
