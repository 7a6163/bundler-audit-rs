use std::io::Write;

use crate::advisory::Criticality;
use crate::fixer::FixResult;
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
    fix: bool,
    fix_results: Option<&[FixResult]>,
) {
    let total_sources = report.insecure_sources.len();
    let total_gems = report.unpatched_gems.len();
    let total_rubies = report.vulnerable_rubies.len();
    let has_more_after_sources =
        !report.unpatched_gems.is_empty() || !report.vulnerable_rubies.is_empty();

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

        if i < total_sources - 1 || has_more_after_sources {
            writeln!(output).ok();
        }
    }

    for (i, vuln) in report.unpatched_gems.iter().enumerate() {
        print_advisory(output, vuln, verbose, use_color);
        if i < total_gems - 1 || total_rubies > 0 {
            if use_color {
                writeln!(output, "{}{}{}", DIM, "─".repeat(40), RESET).ok();
            } else {
                writeln!(output, "{}", "─".repeat(40)).ok();
            }
            writeln!(output).ok();
        }
    }

    for (i, vuln) in report.vulnerable_rubies.iter().enumerate() {
        print_ruby_advisory(output, vuln, verbose, use_color);
        if i < total_rubies - 1 {
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
        if total_rubies > 0 {
            parts.push(format!(
                "{} vulnerable Ruby version{}",
                total_rubies,
                if total_rubies == 1 { "" } else { "s" }
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

    if fix && report.vulnerable() {
        if let Some(results) = fix_results {
            print_fix_results(results, output, use_color);
        } else {
            print_remediations(report, output, use_color);
        }
    }
}

/// Print fix results (resolved versions or unresolvable).
fn print_fix_results(results: &[FixResult], output: &mut dyn Write, use_color: bool) {
    if results.is_empty() {
        return;
    }

    writeln!(output).ok();
    if use_color {
        writeln!(output, "{}{}Fixes:{}", BOLD, CYAN, RESET).ok();
    } else {
        writeln!(output, "Fixes:").ok();
    }

    for result in results {
        match result {
            FixResult::Fixed(f) => {
                if use_color {
                    writeln!(
                        output,
                        "  {}{}{} ({} -> {}{}{})",
                        BOLD, f.name, RESET, f.current_version, GREEN, f.resolved_version, RESET
                    )
                    .ok();
                } else {
                    writeln!(
                        output,
                        "  {} ({} -> {})",
                        f.name, f.current_version, f.resolved_version
                    )
                    .ok();
                }
            }
            FixResult::Unresolvable { name, current_version, .. } => {
                if use_color {
                    writeln!(
                        output,
                        "  {}{}{} ({} -> {}{}no safe version found{})",
                        BOLD, name, RESET, current_version, RED, BOLD, RESET
                    )
                    .ok();
                } else {
                    writeln!(
                        output,
                        "  {} ({} -> no safe version found)",
                        name, current_version
                    )
                    .ok();
                }
            }
        }
    }
}

/// Print grouped remediation suggestions after the main report.
pub fn print_remediations(report: &Report, output: &mut dyn Write, use_color: bool) {
    let remediations = report.remediations();
    if remediations.is_empty() {
        return;
    }

    writeln!(output).ok();
    if use_color {
        writeln!(output, "{}{}Remediation:{}", BOLD, CYAN, RESET).ok();
    } else {
        writeln!(output, "Remediation:").ok();
    }

    for remediation in &remediations {
        // Collect the union of all patched_versions across advisories
        let mut all_patched: Vec<String> = Vec::new();
        let mut seen_patched: std::collections::HashSet<String> = std::collections::HashSet::new();
        for adv in &remediation.advisories {
            for pv in &adv.patched_versions {
                let s = format!("'{}'", pv);
                if seen_patched.insert(s.clone()) {
                    all_patched.push(s);
                }
            }
        }

        writeln!(output).ok();

        // Gem name with version and upgrade suggestion
        if all_patched.is_empty() {
            if use_color {
                writeln!(
                    output,
                    "  {}{}{} ({} -> {}{}no patch available{})",
                    BOLD, remediation.name, RESET, remediation.version, RED, BOLD, RESET
                )
                .ok();
            } else {
                writeln!(
                    output,
                    "  {} ({} -> no patch available)",
                    remediation.name, remediation.version
                )
                .ok();
            }
        } else {
            let versions_str = all_patched.join(", ");
            if use_color {
                writeln!(
                    output,
                    "  {}{}{} ({} -> upgrade to {})",
                    BOLD, remediation.name, RESET, remediation.version, versions_str
                )
                .ok();
            } else {
                writeln!(
                    output,
                    "  {} ({} -> upgrade to {})",
                    remediation.name, remediation.version, versions_str
                )
                .ok();
            }
        }

        // List advisory IDs
        let ids: Vec<String> = remediation
            .advisories
            .iter()
            .map(|a| a.id.clone())
            .collect();
        if use_color {
            writeln!(output, "    - {}{}{}", DIM, ids.join(", "), RESET).ok();
        } else {
            writeln!(output, "    - {}", ids.join(", ")).ok();
        }

        // Bundle update command
        if use_color {
            writeln!(
                output,
                "    {}$ bundle update {}{}",
                DIM, remediation.name, RESET
            )
            .ok();
        } else {
            writeln!(output, "    $ bundle update {}", remediation.name).ok();
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

fn print_ruby_advisory(
    output: &mut dyn Write,
    vuln: &crate::scanner::VulnerableRuby,
    verbose: bool,
    use_color: bool,
) {
    let adv = &vuln.advisory;

    label_value(output, "Engine", &vuln.engine, use_color);
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
                "{}{:>width$}:{} upgrade Ruby to {}",
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
                "{:>width$}: upgrade Ruby to {}",
                "Solution",
                versions.join(", "),
                width = LABEL_WIDTH
            )
            .ok();
        }
    } else if use_color {
        writeln!(
            output,
            "{}{:>width$}:{} {}{}upgrade Ruby to a patched version!{}",
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
            "{:>width$}: upgrade Ruby to a patched version!",
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
            vulnerable_rubies: vec![],
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
            vulnerable_rubies: vec![],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        }
    }

    #[test]
    fn text_output_no_vulnerabilities() {
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![],
            vulnerable_rubies: vec![],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, false, false, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("No vulnerabilities found"));
    }

    #[test]
    fn text_output_quiet_suppresses_no_vulns() {
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![],
            vulnerable_rubies: vec![],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, true, false, false, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(!output.contains("No vulnerabilities found"));
    }

    #[test]
    fn text_output_insecure_source() {
        let report = make_report_with_insecure_source();
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, false, false, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Insecure Source URI found: http://rubygems.org/"));
        assert!(output.contains("Vulnerabilities found!"));
    }

    #[test]
    fn text_output_unpatched_gem() {
        let report = make_report_with_vuln();
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, false, false, None);
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
            vulnerable_rubies: vec![],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, true, false, false, false, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Description"));
        assert!(output.contains("Detailed description here."));
        assert!(!output.contains("Title"));
    }

    #[test]
    fn text_output_no_color() {
        let report = make_report_with_vuln();
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, false, false, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(!output.contains("\x1b["));
    }

    #[test]
    fn text_output_fix_shows_remediation() {
        let report = make_report_with_vuln();
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, false, true, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Remediation:"));
        assert!(output.contains("test (0.5.0 -> upgrade to '>= 1.0.0')"));
        assert!(output.contains("- CVE-2020-1234"));
        assert!(output.contains("$ bundle update test"));
    }

    #[test]
    fn text_output_fix_no_remediation_when_clean() {
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![],
            vulnerable_rubies: vec![],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, false, true, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(!output.contains("Remediation:"));
    }

    fn make_report_with_multiple_vulns() -> Report {
        let yaml1 = "---\ngem: test\ncve: 2020-1234\ntitle: First vuln\ncvss_v3: 9.8\npatched_versions:\n  - \">= 1.0.0\"\n";
        let yaml2 = "---\ngem: test\ncve: 2020-5678\ntitle: Second vuln\ncvss_v3: 7.5\npatched_versions:\n  - \">= 1.2.0\"\n";
        let adv1 = Advisory::from_yaml(yaml1, Path::new("CVE-2020-1234.yml")).unwrap();
        let adv2 = Advisory::from_yaml(yaml2, Path::new("CVE-2020-5678.yml")).unwrap();
        Report {
            insecure_sources: vec![],
            unpatched_gems: vec![
                UnpatchedGem {
                    name: "test".to_string(),
                    version: "0.5.0".to_string(),
                    advisory: adv1,
                },
                UnpatchedGem {
                    name: "test".to_string(),
                    version: "0.5.0".to_string(),
                    advisory: adv2,
                },
            ],
            vulnerable_rubies: vec![],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        }
    }

    #[test]
    fn text_output_fix_groups_multiple_advisories() {
        let report = make_report_with_multiple_vulns();
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, false, true, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Remediation:"));
        // Should show both patched versions
        assert!(output.contains("'>= 1.0.0'"));
        assert!(output.contains("'>= 1.2.0'"));
        // Should list both CVEs
        assert!(output.contains("CVE-2020-1234"));
        assert!(output.contains("CVE-2020-5678"));
        // Should only have one "bundle update test" line
        let update_count = output.matches("$ bundle update test").count();
        assert_eq!(update_count, 1);
    }

    #[test]
    fn text_output_without_fix_no_remediation() {
        let report = make_report_with_vuln();
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, false, false, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(!output.contains("Remediation:"));
        assert!(!output.contains("$ bundle update"));
    }

    // ========== Color Output ==========

    #[test]
    fn text_output_color_insecure_source() {
        let report = make_report_with_insecure_source();
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, true, false, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("\x1b["));
        assert!(output.contains("Insecure Source URI found:"));
    }

    #[test]
    fn text_output_color_vulnerability() {
        let report = make_report_with_vuln();
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, true, false, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("\x1b["));
        // Red+bold for "Vulnerabilities found!"
        assert!(output.contains(&format!("{}{}Vulnerabilities found!", RED, BOLD)));
    }

    #[test]
    fn text_output_color_no_vulnerabilities() {
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![],
            vulnerable_rubies: vec![],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, true, false, None);
        let output = String::from_utf8(buf).unwrap();
        // Green+bold for "No vulnerabilities found"
        assert!(output.contains(&format!("{}{}No vulnerabilities found", GREEN, BOLD)));
    }

    #[test]
    fn text_output_color_criticality_medium() {
        let yaml = "---\ngem: test\ncve: 2020-1234\ntitle: Test\ncvss_v3: 5.0\npatched_versions:\n  - \">= 1.0\"\n";
        let advisory = Advisory::from_yaml(yaml, Path::new("CVE-2020-1234.yml")).unwrap();
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![UnpatchedGem {
                name: "test".to_string(),
                version: "0.5.0".to_string(),
                advisory,
            }],
            vulnerable_rubies: vec![],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, true, false, None);
        let output = String::from_utf8(buf).unwrap();
        // Medium criticality should be yellow
        assert!(output.contains(&format!("{}Medium{}", YELLOW, RESET)));
    }

    #[test]
    fn text_output_color_criticality_high() {
        let yaml = "---\ngem: test\ncve: 2020-1234\ntitle: Test\ncvss_v3: 7.5\npatched_versions:\n  - \">= 1.0\"\n";
        let advisory = Advisory::from_yaml(yaml, Path::new("CVE-2020-1234.yml")).unwrap();
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![UnpatchedGem {
                name: "test".to_string(),
                version: "0.5.0".to_string(),
                advisory,
            }],
            vulnerable_rubies: vec![],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, true, false, None);
        let output = String::from_utf8(buf).unwrap();
        // High criticality should be red+bold
        assert!(output.contains(&format!("{}{}High{}", RED, BOLD, RESET)));
    }

    #[test]
    fn text_output_color_criticality_low() {
        let yaml = "---\ngem: test\ncve: 2020-1234\ntitle: Test\ncvss_v3: 2.0\npatched_versions:\n  - \">= 1.0\"\n";
        let advisory = Advisory::from_yaml(yaml, Path::new("CVE-2020-1234.yml")).unwrap();
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![UnpatchedGem {
                name: "test".to_string(),
                version: "0.5.0".to_string(),
                advisory,
            }],
            vulnerable_rubies: vec![],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, true, false, None);
        let output = String::from_utf8(buf).unwrap();
        // Low criticality should be plain (no extra color beyond the cyan label)
        assert!(output.contains("Low"));
    }

    // ========== Warning Counts ==========

    #[test]
    fn text_output_warning_counts_plural() {
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![],
            vulnerable_rubies: vec![],
            version_parse_errors: 3,
            advisory_load_errors: 2,
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, false, false, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("3 version parse errors"));
        assert!(output.contains("2 advisory load errors"));
    }

    #[test]
    fn text_output_warning_counts_singular() {
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![],
            vulnerable_rubies: vec![],
            version_parse_errors: 1,
            advisory_load_errors: 1,
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, false, false, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("1 version parse error"));
        assert!(!output.contains("1 version parse errors"));
        assert!(output.contains("1 advisory load error"));
        assert!(!output.contains("1 advisory load errors"));
    }

    #[test]
    fn text_output_warning_counts_with_color() {
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![],
            vulnerable_rubies: vec![],
            version_parse_errors: 1,
            advisory_load_errors: 0,
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, true, false, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("\x1b["));
        assert!(output.contains("1 version parse error"));
    }

    // ========== No Patch Available ==========

    #[test]
    fn text_output_no_patched_versions_solution() {
        let yaml = "---\ngem: test\ncve: 2020-9999\ntitle: No fix yet\ncvss_v3: 9.0\n";
        let advisory = Advisory::from_yaml(yaml, Path::new("CVE-2020-9999.yml")).unwrap();
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![UnpatchedGem {
                name: "test".to_string(),
                version: "0.5.0".to_string(),
                advisory,
            }],
            vulnerable_rubies: vec![],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, false, false, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("remove or disable this gem until a patch is available!"));
    }

    #[test]
    fn text_output_no_patched_versions_solution_color() {
        let yaml = "---\ngem: test\ncve: 2020-9999\ntitle: No fix yet\ncvss_v3: 9.0\n";
        let advisory = Advisory::from_yaml(yaml, Path::new("CVE-2020-9999.yml")).unwrap();
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![UnpatchedGem {
                name: "test".to_string(),
                version: "0.5.0".to_string(),
                advisory,
            }],
            vulnerable_rubies: vec![],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, true, false, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("remove or disable this gem"));
        assert!(output.contains("\x1b["));
    }

    #[test]
    fn text_output_fix_no_patch_available() {
        let yaml = "---\ngem: test\ncve: 2020-9999\ntitle: No fix yet\ncvss_v3: 9.0\n";
        let advisory = Advisory::from_yaml(yaml, Path::new("CVE-2020-9999.yml")).unwrap();
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![UnpatchedGem {
                name: "test".to_string(),
                version: "0.5.0".to_string(),
                advisory,
            }],
            vulnerable_rubies: vec![],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, false, true, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("no patch available"));
    }

    // ========== Combined Report ==========

    #[test]
    fn text_output_combined_sources_and_gems() {
        let yaml = "---\ngem: test\ncve: 2020-1234\ntitle: Test\ncvss_v3: 9.8\npatched_versions:\n  - \">= 1.0.0\"\n";
        let advisory = Advisory::from_yaml(yaml, Path::new("CVE-2020-1234.yml")).unwrap();
        let report = Report {
            insecure_sources: vec![
                InsecureSource {
                    source: "http://rubygems.org/".to_string(),
                },
                InsecureSource {
                    source: "git://github.com/foo/bar.git".to_string(),
                },
            ],
            unpatched_gems: vec![UnpatchedGem {
                name: "test".to_string(),
                version: "0.5.0".to_string(),
                advisory,
            }],
            vulnerable_rubies: vec![],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, false, false, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("2 insecure sources"));
        assert!(output.contains("1 unpatched gem"));
        assert!(output.contains("Insecure Source URI found: http://rubygems.org/"));
        assert!(output.contains("Insecure Source URI found: git://github.com/foo/bar.git"));
    }

    // ========== Multiple gem separator ==========

    #[test]
    fn text_output_separator_between_multiple_gems() {
        let report = make_report_with_multiple_vulns();
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, false, false, None);
        let output = String::from_utf8(buf).unwrap();
        // Should have separator between vulns
        assert!(output.contains("─".repeat(40).as_str()));
    }

    #[test]
    fn text_output_separator_with_color() {
        let report = make_report_with_multiple_vulns();
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, true, false, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains(DIM));
        assert!(output.contains("─".repeat(40).as_str()));
    }

    // ========== Ruby Advisory Output ==========

    fn make_ruby_advisory() -> crate::advisory::Advisory {
        let yaml = "---\nengine: ruby\ncve: 2021-31810\nghsa: xxxx-yyyy-zzzz\nurl: https://www.ruby-lang.org/en/news/2021/07/07/\ntitle: Trusting FTP PASV responses vulnerability in Net::FTP\ncvss_v3: 5.9\npatched_versions:\n  - \">= 3.0.2\"\n  - \"~> 2.7.4\"\n  - \"~> 2.6.8\"\n";
        crate::advisory::Advisory::from_yaml(yaml, Path::new("CVE-2021-31810.yml")).unwrap()
    }

    fn make_report_with_ruby_vuln() -> Report {
        Report {
            insecure_sources: vec![],
            unpatched_gems: vec![],
            vulnerable_rubies: vec![crate::scanner::VulnerableRuby {
                engine: "ruby".to_string(),
                version: "2.6.0".to_string(),
                advisory: make_ruby_advisory(),
            }],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        }
    }

    #[test]
    fn text_output_ruby_vulnerability_plain() {
        let report = make_report_with_ruby_vuln();
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, false, false, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Engine: ruby"));
        assert!(output.contains("Version: 2.6.0"));
        assert!(output.contains("CVE-2021-31810"));
        assert!(output.contains("GHSA-xxxx-yyyy-zzzz"));
        assert!(output.contains("Medium"));
        assert!(output.contains("https://www.ruby-lang.org"));
        assert!(output.contains("Trusting FTP PASV"));
        assert!(output.contains("upgrade Ruby to '>= 3.0.2'"));
        assert!(output.contains("1 vulnerable Ruby version"));
        assert!(!output.contains("\x1b["));
    }

    #[test]
    fn text_output_ruby_vulnerability_color() {
        let report = make_report_with_ruby_vuln();
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, true, false, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("\x1b["));
        assert!(output.contains("Engine"));
        assert!(output.contains("ruby"));
        assert!(output.contains("upgrade Ruby to"));
        // Medium criticality should be yellow
        assert!(output.contains(&format!("{}Medium{}", YELLOW, RESET)));
    }

    #[test]
    fn text_output_ruby_vulnerability_verbose() {
        let yaml = "---\nengine: ruby\ncve: 2021-31810\ntitle: Test\ndescription: |\n  Detailed ruby vulnerability description.\ncvss_v3: 5.9\npatched_versions:\n  - \">= 3.0.2\"\n";
        let advisory =
            crate::advisory::Advisory::from_yaml(yaml, Path::new("CVE-2021-31810.yml")).unwrap();
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![],
            vulnerable_rubies: vec![crate::scanner::VulnerableRuby {
                engine: "ruby".to_string(),
                version: "2.6.0".to_string(),
                advisory,
            }],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, true, false, false, false, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Description"));
        assert!(output.contains("Detailed ruby vulnerability description."));
        assert!(!output.contains("Title"));
    }

    #[test]
    fn text_output_ruby_vulnerability_verbose_color() {
        let yaml = "---\nengine: ruby\ncve: 2021-31810\ntitle: Test\ndescription: |\n  Detailed description.\ncvss_v3: 5.9\npatched_versions:\n  - \">= 3.0.2\"\n";
        let advisory =
            crate::advisory::Advisory::from_yaml(yaml, Path::new("CVE-2021-31810.yml")).unwrap();
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![],
            vulnerable_rubies: vec![crate::scanner::VulnerableRuby {
                engine: "ruby".to_string(),
                version: "2.6.0".to_string(),
                advisory,
            }],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, true, false, true, false, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("\x1b["));
        assert!(output.contains("Description"));
        assert!(output.contains("Detailed description."));
    }

    #[test]
    fn text_output_ruby_no_patched_versions_plain() {
        let yaml = "---\nengine: ruby\ncve: 2021-99999\ntitle: No fix\ncvss_v3: 9.0\n";
        let advisory =
            crate::advisory::Advisory::from_yaml(yaml, Path::new("CVE-2021-99999.yml")).unwrap();
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![],
            vulnerable_rubies: vec![crate::scanner::VulnerableRuby {
                engine: "ruby".to_string(),
                version: "2.6.0".to_string(),
                advisory,
            }],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, false, false, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("upgrade Ruby to a patched version!"));
        assert!(!output.contains("\x1b["));
    }

    #[test]
    fn text_output_ruby_no_patched_versions_color() {
        let yaml = "---\nengine: ruby\ncve: 2021-99999\ntitle: No fix\ncvss_v3: 9.0\n";
        let advisory =
            crate::advisory::Advisory::from_yaml(yaml, Path::new("CVE-2021-99999.yml")).unwrap();
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![],
            vulnerable_rubies: vec![crate::scanner::VulnerableRuby {
                engine: "ruby".to_string(),
                version: "2.6.0".to_string(),
                advisory,
            }],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, true, false, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("upgrade Ruby to a patched version!"));
        assert!(output.contains("\x1b["));
    }

    #[test]
    fn text_output_ruby_high_criticality_color() {
        let yaml = "---\nengine: ruby\ncve: 2021-99999\ntitle: High severity\ncvss_v3: 8.0\npatched_versions:\n  - \">= 3.0.2\"\n";
        let advisory =
            crate::advisory::Advisory::from_yaml(yaml, Path::new("CVE-2021-99999.yml")).unwrap();
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![],
            vulnerable_rubies: vec![crate::scanner::VulnerableRuby {
                engine: "ruby".to_string(),
                version: "2.6.0".to_string(),
                advisory,
            }],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, true, false, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains(&format!("{}{}High{}", RED, BOLD, RESET)));
    }

    #[test]
    fn text_output_ruby_critical_criticality_color() {
        let yaml = "---\nengine: ruby\ncve: 2021-99999\ntitle: Critical severity\ncvss_v3: 9.5\npatched_versions:\n  - \">= 3.0.2\"\n";
        let advisory =
            crate::advisory::Advisory::from_yaml(yaml, Path::new("CVE-2021-99999.yml")).unwrap();
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![],
            vulnerable_rubies: vec![crate::scanner::VulnerableRuby {
                engine: "ruby".to_string(),
                version: "2.6.0".to_string(),
                advisory,
            }],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, true, false, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains(&format!("{}{}Critical{}", RED, BOLD, RESET)));
    }

    #[test]
    fn text_output_gems_and_rubies_separator() {
        let gem_yaml = "---\ngem: test\ncve: 2020-1234\ntitle: Test\ncvss_v3: 9.8\npatched_versions:\n  - \">= 1.0.0\"\n";
        let gem_advisory =
            crate::advisory::Advisory::from_yaml(gem_yaml, Path::new("CVE-2020-1234.yml")).unwrap();
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![UnpatchedGem {
                name: "test".to_string(),
                version: "0.5.0".to_string(),
                advisory: gem_advisory,
            }],
            vulnerable_rubies: vec![crate::scanner::VulnerableRuby {
                engine: "ruby".to_string(),
                version: "2.6.0".to_string(),
                advisory: make_ruby_advisory(),
            }],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, false, false, None);
        let output = String::from_utf8(buf).unwrap();
        // Should contain both gem and ruby info
        assert!(output.contains("Name: test"));
        assert!(output.contains("Engine: ruby"));
        // Should have separator between them
        assert!(output.contains("─".repeat(40).as_str()));
        // Summary should include both counts
        assert!(output.contains("1 unpatched gem"));
        assert!(output.contains("1 vulnerable Ruby version"));
    }

    #[test]
    fn text_output_gems_and_rubies_separator_color() {
        let gem_yaml = "---\ngem: test\ncve: 2020-1234\ntitle: Test\ncvss_v3: 9.8\npatched_versions:\n  - \">= 1.0.0\"\n";
        let gem_advisory =
            crate::advisory::Advisory::from_yaml(gem_yaml, Path::new("CVE-2020-1234.yml")).unwrap();
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![UnpatchedGem {
                name: "test".to_string(),
                version: "0.5.0".to_string(),
                advisory: gem_advisory,
            }],
            vulnerable_rubies: vec![crate::scanner::VulnerableRuby {
                engine: "ruby".to_string(),
                version: "2.6.0".to_string(),
                advisory: make_ruby_advisory(),
            }],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, true, false, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains(DIM));
        assert!(output.contains("─".repeat(40).as_str()));
    }

    #[test]
    fn text_output_multiple_ruby_vulns_separator() {
        let yaml1 = "---\nengine: ruby\ncve: 2021-31810\ntitle: First\ncvss_v3: 5.9\npatched_versions:\n  - \">= 3.0.2\"\n";
        let yaml2 = "---\nengine: ruby\ncve: 2021-99999\ntitle: Second\ncvss_v3: 7.5\npatched_versions:\n  - \">= 3.1.0\"\n";
        let adv1 =
            crate::advisory::Advisory::from_yaml(yaml1, Path::new("CVE-2021-31810.yml")).unwrap();
        let adv2 =
            crate::advisory::Advisory::from_yaml(yaml2, Path::new("CVE-2021-99999.yml")).unwrap();
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![],
            vulnerable_rubies: vec![
                crate::scanner::VulnerableRuby {
                    engine: "ruby".to_string(),
                    version: "2.6.0".to_string(),
                    advisory: adv1,
                },
                crate::scanner::VulnerableRuby {
                    engine: "ruby".to_string(),
                    version: "2.6.0".to_string(),
                    advisory: adv2,
                },
            ],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, false, false, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("2 vulnerable Ruby versions"));
        // Separator between the two ruby vulns
        assert!(output.contains("─".repeat(40).as_str()));
    }

    #[test]
    fn text_output_multiple_ruby_vulns_separator_color() {
        let yaml1 = "---\nengine: ruby\ncve: 2021-31810\ntitle: First\ncvss_v3: 5.9\npatched_versions:\n  - \">= 3.0.2\"\n";
        let yaml2 = "---\nengine: ruby\ncve: 2021-99999\ntitle: Second\ncvss_v3: 7.5\npatched_versions:\n  - \">= 3.1.0\"\n";
        let adv1 =
            crate::advisory::Advisory::from_yaml(yaml1, Path::new("CVE-2021-31810.yml")).unwrap();
        let adv2 =
            crate::advisory::Advisory::from_yaml(yaml2, Path::new("CVE-2021-99999.yml")).unwrap();
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![],
            vulnerable_rubies: vec![
                crate::scanner::VulnerableRuby {
                    engine: "ruby".to_string(),
                    version: "2.6.0".to_string(),
                    advisory: adv1,
                },
                crate::scanner::VulnerableRuby {
                    engine: "ruby".to_string(),
                    version: "2.6.0".to_string(),
                    advisory: adv2,
                },
            ],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, true, false, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains(DIM));
        assert!(output.contains("─".repeat(40).as_str()));
    }

    #[test]
    fn text_output_sources_and_rubies_no_gems() {
        let report = Report {
            insecure_sources: vec![InsecureSource {
                source: "http://rubygems.org/".to_string(),
            }],
            unpatched_gems: vec![],
            vulnerable_rubies: vec![crate::scanner::VulnerableRuby {
                engine: "ruby".to_string(),
                version: "2.6.0".to_string(),
                advisory: make_ruby_advisory(),
            }],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, false, false, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Insecure Source URI found: http://rubygems.org/"));
        assert!(output.contains("Engine: ruby"));
        assert!(output.contains("1 insecure source"));
        assert!(output.contains("1 vulnerable Ruby version"));
    }

    #[test]
    fn text_output_sources_and_rubies_no_gems_color() {
        let report = Report {
            insecure_sources: vec![InsecureSource {
                source: "http://rubygems.org/".to_string(),
            }],
            unpatched_gems: vec![],
            vulnerable_rubies: vec![crate::scanner::VulnerableRuby {
                engine: "ruby".to_string(),
                version: "2.6.0".to_string(),
                advisory: make_ruby_advisory(),
            }],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, true, false, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("\x1b["));
        assert!(output.contains("Insecure Source URI found:"));
        assert!(output.contains("Engine"));
    }

    #[test]
    fn text_output_ruby_no_url_no_ghsa() {
        let yaml = "---\nengine: ruby\ncve: 2021-99999\ntitle: Minimal advisory\ncvss_v3: 5.0\npatched_versions:\n  - \">= 3.0.2\"\n";
        let advisory =
            crate::advisory::Advisory::from_yaml(yaml, Path::new("CVE-2021-99999.yml")).unwrap();
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![],
            vulnerable_rubies: vec![crate::scanner::VulnerableRuby {
                engine: "ruby".to_string(),
                version: "2.6.0".to_string(),
                advisory,
            }],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, false, false, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Engine: ruby"));
        assert!(!output.contains("GHSA"));
        assert!(!output.contains("URL"));
    }

    // ========== Color remediation ==========

    #[test]
    fn text_output_color_remediation() {
        let report = make_report_with_vuln();
        let mut buf = Vec::new();
        print_text(&report, &mut buf, false, false, true, true, None);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Remediation:"));
        assert!(output.contains("\x1b["));
        assert!(output.contains(BOLD));
    }
}
