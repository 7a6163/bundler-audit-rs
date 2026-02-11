use std::io::Write;

use crate::advisory::Criticality;
use crate::scanner::Report;

// ANSI color codes
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

/// Print the scan report as human-readable text.
pub fn print_text(
    report: &Report,
    output: &mut dyn Write,
    verbose: bool,
    quiet: bool,
    use_color: bool,
) {
    for source in &report.insecure_sources {
        if use_color {
            writeln!(output, "{}Insecure Source URI found: {}{}", YELLOW, source.source, RESET).ok();
        } else {
            writeln!(output, "Insecure Source URI found: {}", source.source).ok();
        }
        writeln!(output).ok();
    }

    for vuln in &report.unpatched_gems {
        print_advisory(output, vuln, verbose, use_color);
    }

    if report.vulnerable() {
        if use_color {
            writeln!(output, "{}Vulnerabilities found!{}", RED, RESET).ok();
        } else {
            writeln!(output, "Vulnerabilities found!").ok();
        }
    } else if !quiet {
        if use_color {
            writeln!(output, "{}No vulnerabilities found{}", GREEN, RESET).ok();
        } else {
            writeln!(output, "No vulnerabilities found").ok();
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
    if use_color {
        write!(output, "{}Criticality: {}", RED, RESET).ok();
    } else {
        write!(output, "Criticality: ").ok();
    }
    match adv.criticality() {
        Some(Criticality::None) => writeln!(output, "None"),
        Some(Criticality::Low) => writeln!(output, "Low"),
        Some(Criticality::Medium) => {
            if use_color {
                writeln!(output, "{}Medium{}", YELLOW, RESET)
            } else {
                writeln!(output, "Medium")
            }
        }
        Some(Criticality::High) => {
            if use_color {
                writeln!(output, "{}{}High{}", RED, BOLD, RESET)
            } else {
                writeln!(output, "High")
            }
        }
        Some(Criticality::Critical) => {
            if use_color {
                writeln!(output, "{}{}Critical{}", RED, BOLD, RESET)
            } else {
                writeln!(output, "Critical")
            }
        }
        None => writeln!(output, "Unknown"),
    }
    .ok();

    if let Some(url) = &adv.url {
        label_value(output, "URL", url, use_color);
    }

    if verbose {
        if let Some(desc) = &adv.description {
            if use_color {
                writeln!(output, "{}Description:{}", RED, RESET).ok();
            } else {
                writeln!(output, "Description:").ok();
            }
            for line in desc.lines() {
                writeln!(output, "  {}", line).ok();
            }
            writeln!(output).ok();
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
            write!(output, "{}Solution: upgrade to {}", RED, RESET).ok();
        } else {
            write!(output, "Solution: upgrade to ").ok();
        }
        writeln!(output, "{}", versions.join(", ")).ok();
    } else if use_color {
        write!(output, "{}Solution: {}", RED, RESET).ok();
        writeln!(
            output,
            "{}{}remove or disable this gem until a patch is available!{}",
            RED, BOLD, RESET
        )
        .ok();
    } else {
        writeln!(
            output,
            "Solution: remove or disable this gem until a patch is available!"
        )
        .ok();
    }

    writeln!(output).ok();
}

fn label_value(output: &mut dyn Write, label: &str, value: &str, use_color: bool) {
    if use_color {
        writeln!(output, "{}{}: {}{}", RED, label, RESET, value).ok();
    } else {
        writeln!(output, "{}: {}", label, value).ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{InsecureSource, Report, UnpatchedGem};
    use crate::advisory::Advisory;
    use std::path::Path;

    fn make_report_with_insecure_source() -> Report {
        Report {
            insecure_sources: vec![InsecureSource {
                source: "http://rubygems.org/".to_string(),
            }],
            unpatched_gems: vec![],
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
        }
    }

    #[test]
    fn text_output_no_vulnerabilities() {
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![],
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
        assert!(output.contains("Name: test"));
        assert!(output.contains("Version: 0.5.0"));
        assert!(output.contains("CVE: CVE-2020-1234"));
        assert!(output.contains("GHSA: GHSA-aaaa-bbbb-cccc"));
        assert!(output.contains("Critical"));
        assert!(output.contains("Solution: upgrade to '>= 1.0.0'"));
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
        };
        let mut buf = Vec::new();
        print_text(&report, &mut buf, true, false, false);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Description:"));
        assert!(output.contains("Detailed description here."));
        assert!(!output.contains("Title:"));
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
