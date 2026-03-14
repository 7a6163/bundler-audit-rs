use std::io::Write;

use serde_json::{Value, json};

use crate::advisory::Advisory;
use crate::fixer::FixResult;
use crate::scanner::Report;

fn advisory_to_json(adv: &Advisory) -> Value {
    json!({
        "id": adv.id,
        "cve": adv.cve_id(),
        "ghsa": adv.ghsa_id(),
        "osvdb": adv.osvdb_id(),
        "url": adv.url,
        "title": adv.title,
        "date": adv.date,
        "criticality": adv.criticality().map(|c| c.to_string()),
        "cvss_v2": adv.cvss_v2,
        "cvss_v3": adv.cvss_v3,
    })
}

/// Print the scan report as JSON.
pub fn print_json(
    report: &Report,
    output: &mut dyn Write,
    pretty: bool,
    fix: bool,
    fix_results: Option<&[FixResult]>,
) {
    let results: Vec<Value> = report
        .insecure_sources
        .iter()
        .map(|s| {
            json!({
                "type": "insecure_source",
                "source": s.source,
            })
        })
        .chain(report.unpatched_gems.iter().map(|v| {
            json!({
                "type": "unpatched_gem",
                "gem": {
                    "name": v.name,
                    "version": v.version,
                },
                "advisory": advisory_to_json(&v.advisory),
            })
        }))
        .chain(report.vulnerable_rubies.iter().map(|v| {
            json!({
                "type": "vulnerable_ruby",
                "ruby": {
                    "engine": v.engine,
                    "version": v.version,
                },
                "advisory": advisory_to_json(&v.advisory),
            })
        }))
        .collect();

    let mut doc = json!({
        "version": env!("CARGO_PKG_VERSION"),
        "results": results,
        "metadata": {
            "version_parse_errors": report.version_parse_errors,
            "advisory_load_errors": report.advisory_load_errors,
        },
    });

    if fix {
        if let Some(results) = fix_results {
            let remediations: Vec<Value> = results
                .iter()
                .map(|r| match r {
                    FixResult::Fixed(f) => json!({
                        "gem": f.name,
                        "current_version": f.current_version,
                        "resolved_version": f.resolved_version.to_string(),
                        "advisories": f.advisory_ids,
                        "status": "fixed",
                    }),
                    FixResult::Unresolvable { name, current_version, advisory_ids } => json!({
                        "gem": name,
                        "current_version": current_version,
                        "resolved_version": null,
                        "advisories": advisory_ids,
                        "status": "unresolvable",
                    }),
                })
                .collect();
            doc["remediations"] = json!(remediations);
        } else {
            // Fallback: no fix results, show patched_versions
            let remediations: Vec<Value> = report
                .remediations()
                .iter()
                .map(|r| {
                    let advisory_ids: Vec<String> =
                        r.advisories.iter().map(|a| a.id.clone()).collect();
                    let mut all_patched: Vec<String> = Vec::new();
                    let mut seen: std::collections::HashSet<String> =
                        std::collections::HashSet::new();
                    for adv in &r.advisories {
                        for pv in &adv.patched_versions {
                            let s = pv.to_string();
                            if seen.insert(s.clone()) {
                                all_patched.push(s);
                            }
                        }
                    }
                    json!({
                        "gem": r.name,
                        "current_version": r.version,
                        "advisories": advisory_ids,
                        "patched_versions": all_patched,
                        "command": format!("bundle update {}", r.name),
                    })
                })
                .collect();
            doc["remediations"] = json!(remediations);
        }
    }

    if pretty {
        serde_json::to_writer_pretty(&mut *output, &doc).ok();
        writeln!(output).ok();
    } else {
        serde_json::to_writer(&mut *output, &doc).ok();
        writeln!(output).ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisory::Advisory;
    use crate::scanner::{InsecureSource, UnpatchedGem};
    use std::path::Path;

    #[test]
    fn json_output_empty_report() {
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![],
            vulnerable_rubies: vec![],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        let mut buf = Vec::new();
        print_json(&report, &mut buf, false, false, None);
        let output = String::from_utf8(buf).unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["results"].as_array().unwrap().len(), 0);
        assert!(parsed["version"].is_string());
    }

    #[test]
    fn json_output_insecure_source() {
        let report = Report {
            insecure_sources: vec![InsecureSource {
                source: "http://rubygems.org/".to_string(),
            }],
            unpatched_gems: vec![],
            vulnerable_rubies: vec![],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        let mut buf = Vec::new();
        print_json(&report, &mut buf, false, false, None);
        let parsed: Value = serde_json::from_str(&String::from_utf8(buf).unwrap()).unwrap();
        let results = parsed["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["type"], "insecure_source");
        assert_eq!(results[0]["source"], "http://rubygems.org/");
    }

    #[test]
    fn json_output_unpatched_gem() {
        let yaml = "---\ngem: test\ncve: 2020-1234\nghsa: aaaa-bbbb-cccc\nurl: https://example.com/\ntitle: Test vuln\ncvss_v3: 9.8\npatched_versions:\n  - \">= 1.0.0\"\n";
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
        print_json(&report, &mut buf, true, false, None);
        let parsed: Value = serde_json::from_str(&String::from_utf8(buf).unwrap()).unwrap();
        let results = parsed["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["type"], "unpatched_gem");
        assert_eq!(results[0]["gem"]["name"], "test");
        assert_eq!(results[0]["gem"]["version"], "0.5.0");
        assert_eq!(results[0]["advisory"]["cve"], "CVE-2020-1234");
        assert_eq!(results[0]["advisory"]["criticality"], "critical");
    }

    #[test]
    fn json_pretty_vs_compact() {
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![],
            vulnerable_rubies: vec![],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };

        let mut pretty_buf = Vec::new();
        print_json(&report, &mut pretty_buf, true, false, None);
        let pretty = String::from_utf8(pretty_buf).unwrap();

        let mut compact_buf = Vec::new();
        print_json(&report, &mut compact_buf, false, false, None);
        let compact = String::from_utf8(compact_buf).unwrap();

        // Pretty should have indentation, compact should not
        assert!(pretty.contains('\n'));
        assert!(pretty.len() > compact.len());
    }

    #[test]
    fn json_output_fix_includes_remediations() {
        let yaml = "---\ngem: test\ncve: 2020-1234\nghsa: aaaa-bbbb-cccc\nurl: https://example.com/\ntitle: Test vuln\ncvss_v3: 9.8\npatched_versions:\n  - \">= 1.0.0\"\n";
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
        print_json(&report, &mut buf, false, true, None);
        let parsed: Value = serde_json::from_str(&String::from_utf8(buf).unwrap()).unwrap();
        let remediations = parsed["remediations"].as_array().unwrap();
        assert_eq!(remediations.len(), 1);
        assert_eq!(remediations[0]["gem"], "test");
        assert_eq!(remediations[0]["current_version"], "0.5.0");
        assert_eq!(remediations[0]["command"], "bundle update test");
        let advisories = remediations[0]["advisories"].as_array().unwrap();
        assert_eq!(advisories.len(), 1);
        assert_eq!(advisories[0], "CVE-2020-1234");
        let patched = remediations[0]["patched_versions"].as_array().unwrap();
        assert_eq!(patched.len(), 1);
        assert_eq!(patched[0], ">= 1.0.0");
    }

    #[test]
    fn json_output_no_fix_excludes_remediations() {
        let yaml = "---\ngem: test\ncve: 2020-1234\ntitle: Test\ncvss_v3: 9.8\npatched_versions:\n  - \">= 1.0.0\"\n";
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
        print_json(&report, &mut buf, false, false, None);
        let parsed: Value = serde_json::from_str(&String::from_utf8(buf).unwrap()).unwrap();
        assert!(parsed.get("remediations").is_none());
    }

    // ========== Metadata Fields ==========

    #[test]
    fn json_output_metadata_fields() {
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![],
            vulnerable_rubies: vec![],
            version_parse_errors: 5,
            advisory_load_errors: 3,
        };
        let mut buf = Vec::new();
        print_json(&report, &mut buf, false, false, None);
        let parsed: Value = serde_json::from_str(&String::from_utf8(buf).unwrap()).unwrap();
        assert_eq!(parsed["metadata"]["version_parse_errors"], 5);
        assert_eq!(parsed["metadata"]["advisory_load_errors"], 3);
    }

    // ========== Combined Insecure + Unpatched ==========

    #[test]
    fn json_output_combined_sources_and_gems() {
        let yaml = "---\ngem: test\ncve: 2020-1234\ntitle: Test\ncvss_v3: 9.8\npatched_versions:\n  - \">= 1.0.0\"\n";
        let advisory = Advisory::from_yaml(yaml, Path::new("CVE-2020-1234.yml")).unwrap();
        let report = Report {
            insecure_sources: vec![InsecureSource {
                source: "http://rubygems.org/".to_string(),
            }],
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
        print_json(&report, &mut buf, false, false, None);
        let parsed: Value = serde_json::from_str(&String::from_utf8(buf).unwrap()).unwrap();
        let results = parsed["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.iter().any(|r| r["type"] == "insecure_source"));
        assert!(results.iter().any(|r| r["type"] == "unpatched_gem"));
    }
}
