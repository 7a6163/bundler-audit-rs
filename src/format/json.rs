use std::io::Write;

use serde_json::{json, Value};

use crate::scanner::Report;

/// Print the scan report as JSON.
pub fn print_json(report: &Report, output: &mut dyn Write, pretty: bool) {
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
            let adv = &v.advisory;
            json!({
                "type": "unpatched_gem",
                "gem": {
                    "name": v.name,
                    "version": v.version,
                },
                "advisory": {
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
                },
            })
        }))
        .collect();

    let doc = json!({
        "version": env!("CARGO_PKG_VERSION"),
        "results": results,
    });

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
        };
        let mut buf = Vec::new();
        print_json(&report, &mut buf, false);
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
        };
        let mut buf = Vec::new();
        print_json(&report, &mut buf, false);
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
        };
        let mut buf = Vec::new();
        print_json(&report, &mut buf, true);
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
        };

        let mut pretty_buf = Vec::new();
        print_json(&report, &mut pretty_buf, true);
        let pretty = String::from_utf8(pretty_buf).unwrap();

        let mut compact_buf = Vec::new();
        print_json(&report, &mut compact_buf, false);
        let compact = String::from_utf8(compact_buf).unwrap();

        // Pretty should have indentation, compact should not
        assert!(pretty.contains('\n'));
        assert!(pretty.len() > compact.len());
    }
}
