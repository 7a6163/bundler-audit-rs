use std::collections::BTreeMap;
use std::fmt;

use crate::advisory::Advisory;

/// A scan result: an insecure source, an unpatched gem, or a vulnerable Ruby version.
#[derive(Debug)]
pub enum ScanResult {
    InsecureSource(InsecureSource),
    UnpatchedGem(Box<UnpatchedGem>),
    VulnerableRuby(Box<VulnerableRuby>),
}

/// An insecure gem source (`git://` or `http://`).
#[derive(Debug, Clone)]
pub struct InsecureSource {
    /// The insecure URI string.
    pub source: String,
}

impl fmt::Display for InsecureSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Insecure Source URI found: {}", self.source)
    }
}

/// A gem with a known vulnerability.
#[derive(Debug)]
pub struct UnpatchedGem {
    /// The gem name.
    pub name: String,
    /// The installed version.
    pub version: String,
    /// The advisory describing the vulnerability.
    pub advisory: Advisory,
}

impl fmt::Display for UnpatchedGem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({}): {}", self.name, self.version, self.advisory.id)
    }
}

/// A Ruby interpreter version with a known vulnerability.
#[derive(Debug)]
pub struct VulnerableRuby {
    /// The Ruby engine (e.g., "ruby", "jruby").
    pub engine: String,
    /// The installed version.
    pub version: String,
    /// The advisory describing the vulnerability.
    pub advisory: Advisory,
}

impl fmt::Display for VulnerableRuby {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}): {}",
            self.engine, self.version, self.advisory.id
        )
    }
}

/// A grouped remediation suggestion for a single gem.
#[derive(Debug)]
pub struct Remediation {
    /// The gem name.
    pub name: String,
    /// The currently installed version.
    pub version: String,
    /// All advisories affecting this gem (deduplicated by advisory ID).
    pub advisories: Vec<Advisory>,
}

/// Aggregated scan report.
#[derive(Debug)]
pub struct Report {
    pub insecure_sources: Vec<InsecureSource>,
    pub unpatched_gems: Vec<UnpatchedGem>,
    pub vulnerable_rubies: Vec<VulnerableRuby>,
    /// Number of gem versions that failed to parse.
    pub version_parse_errors: usize,
    /// Number of advisory YAML files that failed to load.
    pub advisory_load_errors: usize,
}

impl Report {
    /// Returns true if any vulnerabilities were found.
    pub fn vulnerable(&self) -> bool {
        !self.insecure_sources.is_empty()
            || !self.unpatched_gems.is_empty()
            || !self.vulnerable_rubies.is_empty()
    }

    /// Total number of issues found.
    pub fn count(&self) -> usize {
        self.insecure_sources.len() + self.unpatched_gems.len() + self.vulnerable_rubies.len()
    }

    /// Group unpatched gems into remediation suggestions.
    ///
    /// Groups vulnerabilities by gem name, deduplicates advisories (by ID),
    /// and collects the union of all patched_versions across advisories.
    pub fn remediations(&self) -> Vec<Remediation> {
        let mut by_name: BTreeMap<&str, (&str, Vec<&Advisory>)> = BTreeMap::new();

        for gem in &self.unpatched_gems {
            let entry = by_name
                .entry(&gem.name)
                .or_insert((&gem.version, Vec::new()));
            // Deduplicate advisories by ID
            if !entry.1.iter().any(|a| a.id == gem.advisory.id) {
                entry.1.push(&gem.advisory);
            }
        }

        by_name
            .into_iter()
            .map(|(name, (version, advisories))| Remediation {
                name: name.to_string(),
                version: version.to_string(),
                advisories: advisories.into_iter().cloned().collect(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn report_vulnerable_when_issues_found() {
        let report = Report {
            insecure_sources: vec![InsecureSource {
                source: "http://rubygems.org/".to_string(),
            }],
            unpatched_gems: vec![],
            vulnerable_rubies: vec![],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        assert!(report.vulnerable());
        assert_eq!(report.count(), 1);
    }

    #[test]
    fn report_not_vulnerable_when_clean() {
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![],
            vulnerable_rubies: vec![],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        assert!(!report.vulnerable());
        assert_eq!(report.count(), 0);
    }

    #[test]
    fn remediations_empty_for_clean_report() {
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![],
            vulnerable_rubies: vec![],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };
        assert!(report.remediations().is_empty());
    }

    #[test]
    fn remediations_groups_by_gem_name() {
        let yaml1 =
            "---\ngem: test\ncve: 2020-1111\ncvss_v3: 9.0\npatched_versions:\n  - \">= 1.0.0\"\n";
        let yaml2 =
            "---\ngem: test\ncve: 2020-2222\ncvss_v3: 7.0\npatched_versions:\n  - \">= 1.2.0\"\n";
        let yaml3 =
            "---\ngem: other\ncve: 2020-3333\ncvss_v3: 5.0\npatched_versions:\n  - \">= 2.0.0\"\n";
        let adv1 = Advisory::from_yaml(yaml1, Path::new("CVE-2020-1111.yml")).unwrap();
        let adv2 = Advisory::from_yaml(yaml2, Path::new("CVE-2020-2222.yml")).unwrap();
        let adv3 = Advisory::from_yaml(yaml3, Path::new("CVE-2020-3333.yml")).unwrap();

        let report = Report {
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
                UnpatchedGem {
                    name: "other".to_string(),
                    version: "1.0.0".to_string(),
                    advisory: adv3,
                },
            ],
            vulnerable_rubies: vec![],
            version_parse_errors: 0,
            advisory_load_errors: 0,
        };

        let remediations = report.remediations();
        assert_eq!(remediations.len(), 2);

        assert_eq!(remediations[0].name, "other");
        assert_eq!(remediations[0].version, "1.0.0");
        assert_eq!(remediations[0].advisories.len(), 1);

        assert_eq!(remediations[1].name, "test");
        assert_eq!(remediations[1].version, "0.5.0");
        assert_eq!(remediations[1].advisories.len(), 2);
    }

    #[test]
    fn remediations_deduplicates_advisories() {
        let yaml =
            "---\ngem: test\ncve: 2020-1111\ncvss_v3: 9.0\npatched_versions:\n  - \">= 1.0.0\"\n";
        let adv1 = Advisory::from_yaml(yaml, Path::new("CVE-2020-1111.yml")).unwrap();
        let adv2 = Advisory::from_yaml(yaml, Path::new("CVE-2020-1111.yml")).unwrap();

        let report = Report {
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
        };

        let remediations = report.remediations();
        assert_eq!(remediations.len(), 1);
        assert_eq!(remediations[0].advisories.len(), 1);
    }

    // ========== Display Impls ==========

    #[test]
    fn insecure_source_display() {
        let src = InsecureSource {
            source: "http://rubygems.org/".to_string(),
        };
        assert_eq!(
            src.to_string(),
            "Insecure Source URI found: http://rubygems.org/"
        );
    }

    #[test]
    fn unpatched_gem_display() {
        let yaml =
            "---\ngem: test\ncve: 2020-1234\ncvss_v3: 9.0\npatched_versions:\n  - \">= 1.0\"\n";
        let advisory = Advisory::from_yaml(yaml, Path::new("CVE-2020-1234.yml")).unwrap();
        let gem = UnpatchedGem {
            name: "test".to_string(),
            version: "0.5.0".to_string(),
            advisory,
        };
        assert_eq!(gem.to_string(), "test (0.5.0): CVE-2020-1234");
    }

    #[test]
    fn vulnerable_ruby_display() {
        let yaml = "---\nengine: ruby\ncve: 2021-31810\ncvss_v3: 5.9\npatched_versions:\n  - \">= 3.0.2\"\n";
        let advisory = Advisory::from_yaml(yaml, Path::new("CVE-2021-31810.yml")).unwrap();
        let ruby = VulnerableRuby {
            engine: "ruby".to_string(),
            version: "2.6.0".to_string(),
            advisory,
        };
        assert_eq!(ruby.to_string(), "ruby (2.6.0): CVE-2021-31810");
    }
}
