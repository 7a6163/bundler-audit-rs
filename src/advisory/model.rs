use std::fmt;
use std::path::Path;
use thiserror::Error;

use serde::Deserialize;

use crate::version::{Requirement, Version};

/// The criticality level of a vulnerability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum Criticality {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Criticality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Criticality::None => write!(f, "none"),
            Criticality::Low => write!(f, "low"),
            Criticality::Medium => write!(f, "medium"),
            Criticality::High => write!(f, "high"),
            Criticality::Critical => write!(f, "critical"),
        }
    }
}

/// Raw YAML structure for deserialization.
#[derive(Debug, Deserialize)]
struct AdvisoryYaml {
    gem: String,
    #[serde(default)]
    cve: Option<String>,
    #[serde(default)]
    osvdb: Option<String>,
    #[serde(default)]
    ghsa: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    date: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    cvss_v2: Option<f64>,
    #[serde(default)]
    cvss_v3: Option<f64>,
    #[serde(default)]
    framework: Option<String>,
    #[serde(default)]
    patched_versions: Option<Vec<String>>,
    #[serde(default)]
    unaffected_versions: Option<Vec<String>>,
    // We intentionally skip `related` — it's metadata only, not used for auditing.
}

/// A security advisory loaded from the ruby-advisory-db.
#[derive(Debug, Clone)]
pub struct Advisory {
    /// The advisory identifier (filename without .yml).
    pub id: String,
    /// The affected gem name.
    pub gem: String,
    /// CVE identifier (e.g., "2020-1234").
    pub cve: Option<String>,
    /// OSVDB identifier.
    pub osvdb: Option<String>,
    /// GitHub Security Advisory identifier (e.g., "aaaa-bbbb-cccc").
    pub ghsa: Option<String>,
    /// URL with vulnerability details.
    pub url: Option<String>,
    /// Vulnerability title.
    pub title: Option<String>,
    /// Discovery/publication date.
    pub date: Option<String>,
    /// Full vulnerability description.
    pub description: Option<String>,
    /// CVSS v2 score (0.0-10.0).
    pub cvss_v2: Option<f64>,
    /// CVSS v3 score (0.0-10.0).
    pub cvss_v3: Option<f64>,
    /// Framework (e.g., "rails").
    pub framework: Option<String>,
    /// Version requirements for patched versions.
    pub patched_versions: Vec<Requirement>,
    /// Version requirements for unaffected versions.
    pub unaffected_versions: Vec<Requirement>,
}

#[derive(Debug, Error)]
pub enum AdvisoryError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("invalid requirement '{version_str}': {error}")]
    InvalidRequirement { version_str: String, error: String },
}

impl Advisory {
    /// Load an advisory from a YAML file.
    pub fn load(path: &Path) -> Result<Self, AdvisoryError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_yaml(&content, path)
    }

    /// Parse an advisory from a YAML string with a path for ID extraction.
    pub fn from_yaml(yaml: &str, path: &Path) -> Result<Self, AdvisoryError> {
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        let raw: AdvisoryYaml = serde_yaml::from_str(yaml)?;

        let patched_versions =
            parse_version_requirements(raw.patched_versions.as_deref().unwrap_or(&[]))?;
        let unaffected_versions =
            parse_version_requirements(raw.unaffected_versions.as_deref().unwrap_or(&[]))?;

        Ok(Advisory {
            id,
            gem: raw.gem,
            cve: raw.cve,
            osvdb: raw.osvdb,
            ghsa: raw.ghsa,
            url: raw.url,
            title: raw.title,
            date: raw.date,
            description: raw.description,
            cvss_v2: raw.cvss_v2,
            cvss_v3: raw.cvss_v3,
            framework: raw.framework,
            patched_versions,
            unaffected_versions,
        })
    }

    /// Check if the given version is patched against this advisory.
    pub fn patched(&self, version: &Version) -> bool {
        self.patched_versions
            .iter()
            .any(|req| req.satisfied_by(version))
    }

    /// Check if the given version is unaffected by this advisory.
    pub fn unaffected(&self, version: &Version) -> bool {
        self.unaffected_versions
            .iter()
            .any(|req| req.satisfied_by(version))
    }

    /// Check if the given version is vulnerable to this advisory.
    ///
    /// A version is vulnerable if it is neither patched nor unaffected.
    pub fn vulnerable(&self, version: &Version) -> bool {
        !self.patched(version) && !self.unaffected(version)
    }

    /// The CVE identifier string (e.g., "CVE-2020-1234").
    pub fn cve_id(&self) -> Option<String> {
        self.cve.as_ref().map(|cve| format!("CVE-{}", cve))
    }

    /// The OSVDB identifier string (e.g., "OSVDB-91452").
    pub fn osvdb_id(&self) -> Option<String> {
        self.osvdb.as_ref().map(|id| format!("OSVDB-{}", id))
    }

    /// The GHSA identifier string (e.g., "GHSA-aaaa-bbbb-cccc").
    pub fn ghsa_id(&self) -> Option<String> {
        self.ghsa.as_ref().map(|id| format!("GHSA-{}", id))
    }

    /// All identifiers (CVE, OSVDB, GHSA) as a list.
    pub fn identifiers(&self) -> Vec<String> {
        [self.cve_id(), self.osvdb_id(), self.ghsa_id()]
            .into_iter()
            .flatten()
            .collect()
    }

    /// Determine the criticality based on CVSS scores.
    ///
    /// CVSS v3 is preferred over v2. Scoring follows NIST/NVD guidelines.
    pub fn criticality(&self) -> Option<Criticality> {
        if let Some(score) = self.cvss_v3 {
            Some(match score {
                0.0 => Criticality::None,
                s if s < 4.0 => Criticality::Low,
                s if s < 7.0 => Criticality::Medium,
                s if s < 9.0 => Criticality::High,
                _ => Criticality::Critical,
            })
        } else {
            self.cvss_v2.map(|score| match score {
                s if s < 4.0 => Criticality::Low,
                s if s < 7.0 => Criticality::Medium,
                _ => Criticality::High,
            })
        }
    }
}

impl fmt::Display for Advisory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}

/// Parse version requirement strings (as they appear in advisory YAML)
/// into `Requirement` objects.
///
/// Each string like `"~> 0.1.42"` or `">= 1.0, < 2.0"` becomes a `Requirement`.
fn parse_version_requirements(versions: &[String]) -> Result<Vec<Requirement>, AdvisoryError> {
    versions
        .iter()
        .map(|v| {
            // Ruby splits on ", " and passes as multiple args to Gem::Requirement.new
            let parts: Vec<&str> = v.split(", ").collect();
            Requirement::parse_multiple(&parts).map_err(|e| AdvisoryError::InvalidRequirement {
                version_str: v.clone(),
                error: e.to_string(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/advisory/CVE-2020-1234.yml")
    }

    fn load_fixture() -> Advisory {
        Advisory::load(&fixture_path()).unwrap()
    }

    // ========== Loading ==========

    #[test]
    fn load_advisory_from_yaml() {
        let adv = load_fixture();
        assert_eq!(adv.id, "CVE-2020-1234");
        assert_eq!(adv.gem, "test");
        assert_eq!(adv.cve, Some("2020-1234".to_string()));
        assert_eq!(adv.ghsa, Some("aaaa-bbbb-cccc".to_string()));
        assert_eq!(adv.url, Some("https://example.com/".to_string()));
        assert_eq!(adv.title, Some("Test advisory".to_string()));
        assert_eq!(adv.cvss_v2, Some(10.0));
        assert_eq!(adv.cvss_v3, Some(9.8));
    }

    #[test]
    fn load_patched_versions() {
        let adv = load_fixture();
        assert_eq!(adv.patched_versions.len(), 3);
        // ~> 0.1.42, ~> 0.2.42, >= 1.0.0
    }

    #[test]
    fn load_unaffected_versions() {
        let adv = load_fixture();
        assert_eq!(adv.unaffected_versions.len(), 1);
        // < 0.1.0
    }

    // ========== Identifiers ==========

    #[test]
    fn cve_id() {
        let adv = load_fixture();
        assert_eq!(adv.cve_id(), Some("CVE-2020-1234".to_string()));
    }

    #[test]
    fn ghsa_id() {
        let adv = load_fixture();
        assert_eq!(adv.ghsa_id(), Some("GHSA-aaaa-bbbb-cccc".to_string()));
    }

    #[test]
    fn identifiers_list() {
        let adv = load_fixture();
        let ids = adv.identifiers();
        assert_eq!(ids.len(), 2); // CVE + GHSA, no OSVDB
        assert!(ids.contains(&"CVE-2020-1234".to_string()));
        assert!(ids.contains(&"GHSA-aaaa-bbbb-cccc".to_string()));
    }

    // ========== Criticality ==========

    #[test]
    fn criticality_uses_cvss_v3() {
        let adv = load_fixture();
        // cvss_v3 = 9.8 -> Critical
        assert_eq!(adv.criticality(), Some(Criticality::Critical));
    }

    #[test]
    fn criticality_cvss_v3_ranges() {
        let test = |v3: f64, expected: Criticality| {
            let yaml = format!(
                "---\ngem: test\ncvss_v3: {}\npatched_versions:\n  - \">= 1.0\"\n",
                v3
            );
            let adv = Advisory::from_yaml(&yaml, Path::new("test.yml")).unwrap();
            assert_eq!(adv.criticality(), Some(expected), "cvss_v3={}", v3);
        };

        test(0.0, Criticality::None);
        test(1.0, Criticality::Low);
        test(3.9, Criticality::Low);
        test(4.0, Criticality::Medium);
        test(6.9, Criticality::Medium);
        test(7.0, Criticality::High);
        test(8.9, Criticality::High);
        test(9.0, Criticality::Critical);
        test(10.0, Criticality::Critical);
    }

    #[test]
    fn criticality_falls_back_to_cvss_v2() {
        let yaml = "---\ngem: test\ncvss_v2: 7.5\npatched_versions:\n  - \">= 1.0\"\n";
        let adv = Advisory::from_yaml(yaml, Path::new("test.yml")).unwrap();
        assert_eq!(adv.criticality(), Some(Criticality::High));
    }

    #[test]
    fn criticality_none_when_no_cvss() {
        let yaml = "---\ngem: test\npatched_versions:\n  - \">= 1.0\"\n";
        let adv = Advisory::from_yaml(yaml, Path::new("test.yml")).unwrap();
        assert_eq!(adv.criticality(), None);
    }

    // ========== Vulnerability Checking ==========

    #[test]
    fn vulnerable_version() {
        let adv = load_fixture();
        // 0.1.0 is not patched and not unaffected -> vulnerable
        assert!(adv.vulnerable(&Version::parse("0.1.0").unwrap()));
        assert!(adv.vulnerable(&Version::parse("0.1.41").unwrap()));
        assert!(adv.vulnerable(&Version::parse("0.2.0").unwrap()));
        assert!(adv.vulnerable(&Version::parse("0.2.41").unwrap()));
    }

    #[test]
    fn patched_version() {
        let adv = load_fixture();
        // Patched by ~> 0.1.42
        assert!(!adv.vulnerable(&Version::parse("0.1.42").unwrap()));
        assert!(!adv.vulnerable(&Version::parse("0.1.50").unwrap()));
        // Patched by ~> 0.2.42
        assert!(!adv.vulnerable(&Version::parse("0.2.42").unwrap()));
        // Patched by >= 1.0.0
        assert!(!adv.vulnerable(&Version::parse("1.0.0").unwrap()));
        assert!(!adv.vulnerable(&Version::parse("2.0.0").unwrap()));
    }

    #[test]
    fn unaffected_version() {
        let adv = load_fixture();
        // Unaffected by < 0.1.0
        assert!(!adv.vulnerable(&Version::parse("0.0.9").unwrap()));
        assert!(!adv.vulnerable(&Version::parse("0.0.1").unwrap()));
    }

    // ========== Edge Cases ==========

    #[test]
    fn advisory_without_optional_fields() {
        let yaml = "---\ngem: minimal\npatched_versions:\n  - \">= 1.0\"\n";
        let adv = Advisory::from_yaml(yaml, Path::new("GHSA-test.yml")).unwrap();
        assert_eq!(adv.id, "GHSA-test");
        assert_eq!(adv.gem, "minimal");
        assert!(adv.cve.is_none());
        assert!(adv.ghsa.is_none());
        assert!(adv.osvdb.is_none());
        assert!(adv.url.is_none());
        assert!(adv.cvss_v2.is_none());
        assert!(adv.cvss_v3.is_none());
        assert!(adv.unaffected_versions.is_empty());
    }

    #[test]
    fn advisory_with_framework() {
        let yaml = "---\ngem: actionpack\nframework: rails\ncve: 2011-0446\npatched_versions:\n  - \"~> 2.3.11\"\n  - \">= 3.0.4\"\n";
        let adv = Advisory::from_yaml(yaml, Path::new("CVE-2011-0446.yml")).unwrap();
        assert_eq!(adv.framework, Some("rails".to_string()));
        assert_eq!(adv.patched_versions.len(), 2);
    }

    #[test]
    fn display_shows_id() {
        let adv = load_fixture();
        assert_eq!(adv.to_string(), "CVE-2020-1234");
    }
}
