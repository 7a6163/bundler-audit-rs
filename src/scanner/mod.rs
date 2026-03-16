mod network;
mod report;

pub use network::{is_insecure_uri, is_internal_source};
pub use report::{InsecureSource, Remediation, Report, ScanResult, UnpatchedGem, VulnerableRuby};

use std::collections::HashSet;
use std::path::Path;
use thiserror::Error;

use crate::advisory::{Advisory, Criticality, Database, DatabaseError};
use crate::lockfile::{self, Lockfile, Source};
use crate::version::Version;

/// Scanner configuration options.
#[derive(Debug, Default)]
pub struct ScanOptions {
    /// Advisory IDs to ignore (e.g., "CVE-2020-1234", "GHSA-aaaa-bbbb-cccc").
    pub ignore: HashSet<String>,
    /// Minimum severity threshold: only report advisories at or above this level.
    pub severity: Option<Criticality>,
    /// Treat parse/load warnings as significant (tracked in report error counters).
    pub strict: bool,
}

impl ScanOptions {
    /// Check whether an advisory should be reported based on ignore list and severity threshold.
    fn should_report(&self, advisory: &Advisory) -> bool {
        if !self.ignore.is_empty() {
            let identifiers: HashSet<String> = advisory.identifiers().into_iter().collect();
            if !self.ignore.is_disjoint(&identifiers) {
                return false;
            }
        }
        if let Some(threshold) = &self.severity {
            match advisory.criticality() {
                Some(crit) if crit >= *threshold => {}
                _ => return false,
            }
        }
        true
    }
}

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("Gemfile.lock not found: {0}")]
    LockfileNotFound(String),
    #[error("failed to parse Gemfile.lock: {0}")]
    LockfileParse(String),
    #[error("database error: {0}")]
    Database(#[from] DatabaseError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// The main scanner that audits a Gemfile.lock for security issues.
pub struct Scanner {
    lockfile: Lockfile,
    database: Database,
}

impl Scanner {
    /// Create a new scanner from a lockfile path and database.
    pub fn new(lockfile_path: &Path, database: Database) -> Result<Self, ScanError> {
        let content = std::fs::read_to_string(lockfile_path)
            .map_err(|_| ScanError::LockfileNotFound(lockfile_path.display().to_string()))?;

        let lockfile =
            lockfile::parse(&content).map_err(|e| ScanError::LockfileParse(e.to_string()))?;

        Ok(Scanner { lockfile, database })
    }

    /// Create a scanner from an already-parsed lockfile and database.
    pub fn from_lockfile(lockfile: Lockfile, database: Database) -> Self {
        Scanner { lockfile, database }
    }

    /// Run a full scan and produce a report.
    pub fn scan(&self, options: &ScanOptions) -> Report {
        let insecure_sources = self.scan_sources();
        let (unpatched_gems, version_parse_errors, advisory_load_errors) = self.scan_specs(options);
        let (vulnerable_rubies, ruby_advisory_errors) = self.scan_ruby(options);

        Report {
            insecure_sources,
            unpatched_gems,
            vulnerable_rubies,
            version_parse_errors,
            advisory_load_errors: advisory_load_errors + ruby_advisory_errors,
        }
    }

    /// Scan gem sources for insecure protocols (`git://`, `http://`).
    pub fn scan_sources(&self) -> Vec<InsecureSource> {
        let mut results = Vec::new();

        for source in &self.lockfile.sources {
            match source {
                Source::Git(git) => {
                    if is_insecure_uri(&git.remote) && !is_internal_source(&git.remote) {
                        results.push(InsecureSource {
                            source: git.remote.clone(),
                        });
                    }
                }
                Source::Rubygems(gem) => {
                    if gem.remote.starts_with("http://") && !is_internal_source(&gem.remote) {
                        results.push(InsecureSource {
                            source: gem.remote.clone(),
                        });
                    }
                }
                Source::Path(_) => {
                    // Local paths are always considered safe
                }
            }
        }

        results
    }

    /// Scan gem specs against the advisory database.
    ///
    /// Returns `(unpatched_gems, version_parse_errors, advisory_load_errors)`.
    pub fn scan_specs(&self, options: &ScanOptions) -> (Vec<UnpatchedGem>, usize, usize) {
        let mut results = Vec::new();
        let mut version_parse_errors: usize = 0;
        let mut advisory_load_errors: usize = 0;

        // Deduplicate: only check each gem name+version once (skip platform variants)
        let mut seen = HashSet::new();

        for spec in &self.lockfile.specs {
            let key = (&spec.name, &spec.version);
            if !seen.insert(key) {
                continue;
            }

            let version = match Version::parse(&spec.version) {
                Ok(v) => v,
                Err(_) => {
                    version_parse_errors += 1;
                    if options.strict {
                        eprintln!(
                            "warning: failed to parse version '{}' for gem '{}'",
                            spec.version, spec.name
                        );
                    }
                    continue;
                }
            };

            let (advisories, load_errors) = self.database.check_gem(&spec.name, &version);
            advisory_load_errors += load_errors;

            for advisory in advisories {
                if !options.should_report(&advisory) {
                    continue;
                }

                results.push(UnpatchedGem {
                    name: spec.name.clone(),
                    version: spec.version.clone(),
                    advisory,
                });
            }
        }

        // Sort by criticality descending (Critical first, None/Unknown last)
        results.sort_by(|a, b| b.advisory.criticality().cmp(&a.advisory.criticality()));

        (results, version_parse_errors, advisory_load_errors)
    }

    /// Scan the Ruby interpreter version against the advisory database.
    ///
    /// Returns `(vulnerable_rubies, advisory_load_errors)`.
    pub fn scan_ruby(&self, options: &ScanOptions) -> (Vec<VulnerableRuby>, usize) {
        let ruby_version = match self.lockfile.parsed_ruby_version() {
            Some(rv) => rv,
            None => return (Vec::new(), 0),
        };

        let version = match Version::parse(&ruby_version.version) {
            Ok(v) => v,
            Err(_) => return (Vec::new(), 0),
        };

        let (advisories, load_errors) = self.database.check_ruby(&ruby_version.engine, &version);

        let mut results = Vec::new();
        for advisory in advisories {
            if !options.should_report(&advisory) {
                continue;
            }

            results.push(VulnerableRuby {
                engine: ruby_version.engine.clone(),
                version: ruby_version.version.clone(),
                advisory,
            });
        }

        // Sort by criticality descending
        results.sort_by(|a, b| b.advisory.criticality().cmp(&a.advisory.criticality()));

        (results, load_errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
    }

    fn mock_database() -> Database {
        let db_dir = fixtures_dir().join("mock_db");
        let gem_dir = db_dir.join("gems").join("test");
        if !gem_dir.exists() {
            std::fs::create_dir_all(&gem_dir).unwrap();
            std::fs::copy(
                fixtures_dir().join("advisory/CVE-2020-1234.yml"),
                gem_dir.join("CVE-2020-1234.yml"),
            )
            .unwrap();
        }
        Database::open(&db_dir).unwrap()
    }

    fn local_database() -> Option<Database> {
        let path = Database::default_path();
        if path.join("gems").is_dir() {
            Database::open(&path).ok()
        } else {
            None
        }
    }

    // ========== Source Scanning ==========

    #[test]
    fn scan_secure_sources() {
        let input = include_str!("../../tests/fixtures/secure/Gemfile.lock");
        let lockfile = lockfile::parse(input).unwrap();
        let db = mock_database();
        let scanner = Scanner::from_lockfile(lockfile, db);

        let insecure = scanner.scan_sources();
        assert!(
            insecure.is_empty(),
            "secure lockfile should have no insecure sources"
        );
    }

    #[test]
    fn scan_insecure_sources() {
        let input = include_str!("../../tests/fixtures/insecure_sources/Gemfile.lock");
        let lockfile = lockfile::parse(input).unwrap();
        let db = mock_database();
        let scanner = Scanner::from_lockfile(lockfile, db);

        let insecure = scanner.scan_sources();
        assert_eq!(insecure.len(), 2);

        let sources: Vec<&str> = insecure.iter().map(|s| s.source.as_str()).collect();
        assert!(sources.contains(&"git://github.com/rails/jquery-rails.git"));
        assert!(sources.contains(&"http://rubygems.org/"));
    }

    // ========== Spec Scanning (with mock DB) ==========

    #[test]
    fn scan_specs_with_mock_db() {
        let input = include_str!("../../tests/fixtures/secure/Gemfile.lock");
        let lockfile = lockfile::parse(input).unwrap();
        let db = mock_database();
        let scanner = Scanner::from_lockfile(lockfile, db);

        let opts = ScanOptions::default();
        let (vulns, _, _) = scanner.scan_specs(&opts);
        assert!(vulns.is_empty());
    }

    // ========== Full Scan with Real DB ==========

    #[test]
    fn scan_unpatched_gems_with_real_db() {
        if let Some(db) = local_database() {
            let input = include_str!("../../tests/fixtures/unpatched_gems/Gemfile.lock");
            let lockfile = lockfile::parse(input).unwrap();
            let scanner = Scanner::from_lockfile(lockfile, db);

            let opts = ScanOptions::default();
            let report = scanner.scan(&opts);

            assert!(
                !report.unpatched_gems.is_empty(),
                "expected vulnerabilities for unpatched_gems fixture"
            );

            let has_activerecord = report
                .unpatched_gems
                .iter()
                .any(|v| v.name == "activerecord");
            assert!(has_activerecord, "expected activerecord vulnerability");
        }
    }

    #[test]
    fn scan_secure_lockfile_with_real_db() {
        if let Some(db) = local_database() {
            let input = include_str!("../../tests/fixtures/secure/Gemfile.lock");
            let lockfile = lockfile::parse(input).unwrap();
            let scanner = Scanner::from_lockfile(lockfile, db);

            let insecure = scanner.scan_sources();
            assert!(insecure.is_empty());
        }
    }

    #[test]
    fn scan_with_ignore_list() {
        if let Some(db) = local_database() {
            let input = include_str!("../../tests/fixtures/unpatched_gems/Gemfile.lock");
            let lockfile = lockfile::parse(input).unwrap();
            let scanner = Scanner::from_lockfile(lockfile, db);

            let all_opts = ScanOptions::default();
            let (all_vulns, _, _) = scanner.scan_specs(&all_opts);

            if let Some(first_vuln) = all_vulns.first() {
                let mut ignore = HashSet::new();
                for id in first_vuln.advisory.identifiers() {
                    ignore.insert(id);
                }
                let filtered_opts = ScanOptions {
                    ignore,
                    ..Default::default()
                };
                let (filtered_vulns, _, _) = scanner.scan_specs(&filtered_opts);

                assert!(
                    filtered_vulns.len() < all_vulns.len(),
                    "ignore list should reduce vulnerability count"
                );
            }
        }
    }

    // ========== ScanError Display ==========

    #[test]
    fn scan_error_lockfile_not_found_display() {
        let err = ScanError::LockfileNotFound("/tmp/missing".to_string());
        assert!(err.to_string().contains("Gemfile.lock not found"));
        assert!(err.to_string().contains("/tmp/missing"));
    }

    #[test]
    fn scan_error_lockfile_parse_display() {
        let err = ScanError::LockfileParse("bad content".to_string());
        assert!(err.to_string().contains("failed to parse Gemfile.lock"));
    }

    #[test]
    fn scan_error_io_display() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = ScanError::Io(io_err);
        assert!(err.to_string().contains("IO error"));
    }

    // ========== Version parse error tracking ==========

    #[test]
    fn scan_specs_tracks_version_parse_errors() {
        let input = "\
GEM
  remote: https://rubygems.org/
  specs:
    badgem (!!!invalid!!!)

PLATFORMS
  ruby

DEPENDENCIES
  badgem
";
        let lockfile = lockfile::parse(input).unwrap();
        let db = mock_database();
        let scanner = Scanner::from_lockfile(lockfile, db);

        let opts = ScanOptions::default();
        let (_, version_parse_errors, _) = scanner.scan_specs(&opts);
        assert!(
            version_parse_errors > 0,
            "expected version parse errors for invalid version"
        );
    }

    #[test]
    fn scan_specs_strict_mode_prints_warning() {
        let input = "\
GEM
  remote: https://rubygems.org/
  specs:
    badgem (!!!invalid!!!)

PLATFORMS
  ruby

DEPENDENCIES
  badgem
";
        let lockfile = lockfile::parse(input).unwrap();
        let db = mock_database();
        let scanner = Scanner::from_lockfile(lockfile, db);

        let opts = ScanOptions {
            strict: true,
            ..Default::default()
        };
        let (_, version_parse_errors, _) = scanner.scan_specs(&opts);
        assert!(version_parse_errors > 0);
    }

    // ========== Path source scanning ==========

    #[test]
    fn scan_path_source_is_safe() {
        let input = "\
PATH
  remote: .
  specs:
    my_gem (0.1.0)

GEM
  remote: https://rubygems.org/
  specs:
    rack (2.0.0)

PLATFORMS
  ruby

DEPENDENCIES
  my_gem!
  rack
";
        let lockfile = lockfile::parse(input).unwrap();
        let db = mock_database();
        let scanner = Scanner::from_lockfile(lockfile, db);

        let insecure = scanner.scan_sources();
        assert!(insecure.is_empty(), "PATH sources should be safe");
    }

    // ========== Ruby Version Scanning ==========

    #[test]
    fn scan_ruby_detects_vulnerable_version() {
        let input = include_str!("../../tests/fixtures/vulnerable_ruby/Gemfile.lock");
        let lockfile = lockfile::parse(input).unwrap();
        let db = mock_database();
        let scanner = Scanner::from_lockfile(lockfile, db);

        let opts = ScanOptions::default();
        let (vulns, _) = scanner.scan_ruby(&opts);
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].engine, "ruby");
        assert_eq!(vulns[0].version, "2.6.0");
        assert_eq!(vulns[0].advisory.id, "CVE-2021-31810");
    }

    #[test]
    fn scan_ruby_no_ruby_version_section() {
        let input = include_str!("../../tests/fixtures/secure/Gemfile.lock");
        let lockfile = lockfile::parse(input).unwrap();
        let db = mock_database();
        let scanner = Scanner::from_lockfile(lockfile, db);

        let opts = ScanOptions::default();
        let (vulns, _) = scanner.scan_ruby(&opts);
        assert!(vulns.is_empty());
    }

    #[test]
    fn scan_ruby_respects_ignore_list() {
        let input = include_str!("../../tests/fixtures/vulnerable_ruby/Gemfile.lock");
        let lockfile = lockfile::parse(input).unwrap();
        let db = mock_database();
        let scanner = Scanner::from_lockfile(lockfile, db);

        let mut ignore = HashSet::new();
        ignore.insert("CVE-2021-31810".to_string());
        let opts = ScanOptions {
            ignore,
            ..Default::default()
        };
        let (vulns, _) = scanner.scan_ruby(&opts);
        assert!(vulns.is_empty());
    }

    #[test]
    fn scan_ruby_respects_severity_filter() {
        let input = include_str!("../../tests/fixtures/vulnerable_ruby/Gemfile.lock");
        let lockfile = lockfile::parse(input).unwrap();
        let db = mock_database();
        let scanner = Scanner::from_lockfile(lockfile, db);

        let opts = ScanOptions {
            severity: Some(Criticality::High),
            ..Default::default()
        };
        let (vulns, _) = scanner.scan_ruby(&opts);
        assert!(vulns.is_empty());
    }

    #[test]
    fn scan_full_includes_ruby_vulnerabilities() {
        let input = include_str!("../../tests/fixtures/vulnerable_ruby/Gemfile.lock");
        let lockfile = lockfile::parse(input).unwrap();
        let db = mock_database();
        let scanner = Scanner::from_lockfile(lockfile, db);

        let opts = ScanOptions::default();
        let report = scanner.scan(&opts);
        assert!(report.vulnerable());
        assert_eq!(report.vulnerable_rubies.len(), 1);
    }

    #[test]
    fn scan_ruby_severity_threshold_met() {
        let input = include_str!("../../tests/fixtures/vulnerable_ruby/Gemfile.lock");
        let lockfile = lockfile::parse(input).unwrap();
        let db = mock_database();
        let scanner = Scanner::from_lockfile(lockfile, db);

        let opts = ScanOptions {
            severity: Some(Criticality::Medium),
            ..Default::default()
        };
        let (vulns, _) = scanner.scan_ruby(&opts);
        assert_eq!(vulns.len(), 1);
    }

    #[test]
    fn scan_ruby_unparseable_version() {
        let input = "\
GEM
  remote: https://rubygems.org/
  specs:
    rack (2.0.0)

PLATFORMS
  ruby

DEPENDENCIES
  rack

RUBY VERSION
   ruby !!!invalid!!!
";
        let lockfile = lockfile::parse(input).unwrap();
        let db = mock_database();
        let scanner = Scanner::from_lockfile(lockfile, db);

        let opts = ScanOptions::default();
        let (vulns, _) = scanner.scan_ruby(&opts);
        assert!(vulns.is_empty());
    }

    #[test]
    fn should_report_ignore_nonmatching() {
        let mut ignore = HashSet::new();
        ignore.insert("CVE-9999-0000".to_string());
        let opts = ScanOptions {
            ignore,
            ..Default::default()
        };
        let yaml =
            "---\ngem: test\ncve: 2020-1234\ncvss_v3: 9.0\npatched_versions:\n  - \">= 1.0\"\n";
        let advisory =
            crate::advisory::Advisory::from_yaml(yaml, Path::new("CVE-2020-1234.yml")).unwrap();
        assert!(opts.should_report(&advisory));
    }

    #[test]
    fn report_count_includes_ruby_vulns() {
        let input = include_str!("../../tests/fixtures/vulnerable_ruby/Gemfile.lock");
        let lockfile = lockfile::parse(input).unwrap();
        let db = mock_database();
        let scanner = Scanner::from_lockfile(lockfile, db);

        let opts = ScanOptions::default();
        let report = scanner.scan(&opts);
        assert!(report.count() >= 1);
    }
}
