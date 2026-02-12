use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::path::Path;
use thiserror::Error;

use crate::advisory::{Advisory, Database, DatabaseError};
use crate::lockfile::{self, Lockfile, Source};
use crate::version::Version;

/// A scan result: either an insecure source or an unpatched gem.
#[derive(Debug)]
pub enum ScanResult {
    InsecureSource(InsecureSource),
    UnpatchedGem(Box<UnpatchedGem>),
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

/// Aggregated scan report.
#[derive(Debug)]
pub struct Report {
    pub insecure_sources: Vec<InsecureSource>,
    pub unpatched_gems: Vec<UnpatchedGem>,
}

impl Report {
    /// Returns true if any vulnerabilities were found.
    pub fn vulnerable(&self) -> bool {
        !self.insecure_sources.is_empty() || !self.unpatched_gems.is_empty()
    }

    /// Total number of issues found.
    pub fn count(&self) -> usize {
        self.insecure_sources.len() + self.unpatched_gems.len()
    }
}

/// Scanner configuration options.
#[derive(Debug, Default)]
pub struct ScanOptions {
    /// Advisory IDs to ignore (e.g., "CVE-2020-1234", "GHSA-aaaa-bbbb-cccc").
    pub ignore: HashSet<String>,
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
        let unpatched_gems = self.scan_specs(options);

        Report {
            insecure_sources,
            unpatched_gems,
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
    pub fn scan_specs(&self, options: &ScanOptions) -> Vec<UnpatchedGem> {
        let mut results = Vec::new();

        // Deduplicate: only check each gem name+version once (skip platform variants)
        let mut seen = HashSet::new();

        for spec in &self.lockfile.specs {
            let key = (&spec.name, &spec.version);
            if !seen.insert(key) {
                continue;
            }

            let version = match Version::parse(&spec.version) {
                Ok(v) => v,
                Err(_) => continue,
            };

            let advisories = self.database.check_gem(&spec.name, &version);

            for advisory in advisories {
                // Check if any of the advisory's identifiers are in the ignore list
                if !options.ignore.is_empty() {
                    let identifiers: HashSet<String> = advisory.identifiers().into_iter().collect();
                    if !options.ignore.is_disjoint(&identifiers) {
                        continue;
                    }
                }

                results.push(UnpatchedGem {
                    name: spec.name.clone(),
                    version: spec.version.clone(),
                    advisory,
                });
            }
        }

        results
    }
}

/// Check if a URI uses an insecure protocol.
fn is_insecure_uri(uri: &str) -> bool {
    uri.starts_with("git://") || uri.starts_with("http://")
}

/// RFC 1918 / RFC 4193 / RFC 6890 internal IP ranges.
const INTERNAL_IPV4_RANGES: &[(Ipv4Addr, u32)] = &[
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(127, 0, 0, 0), 8),
];

/// Check if an IPv4 address is in a CIDR range.
fn ipv4_in_cidr(addr: Ipv4Addr, network: Ipv4Addr, prefix_len: u32) -> bool {
    let addr_bits = u32::from(addr);
    let net_bits = u32::from(network);
    let mask = if prefix_len == 0 {
        0
    } else {
        !0u32 << (32 - prefix_len)
    };
    (addr_bits & mask) == (net_bits & mask)
}

/// Check if an IP address is internal/private.
fn is_internal_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => INTERNAL_IPV4_RANGES
            .iter()
            .any(|(net, prefix)| ipv4_in_cidr(v4, *net, *prefix)),
        IpAddr::V6(v6) => {
            // ::1 (loopback)
            v6 == Ipv6Addr::LOCALHOST
                // fc00::/7 (unique local)
                || (v6.octets()[0] & 0xfe) == 0xfc
        }
    }
}

/// Check if a source URI points to an internal/private host.
fn is_internal_source(uri: &str) -> bool {
    let host = extract_host(uri);
    match host {
        Some(h) => is_internal_host(&h),
        None => false,
    }
}

/// Extract the hostname from a URI string.
fn extract_host(uri: &str) -> Option<String> {
    // Handle git:// , http:// , https://
    let after_scheme = uri.split("://").nth(1)?;
    let host_port = after_scheme.split('/').next()?;
    let host = host_port.split(':').next()?;
    // Strip user@ prefix
    let host = if let Some(at_pos) = host.rfind('@') {
        &host[at_pos + 1..]
    } else {
        host
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Check if a hostname resolves to only internal IPs.
fn is_internal_host(host: &str) -> bool {
    // Try parsing as IP address first
    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_internal_ip(ip);
    }

    // Try DNS resolution
    let sock_addr = format!("{}:0", host);
    match sock_addr.to_socket_addrs() {
        Ok(addrs) => {
            let addrs: Vec<_> = addrs.collect();
            !addrs.is_empty() && addrs.iter().all(|a| is_internal_ip(a.ip()))
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lockfile;
    use std::path::PathBuf;

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
    }

    fn mock_database() -> Database {
        // Use the mock_db fixture; create it if it doesn't exist
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

    // ========== URI Security ==========

    #[test]
    fn git_protocol_is_insecure() {
        assert!(is_insecure_uri("git://github.com/foo/bar.git"));
    }

    #[test]
    fn http_is_insecure() {
        assert!(is_insecure_uri("http://rubygems.org/"));
    }

    #[test]
    fn https_is_secure() {
        assert!(!is_insecure_uri("https://rubygems.org/"));
    }

    #[test]
    fn ssh_is_secure() {
        assert!(!is_insecure_uri("git@github.com:foo/bar.git"));
    }

    // ========== Host Extraction ==========

    #[test]
    fn extract_host_from_git_uri() {
        assert_eq!(
            extract_host("git://github.com/rails/jquery-rails.git"),
            Some("github.com".to_string())
        );
    }

    #[test]
    fn extract_host_from_http_uri() {
        assert_eq!(
            extract_host("http://rubygems.org/"),
            Some("rubygems.org".to_string())
        );
    }

    #[test]
    fn extract_host_with_port() {
        assert_eq!(
            extract_host("http://gems.example.com:8080/"),
            Some("gems.example.com".to_string())
        );
    }

    #[test]
    fn extract_host_with_user() {
        assert_eq!(
            extract_host("http://user@gems.example.com/"),
            Some("gems.example.com".to_string())
        );
    }

    // ========== Internal IP Detection ==========

    #[test]
    fn localhost_is_internal() {
        assert!(is_internal_ip("127.0.0.1".parse().unwrap()));
        assert!(is_internal_ip("127.0.0.42".parse().unwrap()));
    }

    #[test]
    fn rfc1918_10_is_internal() {
        assert!(is_internal_ip("10.0.0.1".parse().unwrap()));
        assert!(is_internal_ip("10.255.255.255".parse().unwrap()));
    }

    #[test]
    fn rfc1918_172_is_internal() {
        assert!(is_internal_ip("172.16.0.1".parse().unwrap()));
        assert!(is_internal_ip("172.31.255.255".parse().unwrap()));
    }

    #[test]
    fn rfc1918_192_is_internal() {
        assert!(is_internal_ip("192.168.0.1".parse().unwrap()));
        assert!(is_internal_ip("192.168.255.255".parse().unwrap()));
    }

    #[test]
    fn public_ip_is_not_internal() {
        assert!(!is_internal_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_internal_ip("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn ipv6_loopback_is_internal() {
        assert!(is_internal_ip("::1".parse().unwrap()));
    }

    #[test]
    fn ipv6_unique_local_is_internal() {
        assert!(is_internal_ip("fc00::1".parse().unwrap()));
        assert!(is_internal_ip("fd12:3456:789a::1".parse().unwrap()));
    }

    // ========== Internal Source Detection ==========

    #[test]
    fn internal_http_source() {
        assert!(is_internal_source("http://192.168.1.1/gems/"));
        assert!(is_internal_source("http://10.0.0.1:8080/"));
        assert!(is_internal_source("http://127.0.0.1/"));
    }

    #[test]
    fn external_http_source() {
        assert!(!is_internal_source("http://rubygems.org/"));
    }

    #[test]
    fn localhost_name_is_internal() {
        assert!(is_internal_source("http://localhost/"));
    }

    // ========== Source Scanning ==========

    #[test]
    fn scan_secure_sources() {
        let input = include_str!("../tests/fixtures/secure/Gemfile.lock");
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
        let input = include_str!("../tests/fixtures/insecure_sources/Gemfile.lock");
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
        // The mock DB has one advisory for gem "test" - our lockfiles
        // don't contain "test" gem, so no vulnerabilities expected
        let input = include_str!("../tests/fixtures/secure/Gemfile.lock");
        let lockfile = lockfile::parse(input).unwrap();
        let db = mock_database();
        let scanner = Scanner::from_lockfile(lockfile, db);

        let opts = ScanOptions::default();
        let vulns = scanner.scan_specs(&opts);
        assert!(vulns.is_empty());
    }

    // ========== Full Scan with Real DB ==========

    #[test]
    fn scan_unpatched_gems_with_real_db() {
        if let Some(db) = local_database() {
            let input = include_str!("../tests/fixtures/unpatched_gems/Gemfile.lock");
            let lockfile = lockfile::parse(input).unwrap();
            let scanner = Scanner::from_lockfile(lockfile, db);

            let opts = ScanOptions::default();
            let report = scanner.scan(&opts);

            // activerecord 3.2.10 should have known vulnerabilities
            assert!(
                !report.unpatched_gems.is_empty(),
                "expected vulnerabilities for unpatched_gems fixture"
            );

            // Verify at least one vulnerability is for activerecord
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
            let input = include_str!("../tests/fixtures/secure/Gemfile.lock");
            let lockfile = lockfile::parse(input).unwrap();
            let scanner = Scanner::from_lockfile(lockfile, db);

            let insecure = scanner.scan_sources();
            assert!(insecure.is_empty());
        }
    }

    #[test]
    fn scan_with_ignore_list() {
        if let Some(db) = local_database() {
            let input = include_str!("../tests/fixtures/unpatched_gems/Gemfile.lock");
            let lockfile = lockfile::parse(input).unwrap();
            let scanner = Scanner::from_lockfile(lockfile, db);

            // First get all vulnerabilities
            let all_opts = ScanOptions::default();
            let all_vulns = scanner.scan_specs(&all_opts);

            if let Some(first_vuln) = all_vulns.first() {
                // Now ignore the first advisory
                let mut ignore = HashSet::new();
                for id in first_vuln.advisory.identifiers() {
                    ignore.insert(id);
                }
                let filtered_opts = ScanOptions { ignore };
                let filtered_vulns = scanner.scan_specs(&filtered_opts);

                assert!(
                    filtered_vulns.len() < all_vulns.len(),
                    "ignore list should reduce vulnerability count"
                );
            }
        }
    }

    // ========== Report ==========

    #[test]
    fn report_vulnerable_when_issues_found() {
        let report = Report {
            insecure_sources: vec![InsecureSource {
                source: "http://rubygems.org/".to_string(),
            }],
            unpatched_gems: vec![],
        };
        assert!(report.vulnerable());
        assert_eq!(report.count(), 1);
    }

    #[test]
    fn report_not_vulnerable_when_clean() {
        let report = Report {
            insecure_sources: vec![],
            unpatched_gems: vec![],
        };
        assert!(!report.vulnerable());
        assert_eq!(report.count(), 0);
    }
}
