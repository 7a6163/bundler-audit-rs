use std::fmt;
use std::path::{Path, PathBuf};
use thiserror::Error;

use super::model::Advisory;
use crate::version::Version;

/// Git URL of the ruby-advisory-db.
const ADVISORY_DB_URL: &str = "https://github.com/rubysec/ruby-advisory-db.git";

/// The ruby-advisory-db database.
#[derive(Debug)]
pub struct Database {
    path: PathBuf,
}

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("database not found at {}", .0.display())]
    NotFound(PathBuf),
    #[error("download failed: {0}")]
    DownloadFailed(String),
    #[error("update failed: {0}")]
    UpdateFailed(String),
    #[error("git error: {0}")]
    Git(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl Database {
    /// Open an existing advisory database at the given path.
    pub fn open(path: &Path) -> Result<Self, DatabaseError> {
        if !path.is_dir() {
            return Err(DatabaseError::NotFound(path.to_path_buf()));
        }
        Ok(Database {
            path: path.to_path_buf(),
        })
    }

    /// The default database path: `~/.local/share/ruby-advisory-db`.
    ///
    /// Can be overridden by `GEM_AUDIT_DB` environment variable.
    pub fn default_path() -> PathBuf {
        if let Ok(custom) = std::env::var("GEM_AUDIT_DB") {
            return PathBuf::from(custom);
        }
        dirs_fallback()
    }

    /// Download the ruby-advisory-db to the given path.
    pub fn download(path: &Path, _quiet: bool) -> Result<Self, DatabaseError> {
        // Ensure the parent directory exists; gix does not create it automatically.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(DatabaseError::Io)?;
        }

        let (mut checkout, _outcome) = gix::prepare_clone(ADVISORY_DB_URL, path)
            .map_err(|e| DatabaseError::DownloadFailed(e.to_string()))?
            .fetch_then_checkout(gix::progress::Discard, &gix::interrupt::IS_INTERRUPTED)
            .map_err(|e| DatabaseError::DownloadFailed(e.to_string()))?;

        let (_repo, _outcome) = checkout
            .main_worktree(gix::progress::Discard, &gix::interrupt::IS_INTERRUPTED)
            .map_err(|e| DatabaseError::DownloadFailed(e.to_string()))?;

        Ok(Database {
            path: path.to_path_buf(),
        })
    }

    /// Update the database by fetching from origin and fast-forwarding.
    ///
    /// If the git fetch fails (e.g. due to ref-update issues in containerised environments),
    /// falls back to a fresh clone so the update always succeeds.
    pub fn update(&self) -> Result<bool, DatabaseError> {
        if !self.is_git() {
            return Ok(false);
        }

        if let Err(e) = self.try_fetch() {
            eprintln!("warning: git fetch failed ({}), re-cloning ...", e);
            return self.reclone();
        }

        self.checkout_head()
    }

    /// Attempt a git fetch from origin.  Returns `Err` on any failure.
    fn try_fetch(&self) -> Result<(), DatabaseError> {
        let repo = gix::open(&self.path).map_err(|e| DatabaseError::Git(e.to_string()))?;

        let remote = repo
            .find_default_remote(gix::remote::Direction::Fetch)
            .ok_or_else(|| DatabaseError::UpdateFailed("no remote configured".to_string()))?
            .map_err(|e| DatabaseError::UpdateFailed(e.to_string()))?;

        let connection = remote
            .connect(gix::remote::Direction::Fetch)
            .map_err(|e| DatabaseError::UpdateFailed(e.to_string()))?;

        connection
            .prepare_fetch(gix::progress::Discard, Default::default())
            .map_err(|e| DatabaseError::UpdateFailed(e.to_string()))?
            .receive(gix::progress::Discard, &gix::interrupt::IS_INTERRUPTED)
            .map_err(|e| DatabaseError::UpdateFailed(e.to_string()))?;

        Ok(())
    }

    /// Checkout the current HEAD into the working tree.
    fn checkout_head(&self) -> Result<bool, DatabaseError> {
        let repo = gix::open(&self.path).map_err(|e| DatabaseError::Git(e.to_string()))?;
        let tree = repo
            .head_commit()
            .map_err(|e| DatabaseError::UpdateFailed(e.to_string()))?
            .tree()
            .map_err(|e| DatabaseError::UpdateFailed(e.to_string()))?;

        let mut index = repo
            .index_from_tree(&tree.id)
            .map_err(|e| DatabaseError::UpdateFailed(e.to_string()))?;

        let opts = gix::worktree::state::checkout::Options {
            overwrite_existing: true,
            ..Default::default()
        };

        gix::worktree::state::checkout(
            &mut index,
            repo.workdir()
                .ok_or_else(|| DatabaseError::UpdateFailed("bare repository".to_string()))?,
            repo.objects
                .clone()
                .into_arc()
                .map_err(|e| DatabaseError::UpdateFailed(e.to_string()))?,
            &gix::progress::Discard,
            &gix::progress::Discard,
            &gix::interrupt::IS_INTERRUPTED,
            opts,
        )
        .map_err(|e| DatabaseError::UpdateFailed(e.to_string()))?;

        Ok(true)
    }

    /// Delete the existing DB and re-clone from scratch.
    ///
    /// Uses an atomic swap: clone to a sibling `_tmp` directory, rename the
    /// existing DB to `_old`, rename `_tmp` to the final path, then remove
    /// `_old`.  This ensures `self.path` always contains a valid database.
    fn reclone(&self) -> Result<bool, DatabaseError> {
        // Derive sibling paths by appending a suffix to the directory name,
        // avoiding `with_extension()` which replaces rather than appends.
        let tmp = {
            let mut p = self.path.clone().into_os_string();
            p.push("_tmp");
            PathBuf::from(p)
        };
        let old = {
            let mut p = self.path.clone().into_os_string();
            p.push("_old");
            PathBuf::from(p)
        };

        // Clean up any leftover from a previous failed attempt.
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::remove_dir_all(&old);

        // Clone into tmp, then atomically swap with the live DB.
        Database::download(&tmp, true)?;
        std::fs::rename(&self.path, &old).map_err(DatabaseError::Io)?;
        std::fs::rename(&tmp, &self.path).map_err(|e| {
            // Best-effort rollback: restore the old DB before returning the error.
            let _ = std::fs::rename(&old, &self.path);
            DatabaseError::Io(e)
        })?;

        // Remove old DB (best-effort, failure is non-fatal).
        let _ = std::fs::remove_dir_all(&old);

        Ok(true)
    }

    /// Check whether the database path is a git repository.
    pub fn is_git(&self) -> bool {
        self.path.join(".git").is_dir()
    }

    /// Check whether the database exists and is non-empty.
    pub fn exists(&self) -> bool {
        self.path.is_dir() && self.path.join("gems").is_dir()
    }

    /// The path to the database.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The last commit ID (HEAD) of the database repository.
    pub fn commit_id(&self) -> Option<String> {
        if !self.is_git() {
            return None;
        }
        let repo = gix::open(&self.path).ok()?;
        let id = repo.head_id().ok()?;
        Some(id.to_string())
    }

    /// The timestamp of the last commit.
    pub fn last_updated_at(&self) -> Option<i64> {
        if !self.is_git() {
            return None;
        }
        let repo = gix::open(&self.path).ok()?;
        let commit = repo.head_commit().ok()?;
        let time = commit.time().ok()?;
        Some(time.seconds)
    }

    /// Enumerate all advisories in the database.
    pub fn advisories(&self) -> Vec<Advisory> {
        let mut results = Vec::new();
        let gems_dir = self.path.join("gems");

        if !gems_dir.is_dir() {
            return results;
        }

        if let Ok(entries) = std::fs::read_dir(&gems_dir) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    let _ = self.load_advisories_from_dir(&entry.path(), &mut results);
                }
            }
        }

        results
    }

    /// Get advisories for a specific gem.
    pub fn advisories_for(&self, gem_name: &str) -> Vec<Advisory> {
        self.advisories_for_with_errors(gem_name).0
    }

    /// Get advisories for a specific gem, along with the count of load errors.
    fn advisories_for_with_errors(&self, gem_name: &str) -> (Vec<Advisory>, usize) {
        let mut results = Vec::new();
        let gem_dir = self.path.join("gems").join(gem_name);

        let errors = if gem_dir.is_dir() {
            self.load_advisories_from_dir(&gem_dir, &mut results)
        } else {
            0
        };

        (results, errors)
    }

    /// Check a gem (name + version) against the database.
    ///
    /// Returns all advisories that the gem version is vulnerable to,
    /// along with the count of advisory files that failed to load.
    pub fn check_gem(&self, gem_name: &str, version: &Version) -> (Vec<Advisory>, usize) {
        let (advisories, errors) = self.advisories_for_with_errors(gem_name);
        let vulnerable = advisories
            .into_iter()
            .filter(|advisory| advisory.vulnerable(version))
            .collect();
        (vulnerable, errors)
    }

    /// Get advisories for a specific Ruby engine (e.g., "ruby", "jruby").
    pub fn advisories_for_ruby(&self, engine: &str) -> Vec<Advisory> {
        self.advisories_for_ruby_with_errors(engine).0
    }

    /// Get advisories for a specific Ruby engine, along with the count of load errors.
    fn advisories_for_ruby_with_errors(&self, engine: &str) -> (Vec<Advisory>, usize) {
        let mut results = Vec::new();
        let engine_dir = self.path.join("rubies").join(engine);

        let errors = if engine_dir.is_dir() {
            self.load_advisories_from_dir(&engine_dir, &mut results)
        } else {
            0
        };

        (results, errors)
    }

    /// Check a Ruby engine+version against the database.
    ///
    /// Returns all advisories that the Ruby version is vulnerable to,
    /// along with the count of advisory files that failed to load.
    pub fn check_ruby(&self, engine: &str, version: &Version) -> (Vec<Advisory>, usize) {
        let (advisories, errors) = self.advisories_for_ruby_with_errors(engine);
        let vulnerable = advisories
            .into_iter()
            .filter(|advisory| advisory.vulnerable(version))
            .collect();
        (vulnerable, errors)
    }

    /// Total number of gem advisories in the database.
    pub fn size(&self) -> usize {
        self.count_advisories_in("gems")
    }

    /// Total number of Ruby interpreter advisories in the database.
    pub fn rubies_size(&self) -> usize {
        self.count_advisories_in("rubies")
    }

    /// Count advisory YAML files under a top-level directory (e.g., "gems" or "rubies").
    fn count_advisories_in(&self, subdir: &str) -> usize {
        let dir = self.path.join(subdir);
        if !dir.is_dir() {
            return 0;
        }

        let mut count = 0;
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                if entry.path().is_dir()
                    && let Ok(advisory_files) = std::fs::read_dir(entry.path())
                {
                    count += advisory_files
                        .flatten()
                        .filter(|f| f.path().extension().is_some_and(|ext| ext == "yml"))
                        .count();
                }
            }
        }

        count
    }

    /// Load all advisory YAML files from a gem directory.
    ///
    /// Returns the number of files that failed to load.
    fn load_advisories_from_dir(&self, dir: &Path, results: &mut Vec<Advisory>) -> usize {
        let mut errors = 0;
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "yml") {
                    match Advisory::load(&path) {
                        Ok(advisory) => results.push(advisory),
                        Err(e) => {
                            eprintln!("warning: failed to load advisory {}: {}", path.display(), e);
                            errors += 1;
                        }
                    }
                }
            }
        }
        errors
    }
}

impl fmt::Display for Database {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.path.display())
    }
}

/// Fallback for getting the default database path when the `dirs` crate is not available.
fn dirs_fallback() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("ruby-advisory-db")
    } else {
        PathBuf::from(".ruby-advisory-db")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== Database with real ruby-advisory-db ==========

    fn local_db() -> Option<Database> {
        let path = Database::default_path();
        if path.is_dir() && path.join("gems").is_dir() {
            Database::open(&path).ok()
        } else {
            None
        }
    }

    #[test]
    fn open_local_database() {
        if let Some(db) = local_db() {
            assert!(db.exists());
            assert!(db.is_git());
        }
    }

    #[test]
    fn database_size() {
        if let Some(db) = local_db() {
            let size = db.size();
            // ruby-advisory-db has hundreds of advisories
            assert!(size > 100, "expected > 100 advisories, got {}", size);
        }
    }

    #[test]
    fn database_commit_id() {
        if let Some(db) = local_db() {
            let commit = db.commit_id();
            assert!(commit.is_some());
            let id = commit.unwrap();
            assert_eq!(id.len(), 40); // SHA-1 hex
        }
    }

    #[test]
    fn database_last_updated() {
        if let Some(db) = local_db() {
            let ts = db.last_updated_at();
            assert!(ts.is_some());
            assert!(ts.unwrap() > 0);
        }
    }

    #[test]
    fn advisories_for_actionpack() {
        if let Some(db) = local_db() {
            let advisories = db.advisories_for("actionpack");
            // actionpack has many known CVEs
            assert!(!advisories.is_empty(), "expected advisories for actionpack");
        }
    }

    #[test]
    fn check_vulnerable_gem() {
        if let Some(db) = local_db() {
            // Rails 3.2.10 is known to have vulnerabilities
            let version = Version::parse("3.2.10").unwrap();
            let (vulnerabilities, _errors) = db.check_gem("activerecord", &version);
            assert!(
                !vulnerabilities.is_empty(),
                "expected activerecord 3.2.10 to have vulnerabilities"
            );
        }
    }

    #[test]
    fn check_nonexistent_gem() {
        if let Some(db) = local_db() {
            let version = Version::parse("1.0.0").unwrap();
            let (vulnerabilities, _errors) = db.check_gem("nonexistent-gem-xyz", &version);
            assert!(vulnerabilities.is_empty());
        }
    }

    // ========== Database with fixture advisory ==========

    #[test]
    fn open_fixture_advisory_dir() {
        let (db_dir, _) = temp_mock_db("fixture");

        let db = Database::open(&db_dir).unwrap();
        assert!(!db.is_git());

        let advisories = db.advisories_for("test");
        assert_eq!(advisories.len(), 1);
        assert_eq!(advisories[0].id, "CVE-2020-1234");

        // Check vulnerable version
        let (vulns, _errors) = db.check_gem("test", &Version::parse("0.1.0").unwrap());
        assert_eq!(vulns.len(), 1);

        // Check patched version
        let (vulns, _errors) = db.check_gem("test", &Version::parse("1.0.0").unwrap());
        assert!(vulns.is_empty());

        std::fs::remove_dir_all(&db_dir).unwrap();
    }

    // ========== Error Cases ==========

    #[test]
    fn open_nonexistent_path() {
        let result = Database::open(Path::new("/nonexistent/path"));
        assert!(result.is_err());
    }

    #[test]
    fn default_path_is_sensible() {
        let path = Database::default_path();
        let path_str = path.to_string_lossy();
        assert!(
            path_str.contains("ruby-advisory-db"),
            "default path should contain ruby-advisory-db: {}",
            path_str
        );
    }

    // Helper: create an isolated temporary mock DB for tests that don't
    // share state with `mock_database()` in scanner tests.
    fn temp_mock_db(suffix: &str) -> (PathBuf, PathBuf) {
        let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let db_dir = std::env::temp_dir().join(format!("gem_audit_db_test_{}", suffix));
        let _ = std::fs::remove_dir_all(&db_dir);
        let gem_dir = db_dir.join("gems").join("test");
        std::fs::create_dir_all(&gem_dir).unwrap();
        std::fs::copy(
            fixture_dir.join("advisory/CVE-2020-1234.yml"),
            gem_dir.join("CVE-2020-1234.yml"),
        )
        .unwrap();
        (db_dir, fixture_dir)
    }

    // ========== Database Display ==========

    #[test]
    fn database_display() {
        let (db_dir, _) = temp_mock_db("display");
        let db = Database::open(&db_dir).unwrap();
        let display = db.to_string();
        assert!(display.contains("gem_audit_db_test_display"));
        std::fs::remove_dir_all(&db_dir).unwrap();
    }

    // ========== Database exists/path ==========

    #[test]
    fn database_exists_with_gems() {
        let (db_dir, _) = temp_mock_db("exists");
        let db = Database::open(&db_dir).unwrap();
        assert!(db.exists());
        assert!(db.path() == db_dir.as_path());
        std::fs::remove_dir_all(&db_dir).unwrap();
    }

    // ========== Database advisories/size with mock ==========

    #[test]
    fn database_advisories_with_mock() {
        let (db_dir, _) = temp_mock_db("advisories");
        let db = Database::open(&db_dir).unwrap();
        let all = db.advisories();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, "CVE-2020-1234");
        std::fs::remove_dir_all(&db_dir).unwrap();
    }

    #[test]
    fn database_size_with_mock() {
        let (db_dir, _) = temp_mock_db("size");
        let db = Database::open(&db_dir).unwrap();
        assert_eq!(db.size(), 1);
        std::fs::remove_dir_all(&db_dir).unwrap();
    }

    // ========== Ruby advisory methods ==========

    #[test]
    fn rubies_size_with_mock() {
        // Use the shared mock_db fixture which has rubies/ruby/CVE-2021-31810.yml
        let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let db_dir = fixture_dir.join("mock_db");
        let db = Database::open(&db_dir).unwrap();
        assert_eq!(db.rubies_size(), 1);
    }

    #[test]
    fn advisories_for_ruby_with_mock() {
        let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let db_dir = fixture_dir.join("mock_db");
        let db = Database::open(&db_dir).unwrap();
        let advisories = db.advisories_for_ruby("ruby");
        assert_eq!(advisories.len(), 1);
        assert_eq!(advisories[0].id, "CVE-2021-31810");
    }

    #[test]
    fn check_ruby_vulnerable_version() {
        let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let db_dir = fixture_dir.join("mock_db");
        let db = Database::open(&db_dir).unwrap();
        let (vulns, _) = db.check_ruby("ruby", &Version::parse("2.6.0").unwrap());
        assert_eq!(vulns.len(), 1);
    }

    #[test]
    fn check_ruby_patched_version() {
        let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let db_dir = fixture_dir.join("mock_db");
        let db = Database::open(&db_dir).unwrap();
        let (vulns, _) = db.check_ruby("ruby", &Version::parse("3.0.2").unwrap());
        assert!(vulns.is_empty());
    }

    #[test]
    fn check_ruby_nonexistent_engine() {
        let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let db_dir = fixture_dir.join("mock_db");
        let db = Database::open(&db_dir).unwrap();
        let (vulns, _) = db.check_ruby("nonexistent", &Version::parse("1.0.0").unwrap());
        assert!(vulns.is_empty());
    }

    // ========== commit_id / last_updated_at for non-git ==========

    #[test]
    fn commit_id_none_for_non_git() {
        let (db_dir, _) = temp_mock_db("nongit");
        let db = Database::open(&db_dir).unwrap();
        assert_eq!(db.commit_id(), None);
        assert_eq!(db.last_updated_at(), None);
        std::fs::remove_dir_all(&db_dir).unwrap();
    }

    // ========== DatabaseError Display ==========

    #[test]
    fn database_error_not_found_display() {
        let err = DatabaseError::NotFound(PathBuf::from("/tmp/missing"));
        assert!(err.to_string().contains("database not found"));
        assert!(err.to_string().contains("/tmp/missing"));
    }

    #[test]
    fn database_error_download_failed_display() {
        let err = DatabaseError::DownloadFailed("network error".to_string());
        assert!(err.to_string().contains("download failed"));
        assert!(err.to_string().contains("network error"));
    }

    #[test]
    fn database_error_update_failed_display() {
        let err = DatabaseError::UpdateFailed("merge conflict".to_string());
        assert!(err.to_string().contains("update failed"));
    }

    #[test]
    fn database_error_git_display() {
        let err = DatabaseError::Git("corrupt repo".to_string());
        assert!(err.to_string().contains("git error"));
    }
}
