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
    /// Can be overridden by `BUNDLER_AUDIT_DB` environment variable.
    pub fn default_path() -> PathBuf {
        if let Ok(custom) = std::env::var("BUNDLER_AUDIT_DB") {
            return PathBuf::from(custom);
        }
        dirs_fallback()
    }

    /// Download the ruby-advisory-db to the given path.
    pub fn download(path: &Path, _quiet: bool) -> Result<Self, DatabaseError> {
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
    pub fn update(&self) -> Result<bool, DatabaseError> {
        if !self.is_git() {
            return Ok(false);
        }

        let repo = gix::open(&self.path).map_err(|e| DatabaseError::Git(e.to_string()))?;

        let remote = repo
            .find_default_remote(gix::remote::Direction::Fetch)
            .ok_or_else(|| DatabaseError::UpdateFailed("no remote configured".to_string()))?
            .map_err(|e| DatabaseError::UpdateFailed(e.to_string()))?;

        let connection = remote
            .connect(gix::remote::Direction::Fetch)
            .map_err(|e| DatabaseError::UpdateFailed(e.to_string()))?;

        let _outcome = connection
            .prepare_fetch(gix::progress::Discard, Default::default())
            .map_err(|e| DatabaseError::UpdateFailed(e.to_string()))?
            .receive(gix::progress::Discard, &gix::interrupt::IS_INTERRUPTED)
            .map_err(|e| DatabaseError::UpdateFailed(e.to_string()))?;

        // Checkout the updated HEAD to working tree
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
                    self.load_advisories_from_dir(&entry.path(), &mut results);
                }
            }
        }

        results
    }

    /// Get advisories for a specific gem.
    pub fn advisories_for(&self, gem_name: &str) -> Vec<Advisory> {
        let mut results = Vec::new();
        let gem_dir = self.path.join("gems").join(gem_name);

        if gem_dir.is_dir() {
            self.load_advisories_from_dir(&gem_dir, &mut results);
        }

        results
    }

    /// Check a gem (name + version) against the database.
    ///
    /// Returns all advisories that the gem version is vulnerable to.
    pub fn check_gem(&self, gem_name: &str, version: &Version) -> Vec<Advisory> {
        self.advisories_for(gem_name)
            .into_iter()
            .filter(|advisory| advisory.vulnerable(version))
            .collect()
    }

    /// Total number of advisories in the database.
    pub fn size(&self) -> usize {
        let gems_dir = self.path.join("gems");
        if !gems_dir.is_dir() {
            return 0;
        }

        let mut count = 0;
        if let Ok(gem_dirs) = std::fs::read_dir(&gems_dir) {
            for entry in gem_dirs.flatten() {
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
    fn load_advisories_from_dir(&self, dir: &Path, results: &mut Vec<Advisory>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "yml") {
                    match Advisory::load(&path) {
                        Ok(advisory) => results.push(advisory),
                        Err(e) => {
                            eprintln!("warning: failed to load advisory {}: {}", path.display(), e);
                        }
                    }
                }
            }
        }
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
            let vulnerabilities = db.check_gem("activerecord", &version);
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
            let vulnerabilities = db.check_gem("nonexistent-gem-xyz", &version);
            assert!(vulnerabilities.is_empty());
        }
    }

    // ========== Database with fixture advisory ==========

    #[test]
    fn open_fixture_advisory_dir() {
        let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        // Create a mini advisory-db structure
        let db_dir = fixture_dir.join("mock_db");
        let gem_dir = db_dir.join("gems").join("test");
        std::fs::create_dir_all(&gem_dir).unwrap();
        std::fs::copy(
            fixture_dir.join("advisory/CVE-2020-1234.yml"),
            gem_dir.join("CVE-2020-1234.yml"),
        )
        .unwrap();

        let db = Database::open(&db_dir).unwrap();
        assert!(!db.is_git());

        let advisories = db.advisories_for("test");
        assert_eq!(advisories.len(), 1);
        assert_eq!(advisories[0].id, "CVE-2020-1234");

        // Check vulnerable version
        let vulns = db.check_gem("test", &Version::parse("0.1.0").unwrap());
        assert_eq!(vulns.len(), 1);

        // Check patched version
        let vulns = db.check_gem("test", &Version::parse("1.0.0").unwrap());
        assert!(vulns.is_empty());

        // Cleanup
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
}
