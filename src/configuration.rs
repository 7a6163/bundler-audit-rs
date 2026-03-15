use std::collections::HashSet;
use std::path::Path;
use thiserror::Error;

/// Configuration loaded from a `.gem-audit.yml` file.
#[derive(Debug, Clone, Default)]
pub struct Configuration {
    /// Advisory IDs to ignore during scanning.
    pub ignore: HashSet<String>,
    /// Maximum database age in days before warning.
    pub max_db_age_days: Option<u64>,
}

/// Errors that can occur when loading a configuration file.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The file was not found.
    #[error("configuration file not found: {0}")]
    FileNotFound(String),
    /// The YAML content is invalid.
    #[error("invalid YAML in configuration: {0}")]
    InvalidYaml(String),
    /// The configuration structure is invalid.
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),
}

impl Configuration {
    /// The default configuration file name.
    pub const DEFAULT_FILE: &str = ".gem-audit.yml";

    /// Legacy configuration file name for backward compatibility.
    pub const LEGACY_FILE: &str = ".bundler-audit.yml";

    /// Load configuration from a YAML file.
    ///
    /// Returns an error if the file exists but contains invalid content.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Err(ConfigError::FileNotFound(path.display().to_string()));
        }

        let content =
            std::fs::read_to_string(path).map_err(|e| ConfigError::FileNotFound(e.to_string()))?;

        Self::from_yaml(&content)
    }

    /// Load configuration from a YAML file path, returning a default
    /// configuration if the file does not exist.
    ///
    /// When the primary path does not exist and its file name matches the
    /// default (`.gem-audit.yml`), the legacy name (`.bundler-audit.yml`)
    /// is tried in the same directory for backward compatibility.
    pub fn load_or_default(path: &Path) -> Result<Self, ConfigError> {
        if path.exists() {
            return Self::load(path);
        }

        // Fall back to legacy config name in the same directory
        if path
            .file_name()
            .map(|f| f == Self::DEFAULT_FILE)
            .unwrap_or(false)
            && let Some(parent) = path.parent()
        {
            let legacy = parent.join(Self::LEGACY_FILE);
            if legacy.exists() {
                return Self::load(&legacy);
            }
        }

        Ok(Self::default())
    }

    /// Save configuration to a YAML file.
    ///
    /// Writes the `ignore` list and optional `max_db_age_days` in a stable,
    /// sorted order so that diffs are minimal across runs.
    ///
    /// An optional `comments` map can annotate each advisory ID with context
    /// (e.g. gem name, version, criticality).
    pub fn save(
        &self,
        path: &Path,
        comments: Option<&std::collections::HashMap<String, String>>,
    ) -> Result<(), ConfigError> {
        let mut lines = Vec::new();
        lines.push("---".to_string());

        if self.ignore.is_empty() && self.max_db_age_days.is_none() {
            lines.push("ignore: []".to_string());
        } else {
            if !self.ignore.is_empty() {
                lines.push("ignore:".to_string());
                let mut sorted: Vec<&String> = self.ignore.iter().collect();
                sorted.sort();
                for id in sorted {
                    let comment = comments.and_then(|c| c.get(id.as_str()));
                    match comment {
                        Some(c) => lines.push(format!("  - {}  # {}", id, c)),
                        None => lines.push(format!("  - {}", id)),
                    }
                }
            }

            if let Some(days) = self.max_db_age_days {
                lines.push(format!("max_db_age_days: {}", days));
            }
        }

        lines.push(String::new()); // trailing newline
        std::fs::write(path, lines.join("\n")).map_err(|e| {
            ConfigError::InvalidConfiguration(format!("failed to write {}: {}", path.display(), e))
        })
    }

    /// Parse configuration from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, ConfigError> {
        let value: serde_yaml::Value =
            serde_yaml::from_str(yaml).map_err(|e| ConfigError::InvalidYaml(e.to_string()))?;

        // Must be a mapping (Hash)
        let mapping = match value.as_mapping() {
            Some(m) => m,
            None => {
                return Err(ConfigError::InvalidConfiguration(
                    "expected a YAML mapping, not a scalar or sequence".to_string(),
                ));
            }
        };

        let mut ignore = HashSet::new();

        if let Some(ignore_val) = mapping.get(serde_yaml::Value::String("ignore".to_string())) {
            let arr = match ignore_val.as_sequence() {
                Some(seq) => seq,
                None => {
                    return Err(ConfigError::InvalidConfiguration(
                        "'ignore' must be an Array".to_string(),
                    ));
                }
            };

            for item in arr {
                match item.as_str() {
                    Some(s) => {
                        ignore.insert(s.to_string());
                    }
                    None => {
                        return Err(ConfigError::InvalidConfiguration(
                            "'ignore' contains a non-String value".to_string(),
                        ));
                    }
                }
            }
        }

        let max_db_age_days = mapping
            .get(serde_yaml::Value::String("max_db_age_days".to_string()))
            .and_then(|v| v.as_u64());

        Ok(Configuration {
            ignore,
            max_db_age_days,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config")
    }

    #[test]
    fn load_valid_config() {
        let config = Configuration::load(&fixtures_dir().join("valid.yml")).unwrap();
        assert_eq!(config.ignore.len(), 2);
        assert!(config.ignore.contains("CVE-123"));
        assert!(config.ignore.contains("CVE-456"));
    }

    #[test]
    fn load_empty_ignore_list() {
        let config = Configuration::from_yaml("---\nignore: []\n").unwrap();
        assert!(config.ignore.is_empty());
    }

    #[test]
    fn load_no_ignore_key() {
        let config = Configuration::from_yaml("---\n{}\n").unwrap();
        assert!(config.ignore.is_empty());
    }

    #[test]
    fn load_missing_file_returns_default() {
        let config =
            Configuration::load_or_default(Path::new("/nonexistent/.gem-audit.yml")).unwrap();
        assert!(config.ignore.is_empty());
    }

    #[test]
    fn load_missing_file_returns_error() {
        let result = Configuration::load(Path::new("/nonexistent/.gem-audit.yml"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ConfigError::FileNotFound(_)));
    }

    #[test]
    fn reject_empty_yaml_file() {
        let result = Configuration::load(&fixtures_dir().join("bad/empty.yml"));
        assert!(result.is_err());
    }

    #[test]
    fn reject_ignore_not_array() {
        let result = Configuration::load(&fixtures_dir().join("bad/ignore_is_not_an_array.yml"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            ConfigError::InvalidConfiguration(msg) => {
                assert!(msg.contains("Array"), "expected 'Array' in error: {}", msg);
            }
            other => panic!("expected InvalidConfiguration, got: {:?}", other),
        }
    }

    #[test]
    fn reject_ignore_contains_non_string() {
        let result =
            Configuration::load(&fixtures_dir().join("bad/ignore_contains_a_non_string.yml"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            ConfigError::InvalidConfiguration(msg) => {
                assert!(
                    msg.contains("non-String"),
                    "expected 'non-String' in error: {}",
                    msg
                );
            }
            other => panic!("expected InvalidConfiguration, got: {:?}", other),
        }
    }

    #[test]
    fn default_config_is_empty() {
        let config = Configuration::default();
        assert!(config.ignore.is_empty());
    }

    #[test]
    fn parse_real_dot_config() {
        let yaml = "---\nignore:\n- OSVDB-89025\n";
        let config = Configuration::from_yaml(yaml).unwrap();
        assert_eq!(config.ignore.len(), 1);
        assert!(config.ignore.contains("OSVDB-89025"));
    }

    #[test]
    fn parse_max_db_age_days() {
        let yaml = "---\nmax_db_age_days: 7\n";
        let config = Configuration::from_yaml(yaml).unwrap();
        assert_eq!(config.max_db_age_days, Some(7));
    }

    #[test]
    fn parse_config_without_max_db_age() {
        let yaml = "---\nignore:\n- CVE-123\n";
        let config = Configuration::from_yaml(yaml).unwrap();
        assert_eq!(config.max_db_age_days, None);
    }

    // ========== Save ==========

    #[test]
    fn save_and_reload_roundtrip() {
        let tmp = std::env::temp_dir().join("gem_audit_test_save");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let path = tmp.join(".gem-audit.yml");
        let mut ignore = HashSet::new();
        ignore.insert("CVE-2020-1234".to_string());
        ignore.insert("GHSA-aaaa-bbbb-cccc".to_string());

        let config = Configuration {
            ignore,
            max_db_age_days: Some(7),
        };
        config.save(&path, None).unwrap();

        let reloaded = Configuration::load(&path).unwrap();
        assert_eq!(reloaded.ignore.len(), 2);
        assert!(reloaded.ignore.contains("CVE-2020-1234"));
        assert!(reloaded.ignore.contains("GHSA-aaaa-bbbb-cccc"));
        assert_eq!(reloaded.max_db_age_days, Some(7));

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn save_empty_config() {
        let tmp = std::env::temp_dir().join("gem_audit_test_save_empty");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let path = tmp.join(".gem-audit.yml");
        let config = Configuration::default();
        config.save(&path, None).unwrap();

        let reloaded = Configuration::load(&path).unwrap();
        assert!(reloaded.ignore.is_empty());
        assert_eq!(reloaded.max_db_age_days, None);

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn save_sorted_output() {
        let tmp = std::env::temp_dir().join("gem_audit_test_save_sorted");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let path = tmp.join(".gem-audit.yml");
        let mut ignore = HashSet::new();
        ignore.insert("CVE-2020-9999".to_string());
        ignore.insert("CVE-2020-0001".to_string());
        ignore.insert("GHSA-zzzz-yyyy-xxxx".to_string());

        let config = Configuration {
            ignore,
            max_db_age_days: None,
        };
        config.save(&path, None).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        // Should be sorted
        assert_eq!(lines[2], "  - CVE-2020-0001");
        assert_eq!(lines[3], "  - CVE-2020-9999");
        assert_eq!(lines[4], "  - GHSA-zzzz-yyyy-xxxx");

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn save_with_comments() {
        let tmp = std::env::temp_dir().join("gem_audit_test_save_comments");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let path = tmp.join(".gem-audit.yml");
        let mut ignore = HashSet::new();
        ignore.insert("CVE-2020-1234".to_string());
        ignore.insert("GHSA-aaaa-bbbb-cccc".to_string());

        let config = Configuration {
            ignore,
            max_db_age_days: None,
        };

        let mut comments = std::collections::HashMap::new();
        comments.insert(
            "CVE-2020-1234".to_string(),
            "activerecord 3.2.10 (Critical)".to_string(),
        );
        comments.insert(
            "GHSA-aaaa-bbbb-cccc".to_string(),
            "rack 1.5.0 (Medium)".to_string(),
        );

        config.save(&path, Some(&comments)).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("CVE-2020-1234  # activerecord 3.2.10 (Critical)"));
        assert!(content.contains("GHSA-aaaa-bbbb-cccc  # rack 1.5.0 (Medium)"));

        // Should still be loadable (YAML ignores comments)
        let reloaded = Configuration::load(&path).unwrap();
        assert_eq!(reloaded.ignore.len(), 2);
        assert!(reloaded.ignore.contains("CVE-2020-1234"));
        assert!(reloaded.ignore.contains("GHSA-aaaa-bbbb-cccc"));

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn display_errors() {
        let e1 = ConfigError::FileNotFound("foo.yml".to_string());
        assert!(e1.to_string().contains("foo.yml"));

        let e2 = ConfigError::InvalidYaml("bad".to_string());
        assert!(e2.to_string().contains("bad"));

        let e3 = ConfigError::InvalidConfiguration("oops".to_string());
        assert!(e3.to_string().contains("oops"));
    }

    // ========== Legacy Config Fallback ==========

    #[test]
    fn legacy_config_fallback() {
        let tmp = std::env::temp_dir().join("gem_audit_test_legacy");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        // Only create the legacy file
        std::fs::write(
            tmp.join(".bundler-audit.yml"),
            "---\nignore:\n  - CVE-LEGACY-001\n",
        )
        .unwrap();

        // load_or_default with default name should fall back
        let config = Configuration::load_or_default(&tmp.join(".gem-audit.yml")).unwrap();
        assert!(config.ignore.contains("CVE-LEGACY-001"));

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn no_legacy_fallback_for_custom_name() {
        // When a custom config name is used, legacy fallback should NOT apply
        let config = Configuration::load_or_default(Path::new("/nonexistent/custom.yml")).unwrap();
        assert!(config.ignore.is_empty());
    }

    // ========== YAML scalar root rejection ==========

    #[test]
    fn reject_yaml_scalar_root() {
        let result = Configuration::from_yaml("hello");
        assert!(result.is_err());
        match result.unwrap_err() {
            ConfigError::InvalidConfiguration(msg) => {
                assert!(msg.contains("expected a YAML mapping"));
            }
            other => panic!("expected InvalidConfiguration, got: {:?}", other),
        }
    }

    #[test]
    fn reject_yaml_sequence_root() {
        let result = Configuration::from_yaml("- item1\n- item2\n");
        assert!(result.is_err());
        match result.unwrap_err() {
            ConfigError::InvalidConfiguration(msg) => {
                assert!(msg.contains("expected a YAML mapping"));
            }
            other => panic!("expected InvalidConfiguration, got: {:?}", other),
        }
    }
}
