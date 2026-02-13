use std::collections::HashSet;
use std::path::Path;
use thiserror::Error;

/// Configuration loaded from a `.gem-audit.yml` file.
#[derive(Debug, Clone, Default)]
pub struct Configuration {
    /// Advisory IDs to ignore during scanning.
    pub ignore: HashSet<String>,
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

        Ok(Configuration { ignore })
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
    fn display_errors() {
        let e1 = ConfigError::FileNotFound("foo.yml".to_string());
        assert!(e1.to_string().contains("foo.yml"));

        let e2 = ConfigError::InvalidYaml("bad".to_string());
        assert!(e2.to_string().contains("bad"));

        let e3 = ConfigError::InvalidConfiguration("oops".to_string());
        assert!(e3.to_string().contains("oops"));
    }
}
