mod parser;
pub mod platform;
mod ruby_version;

pub use parser::parse;
pub use ruby_version::RubyVersion;

use thiserror::Error;

/// A parsed Gemfile.lock file.
#[derive(Debug, Clone)]
pub struct Lockfile {
    /// All gem sources (GEM, GIT, PATH sections).
    pub sources: Vec<Source>,
    /// All resolved gem specifications across all sources.
    pub specs: Vec<GemSpec>,
    /// Target platforms.
    pub platforms: Vec<String>,
    /// Top-level dependencies from the DEPENDENCIES section.
    pub dependencies: Vec<Dependency>,
    /// Ruby version constraint, if specified.
    pub ruby_version: Option<String>,
    /// Bundler version that generated this lockfile.
    pub bundled_with: Option<String>,
}

impl Lockfile {
    /// Find a gem spec by name. Returns the first match (without platform suffix).
    pub fn find_spec(&self, name: &str) -> Option<&GemSpec> {
        self.specs
            .iter()
            .find(|s| s.name == name && s.platform.is_none())
    }

    /// Find all gem specs by name (including platform variants).
    pub fn find_specs(&self, name: &str) -> Vec<&GemSpec> {
        self.specs.iter().filter(|s| s.name == name).collect()
    }

    /// Parse the `RUBY VERSION` section into a `RubyVersion`.
    ///
    /// Returns `None` if the section is absent or cannot be parsed.
    pub fn parsed_ruby_version(&self) -> Option<RubyVersion> {
        self.ruby_version.as_deref().and_then(RubyVersion::parse)
    }
}

/// A gem source section (GEM, GIT, or PATH).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Rubygems(RubygemsSource),
    Git(GitSource),
    Path(PathSource),
}

impl Source {
    /// Returns the remote URL/path of this source.
    pub fn remote(&self) -> &str {
        match self {
            Source::Rubygems(s) => &s.remote,
            Source::Git(s) => &s.remote,
            Source::Path(s) => &s.remote,
        }
    }
}

/// A RubyGems source (GEM section).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RubygemsSource {
    pub remote: String,
}

/// A Git source (GIT section).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitSource {
    pub remote: String,
    pub revision: Option<String>,
    pub branch: Option<String>,
    pub tag: Option<String>,
}

/// A local path source (PATH section).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSource {
    pub remote: String,
}

/// A resolved gem specification from the lockfile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GemSpec {
    /// Gem name (e.g., "rails").
    pub name: String,
    /// Resolved version string (e.g., "5.2.8").
    pub version: String,
    /// Platform suffix, if any (e.g., "x86_64-linux").
    pub platform: Option<String>,
    /// Direct dependencies of this gem.
    pub dependencies: Vec<GemDependency>,
    /// Which source this gem came from.
    pub source_index: usize,
}

/// A dependency of a resolved gem (sub-dependency with version constraints).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GemDependency {
    /// Dependency gem name.
    pub name: String,
    /// Version constraint string (e.g., "~> 2.0, >= 2.0.8"), or None if unconstrained.
    pub requirement: Option<String>,
}

/// A top-level dependency from the DEPENDENCIES section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    /// Gem name.
    pub name: String,
    /// Version constraint, if specified.
    pub requirement: Option<String>,
    /// Whether this dependency was pinned with `!` in the Gemfile.
    pub pinned: bool,
}

/// Errors that can occur while parsing a Gemfile.lock.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseError {
    /// An unexpected line was encountered.
    #[error("unexpected line at {line_number}: '{content}'")]
    UnexpectedLine { line_number: usize, content: String },
    /// A required field was missing.
    #[error("missing field '{field}' in section '{section}'")]
    MissingField { section: String, field: String },
    /// The file is empty or contains no parseable content.
    #[error("empty or unparseable lockfile")]
    Empty,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_lockfile() -> Lockfile {
        let input = "\
GEM
  remote: https://rubygems.org/
  specs:
    rack (2.2.0)
    rack (2.2.0-x86_64-linux)
    json (2.6.0)

PLATFORMS
  ruby

DEPENDENCIES
  rack
";
        parse(input).unwrap()
    }

    #[test]
    fn source_remote_rubygems() {
        let src = Source::Rubygems(RubygemsSource {
            remote: "https://rubygems.org/".to_string(),
        });
        assert_eq!(src.remote(), "https://rubygems.org/");
    }

    #[test]
    fn source_remote_git() {
        let src = Source::Git(GitSource {
            remote: "git://github.com/foo/bar.git".to_string(),
            revision: None,
            branch: None,
            tag: None,
        });
        assert_eq!(src.remote(), "git://github.com/foo/bar.git");
    }

    #[test]
    fn source_remote_path() {
        let src = Source::Path(PathSource {
            remote: ".".to_string(),
        });
        assert_eq!(src.remote(), ".");
    }

    #[test]
    fn find_spec_returns_platformless() {
        let lockfile = sample_lockfile();
        let spec = lockfile.find_spec("rack").unwrap();
        assert_eq!(spec.version, "2.2.0");
        assert!(spec.platform.is_none());
    }

    #[test]
    fn find_spec_nonexistent() {
        let lockfile = sample_lockfile();
        assert!(lockfile.find_spec("nonexistent").is_none());
    }

    #[test]
    fn find_specs_returns_all_variants() {
        let lockfile = sample_lockfile();
        let specs = lockfile.find_specs("rack");
        assert_eq!(specs.len(), 2);
    }

    #[test]
    fn find_specs_nonexistent() {
        let lockfile = sample_lockfile();
        let specs = lockfile.find_specs("nonexistent");
        assert!(specs.is_empty());
    }

    #[test]
    fn parse_error_unexpected_line_display() {
        let err = ParseError::UnexpectedLine {
            line_number: 42,
            content: "bad line".to_string(),
        };
        assert_eq!(err.to_string(), "unexpected line at 42: 'bad line'");
    }

    #[test]
    fn parse_error_missing_field_display() {
        let err = ParseError::MissingField {
            section: "GEM".to_string(),
            field: "remote".to_string(),
        };
        assert_eq!(err.to_string(), "missing field 'remote' in section 'GEM'");
    }

    #[test]
    fn parse_error_empty_display() {
        let err = ParseError::Empty;
        assert_eq!(err.to_string(), "empty or unparseable lockfile");
    }
}
