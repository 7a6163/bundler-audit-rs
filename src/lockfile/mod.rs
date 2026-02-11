mod parser;

pub use parser::parse;

use std::fmt;

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
        self.specs.iter().find(|s| s.name == name && s.platform.is_none())
    }

    /// Find all gem specs by name (including platform variants).
    pub fn find_specs(&self, name: &str) -> Vec<&GemSpec> {
        self.specs.iter().filter(|s| s.name == name).collect()
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// An unexpected line was encountered.
    UnexpectedLine { line_number: usize, content: String },
    /// A required field was missing.
    MissingField { section: String, field: String },
    /// The file is empty or contains no parseable content.
    Empty,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::UnexpectedLine { line_number, content } => {
                write!(f, "unexpected line at {}: '{}'", line_number, content)
            }
            ParseError::MissingField { section, field } => {
                write!(f, "missing field '{}' in section '{}'", field, section)
            }
            ParseError::Empty => write!(f, "empty or unparseable lockfile"),
        }
    }
}

impl std::error::Error for ParseError {}
