use std::fmt;
use thiserror::Error;

use super::gem_version::Version;

/// The comparison operator for a version constraint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operator {
    /// `=`  — exactly equal
    Equal,
    /// `!=` — not equal
    NotEqual,
    /// `>`  — strictly greater than
    GreaterThan,
    /// `<`  — strictly less than
    LessThan,
    /// `>=` — greater than or equal
    GreaterThanOrEqual,
    /// `<=` — less than or equal
    LessThanOrEqual,
    /// `~>` — pessimistic version constraint
    Pessimistic,
}

impl fmt::Display for Operator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operator::Equal => write!(f, "="),
            Operator::NotEqual => write!(f, "!="),
            Operator::GreaterThan => write!(f, ">"),
            Operator::LessThan => write!(f, "<"),
            Operator::GreaterThanOrEqual => write!(f, ">="),
            Operator::LessThanOrEqual => write!(f, "<="),
            Operator::Pessimistic => write!(f, "~>"),
        }
    }
}

/// A single version constraint, e.g., `>= 1.0.0` or `~> 2.3`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionConstraint {
    pub operator: Operator,
    pub version: Version,
}

impl VersionConstraint {
    /// Check if the given version satisfies this constraint.
    pub fn satisfied_by(&self, version: &Version) -> bool {
        match &self.operator {
            Operator::Equal => version == &self.version,
            Operator::NotEqual => version != &self.version,
            Operator::GreaterThan => version > &self.version,
            Operator::LessThan => version < &self.version,
            Operator::GreaterThanOrEqual => version >= &self.version,
            Operator::LessThanOrEqual => version <= &self.version,
            Operator::Pessimistic => {
                // ~> X.Y.Z means >= X.Y.Z AND < X.Y+1.0
                // ~> X.Y means >= X.Y AND < X+1.0
                let upper = self.version.bump();
                version >= &self.version && version < &upper
            }
        }
    }
}

impl fmt::Display for VersionConstraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.operator, self.version)
    }
}

/// A compound version requirement (one or more constraints, all must be satisfied).
///
/// This is equivalent to Ruby's `Gem::Requirement`. A version must satisfy ALL
/// constraints to match the requirement.
///
/// # Examples
/// ```
/// use bundler_audit::version::Requirement;
///
/// let req = Requirement::parse("~> 1.2.3").unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    pub constraints: Vec<VersionConstraint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RequirementError {
    #[error("invalid operator: '{0}'")]
    InvalidOperator(String),
    #[error("invalid version: '{0}'")]
    InvalidVersion(String),
    #[error("empty requirement string")]
    Empty,
}

impl Requirement {
    /// Parse a requirement string.
    ///
    /// Supports:
    /// - Single constraint: `">= 1.0.0"`, `"~> 2.3"`
    /// - Compound constraints (comma-separated): `">= 1.0, < 2.0"`
    /// - Default operator is `=` when omitted: `"1.0.0"` means `"= 1.0.0"`
    pub fn parse(input: &str) -> Result<Self, RequirementError> {
        let input = input.trim();
        if input.is_empty() {
            return Ok(Requirement::default());
        }

        let parts: Vec<&str> = input.split(',').map(|s| s.trim()).collect();
        let mut constraints = Vec::with_capacity(parts.len());

        for part in parts {
            let constraint = parse_single_constraint(part)?;
            constraints.push(constraint);
        }

        if constraints.is_empty() {
            return Err(RequirementError::Empty);
        }

        Ok(Requirement { constraints })
    }

    /// Parse multiple requirement strings (as Ruby's `Gem::Requirement.new(*args)`).
    ///
    /// Each string can itself contain comma-separated constraints.
    pub fn parse_multiple(inputs: &[&str]) -> Result<Self, RequirementError> {
        let mut constraints = Vec::new();

        for input in inputs {
            let req = Requirement::parse(input)?;
            constraints.extend(req.constraints);
        }

        if constraints.is_empty() {
            return Ok(Requirement::default());
        }

        Ok(Requirement { constraints })
    }

    /// Check if the given version satisfies all constraints in this requirement.
    pub fn satisfied_by(&self, version: &Version) -> bool {
        self.constraints.iter().all(|c| c.satisfied_by(version))
    }
}

impl Default for Requirement {
    /// The default requirement: `>= 0` (matches any version).
    fn default() -> Self {
        Requirement {
            constraints: vec![VersionConstraint {
                operator: Operator::GreaterThanOrEqual,
                version: Version::parse("0").unwrap(),
            }],
        }
    }
}

impl fmt::Display for Requirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parts: Vec<String> = self.constraints.iter().map(|c| c.to_string()).collect();
        write!(f, "{}", parts.join(", "))
    }
}

/// Parse a single constraint string like ">= 1.0.0" or "~> 2.3" or "1.0.0".
fn parse_single_constraint(input: &str) -> Result<VersionConstraint, RequirementError> {
    let input = input.trim();

    if input.is_empty() {
        return Err(RequirementError::Empty);
    }

    // Try to extract operator + version (check 2-char operators first)
    let (operator, version_str) = if let Some(rest) = input.strip_prefix("~>") {
        (Operator::Pessimistic, rest.trim())
    } else if let Some(rest) = input.strip_prefix(">=") {
        (Operator::GreaterThanOrEqual, rest.trim())
    } else if let Some(rest) = input.strip_prefix("<=") {
        (Operator::LessThanOrEqual, rest.trim())
    } else if let Some(rest) = input.strip_prefix("!=") {
        (Operator::NotEqual, rest.trim())
    } else if let Some(rest) = input.strip_prefix('>') {
        (Operator::GreaterThan, rest.trim())
    } else if let Some(rest) = input.strip_prefix('<') {
        (Operator::LessThan, rest.trim())
    } else if let Some(rest) = input.strip_prefix('=') {
        (Operator::Equal, rest.trim())
    } else {
        // No operator, default to Equal
        (Operator::Equal, input)
    };

    let version = Version::parse(version_str)
        .map_err(|_| RequirementError::InvalidVersion(version_str.to_string()))?;

    Ok(VersionConstraint { operator, version })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== Parsing Tests ==========

    #[test]
    fn parse_simple_equality() {
        let req = Requirement::parse("= 1.0.0").unwrap();
        assert_eq!(req.constraints.len(), 1);
        assert_eq!(req.constraints[0].operator, Operator::Equal);
        assert_eq!(req.constraints[0].version, Version::parse("1.0.0").unwrap());
    }

    #[test]
    fn parse_pessimistic() {
        let req = Requirement::parse("~> 1.2.3").unwrap();
        assert_eq!(req.constraints[0].operator, Operator::Pessimistic);
        assert_eq!(req.constraints[0].version, Version::parse("1.2.3").unwrap());
    }

    #[test]
    fn parse_greater_than_or_equal() {
        let req = Requirement::parse(">= 2.0").unwrap();
        assert_eq!(req.constraints[0].operator, Operator::GreaterThanOrEqual);
    }

    #[test]
    fn parse_less_than() {
        let req = Requirement::parse("< 3.0").unwrap();
        assert_eq!(req.constraints[0].operator, Operator::LessThan);
    }

    #[test]
    fn parse_not_equal() {
        let req = Requirement::parse("!= 1.5").unwrap();
        assert_eq!(req.constraints[0].operator, Operator::NotEqual);
    }

    #[test]
    fn parse_compound_requirement() {
        let req = Requirement::parse(">= 1.0, < 2.0").unwrap();
        assert_eq!(req.constraints.len(), 2);
        assert_eq!(req.constraints[0].operator, Operator::GreaterThanOrEqual);
        assert_eq!(req.constraints[1].operator, Operator::LessThan);
    }

    #[test]
    fn parse_no_operator_defaults_to_equal() {
        let req = Requirement::parse("1.0.0").unwrap();
        assert_eq!(req.constraints[0].operator, Operator::Equal);
        assert_eq!(req.constraints[0].version, Version::parse("1.0.0").unwrap());
    }

    #[test]
    fn parse_multiple_strings() {
        let req = Requirement::parse_multiple(&[">= 1.0", "< 2.0", "!= 1.5"]).unwrap();
        assert_eq!(req.constraints.len(), 3);
    }

    // ========== Default Requirement ==========

    #[test]
    fn default_requirement_matches_any() {
        let req = Requirement::default();
        assert!(req.satisfied_by(&Version::parse("0").unwrap()));
        assert!(req.satisfied_by(&Version::parse("1.0.0").unwrap()));
        assert!(req.satisfied_by(&Version::parse("999.999.999").unwrap()));
    }

    // ========== Equality Operator ==========

    #[test]
    fn equal_matches_exact() {
        let req = Requirement::parse("= 1.0.0").unwrap();
        assert!(req.satisfied_by(&Version::parse("1.0.0").unwrap()));
        assert!(req.satisfied_by(&Version::parse("1.0").unwrap())); // trailing zero equivalence
        assert!(!req.satisfied_by(&Version::parse("1.0.1").unwrap()));
        assert!(!req.satisfied_by(&Version::parse("0.9.9").unwrap()));
    }

    // ========== Not Equal Operator ==========

    #[test]
    fn not_equal_excludes_version() {
        let req = Requirement::parse("!= 1.5").unwrap();
        assert!(req.satisfied_by(&Version::parse("1.0").unwrap()));
        assert!(req.satisfied_by(&Version::parse("2.0").unwrap()));
        assert!(!req.satisfied_by(&Version::parse("1.5").unwrap()));
        assert!(!req.satisfied_by(&Version::parse("1.5.0").unwrap()));
    }

    // ========== Greater Than ==========

    #[test]
    fn greater_than() {
        let req = Requirement::parse("> 1.0").unwrap();
        assert!(req.satisfied_by(&Version::parse("1.0.1").unwrap()));
        assert!(req.satisfied_by(&Version::parse("2.0").unwrap()));
        assert!(!req.satisfied_by(&Version::parse("1.0").unwrap()));
        assert!(!req.satisfied_by(&Version::parse("0.9").unwrap()));
    }

    // ========== Less Than ==========

    #[test]
    fn less_than() {
        let req = Requirement::parse("< 2.0").unwrap();
        assert!(req.satisfied_by(&Version::parse("1.9.9").unwrap()));
        assert!(req.satisfied_by(&Version::parse("1.0").unwrap()));
        assert!(!req.satisfied_by(&Version::parse("2.0").unwrap()));
        assert!(!req.satisfied_by(&Version::parse("2.0.1").unwrap()));
    }

    // ========== Greater Than Or Equal ==========

    #[test]
    fn greater_than_or_equal() {
        let req = Requirement::parse(">= 1.0").unwrap();
        assert!(req.satisfied_by(&Version::parse("1.0").unwrap()));
        assert!(req.satisfied_by(&Version::parse("1.0.0").unwrap()));
        assert!(req.satisfied_by(&Version::parse("2.0").unwrap()));
        assert!(!req.satisfied_by(&Version::parse("0.9.9").unwrap()));
    }

    // ========== Less Than Or Equal ==========

    #[test]
    fn less_than_or_equal() {
        let req = Requirement::parse("<= 2.0").unwrap();
        assert!(req.satisfied_by(&Version::parse("2.0").unwrap()));
        assert!(req.satisfied_by(&Version::parse("1.0").unwrap()));
        assert!(!req.satisfied_by(&Version::parse("2.0.1").unwrap()));
    }

    // ========== Pessimistic Operator (~>) ==========

    #[test]
    fn pessimistic_two_segments() {
        // ~> 2.3 means >= 2.3, < 3.0
        let req = Requirement::parse("~> 2.3").unwrap();
        assert!(req.satisfied_by(&Version::parse("2.3").unwrap()));
        assert!(req.satisfied_by(&Version::parse("2.5").unwrap()));
        assert!(req.satisfied_by(&Version::parse("2.9.9").unwrap()));
        assert!(!req.satisfied_by(&Version::parse("3.0").unwrap()));
        assert!(!req.satisfied_by(&Version::parse("2.2").unwrap()));
    }

    #[test]
    fn pessimistic_three_segments() {
        // ~> 2.3.0 means >= 2.3.0, < 2.4.0
        let req = Requirement::parse("~> 2.3.0").unwrap();
        assert!(req.satisfied_by(&Version::parse("2.3.0").unwrap()));
        assert!(req.satisfied_by(&Version::parse("2.3.5").unwrap()));
        assert!(req.satisfied_by(&Version::parse("2.3.99").unwrap()));
        assert!(!req.satisfied_by(&Version::parse("2.4.0").unwrap()));
        assert!(!req.satisfied_by(&Version::parse("2.2.9").unwrap()));
    }

    #[test]
    fn pessimistic_three_segments_nonzero() {
        // ~> 2.3.18 means >= 2.3.18, < 2.4.0
        let req = Requirement::parse("~> 2.3.18").unwrap();
        assert!(req.satisfied_by(&Version::parse("2.3.18").unwrap()));
        assert!(req.satisfied_by(&Version::parse("2.3.20").unwrap()));
        assert!(!req.satisfied_by(&Version::parse("2.3.17").unwrap()));
        assert!(!req.satisfied_by(&Version::parse("2.4.0").unwrap()));
    }

    #[test]
    fn pessimistic_single_segment() {
        // ~> 2 means >= 2, < 3
        let req = Requirement::parse("~> 2").unwrap();
        assert!(req.satisfied_by(&Version::parse("2.0").unwrap()));
        assert!(req.satisfied_by(&Version::parse("2.9.9").unwrap()));
        assert!(!req.satisfied_by(&Version::parse("3.0").unwrap()));
        assert!(!req.satisfied_by(&Version::parse("1.9").unwrap()));
    }

    #[test]
    fn pessimistic_four_segments() {
        // ~> 1.2.3.4 means >= 1.2.3.4, < 1.2.4.0
        let req = Requirement::parse("~> 1.2.3.4").unwrap();
        assert!(req.satisfied_by(&Version::parse("1.2.3.4").unwrap()));
        assert!(req.satisfied_by(&Version::parse("1.2.3.99").unwrap()));
        assert!(!req.satisfied_by(&Version::parse("1.2.4.0").unwrap()));
        assert!(!req.satisfied_by(&Version::parse("1.2.3.3").unwrap()));
    }

    // ========== Compound Requirements ==========

    #[test]
    fn compound_range() {
        let req = Requirement::parse(">= 1.0, < 2.0").unwrap();
        assert!(req.satisfied_by(&Version::parse("1.0").unwrap()));
        assert!(req.satisfied_by(&Version::parse("1.5").unwrap()));
        assert!(req.satisfied_by(&Version::parse("1.9.9").unwrap()));
        assert!(!req.satisfied_by(&Version::parse("0.9").unwrap()));
        assert!(!req.satisfied_by(&Version::parse("2.0").unwrap()));
    }

    #[test]
    fn compound_with_exclusion() {
        let req = Requirement::parse(">= 1.0, < 2.0, != 1.5").unwrap();
        assert!(req.satisfied_by(&Version::parse("1.0").unwrap()));
        assert!(req.satisfied_by(&Version::parse("1.4.9").unwrap()));
        assert!(req.satisfied_by(&Version::parse("1.5.1").unwrap()));
        assert!(!req.satisfied_by(&Version::parse("1.5").unwrap()));
        assert!(!req.satisfied_by(&Version::parse("2.0").unwrap()));
    }

    // ========== Real-world Advisory Patterns ==========

    #[test]
    fn advisory_patched_versions_pattern() {
        // From a typical advisory:
        // patched_versions:
        //   - "~> 0.1.42"
        //   - "~> 0.2.42"
        //   - ">= 1.0.0"

        let patch1 = Requirement::parse("~> 0.1.42").unwrap();
        let patch2 = Requirement::parse("~> 0.2.42").unwrap();
        let patch3 = Requirement::parse(">= 1.0.0").unwrap();

        let is_patched = |v: &str| -> bool {
            let ver = Version::parse(v).unwrap();
            patch1.satisfied_by(&ver) || patch2.satisfied_by(&ver) || patch3.satisfied_by(&ver)
        };

        // Patched versions
        assert!(is_patched("0.1.42"));
        assert!(is_patched("0.1.50"));
        assert!(is_patched("0.2.42"));
        assert!(is_patched("0.2.99"));
        assert!(is_patched("1.0.0"));
        assert!(is_patched("2.0.0"));

        // Vulnerable versions
        assert!(!is_patched("0.1.0"));
        assert!(!is_patched("0.1.41"));
        assert!(!is_patched("0.2.0"));
        assert!(!is_patched("0.2.41"));
        assert!(!is_patched("0.3.0")); // not covered by ~> 0.2.42 (which is < 0.3.0)
        assert!(!is_patched("0.9.0"));
    }

    #[test]
    fn advisory_unaffected_versions_pattern() {
        // unaffected_versions:
        //   - "< 0.1.0"
        let unaffected = Requirement::parse("< 0.1.0").unwrap();

        assert!(unaffected.satisfied_by(&Version::parse("0.0.9").unwrap()));
        assert!(unaffected.satisfied_by(&Version::parse("0.0.1").unwrap()));
        assert!(!unaffected.satisfied_by(&Version::parse("0.1.0").unwrap()));
        assert!(!unaffected.satisfied_by(&Version::parse("0.2.0").unwrap()));
    }

    #[test]
    fn vulnerability_check_full() {
        // Simulating the full vulnerability check logic from advisory.rb
        let patched: Vec<Requirement> = vec![
            Requirement::parse("~> 0.1.42").unwrap(),
            Requirement::parse("~> 0.2.42").unwrap(),
            Requirement::parse(">= 1.0.0").unwrap(),
        ];
        let unaffected: Vec<Requirement> = vec![Requirement::parse("< 0.1.0").unwrap()];

        let is_patched = |v: &Version| -> bool { patched.iter().any(|req| req.satisfied_by(v)) };
        let is_unaffected =
            |v: &Version| -> bool { unaffected.iter().any(|req| req.satisfied_by(v)) };
        let is_vulnerable = |v: &str| -> bool {
            let ver = Version::parse(v).unwrap();
            !is_patched(&ver) && !is_unaffected(&ver)
        };

        // Unaffected (too old to be affected)
        assert!(!is_vulnerable("0.0.9"));

        // Patched
        assert!(!is_vulnerable("0.1.42"));
        assert!(!is_vulnerable("1.0.0"));
        assert!(!is_vulnerable("2.0.0"));

        // Vulnerable
        assert!(is_vulnerable("0.1.0"));
        assert!(is_vulnerable("0.1.41"));
        assert!(is_vulnerable("0.2.0"));
        assert!(is_vulnerable("0.2.41"));
        assert!(is_vulnerable("0.3.0"));
    }

    // ========== Display ==========

    #[test]
    fn display_single_constraint() {
        let req = Requirement::parse("~> 1.2.3").unwrap();
        assert_eq!(req.to_string(), "~> 1.2.3");
    }

    #[test]
    fn display_compound() {
        let req = Requirement::parse(">= 1.0, < 2.0").unwrap();
        assert_eq!(req.to_string(), ">= 1.0, < 2.0");
    }
}
