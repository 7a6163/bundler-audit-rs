use std::cmp::Ordering;
use std::fmt;

/// A segment of a gem version string.
///
/// Each segment is either an integer (e.g., `1`, `42`) or a string (e.g., `"alpha"`, `"rc"`).
/// When comparing: integer segments are always greater than string segments.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Segment {
    Numeric(u64),
    String(String),
}

impl PartialOrd for Segment {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Segment {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Segment::Numeric(a), Segment::Numeric(b)) => a.cmp(b),
            (Segment::String(a), Segment::String(b)) => a.cmp(b),
            // Integer is always greater than string
            (Segment::Numeric(_), Segment::String(_)) => Ordering::Greater,
            (Segment::String(_), Segment::Numeric(_)) => Ordering::Less,
        }
    }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Segment::Numeric(n) => write!(f, "{}", n),
            Segment::String(s) => write!(f, "{}", s),
        }
    }
}

/// Represents a RubyGems version with full semantic compatibility.
///
/// Implements the same parsing and comparison rules as Ruby's `Gem::Version`:
/// - Dot-separated segments (numeric and string)
/// - Trailing zeros are ignored in comparisons (`1.0 == 1.0.0`)
/// - String segments denote pre-release versions
/// - Pre-release versions sort before their release counterparts
///
/// # Examples
/// ```
/// use bundler_audit::version::Version;
///
/// let v1 = Version::parse("1.2.3").unwrap();
/// let v2 = Version::parse("1.2.4").unwrap();
/// assert!(v1 < v2);
///
/// let pre = Version::parse("1.0.0.alpha").unwrap();
/// let release = Version::parse("1.0.0").unwrap();
/// assert!(pre < release);
/// ```
#[derive(Debug, Clone, Eq)]
pub struct Version {
    segments: Vec<Segment>,
    original: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionError {
    Empty,
    InvalidCharacter(char),
    InvalidFormat(String),
}

impl fmt::Display for VersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VersionError::Empty => write!(f, "empty version string"),
            VersionError::InvalidCharacter(c) => write!(f, "invalid character in version: '{}'", c),
            VersionError::InvalidFormat(s) => write!(f, "invalid version format: '{}'", s),
        }
    }
}

impl std::error::Error for VersionError {}

impl Version {
    /// Parse a version string into a `Version`.
    ///
    /// Follows RubyGems parsing rules:
    /// - Segments are split by `.`
    /// - Within each segment, numeric and alphabetic parts are separated
    /// - Leading zeros in numeric segments are stripped
    /// - Hyphens are converted to `.pre.`
    /// - Empty string becomes version "0"
    pub fn parse(input: &str) -> Result<Self, VersionError> {
        let input = input.trim();

        if input.is_empty() {
            return Ok(Version {
                segments: vec![Segment::Numeric(0)],
                original: "0".to_string(),
            });
        }

        // Validate characters: only allow alphanumeric, dots, and hyphens
        for c in input.chars() {
            if !c.is_ascii_alphanumeric() && c != '.' && c != '-' {
                return Err(VersionError::InvalidCharacter(c));
            }
        }

        // Replace hyphens with .pre.
        let normalized = input.replace('-', ".pre.");

        let segments = parse_segments(&normalized)?;

        if segments.is_empty() {
            return Err(VersionError::InvalidFormat(input.to_string()));
        }

        Ok(Version {
            segments,
            original: input.to_string(),
        })
    }

    /// Returns true if this version is a pre-release.
    ///
    /// A version is pre-release if any of its segments is a string.
    pub fn is_prerelease(&self) -> bool {
        self.segments.iter().any(|s| matches!(s, Segment::String(_)))
    }

    /// Bump this version: drop the last segment and increment the new last segment.
    ///
    /// This is equivalent to Ruby's `Gem::Version#bump`:
    /// - `1.2.3.bump()` -> `1.3`
    /// - `1.0.bump()` -> `2`
    /// - `1.bump()` -> `2`
    pub fn bump(&self) -> Version {
        // Ruby's Gem::Version#bump algorithm:
        // 1. Copy segments
        // 2. Pop while any segment is a String (remove all string segments from end)
        // 3. Pop one more if more than 1 segment remains
        // 4. Increment the last segment
        let mut new_segments = self.segments.clone();

        // Remove trailing string segments
        while new_segments
            .last()
            .is_some_and(|s| matches!(s, Segment::String(_)))
        {
            new_segments.pop();
        }

        // Drop the last numeric segment if more than one remains
        if new_segments.len() > 1 {
            new_segments.pop();
        }

        // Increment the last segment
        if let Some(Segment::Numeric(n)) = new_segments.last_mut() {
            *n += 1;
        }

        if new_segments.is_empty() {
            new_segments.push(Segment::Numeric(1));
        }

        let original = new_segments
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(".");

        Version {
            segments: new_segments,
            original,
        }
    }

    /// Returns the segments of this version.
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }
}

/// Parse the normalized version string into segments.
fn parse_segments(input: &str) -> Result<Vec<Segment>, VersionError> {
    let mut segments = Vec::new();

    for part in input.split('.') {
        if part.is_empty() {
            continue;
        }

        // Within each dot-separated part, split numeric and alphabetic runs.
        // e.g., "3rc4" -> [Numeric(3), String("rc"), Numeric(4)]
        let mut chars = part.chars().peekable();
        while chars.peek().is_some() {
            let first = *chars.peek().unwrap();
            if first.is_ascii_digit() {
                let mut num_str = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_ascii_digit() {
                        num_str.push(c);
                        chars.next();
                    } else {
                        break;
                    }
                }
                let n: u64 = num_str.parse().map_err(|_| {
                    VersionError::InvalidFormat(format!("numeric overflow: {}", num_str))
                })?;
                segments.push(Segment::Numeric(n));
            } else if first.is_ascii_alphabetic() {
                let mut s = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_ascii_alphabetic() {
                        s.push(c);
                        chars.next();
                    } else {
                        break;
                    }
                }
                segments.push(Segment::String(s));
            } else {
                return Err(VersionError::InvalidCharacter(first));
            }
        }
    }

    Ok(segments)
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        let a = &self.segments;
        let b = &other.segments;
        let max_len = a.len().max(b.len());

        for i in 0..max_len {
            let seg_a = a.get(i);
            let seg_b = b.get(i);

            let ord = match (seg_a, seg_b) {
                (Some(sa), Some(sb)) => sa.cmp(sb),
                // Missing segment is implicitly 0
                (Some(sa), None) => sa.cmp(&Segment::Numeric(0)),
                (None, Some(sb)) => Segment::Numeric(0).cmp(sb),
                (None, None) => Ordering::Equal,
            };

            if ord != Ordering::Equal {
                return ord;
            }
        }

        Ordering::Equal
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.original)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== Parsing Tests ==========

    #[test]
    fn parse_simple_version() {
        let v = Version::parse("1.2.3").unwrap();
        assert_eq!(
            v.segments,
            vec![Segment::Numeric(1), Segment::Numeric(2), Segment::Numeric(3)]
        );
    }

    #[test]
    fn parse_single_segment() {
        let v = Version::parse("5").unwrap();
        assert_eq!(v.segments, vec![Segment::Numeric(5)]);
    }

    #[test]
    fn parse_with_leading_zeros() {
        let v = Version::parse("01.02.03").unwrap();
        assert_eq!(
            v.segments,
            vec![Segment::Numeric(1), Segment::Numeric(2), Segment::Numeric(3)]
        );
    }

    #[test]
    fn parse_prerelease_with_dot() {
        let v = Version::parse("1.0.0.alpha").unwrap();
        assert_eq!(
            v.segments,
            vec![
                Segment::Numeric(1),
                Segment::Numeric(0),
                Segment::Numeric(0),
                Segment::String("alpha".to_string()),
            ]
        );
        assert!(v.is_prerelease());
    }

    #[test]
    fn parse_prerelease_inline() {
        let v = Version::parse("1.0.0rc1").unwrap();
        assert_eq!(
            v.segments,
            vec![
                Segment::Numeric(1),
                Segment::Numeric(0),
                Segment::Numeric(0),
                Segment::String("rc".to_string()),
                Segment::Numeric(1),
            ]
        );
    }

    #[test]
    fn parse_prerelease_with_hyphen() {
        let v = Version::parse("1.0.0-rc1").unwrap();
        assert_eq!(
            v.segments,
            vec![
                Segment::Numeric(1),
                Segment::Numeric(0),
                Segment::Numeric(0),
                Segment::String("pre".to_string()),
                Segment::String("rc".to_string()),
                Segment::Numeric(1),
            ]
        );
    }

    #[test]
    fn parse_empty_string() {
        let v = Version::parse("").unwrap();
        assert_eq!(v.segments, vec![Segment::Numeric(0)]);
    }

    #[test]
    fn parse_invalid_character() {
        assert!(Version::parse("1.0+build").is_err());
        assert!(Version::parse("1.0_pre1").is_err());
    }

    // ========== Comparison Tests ==========

    #[test]
    fn compare_simple_versions() {
        let v1 = Version::parse("1.0.0").unwrap();
        let v2 = Version::parse("1.0.1").unwrap();
        assert!(v1 < v2);
    }

    #[test]
    fn compare_major_versions() {
        let v1 = Version::parse("1.0.0").unwrap();
        let v2 = Version::parse("2.0.0").unwrap();
        assert!(v1 < v2);
    }

    #[test]
    fn trailing_zeros_are_equal() {
        let v1 = Version::parse("1.0").unwrap();
        let v2 = Version::parse("1.0.0").unwrap();
        let v3 = Version::parse("1.0.0.0").unwrap();
        assert_eq!(v1, v2);
        assert_eq!(v2, v3);
        assert_eq!(v1, v3);
    }

    #[test]
    fn single_segment_equals_with_trailing_zeros() {
        let v1 = Version::parse("1").unwrap();
        let v2 = Version::parse("1.0").unwrap();
        assert_eq!(v1, v2);
    }

    #[test]
    fn prerelease_less_than_release() {
        let pre = Version::parse("1.0.0.alpha").unwrap();
        let rel = Version::parse("1.0.0").unwrap();
        assert!(pre < rel);
    }

    #[test]
    fn prerelease_inline_less_than_release() {
        let pre = Version::parse("1.0.0a").unwrap();
        let rel = Version::parse("1.0.0").unwrap();
        assert!(pre < rel);
    }

    #[test]
    fn prerelease_ordering() {
        let alpha = Version::parse("1.0.0.alpha").unwrap();
        let beta = Version::parse("1.0.0.beta").unwrap();
        let rc = Version::parse("1.0.0.rc").unwrap();
        let release = Version::parse("1.0.0").unwrap();

        assert!(alpha < beta);
        assert!(beta < rc);
        assert!(rc < release);
    }

    #[test]
    fn prerelease_a_b_ordering() {
        let a = Version::parse("1.0.0a").unwrap();
        let b = Version::parse("1.0.0b").unwrap();
        assert!(a < b);
    }

    #[test]
    fn string_segment_less_than_integer() {
        // Integer segments are always greater than string segments
        let with_str = Version::parse("1.0.0.alpha").unwrap();
        let without = Version::parse("1.0.0").unwrap();
        assert!(with_str < without);

        let with_str2 = Version::parse("1.0.0a").unwrap();
        assert!(with_str2 < without);
    }

    #[test]
    fn compare_different_lengths() {
        let short = Version::parse("1.0").unwrap();
        let long = Version::parse("1.0.1").unwrap();
        assert!(short < long);
    }

    #[test]
    fn compare_year_based_versions() {
        let v1 = Version::parse("2020.1.1").unwrap();
        let v2 = Version::parse("2021.1.1").unwrap();
        assert!(v1 < v2);
    }

    // ========== Pre-release Detection ==========

    #[test]
    fn not_prerelease() {
        let v = Version::parse("1.2.3").unwrap();
        assert!(!v.is_prerelease());
    }

    #[test]
    fn is_prerelease_with_alpha() {
        let v = Version::parse("1.0.0.alpha").unwrap();
        assert!(v.is_prerelease());
    }

    #[test]
    fn is_prerelease_inline() {
        let v = Version::parse("1.0.0rc1").unwrap();
        assert!(v.is_prerelease());
    }

    #[test]
    fn four_segment_numeric_not_prerelease() {
        let v = Version::parse("1.0.0.1").unwrap();
        assert!(!v.is_prerelease());
    }

    // ========== Bump Tests ==========

    #[test]
    fn bump_three_segments() {
        let v = Version::parse("1.2.3").unwrap();
        let bumped = v.bump();
        assert_eq!(bumped, Version::parse("1.3").unwrap());
    }

    #[test]
    fn bump_two_segments() {
        let v = Version::parse("1.0").unwrap();
        let bumped = v.bump();
        assert_eq!(bumped, Version::parse("2").unwrap());
    }

    #[test]
    fn bump_single_segment() {
        let v = Version::parse("1").unwrap();
        let bumped = v.bump();
        assert_eq!(bumped, Version::parse("2").unwrap());
    }

    #[test]
    fn bump_four_segments() {
        let v = Version::parse("1.2.3.4").unwrap();
        let bumped = v.bump();
        assert_eq!(bumped, Version::parse("1.2.4").unwrap());
    }

    #[test]
    fn bump_with_trailing_zeros() {
        // Ruby: Gem::Version.new("1.0.0").bump => "1.1"
        // Segments [1,0,0] → pop last → [1,0] → increment → [1,1]
        let v = Version::parse("1.0.0").unwrap();
        let bumped = v.bump();
        assert_eq!(bumped, Version::parse("1.1").unwrap());
    }

    // ========== Display ==========

    #[test]
    fn display_preserves_original() {
        let v = Version::parse("1.2.3").unwrap();
        assert_eq!(v.to_string(), "1.2.3");
    }

    #[test]
    fn display_prerelease() {
        let v = Version::parse("1.0.0.alpha").unwrap();
        assert_eq!(v.to_string(), "1.0.0.alpha");
    }
}
