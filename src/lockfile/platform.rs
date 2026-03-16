/// Known platform patterns that appear after a hyphen in gem versions.
///
/// These are ordered from most specific to least specific to ensure
/// correct matching (e.g., "x86_64-linux-musl" before "x86_64-linux").
const PLATFORM_PATTERNS: &[&str] = &[
    "x86_64-linux-gnu",
    "x86_64-linux-musl",
    "x86_64-linux",
    "x86_64-darwin",
    "x86-linux",
    "x86-mingw32",
    "x86-mswin32",
    "x64-mingw32",
    "x64-mingw-ucrt",
    "arm64-darwin",
    "aarch64-linux-gnu",
    "aarch64-linux-musl",
    "aarch64-linux",
    "arm-linux-gnu",
    "arm-linux-musl",
    "arm-linux",
    "java",
    "jruby",
    "mswin32",
    "mingw32",
    "universal-darwin",
];

/// Split a version-platform string like "1.13.10-x86_64-linux" into
/// the version part and an optional platform suffix.
///
/// Used by both the lockfile parser and the lockfile patcher.
pub fn split_version_platform(input: &str) -> (&str, Option<&str>) {
    // Try exact suffix match against known patterns (most specific first)
    for pattern in PLATFORM_PATTERNS {
        if let Some(prefix) = input.strip_suffix(pattern)
            && let Some(version) = prefix.strip_suffix('-')
        {
            return (version, Some(pattern));
        }
    }

    // Fallback heuristic: scan for platform-like suffix after a hyphen
    for (pos, _) in input.match_indices('-') {
        let after = &input[pos + 1..];
        if after.starts_with("x86")
            || after.starts_with("x64")
            || after.starts_with("arm")
            || after.starts_with("aarch")
            || after == "java"
            || after == "jruby"
            || after.starts_with("universal")
            || after.contains("mingw")
            || after.contains("mswin")
        {
            return (&input[..pos], Some(after));
        }
    }

    (input, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_version() {
        let (v, p) = split_version_platform("1.13.10");
        assert_eq!(v, "1.13.10");
        assert_eq!(p, None);
    }

    #[test]
    fn x86_64_linux() {
        let (v, p) = split_version_platform("1.13.10-x86_64-linux");
        assert_eq!(v, "1.13.10");
        assert_eq!(p, Some("x86_64-linux"));
    }

    #[test]
    fn arm64_darwin() {
        let (v, p) = split_version_platform("1.13.10-arm64-darwin");
        assert_eq!(v, "1.13.10");
        assert_eq!(p, Some("arm64-darwin"));
    }

    #[test]
    fn java_platform() {
        let (v, p) = split_version_platform("9.2.14.0-java");
        assert_eq!(v, "9.2.14.0");
        assert_eq!(p, Some("java"));
    }

    #[test]
    fn aarch64_linux_musl() {
        let (v, p) = split_version_platform("1.19.1-aarch64-linux-musl");
        assert_eq!(v, "1.19.1");
        assert_eq!(p, Some("aarch64-linux-musl"));
    }

    #[test]
    fn x86_64_linux_musl() {
        let (v, p) = split_version_platform("1.19.1-x86_64-linux-musl");
        assert_eq!(v, "1.19.1");
        assert_eq!(p, Some("x86_64-linux-musl"));
    }

    #[test]
    fn x86_64_linux_gnu() {
        let (v, p) = split_version_platform("1.19.1-x86_64-linux-gnu");
        assert_eq!(v, "1.19.1");
        assert_eq!(p, Some("x86_64-linux-gnu"));
    }

    #[test]
    fn universal_darwin() {
        let (v, p) = split_version_platform("2.0.0-universal-darwin");
        assert_eq!(v, "2.0.0");
        assert_eq!(p, Some("universal-darwin"));
    }
}
