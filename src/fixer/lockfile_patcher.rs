use thiserror::Error;

use super::version_resolver::FixSuggestion;

#[derive(Debug, Error)]
pub enum PatchError {
    #[error("gem '{name}' not found in lockfile")]
    GemNotFound { name: String },
}

/// Patch a Gemfile.lock's raw text, replacing vulnerable gem versions with fixed versions.
///
/// Only modifies spec lines (indent=4) within GEM/GIT/PATH sections.
/// Preserves platform suffixes, formatting, and all other content.
///
/// Returns the patched content and a list of gem names that were actually modified.
pub fn patch_lockfile(content: &str, fixes: &[FixSuggestion]) -> (String, Vec<String>) {
    if fixes.is_empty() {
        return (content.to_string(), Vec::new());
    }

    let mut patched_names = Vec::new();
    let mut output = String::with_capacity(content.len());

    for line in content.lines() {
        if let Some(patched_line) = try_patch_spec_line(line, fixes) {
            output.push_str(&patched_line);
            // Extract gem name from the patched line
            if let Some(name) = extract_gem_name(line)
                && !patched_names.contains(&name)
            {
                patched_names.push(name);
            }
        } else {
            output.push_str(line);
        }
        output.push('\n');
    }

    // Preserve whether original content ended with newline
    if !content.ends_with('\n') && output.ends_with('\n') {
        output.pop();
    }

    (output, patched_names)
}

/// Try to patch a single spec line. Returns Some(patched_line) if matched, None otherwise.
///
/// Matches lines like:
///   `    nokogiri (1.13.10)`
///   `    nokogiri (1.13.10-x86_64-linux)`
fn try_patch_spec_line(line: &str, fixes: &[FixSuggestion]) -> Option<String> {
    // Spec lines have exactly 4 spaces indent
    if !line.starts_with("    ") || line.starts_with("      ") {
        return None;
    }

    let trimmed = line.trim_start();

    // Must have format: `name (version)` or `name (version-platform)`
    let paren_start = trimmed.find('(')?;
    let paren_end = trimmed.find(')')?;
    if paren_end <= paren_start {
        return None;
    }

    let gem_name = trimmed[..paren_start].trim();
    let version_platform = &trimmed[paren_start + 1..paren_end];

    // Find if this gem has a fix
    let fix = fixes.iter().find(|f| f.name == gem_name)?;

    // Split version from platform suffix
    let (old_version, platform) = split_version_platform(version_platform);

    // Only patch if the old version matches (safety check)
    if old_version != fix.current_version {
        return None;
    }

    let new_version = fix.resolved_version.to_string();
    let new_version_platform = match platform {
        Some(p) => format!("{}-{}", new_version, p),
        None => new_version,
    };

    // Reconstruct the line preserving original indentation
    let indent = &line[..line.len() - line.trim_start().len()];
    Some(format!("{}{} ({})", indent, gem_name, new_version_platform))
}

/// Split "1.13.10-x86_64-linux" into ("1.13.10", Some("x86_64-linux")).
fn split_version_platform(input: &str) -> (&str, Option<&str>) {
    // Known arch prefixes that start platform suffixes
    let arch_prefixes = ["x86_64-", "x86-", "x64-", "arm64-", "aarch64-", "arm-"];
    let keyword_platforms = ["java", "jruby", "universal-"];

    for prefix in &arch_prefixes {
        if let Some(pos) = input.find(prefix)
            && pos > 0
            && input.as_bytes()[pos - 1] == b'-'
        {
            return (&input[..pos - 1], Some(&input[pos..]));
        }
    }

    for kw in &keyword_platforms {
        if let Some(pos) = input.find(kw)
            && pos > 0
            && input.as_bytes()[pos - 1] == b'-'
        {
            return (&input[..pos - 1], Some(&input[pos..]));
        }
    }

    (input, None)
}

fn extract_gem_name(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let paren_start = trimmed.find('(')?;
    Some(trimmed[..paren_start].trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::Version;

    fn make_fix(name: &str, current: &str, resolved: &str) -> FixSuggestion {
        FixSuggestion {
            name: name.to_string(),
            current_version: current.to_string(),
            resolved_version: Version::parse(resolved).unwrap(),
            advisory_ids: vec![],
        }
    }

    #[test]
    fn basic_version_replacement() {
        let content = "\
GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.13.10)
      mini_portile2 (~> 2.8.0)

PLATFORMS
  ruby

DEPENDENCIES
  nokogiri
";
        let fixes = vec![make_fix("nokogiri", "1.13.10", "1.14.0")];
        let (patched, names) = patch_lockfile(content, &fixes);
        assert!(patched.contains("    nokogiri (1.14.0)"));
        assert!(!patched.contains("1.13.10"));
        assert_eq!(names, vec!["nokogiri"]);
    }

    #[test]
    fn preserves_platform_suffix() {
        let content = "\
GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.13.10-x86_64-linux)
";
        let fixes = vec![make_fix("nokogiri", "1.13.10", "1.14.0")];
        let (patched, _) = patch_lockfile(content, &fixes);
        assert!(patched.contains("    nokogiri (1.14.0-x86_64-linux)"));
    }

    #[test]
    fn preserves_musl_platform_suffix() {
        let content = "\
GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.19.1-aarch64-linux-musl)
";
        let fixes = vec![make_fix("nokogiri", "1.19.1", "1.19.2")];
        let (patched, _) = patch_lockfile(content, &fixes);
        assert!(patched.contains("    nokogiri (1.19.2-aarch64-linux-musl)"));
    }

    #[test]
    fn multiple_platform_variants_all_updated() {
        let content = "\
GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.13.10)
    nokogiri (1.13.10-x86_64-linux)
    nokogiri (1.13.10-arm64-darwin)
";
        let fixes = vec![make_fix("nokogiri", "1.13.10", "1.14.0")];
        let (patched, names) = patch_lockfile(content, &fixes);
        assert!(patched.contains("    nokogiri (1.14.0)"));
        assert!(patched.contains("    nokogiri (1.14.0-x86_64-linux)"));
        assert!(patched.contains("    nokogiri (1.14.0-arm64-darwin)"));
        // Name should appear only once in the list
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn does_not_modify_dependency_lines() {
        let content = "\
GEM
  remote: https://rubygems.org/
  specs:
    actionpack (3.2.10)
      activemodel (= 3.2.10)
";
        let fixes = vec![make_fix("actionpack", "3.2.10", "5.2.8")];
        let (patched, _) = patch_lockfile(content, &fixes);
        assert!(patched.contains("    actionpack (5.2.8)"));
        // Dependency line (6-space indent) should NOT be modified
        assert!(patched.contains("      activemodel (= 3.2.10)"));
    }

    #[test]
    fn does_not_modify_dependencies_section() {
        let content = "\
DEPENDENCIES
  actionpack
  nokogiri (~> 1.13)
";
        let fixes = vec![make_fix("nokogiri", "1.13.10", "1.14.0")];
        let (patched, names) = patch_lockfile(content, &fixes);
        assert_eq!(patched, content);
        assert!(names.is_empty());
    }

    #[test]
    fn empty_fixes_returns_original() {
        let content = "GEM\n  specs:\n    test (1.0)\n";
        let (patched, names) = patch_lockfile(content, &[]);
        assert_eq!(patched, content);
        assert!(names.is_empty());
    }

    #[test]
    fn gem_not_in_lockfile_skipped() {
        let content = "GEM\n  specs:\n    rack (2.0.0)\n";
        let fixes = vec![make_fix("nonexistent", "1.0", "2.0")];
        let (patched, names) = patch_lockfile(content, &fixes);
        assert_eq!(patched, content);
        assert!(names.is_empty());
    }

    #[test]
    fn version_mismatch_not_patched() {
        let content = "GEM\n  specs:\n    rack (2.0.0)\n";
        let fixes = vec![make_fix("rack", "1.0.0", "2.0.0")]; // wrong current version
        let (patched, names) = patch_lockfile(content, &fixes);
        assert_eq!(patched, content);
        assert!(names.is_empty());
    }

    #[test]
    fn java_platform_preserved() {
        let content = "GEM\n  specs:\n    jruby-openssl (9.2.14.0-java)\n";
        let fixes = vec![make_fix("jruby-openssl", "9.2.14.0", "9.2.15.0")];
        let (patched, _) = patch_lockfile(content, &fixes);
        assert!(patched.contains("    jruby-openssl (9.2.15.0-java)"));
    }

    #[test]
    fn split_version_platform_plain() {
        let (v, p) = split_version_platform("1.13.10");
        assert_eq!(v, "1.13.10");
        assert_eq!(p, None);
    }

    #[test]
    fn split_version_platform_linux() {
        let (v, p) = split_version_platform("1.13.10-x86_64-linux");
        assert_eq!(v, "1.13.10");
        assert_eq!(p, Some("x86_64-linux"));
    }

    #[test]
    fn split_version_platform_musl() {
        let (v, p) = split_version_platform("1.19.1-aarch64-linux-musl");
        assert_eq!(v, "1.19.1");
        assert_eq!(p, Some("aarch64-linux-musl"));
    }

    #[test]
    fn split_version_platform_java() {
        let (v, p) = split_version_platform("9.2.14.0-java");
        assert_eq!(v, "9.2.14.0");
        assert_eq!(p, Some("java"));
    }
}
