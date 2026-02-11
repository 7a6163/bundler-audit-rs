use super::*;

/// The current section being parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Section {
    None,
    Git,
    Gem,
    Path,
    Platforms,
    Dependencies,
    RubyVersion,
    BundledWith,
}

/// Parse a Gemfile.lock string into a `Lockfile`.
pub fn parse(input: &str) -> Result<Lockfile, ParseError> {
    let mut sources: Vec<Source> = Vec::new();
    let mut specs: Vec<GemSpec> = Vec::new();
    let mut platforms: Vec<String> = Vec::new();
    let mut dependencies: Vec<Dependency> = Vec::new();
    let mut ruby_version: Option<String> = None;
    let mut bundled_with: Option<String> = None;

    let mut section = Section::None;
    let mut in_specs = false;

    // Current source being built
    let mut current_remote: Option<String> = None;
    let mut current_revision: Option<String> = None;
    let mut current_branch: Option<String> = None;
    let mut current_tag: Option<String> = None;

    // Current gem spec being built
    let mut current_spec: Option<GemSpec> = None;

    let lines: Vec<&str> = input.lines().collect();

    for (line_idx, &line) in lines.iter().enumerate() {
        let _line_number = line_idx + 1;

        // Empty line — finalize current spec if any
        if line.trim().is_empty() {
            if let Some(spec) = current_spec.take() {
                specs.push(spec);
            }
            continue;
        }

        let indent = count_indent(line);
        let trimmed = line.trim();

        // Section headers (indent == 0)
        if indent == 0 {
            // Finalize any in-progress spec
            if let Some(spec) = current_spec.take() {
                specs.push(spec);
            }
            // Finalize any in-progress source
            finalize_source(&section, &mut sources, &mut current_remote, &mut current_revision, &mut current_branch, &mut current_tag);

            in_specs = false;
            section = match trimmed {
                "GIT" => Section::Git,
                "GEM" => Section::Gem,
                "PATH" => Section::Path,
                "PLATFORMS" => Section::Platforms,
                "DEPENDENCIES" => Section::Dependencies,
                "RUBY VERSION" => Section::RubyVersion,
                "BUNDLED WITH" => Section::BundledWith,
                _ => Section::None,
            };
            continue;
        }

        match section {
            Section::Git | Section::Gem | Section::Path => {
                parse_source_line(
                    trimmed,
                    indent,
                    &section,
                    &mut in_specs,
                    &mut current_remote,
                    &mut current_revision,
                    &mut current_branch,
                    &mut current_tag,
                    &mut current_spec,
                    &mut specs,
                    sources.len(),
                );
            }
            Section::Platforms => {
                if indent >= 2 {
                    platforms.push(trimmed.to_string());
                }
            }
            Section::Dependencies => {
                if indent >= 2 {
                    dependencies.push(parse_dependency_line(trimmed));
                }
            }
            Section::RubyVersion => {
                if indent >= 2 {
                    ruby_version = Some(trimmed.to_string());
                }
            }
            Section::BundledWith => {
                if indent >= 2 {
                    bundled_with = Some(trimmed.to_string());
                }
            }
            Section::None => {}
        }
    }

    // Finalize remaining state
    if let Some(spec) = current_spec.take() {
        specs.push(spec);
    }
    finalize_source(&section, &mut sources, &mut current_remote, &mut current_revision, &mut current_branch, &mut current_tag);

    if sources.is_empty() && specs.is_empty() {
        return Err(ParseError::Empty);
    }

    Ok(Lockfile {
        sources,
        specs,
        platforms,
        dependencies,
        ruby_version,
        bundled_with,
    })
}

/// Count leading spaces in a line.
fn count_indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// Finalize the current source section and add it to the sources list.
fn finalize_source(
    section: &Section,
    sources: &mut Vec<Source>,
    current_remote: &mut Option<String>,
    current_revision: &mut Option<String>,
    current_branch: &mut Option<String>,
    current_tag: &mut Option<String>,
) {
    if let Some(remote) = current_remote.take() {
        match section {
            Section::Gem => {
                sources.push(Source::Rubygems(RubygemsSource { remote }));
            }
            Section::Git => {
                sources.push(Source::Git(GitSource {
                    remote,
                    revision: current_revision.take(),
                    branch: current_branch.take(),
                    tag: current_tag.take(),
                }));
            }
            Section::Path => {
                sources.push(Source::Path(PathSource { remote }));
            }
            _ => {}
        }
    }
    *current_revision = None;
    *current_branch = None;
    *current_tag = None;
}

/// Parse a line inside a GEM/GIT/PATH section.
#[allow(clippy::too_many_arguments)]
fn parse_source_line(
    trimmed: &str,
    indent: usize,
    _section: &Section,
    in_specs: &mut bool,
    current_remote: &mut Option<String>,
    current_revision: &mut Option<String>,
    current_branch: &mut Option<String>,
    current_tag: &mut Option<String>,
    current_spec: &mut Option<GemSpec>,
    specs: &mut Vec<GemSpec>,
    source_index: usize,
) {
    // Indent 2: attributes (remote:, revision:, specs:, branch:, tag:)
    if indent == 2 {
        if let Some(value) = trimmed.strip_prefix("remote:") {
            *current_remote = Some(value.trim().to_string());
            *in_specs = false;
        } else if let Some(value) = trimmed.strip_prefix("revision:") {
            *current_revision = Some(value.trim().to_string());
        } else if let Some(value) = trimmed.strip_prefix("branch:") {
            *current_branch = Some(value.trim().to_string());
        } else if let Some(value) = trimmed.strip_prefix("tag:") {
            *current_tag = Some(value.trim().to_string());
        } else if trimmed == "specs:" {
            *in_specs = true;
        }
        return;
    }

    if !*in_specs {
        return;
    }

    // Indent 4: gem spec entry — "name (version)" or "name (version-platform)"
    if indent == 4 {
        // Finalize previous spec
        if let Some(spec) = current_spec.take() {
            specs.push(spec);
        }

        if let Some(spec) = parse_gem_spec_line(trimmed, source_index) {
            *current_spec = Some(spec);
        }
        return;
    }

    // Indent 6: dependency of current spec — "name (constraint)" or "name"
    if indent == 6
        && let Some(spec) = current_spec
    {
        spec.dependencies.push(parse_gem_dependency(trimmed));
    }
}

/// Parse a gem spec line like "actioncable (5.2.8)" or "nokogiri (1.13.10-x86_64-linux)".
fn parse_gem_spec_line(trimmed: &str, source_index: usize) -> Option<GemSpec> {
    let (name, rest) = trimmed.split_once(' ')?;
    // rest should be "(version)" or "(version-platform)"
    let version_str = rest.strip_prefix('(')?.strip_suffix(')')?;

    let (version, platform) = parse_version_platform(version_str);

    Some(GemSpec {
        name: name.to_string(),
        version,
        platform,
        dependencies: Vec::new(),
        source_index,
    })
}

/// Split "1.13.10-x86_64-linux" into version "1.13.10" and platform "x86_64-linux".
///
/// Platform detection: if the string contains a hyphen followed by a known platform
/// pattern (like x86_64-linux, arm64-darwin, java, etc.), split there.
/// Otherwise, the entire string is the version.
fn parse_version_platform(input: &str) -> (String, Option<String>) {
    // Known platform patterns that appear after a hyphen in gem versions
    let platform_patterns = [
        "x86_64-linux",
        "x86_64-darwin",
        "x86-linux",
        "x86-mingw32",
        "x86-mswin32",
        "x64-mingw32",
        "x64-mingw-ucrt",
        "arm64-darwin",
        "aarch64-linux",
        "arm-linux",
        "java",
        "jruby",
        "mswin32",
        "mingw32",
        "universal-darwin",
    ];

    for pattern in &platform_patterns {
        if let Some(prefix) = input.strip_suffix(pattern)
            && let Some(version) = prefix.strip_suffix('-')
        {
            return (version.to_string(), Some(pattern.to_string()));
        }
    }

    // Fallback: heuristic — find the last hyphen where the part after it
    // contains non-numeric characters (likely a platform)
    // But only if the part after doesn't look like a pre-release version segment
    if let Some(pos) = input.rfind('-') {
        let after = &input[pos + 1..];
        // If after contains a known arch prefix, it's a platform
        if after.starts_with("x86")
            || after.starts_with("x64")
            || after.starts_with("arm")
            || after.starts_with("aarch")
            || after == "java"
            || after == "jruby"
            || after.starts_with("universal")
            || after.contains("mingw")
            || after.contains("mswin")
            || after.contains("linux")
            || after.contains("darwin")
        {
            return (
                input[..pos].to_string(),
                Some(after.to_string()),
            );
        }
    }

    (input.to_string(), None)
}

/// Parse a gem dependency line like "actionpack (= 5.2.8)" or "method_source" or "rack (~> 2.0, >= 2.0.8)".
fn parse_gem_dependency(trimmed: &str) -> GemDependency {
    if let Some(paren_start) = trimmed.find('(') {
        let name = trimmed[..paren_start].trim();
        let constraint = trimmed[paren_start + 1..]
            .strip_suffix(')')
            .unwrap_or(&trimmed[paren_start + 1..])
            .trim();
        GemDependency {
            name: name.to_string(),
            requirement: if constraint.is_empty() {
                None
            } else {
                Some(constraint.to_string())
            },
        }
    } else {
        GemDependency {
            name: trimmed.to_string(),
            requirement: None,
        }
    }
}

/// Parse a DEPENDENCIES line like "rails (~> 5.2)" or "jquery-rails!" or "activerecord (= 3.2.10)".
fn parse_dependency_line(trimmed: &str) -> Dependency {
    let pinned = trimmed.ends_with('!');
    let trimmed = if pinned {
        trimmed.strip_suffix('!').unwrap().trim()
    } else {
        trimmed
    };

    if let Some(paren_start) = trimmed.find('(') {
        let name = trimmed[..paren_start].trim();
        let constraint = trimmed[paren_start + 1..]
            .strip_suffix(')')
            .unwrap_or(&trimmed[paren_start + 1..])
            .trim();
        Dependency {
            name: name.to_string(),
            requirement: if constraint.is_empty() {
                None
            } else {
                Some(constraint.to_string())
            },
            pinned,
        }
    } else {
        Dependency {
            name: trimmed.to_string(),
            requirement: None,
            pinned,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== Secure Lockfile ==========

    #[test]
    fn parse_secure_lockfile() {
        let input = include_str!("../../tests/fixtures/secure/Gemfile.lock");
        let lockfile = parse(input).unwrap();

        // Should have one GEM source
        assert_eq!(lockfile.sources.len(), 1);
        assert_eq!(
            lockfile.sources[0],
            Source::Rubygems(RubygemsSource {
                remote: "https://rubygems.org/".to_string(),
            })
        );

        // Check platforms
        assert_eq!(lockfile.platforms, vec!["ruby", "x86_64-linux"]);

        // Check bundled with
        assert_eq!(lockfile.bundled_with, Some("2.3.6".to_string()));

        // Check dependencies
        assert_eq!(lockfile.dependencies.len(), 2);
        assert_eq!(lockfile.dependencies[0].name, "rails");
        assert_eq!(
            lockfile.dependencies[0].requirement,
            Some("~> 5.2".to_string())
        );
        assert!(!lockfile.dependencies[0].pinned);
    }

    #[test]
    fn parse_secure_specs() {
        let input = include_str!("../../tests/fixtures/secure/Gemfile.lock");
        let lockfile = parse(input).unwrap();

        // Check a specific gem
        let actioncable = lockfile.find_spec("actioncable").unwrap();
        assert_eq!(actioncable.version, "5.2.8");
        assert_eq!(actioncable.dependencies.len(), 3);
        assert_eq!(actioncable.dependencies[0].name, "actionpack");
        assert_eq!(
            actioncable.dependencies[0].requirement,
            Some("= 5.2.8".to_string())
        );

        // Check nokogiri with platform variant
        let nokogiri_specs = lockfile.find_specs("nokogiri");
        assert_eq!(nokogiri_specs.len(), 2);

        let nokogiri_plain = nokogiri_specs.iter().find(|s| s.platform.is_none()).unwrap();
        assert_eq!(nokogiri_plain.version, "1.13.10");
        assert_eq!(nokogiri_plain.dependencies.len(), 2);

        let nokogiri_linux = nokogiri_specs
            .iter()
            .find(|s| s.platform.as_deref() == Some("x86_64-linux"))
            .unwrap();
        assert_eq!(nokogiri_linux.version, "1.13.10");
        assert_eq!(nokogiri_linux.dependencies.len(), 1); // only racc
    }

    #[test]
    fn parse_secure_gem_count() {
        let input = include_str!("../../tests/fixtures/secure/Gemfile.lock");
        let lockfile = parse(input).unwrap();

        // Count unique gem names (some may have platform variants)
        let unique_names: std::collections::HashSet<&str> =
            lockfile.specs.iter().map(|s| s.name.as_str()).collect();

        // From the file: actioncable, actionmailer, actionpack, actionview,
        // activejob, activemodel, activerecord, activestorage, activesupport,
        // arel, builder, concurrent-ruby, crass, erubi, globalid, i18n, loofah,
        // mail, marcel, method_source, mini_mime, mini_portile2, minitest, nio4r,
        // nokogiri (x2 with platform), racc, rack, rack-test, rails,
        // rails-dom-testing, rails-html-sanitizer, railties, rake, sprockets,
        // sprockets-rails, thor, thread_safe, tzinfo, websocket-driver,
        // websocket-extensions
        assert!(unique_names.len() >= 30);
    }

    // ========== Insecure Sources Lockfile ==========

    #[test]
    fn parse_insecure_sources_lockfile() {
        let input = include_str!("../../tests/fixtures/insecure_sources/Gemfile.lock");
        let lockfile = parse(input).unwrap();

        // Should have two sources: GIT + GEM
        assert_eq!(lockfile.sources.len(), 2);

        // First source: GIT
        match &lockfile.sources[0] {
            Source::Git(git) => {
                assert_eq!(git.remote, "git://github.com/rails/jquery-rails.git");
                assert_eq!(
                    git.revision,
                    Some("a8b003d726522cf663611c114d8f0e79abf8d200".to_string())
                );
            }
            other => panic!("expected Git source, got {:?}", other),
        }

        // Second source: GEM with http (insecure)
        match &lockfile.sources[1] {
            Source::Rubygems(gem) => {
                assert_eq!(gem.remote, "http://rubygems.org/");
            }
            other => panic!("expected Rubygems source, got {:?}", other),
        }
    }

    #[test]
    fn parse_insecure_git_source_specs() {
        let input = include_str!("../../tests/fixtures/insecure_sources/Gemfile.lock");
        let lockfile = parse(input).unwrap();

        // jquery-rails comes from GIT source (index 0)
        let jquery = lockfile.find_spec("jquery-rails").unwrap();
        assert_eq!(jquery.version, "4.4.0");
        assert_eq!(jquery.source_index, 0);
        assert_eq!(jquery.dependencies.len(), 3);
    }

    #[test]
    fn parse_insecure_pinned_dependency() {
        let input = include_str!("../../tests/fixtures/insecure_sources/Gemfile.lock");
        let lockfile = parse(input).unwrap();

        let jquery_dep = lockfile
            .dependencies
            .iter()
            .find(|d| d.name == "jquery-rails")
            .unwrap();
        assert!(jquery_dep.pinned);
        assert!(jquery_dep.requirement.is_none());

        let rails_dep = lockfile
            .dependencies
            .iter()
            .find(|d| d.name == "rails")
            .unwrap();
        assert!(!rails_dep.pinned);
        assert!(rails_dep.requirement.is_none());
    }

    // ========== Unpatched Gems Lockfile ==========

    #[test]
    fn parse_unpatched_gems_lockfile() {
        let input = include_str!("../../tests/fixtures/unpatched_gems/Gemfile.lock");
        let lockfile = parse(input).unwrap();

        assert_eq!(lockfile.sources.len(), 1);
        assert_eq!(lockfile.bundled_with, Some("2.2.0".to_string()));

        let activerecord = lockfile.find_spec("activerecord").unwrap();
        assert_eq!(activerecord.version, "3.2.10");

        // DEPENDENCIES section has "activerecord (= 3.2.10)"
        assert_eq!(lockfile.dependencies.len(), 1);
        assert_eq!(lockfile.dependencies[0].name, "activerecord");
        assert_eq!(
            lockfile.dependencies[0].requirement,
            Some("= 3.2.10".to_string())
        );
    }

    // ========== Version-Platform Parsing ==========

    #[test]
    fn parse_version_platform_plain() {
        let (v, p) = parse_version_platform("1.13.10");
        assert_eq!(v, "1.13.10");
        assert_eq!(p, None);
    }

    #[test]
    fn parse_version_platform_with_linux() {
        let (v, p) = parse_version_platform("1.13.10-x86_64-linux");
        assert_eq!(v, "1.13.10");
        assert_eq!(p, Some("x86_64-linux".to_string()));
    }

    #[test]
    fn parse_version_platform_java() {
        let (v, p) = parse_version_platform("9.2.14.0-java");
        assert_eq!(v, "9.2.14.0");
        assert_eq!(p, Some("java".to_string()));
    }

    #[test]
    fn parse_version_platform_darwin() {
        let (v, p) = parse_version_platform("1.13.10-arm64-darwin");
        assert_eq!(v, "1.13.10");
        assert_eq!(p, Some("arm64-darwin".to_string()));
    }

    // ========== Dependency Line Parsing ==========

    #[test]
    fn parse_dependency_with_constraint() {
        let dep = parse_dependency_line("rails (~> 5.2)");
        assert_eq!(dep.name, "rails");
        assert_eq!(dep.requirement, Some("~> 5.2".to_string()));
        assert!(!dep.pinned);
    }

    #[test]
    fn parse_dependency_pinned() {
        let dep = parse_dependency_line("jquery-rails!");
        assert_eq!(dep.name, "jquery-rails");
        assert!(dep.requirement.is_none());
        assert!(dep.pinned);
    }

    #[test]
    fn parse_dependency_plain() {
        let dep = parse_dependency_line("rails");
        assert_eq!(dep.name, "rails");
        assert!(dep.requirement.is_none());
        assert!(!dep.pinned);
    }

    // ========== Gem Dependency Parsing ==========

    #[test]
    fn parse_gem_dep_with_constraint() {
        let dep = parse_gem_dependency("actionpack (= 5.2.8)");
        assert_eq!(dep.name, "actionpack");
        assert_eq!(dep.requirement, Some("= 5.2.8".to_string()));
    }

    #[test]
    fn parse_gem_dep_compound_constraint() {
        let dep = parse_gem_dependency("rack (~> 2.0, >= 2.0.8)");
        assert_eq!(dep.name, "rack");
        assert_eq!(dep.requirement, Some("~> 2.0, >= 2.0.8".to_string()));
    }

    #[test]
    fn parse_gem_dep_no_constraint() {
        let dep = parse_gem_dependency("method_source");
        assert_eq!(dep.name, "method_source");
        assert!(dep.requirement.is_none());
    }

    // ========== Edge Cases ==========

    #[test]
    fn parse_empty_input() {
        let result = parse("");
        assert!(result.is_err());
    }

    #[test]
    fn parse_minimal_lockfile() {
        let input = "\
GEM
  remote: https://rubygems.org/
  specs:
    rack (2.2.0)

PLATFORMS
  ruby

DEPENDENCIES
  rack
";
        let lockfile = parse(input).unwrap();
        assert_eq!(lockfile.specs.len(), 1);
        assert_eq!(lockfile.specs[0].name, "rack");
        assert_eq!(lockfile.specs[0].version, "2.2.0");
        assert_eq!(lockfile.platforms, vec!["ruby"]);
        assert_eq!(lockfile.dependencies.len(), 1);
    }

    #[test]
    fn all_specs_have_valid_source_index() {
        let input = include_str!("../../tests/fixtures/insecure_sources/Gemfile.lock");
        let lockfile = parse(input).unwrap();

        for spec in &lockfile.specs {
            assert!(
                spec.source_index < lockfile.sources.len(),
                "spec {} has source_index {} but only {} sources",
                spec.name,
                spec.source_index,
                lockfile.sources.len()
            );
        }
    }
}
