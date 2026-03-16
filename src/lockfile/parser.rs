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

/// Mutable state accumulated while parsing a source section (GEM/GIT/PATH).
struct SourceState {
    remote: Option<String>,
    revision: Option<String>,
    branch: Option<String>,
    tag: Option<String>,
    in_specs: bool,
    current_spec: Option<GemSpec>,
}

impl SourceState {
    fn new() -> Self {
        Self {
            remote: None,
            revision: None,
            branch: None,
            tag: None,
            in_specs: false,
            current_spec: None,
        }
    }

    /// Finalize the current source and push it to `sources`.
    fn finalize_source(&mut self, section: &Section, sources: &mut Vec<Source>) {
        if let Some(remote) = self.remote.take() {
            match section {
                Section::Gem => {
                    sources.push(Source::Rubygems(RubygemsSource { remote }));
                }
                Section::Git => {
                    sources.push(Source::Git(GitSource {
                        remote,
                        revision: self.revision.take(),
                        branch: self.branch.take(),
                        tag: self.tag.take(),
                    }));
                }
                Section::Path => {
                    sources.push(Source::Path(PathSource { remote }));
                }
                _ => {}
            }
        }
        self.revision = None;
        self.branch = None;
        self.tag = None;
    }

    /// Flush the current in-progress spec to `specs`.
    fn flush_spec(&mut self, specs: &mut Vec<GemSpec>) {
        if let Some(spec) = self.current_spec.take() {
            specs.push(spec);
        }
    }

    /// Parse a line inside a GEM/GIT/PATH section.
    fn parse_source_line(
        &mut self,
        trimmed: &str,
        indent: usize,
        specs: &mut Vec<GemSpec>,
        source_index: usize,
    ) {
        // Indent 2: attributes (remote:, revision:, specs:, branch:, tag:)
        if indent == 2 {
            if let Some(value) = trimmed.strip_prefix("remote:") {
                self.remote = Some(value.trim().to_string());
                self.in_specs = false;
            } else if let Some(value) = trimmed.strip_prefix("revision:") {
                self.revision = Some(value.trim().to_string());
            } else if let Some(value) = trimmed.strip_prefix("branch:") {
                self.branch = Some(value.trim().to_string());
            } else if let Some(value) = trimmed.strip_prefix("tag:") {
                self.tag = Some(value.trim().to_string());
            } else if trimmed == "specs:" {
                self.in_specs = true;
            }
            return;
        }

        if !self.in_specs {
            return;
        }

        // Indent 4: gem spec entry — "name (version)" or "name (version-platform)"
        if indent == 4 {
            self.flush_spec(specs);

            if let Some(spec) = parse_gem_spec_line(trimmed, source_index) {
                self.current_spec = Some(spec);
            }
            return;
        }

        // Indent 6: dependency of current spec — "name (constraint)" or "name"
        if indent == 6
            && let Some(spec) = &mut self.current_spec
        {
            spec.dependencies.push(parse_gem_dependency(trimmed));
        }
    }
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
    let mut state = SourceState::new();

    for line in input.lines() {
        // Empty line — finalize current spec if any
        if line.trim().is_empty() {
            state.flush_spec(&mut specs);
            continue;
        }

        let indent = count_indent(line);
        let trimmed = line.trim();

        // Section headers (indent == 0)
        if indent == 0 {
            state.flush_spec(&mut specs);
            state.finalize_source(&section, &mut sources);
            state.in_specs = false;

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
                state.parse_source_line(trimmed, indent, &mut specs, sources.len());
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
    state.flush_spec(&mut specs);
    state.finalize_source(&section, &mut sources);

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
/// Delegates to the shared `platform::split_version_platform` function.
fn parse_version_platform(input: &str) -> (String, Option<String>) {
    let (version, platform) = super::platform::split_version_platform(input);
    (version.to_string(), platform.map(String::from))
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

        let nokogiri_plain = nokogiri_specs
            .iter()
            .find(|s| s.platform.is_none())
            .unwrap();
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

    #[test]
    fn parse_version_platform_musl() {
        let (v, p) = parse_version_platform("1.19.1-aarch64-linux-musl");
        assert_eq!(v, "1.19.1");
        assert_eq!(p, Some("aarch64-linux-musl".to_string()));
    }

    #[test]
    fn parse_version_platform_x86_musl() {
        let (v, p) = parse_version_platform("1.19.1-x86_64-linux-musl");
        assert_eq!(v, "1.19.1");
        assert_eq!(p, Some("x86_64-linux-musl".to_string()));
    }

    #[test]
    fn parse_version_platform_gnu() {
        let (v, p) = parse_version_platform("1.19.1-x86_64-linux-gnu");
        assert_eq!(v, "1.19.1");
        assert_eq!(p, Some("x86_64-linux-gnu".to_string()));
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

    // ========== PATH Source ==========

    #[test]
    fn parse_path_source() {
        let input = "\
PATH
  remote: .
  specs:
    my_gem (0.1.0)

GEM
  remote: https://rubygems.org/
  specs:
    rack (2.0.0)

PLATFORMS
  ruby

DEPENDENCIES
  my_gem!
  rack
";
        let lockfile = parse(input).unwrap();
        assert_eq!(lockfile.sources.len(), 2);
        match &lockfile.sources[0] {
            Source::Path(p) => assert_eq!(p.remote, "."),
            other => panic!("expected Path source, got {:?}", other),
        }
        let my_gem = lockfile.find_spec("my_gem").unwrap();
        assert_eq!(my_gem.version, "0.1.0");
        assert_eq!(my_gem.source_index, 0);
    }

    // ========== GIT with tag ==========

    #[test]
    fn parse_git_source_with_tag() {
        let input = "\
GIT
  remote: https://github.com/foo/bar.git
  revision: abc123
  tag: v1.0.0
  specs:
    bar (1.0.0)

GEM
  remote: https://rubygems.org/
  specs:
    rack (2.0.0)

PLATFORMS
  ruby

DEPENDENCIES
  bar!
  rack
";
        let lockfile = parse(input).unwrap();
        match &lockfile.sources[0] {
            Source::Git(git) => {
                assert_eq!(git.tag, Some("v1.0.0".to_string()));
                assert_eq!(git.revision, Some("abc123".to_string()));
            }
            other => panic!("expected Git source, got {:?}", other),
        }
    }

    // ========== RUBY VERSION section ==========

    #[test]
    fn parse_ruby_version_section() {
        let input = "\
GEM
  remote: https://rubygems.org/
  specs:
    rack (2.0.0)

PLATFORMS
  ruby

DEPENDENCIES
  rack

RUBY VERSION
   ruby 3.0.0p0

BUNDLED WITH
   2.3.6
";
        let lockfile = parse(input).unwrap();
        assert_eq!(lockfile.ruby_version, Some("ruby 3.0.0p0".to_string()));
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
