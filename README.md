# gem-audit

Patch-level verification for [Bundler] dependencies, rewritten in Rust.

A security auditor for `Gemfile.lock` inspired by [bundler-audit], compiled to a
single static binary with zero runtime dependencies -- no Ruby, no Bundler, no
gem install required.

## Features

* Checks for vulnerable versions of gems in `Gemfile.lock`.
* Checks for insecure gem sources (`http://` and `git://`).
* Allows ignoring specific advisories via CLI flags or a configuration file.
* Prints advisory information (CVE, GHSA, CVSS criticality, solution).
* Supports text and JSON output formats.
* Downloads and updates the [ruby-advisory-db] automatically.
* Does not require Ruby or Bundler to be installed.

## Install

### From source

```
$ cargo install --path .
```

### Build from source

```
$ git clone https://github.com/user/gem-audit.git
$ cd gem-audit
$ cargo build --release
$ ./target/release/gem-audit --version
```

## Usage

Audit a project's `Gemfile.lock`:

```
$ gem-audit
Name: activerecord
Version: 3.2.10
CVE: CVE-2015-7577
GHSA: GHSA-xrr6-3pc4-m447
Criticality: Medium
URL: https://groups.google.com/forum/#!topic/rubyonrails-security/cawsWcQ6c8g
Title: Nested attributes rejection proc bypass in Active Record
Solution: upgrade to '>= 5.0.0.beta1.1', '~> 4.2.5, >= 4.2.5.1', '~> 4.1.14, >= 4.1.14.1', '~> 3.2.22.1'

Vulnerabilities found!
```

Update the [ruby-advisory-db] before checking:

```
$ gem-audit check --update
```

Ignore specific advisories:

```
$ gem-audit check --ignore CVE-2020-1234 GHSA-xxxx-yyyy-zzzz
```

Audit a specific directory:

```
$ gem-audit check /path/to/project
```

Check a custom `Gemfile.lock` file:

```
$ gem-audit check --gemfile-lock Gemfile.custom.lock
```

Output in JSON format:

```
$ gem-audit check --format json
```

Output to a file:

```
$ gem-audit check --format json --output audit-results.json
```

## Commands

| Command    | Description                                              |
|------------|----------------------------------------------------------|
| `check`    | Check `Gemfile.lock` for insecure dependencies (default) |
| `update`   | Update the ruby-advisory-db                              |
| `download` | Download the ruby-advisory-db                            |
| `stats`    | Print ruby-advisory-db statistics                        |
| `version`  | Print the gem-audit version                              |

Running `gem-audit` with no subcommand is equivalent to `gem-audit check`.

## Check Options

| Flag                        | Description                                |
|-----------------------------|--------------------------------------------|
| `-q`, `--quiet`             | Suppress output                            |
| `-v`, `--verbose`           | Show detailed advisory descriptions        |
| `-i`, `--ignore <IDS>...`   | Advisory IDs to ignore                     |
| `-u`, `--update`            | Update the advisory database before check  |
| `-D`, `--database <PATH>`   | Path to the advisory database              |
| `-F`, `--format <FORMAT>`   | Output format: `text` (default) or `json`  |
| `-G`, `--gemfile-lock <FILE>` | Path to the Gemfile.lock file            |
| `-c`, `--config <FILE>`     | Configuration file (default: `.gem-audit.yml`) |
| `-o`, `--output <FILE>`     | Write output to a file instead of stdout   |

## Configuration File

gem-audit supports a per-project configuration file (`.gem-audit.yml`):

```yaml
---
ignore:
  - CVE-2020-1234
  - GHSA-xxxx-yyyy-zzzz
```

* `ignore:` \[Array\<String\>\] - Advisory IDs to ignore (CVE, GHSA, or OSVDB).

The legacy `.bundler-audit.yml` file name is also supported for backward
compatibility.

You can specify a custom config file path:

```
$ gem-audit check --config custom-audit.yml
```

CLI `--ignore` flags take precedence over the configuration file.

## Performance

Benchmarked with [hyperfine] on Apple M-series, comparing against Ruby bundler-audit 0.9.2:

| Benchmark | Rust | Ruby | Speedup |
|-----------|------|------|---------|
| check (unpatched gems) | 9.9 ms | 229.9 ms | **23x** |
| check (secure, no vulns) | 17.9 ms | 262.5 ms | **15x** |
| check --format json | 10.3 ms | 231.3 ms | **23x** |
| startup (version) | 6.8 ms | 198.4 ms | **29x** |

Run the benchmark yourself:

```
$ ./benchmarks/bench.sh
```

## Compatibility

This is a Rust reimplementation inspired by [bundler-audit] v0.9.x.
It uses the same [ruby-advisory-db] and produces equivalent output.

Key differences from the Ruby version:

* Single static binary -- no Ruby runtime required.
* Uses [gix] (gitoxide), a pure Rust git implementation.
* No Rake task integration (not applicable outside Ruby projects).
* No JUnit output format (text and JSON only).

## Architecture

```
src/
  version/          # RubyGems version parsing and comparison
    gem_version.rs  # Gem::Version semantics (segments, ordering, bump)
    requirement.rs  # Gem::Requirement with all 7 operators (=, !=, >, <, >=, <=, ~>)
  lockfile/         # Gemfile.lock parser
    parser.rs       # State-machine parser with indentation tracking
  advisory/         # Advisory database
    model.rs        # Advisory YAML deserialization, vulnerability checking, CVSS
    database.rs     # Database clone/update via gix, advisory enumeration
  scanner.rs        # Ties lockfile + database; source & spec scanning
  configuration.rs  # .gem-audit.yml loading and validation
  format/           # Output formatters
    text.rs         # Human-readable text with ANSI colors
    json.rs         # JSON output with serde_json
  main.rs           # CLI (clap)
```

## License

MIT. See [LICENSE.md](LICENSE.md) for details.

[Bundler]: https://bundler.io
[bundler-audit]: https://github.com/rubysec/bundler-audit
[ruby-advisory-db]: https://github.com/rubysec/ruby-advisory-db
[gix]: https://github.com/Byron/gitoxide
[hyperfine]: https://github.com/sharkdp/hyperfine
