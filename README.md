# gem-audit

[![CI](https://github.com/7a6163/gem-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/7a6163/gem-audit/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/7a6163/gem-audit/graph/badge.svg)](https://codecov.io/gh/7a6163/gem-audit)
[![Crates.io](https://img.shields.io/crates/v/gem-audit)](https://crates.io/crates/gem-audit)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE.md)

Ultra-fast, standalone security auditor for [Bundler] dependencies, written in Rust.

A security auditor for `Gemfile.lock` inspired by [bundler-audit], compiled to a
single static binary with zero runtime dependencies -- no Ruby, no Bundler, no
gem install required.

## Features

* Checks for vulnerable versions of gems in `Gemfile.lock`.
* Checks the Ruby interpreter version against known CVEs.
* Checks for insecure gem sources (`http://` and `git://`).
* Allows ignoring specific advisories via CLI flags or a configuration file.
* Filters by severity threshold (`--severity`).
* Warns when the advisory database is stale (`--max-db-age`).
* Strict mode treats parse/load warnings as errors (`--strict`).
* Semantic exit codes for CI/CD integration (0/1/2/3).
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

Vulnerabilities found! (1 unpatched gem)
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

Only report high and critical vulnerabilities:

```
$ gem-audit check --severity high
```

Warn if the advisory database is older than 7 days:

```
$ gem-audit check --max-db-age 7
```

Fail in CI if the database is stale:

```
$ gem-audit check --max-db-age 7 --fail-on-stale
```

Treat parse/load warnings as errors:

```
$ gem-audit check --strict
```

Show remediation suggestions (dry-run, no files modified):

```
$ gem-audit check --fix
```

Use in CI (always update the advisory database before checking):

```
$ gem-audit check --update
```

A minimal GitHub Actions example:

```yaml
- name: Audit gems
  run: gem-audit check --update
```

For stricter CI enforcement — fail if the database couldn't be updated or is stale:

```yaml
- name: Audit gems
  run: gem-audit check --update --max-db-age 1 --fail-on-stale
```

To use the Docker image in GitLab CI, use the CI cache to store the advisory
database in a writable directory. This avoids git locking issues that can occur
on container overlay filesystems:

```yaml
audit:
  image:
    name: ghcr.io/7a6163/gem-audit
    entrypoint: [""]
  variables:
    GEM_AUDIT_DB: "$CI_PROJECT_DIR/.ruby-advisory-db"
  cache:
    key: ruby-advisory-db
    paths:
      - .ruby-advisory-db/
  script:
    - gem-audit check --update
```

The first run clones the advisory database into the cache. Subsequent runs
restore it from cache and fetch only the latest changes.

The Ruby interpreter version from the `RUBY VERSION` section is also checked:

```
$ gem-audit
      Engine: ruby
     Version: 2.6.0
         CVE: CVE-2021-31810
 Criticality: Medium
         URL: https://www.ruby-lang.org/en/news/2021/07/07/...
       Title: Trusting FTP PASV responses vulnerability in Net::FTP
    Solution: upgrade Ruby to '>= 3.0.2', '~> 2.7.4', '~> 2.6.8'

Vulnerabilities found! (1 vulnerable Ruby version)
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
| `-S`, `--severity <LEVEL>`  | Minimum severity: `none`, `low`, `medium`, `high`, `critical` |
| `--max-db-age <DAYS>`       | Warn if the advisory database is older than DAYS days |
| `--fail-on-stale`           | Exit with code 3 if the database is stale  |
| `--strict`                  | Treat parse/load warnings as errors (exit code 2) |
| `--fix`                     | Show remediation suggestions for vulnerable gems   |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | No vulnerabilities found |
| `1`  | Vulnerabilities found |
| `2`  | Tool error (missing files, parse failures, `--strict` violations) |
| `3`  | Advisory database is stale (`--fail-on-stale`) |

## Configuration File

gem-audit supports a per-project configuration file (`.gem-audit.yml`):

```yaml
---
ignore:
  - CVE-2020-1234
  - GHSA-xxxx-yyyy-zzzz
max_db_age_days: 7
```

* `ignore:` \[Array\<String\>\] - Advisory IDs to ignore (CVE, GHSA, or OSVDB).
* `max_db_age_days:` \[Integer\] - Warn if the database is older than this many days. CLI `--max-db-age` overrides this value.

The legacy `.bundler-audit.yml` file name is also supported for backward
compatibility.

You can specify a custom config file path:

```
$ gem-audit check --config custom-audit.yml
```

CLI `--ignore` flags take precedence over the configuration file.

## GitHub Actions

A dedicated [gem-audit-action] is available on the GitHub Marketplace:

```yaml
- uses: 7a6163/gem-audit-action@v1
```

Or use the binary directly in your workflow:

### Basic check

```yaml
name: Security Audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: 7a6163/gem-audit-action@v1
```

### Severity threshold

Only fail on high and critical vulnerabilities:

```yaml
      - uses: 7a6163/gem-audit-action@v1
        with:
          severity: high
```

### Strict mode with fresh database

```yaml
      - uses: 7a6163/gem-audit-action@v1
        with:
          strict: true
          max-db-age: 7
          fail-on-stale: true
```

### JSON report as artifact

```yaml
      - uses: 7a6163/gem-audit-action@v1
        with:
          format: json
          output: audit-report.json
        continue-on-error: true

      - uses: actions/upload-artifact@v7
        with:
          name: audit-report
          path: audit-report.json
```

[gem-audit-action]: https://github.com/7a6163/gem-audit-action

## Docker

A Docker image is available for running gem-audit in any CI environment:

```
$ docker build -t gem-audit .
$ docker run --rm -v $(pwd):/workspace gem-audit check
```

The image uses `gcr.io/distroless/cc-debian13:debug` as the runtime base.
The advisory database is downloaded on first run and stored in `/db` inside
the container. Mount a volume or use a CI cache to persist it across runs.

### CI Examples

**GitLab CI:**

```yaml
gem-audit:
  image: ghcr.io/7a6163/gem-audit:latest
  script:
    - gem-audit check
```

**CircleCI:**

```yaml
jobs:
  gem-audit:
    docker:
      - image: ghcr.io/7a6163/gem-audit:latest
    steps:
      - checkout
      - run: gem-audit check
```

**Bitbucket Pipelines:**

```yaml
pipelines:
  default:
    - step:
        name: gem-audit
        image: ghcr.io/7a6163/gem-audit:latest
        script:
          - gem-audit check
```

**Drone CI:**

```yaml
steps:
  - name: gem-audit
    image: ghcr.io/7a6163/gem-audit:latest
    commands:
      - gem-audit check
```

**Azure Pipelines:**

```yaml
jobs:
  - job: gem_audit
    container: ghcr.io/7a6163/gem-audit:latest
    steps:
      - checkout: self
      - script: gem-audit check
```

## Performance

Benchmarked with [hyperfine] on Apple M-series, comparing against Ruby bundler-audit 0.9.2:

| Benchmark | gem-audit (Rust) | bundler-audit (Ruby) | Speedup |
|-----------|-----------------|----------------------|---------|
| check (unpatched gems) | 7.0 ms | 216.5 ms | **~31x** |
| check (secure, no vulns) | 16.6 ms | 250.2 ms | **~15x** |
| startup (`version`) | 4.6 ms | 188.4 ms | **~41x** |

Run the benchmark yourself:

```
$ ./benchmarks/bench.sh
```

## Comparison with bundler-audit

gem-audit is a Rust reimplementation inspired by [bundler-audit] v0.9.x.
Both use the same [ruby-advisory-db] and produce equivalent output.

### Feature comparison

| Feature | gem-audit | bundler-audit |
|---------|-----------|---------------|
| Language | Rust | Ruby |
| Runtime dependencies | **None** (single static binary) | Ruby, Bundler, Git |
| Advisory database | [ruby-advisory-db] | [ruby-advisory-db] |
| Git implementation | [gix] (pure Rust) | System Git CLI |
| Vulnerability check | Yes | Yes |
| Ruby version check | Yes | No (see [ruby_audit]) |
| Insecure source check | Yes | Yes |
| Ignore advisories | `--ignore` + config file | `--ignore` + config file |
| Output formats | Text, JSON | Text, JSON |
| Output to file | `--output` | `--output` |
| Severity filtering | `--severity` | No |
| Stale DB warning | `--max-db-age` | No |
| Fail on stale DB | `--fail-on-stale` | No |
| Strict mode | `--strict` | No |
| Exit codes | 0 / 1 / 2 / 3 (semantic) | 0 / 1 |
| DB statistics | `gem-audit stats` | No |
| Configuration file | `.gem-audit.yml` | `.bundler-audit.yml` |
| Backward-compatible config | `.bundler-audit.yml` supported | — |
| Rake integration | No | Yes |
| GitHub Action | [gem-audit-action] | Community actions |
| Performance | ~7–17 ms | ~190–250 ms |

### Why choose gem-audit?

* **Zero dependencies** -- no Ruby, Bundler, or Git required. Drop a single binary into any CI image.
* **15-41x faster** -- finishes in milliseconds, ideal for pre-commit hooks and fast CI pipelines.
* **Ruby version scanning** -- checks the interpreter version against CVEs, built-in (no extra gem like [ruby_audit] needed).
* **Severity filtering** -- only fail on `high` or `critical` vulnerabilities with `--severity`.
* **Database freshness** -- `--max-db-age` and `--fail-on-stale` ensure your advisory data is never outdated.
* **Strict mode** -- treat parse/load warnings as errors for stricter CI policies.
* **Richer exit codes** -- distinguish between vulnerabilities (1), tool errors (2), and stale database (3).

### Why choose bundler-audit?

* **Rake integration** -- useful if your build is driven by Rake tasks.
* **Ruby ecosystem** -- installs via `gem install bundler-audit`, no extra toolchain needed if Ruby is already present.

## Architecture

```
src/
  version/            # RubyGems version parsing and comparison
    gem_version.rs    # Gem::Version semantics (segments, ordering, bump)
    requirement.rs    # Gem::Requirement with all 7 operators (=, !=, >, <, >=, <=, ~>)
  lockfile/           # Gemfile.lock parser
    parser.rs         # State-machine parser with indentation tracking
    ruby_version.rs   # Ruby interpreter version parser (engine + patchlevel stripping)
  advisory/           # Advisory database
    model.rs          # Advisory YAML deserialization, vulnerability checking, CVSS
    database.rs       # Database clone/update via gix, advisory enumeration
  scanner.rs          # Ties lockfile + database; source, spec & Ruby scanning
  configuration.rs    # .gem-audit.yml loading and validation
  format/             # Output formatters
    text.rs           # Human-readable text with ANSI colors
    json.rs           # JSON output with serde_json
  main.rs             # CLI (clap)
```

## License

MIT. See [LICENSE.md](LICENSE.md) for details.

[Bundler]: https://bundler.io
[bundler-audit]: https://github.com/rubysec/bundler-audit
[ruby_audit]: https://github.com/civisanalytics/ruby_audit
[ruby-advisory-db]: https://github.com/rubysec/ruby-advisory-db
[gix]: https://github.com/Byron/gitoxide
[hyperfine]: https://github.com/sharkdp/hyperfine
