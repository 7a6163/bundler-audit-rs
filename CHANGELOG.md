### 2.10.0 / 2026-04-02

#### Changed

* **Removed `download` subcommand.** The `update` subcommand now handles both
  downloading (when no database exists) and updating (when one exists).
  Previously `download` would refuse to run if the database already existed,
  causing confusion. Now `gem-audit update` is the single command for all
  database management.

#### Security

* **Replaced `serde_yml` with `yaml_serde`.** The `serde_yml` and `libyml`
  crates were flagged as unsound and unmaintained (RUSTSEC-2025-0067,
  RUSTSEC-2025-0068). Switched to `yaml_serde` 0.10, the YAML Organization's
  maintained fork of `serde_yaml`.
* **Updated `aws-lc-sys`** to 0.39.1 to resolve CRL distribution point
  scope check vulnerability (RUSTSEC-2026-0048).
* **Updated `rustls-webpki`** to 0.103.10 to resolve CRL authority matching
  bug (RUSTSEC-2026-0049).

---

### 2.9.0 / 2026-03-30

#### Fixed

* **`update` now correctly fast-forwards the local branch to the remote.**
  Previously, `gem-audit update` fetched remote refs but never advanced the
  local branch (HEAD) to match `origin/main`, so the working tree stayed at
  the old commit despite reporting "Updated". The advisory database would
  remain stale until a full re-clone. `checkout_head` now resolves the
  remote tracking ref and updates the local branch before checking out.

#### Security

* **Path traversal guard for gem and Ruby engine names.** A crafted
  `Gemfile.lock` containing a gem name with `..` sequences (e.g.
  `../../etc`) could cause the scanner to read YAML files outside the
  advisory database directory. Added `is_contained_in()` validation to
  `advisories_for_with_errors` and `advisories_for_ruby_with_errors`.

#### Changed

* Use `PreviousValue::MustExist` instead of `PreviousValue::Any` when
  updating the local branch ref, catching corrupted repository state
  earlier.

#### Internal

* Removed unused `_suffix` parameter from `temp_mock_db` test helper.
* Added doc comments to `find_remote_head` describing fallback behaviour.

---

### 2.8.1 / 2026-03-19

#### Fixed

* **`--write-ignore` now preserves existing inline comments.** Previously,
  running `--write-ignore` a second time would strip `# comments` from
  already-ignored advisory entries because the YAML parser discards comments
  and the scanner skips already-ignored advisories (so `build_ignore_comments`
  could not regenerate them). The configuration loader now extracts inline
  comments from the raw YAML text before parsing and merges them with newly
  generated comments on save, with new comments taking precedence.

---

### 2.4.0 / 2026-03-11

#### Fixed

* **False positive on platform-suffixed gem versions.** Versions like
  `1.19.1-aarch64-linux-musl` were not correctly split into version and
  platform, causing the version to be treated as a pre-release and
  incorrectly flagged as vulnerable even when it satisfied `patched_versions`.
* Added `musl` and `gnu` libc variants (`aarch64-linux-musl`,
  `x86_64-linux-musl`, `aarch64-linux-gnu`, `x86_64-linux-gnu`,
  `arm-linux-musl`, `arm-linux-gnu`) to the known platform patterns.
* Improved platform heuristic fallback to scan all hyphen positions
  (left-to-right) instead of only the last one, so multi-segment platforms
  like `aarch64-linux-musl` are correctly detected.

#### CI

* Updated GitHub Actions from Node.js 20 to Node.js 24-compatible versions:
  `actions/checkout` v4 → v5, `actions/upload-artifact` v4 → v7,
  `actions/download-artifact` v4 → v8, `codecov/codecov-action` v4 → v5.

---

### 2.3.3 / 2026-03-01

#### Fixed

* `download()` now calls `create_dir_all` on the parent directory before
  cloning, preventing failures when the default path (`/root/.local/share/`)
  does not exist in the container.
* Docker image default `GEM_AUDIT_DB` changed from `~/.local/share/ruby-advisory-db`
  to `/db`, a pre-created writable directory in the image that works without
  any volume mount or environment override.

---

### 2.3.2 / 2026-03-01

#### Fixed

* `update()` now falls back to a fresh clone if the git fetch ref-update step
  fails, preventing CI failures caused by gix locking issues on container
  overlay filesystems (overlayfs).
* `--update` failure when the database already exists is now a warning rather
  than a fatal error; the scan continues with the existing database.
* Removed the advisory database pre-download from the Docker image. The database
  is no longer baked into the image layers, eliminating git ref-update failures
  in containerised CI environments.

#### Documentation

* Updated GitLab CI example to use `GEM_AUDIT_DB` + CI cache, storing the
  advisory database in a writable directory outside the container image layers.

---

### 2.3.1 / 2026-02-25

#### Fixed

* Docker image switched from `distroless/cc-debian13` to `distroless/cc-debian13:debug`
  so the image can be used directly as a GitLab CI job image. The debug variant
  ships busybox (`/bin/sh`) while keeping the same glibc runtime and minimal footprint.
* Removed the advisory database pre-download from the Docker image. The database
  is no longer baked into the image layers, eliminating git ref-update failures
  caused by container overlay filesystems (overlayfs).
* `update()` now falls back to a fresh clone if the git fetch ref-update step
  fails, preventing CI failures due to transient gix locking issues.
* `--update` failure when the database already exists is now a warning rather
  than a fatal error, so the scan continues with the existing database.

#### Documentation

* Updated GitLab CI example in README to use `GEM_AUDIT_DB` and CI cache,
  which stores the advisory database in a proper writable directory and avoids
  overlay filesystem locking issues.
* Added `--update` flag recommendation and stricter `--max-db-age 1 --fail-on-stale` variant.

---

### 2.3.0 / 2026-02-25

#### Added

* **Ruby interpreter version scanning.** gem-audit now checks the `RUBY VERSION`
  section of `Gemfile.lock` against known CVEs in the `rubies/` directory of
  [ruby-advisory-db]. Inspired by [ruby_audit](https://github.com/civisanalytics/ruby_audit).
  * Detects vulnerable Ruby interpreter versions (ruby, jruby, mruby, etc.).
  * Text output shows "Engine" and "Version" with "upgrade Ruby to" solutions.
  * JSON output adds `"type": "vulnerable_ruby"` entries with
    `"ruby": { "engine": ..., "version": ... }` structure.
  * Summary line includes "N vulnerable Ruby version(s)" alongside gem counts.
  * `--ignore` and `--severity` filters apply to Ruby advisories too.
* `gem-audit stats` now shows separate gem and Ruby advisory counts.

#### Changed

* **Renamed `Advisory.gem` to `Advisory.name`.** The field now generically
  represents both gem names and Ruby engine names. Added `Advisory.kind`
  (`AdvisoryKind::Gem` or `AdvisoryKind::Ruby`) to distinguish the two.
* Advisory YAML files with an `engine:` field (instead of `gem:`) are now
  supported. Files missing both fields produce an `AdvisoryError::MissingField`
  error.

#### Internal

* Extracted `ScanOptions::should_report()` to deduplicate ignore/severity
  filtering logic between gem and Ruby scanning.
* Extracted `advisory_to_json()` helper in the JSON formatter.
* Refactored `Database::size()` into a shared `count_advisories_in()` helper,
  reused by `rubies_size()`.
* Added `RubyVersion` parser (`src/lockfile/ruby_version.rs`) with patchlevel
  stripping and engine extraction.
* Expanded test suite from 253 to 284 tests.

### 2.2.0 / 2026-02-24

#### Added

* **Remediation suggestions** (`--fix`). When passed to `gem-audit check`,
  appends a "Remediation" section that groups vulnerabilities by gem and
  suggests upgrade paths with `bundle update` commands. This is a dry-run
  flag — no files are modified.
  * Text output shows grouped remediation with patched version ranges,
    advisory IDs, and ready-to-run `bundle update` commands.
  * JSON output adds a `remediations` array with `gem`, `current_version`,
    `advisories`, `patched_versions`, and `command` fields.

#### Internal

* Extracted `format_timestamp` and `days_to_date` helpers into `src/util.rs`.
* Expanded test suite from 176 to 253 tests (83.7% line coverage).

### 2.1.1 / 2026-02-16

#### Fixed

* Replaced `blocking-http-transport-curl` with `blocking-http-transport-reqwest-rust-tls`
  for HTTPS support. The curl backend required system OpenSSL, which broke
  cross-compilation for `aarch64-unknown-linux-gnu` and failed at runtime on
  minimal Linux environments with `'https' is not compiled in`.

#### Changed

* Updated package description.
* Added `repository`, `homepage`, `keywords`, and `categories` metadata to
  `Cargo.toml` for crates.io publishing.
* Added CI, Codecov, Crates.io, and license badges to README.
* Added `codecov.yml` with coverage thresholds.

### 2.1.0 / 2026-02-15

#### Added

* **Semantic exit codes.** Exit code `0` = no vulnerabilities, `1` =
  vulnerabilities found, `2` = tool error, `3` = stale database. Previously
  all failures used exit code 1.
* **Severity threshold** (`--severity` / `-S`). Only report advisories at or
  above the given level (`none`, `low`, `medium`, `high`, `critical`).
  Advisories without a CVSS score are excluded when a threshold is set.
* **Database staleness warning** (`--max-db-age <DAYS>`). Warns on stderr
  when the advisory database is older than the specified number of days.
  Combine with `--fail-on-stale` to exit with code 3.
  Also configurable via `max_db_age_days` in `.gem-audit.yml`.
* **Strict mode** (`--strict`). Treats version parse errors and advisory
  load failures as errors (exit code 2). Without this flag, they are
  silently skipped as before.
* Text output now shows a warnings summary line when version parse errors
  or advisory load errors occur (e.g., "Warnings: 3 version parse errors").
* JSON output now includes a `metadata` object with `version_parse_errors`
  and `advisory_load_errors` counts.

### 2.0.0 / 2026-02-13

#### Changed

* **Renamed project from `bundler-audit` to `gem-audit`.**
  Binary, crate name, and all CLI output now use the `gem-audit` name.
* Changed default configuration file from `.bundler-audit.yml` to
  `.gem-audit.yml`. The legacy `.bundler-audit.yml` is still loaded
  automatically as a fallback for backward compatibility.
* Changed environment variable from `BUNDLER_AUDIT_DB` to `GEM_AUDIT_DB`.
* Changed license from GPL-3.0-or-later to MIT.

### 1.2.0 / 2026-02-12

#### Changed

* Migrated all 7 error types to [thiserror], replacing ~124 lines of
  hand-written `impl Display`, `impl Error`, and `impl From` boilerplate
  with derive macros (`#[error("...")]`, `#[from]`).

[thiserror]: https://github.com/dtolnay/thiserror

### 1.1.0 / 2026-02-12

#### Changed

* Migrated from `git2` (libgit2 C bindings) to [gix] (gitoxide), a pure
  Rust git implementation. This eliminates OpenSSL and libssh2 system
  dependencies, enabling clean cross-compilation for all targets.

#### Added

* Added GitHub Actions CI workflow: `cargo check`, `cargo fmt --check`,
  `cargo clippy -D warnings`, and `cargo test` across Linux, macOS, and
  Windows.
* Added GitHub Actions release workflow: cross-compiles for 5 targets
  (`x86_64-linux`, `aarch64-linux`, `x86_64-darwin`, `aarch64-darwin`,
  `x86_64-windows`) and uploads binaries to GitHub Releases on tag push.
* Added performance benchmarks (`benchmarks/bench.sh`) using hyperfine.
* Added `LICENSE.md` (GPL-3.0-or-later).

[gix]: https://github.com/Byron/gitoxide

### 1.0.0 / 2026-02-11

Initial release -- a complete Rust rewrite of [bundler-audit] v0.9.x.

#### Core

* Implemented RubyGems `Gem::Version` parsing and comparison semantics,
  including inline alphanumeric segments and pre-release ordering.
* Implemented `Gem::Requirement` with all 7 operators
  (`=`, `!=`, `>`, `<`, `>=`, `<=`, `~>`).
* Implemented `Gemfile.lock` parser as a state-machine with indentation
  tracking. Handles GEM, GIT, PATH sections, platform variants, pinned
  dependencies, and compound version constraints.
* Implemented advisory YAML deserialization with vulnerability checking
  (`patched_versions`, `unaffected_versions`) and CVSS v3/v2 criticality.
* Implemented advisory database management using [gix] (gitoxide) for
  clone and fast-forward update of [ruby-advisory-db].
* Implemented scanner that ties lockfile and database together:
  * Detects insecure gem sources (`git://` and `http://` protocols).
  * Checks each gem against the advisory database.
  * Ignores internal/private sources (RFC 1918, RFC 4193, RFC 6890 IP ranges).
  * Supports ignore lists by advisory ID (CVE, GHSA, OSVDB).
* Added `.gem-audit.yml` configuration file support with strict
  YAML validation. CLI `--ignore` takes precedence over the config file.

#### CLI

* Added `gem-audit check` command (also the default when no subcommand
  is given), with options:
  * `--quiet` / `-q` to suppress output.
  * `--verbose` / `-v` to show full advisory descriptions.
  * `--ignore` / `-i` to ignore specific advisory IDs.
  * `--update` / `-u` to update the database before checking.
  * `--database` / `-D` to specify a custom advisory database path.
  * `--format` / `-F` to select output format (`text` or `json`).
  * `--gemfile-lock` / `-G` to specify a custom lockfile path.
  * `--config` / `-c` to specify a custom configuration file path.
  * `--output` / `-o` to write output to a file.
* Added `gem-audit update` command.
* Added `gem-audit download` command.
* Added `gem-audit stats` command.
* Added `gem-audit version` command.
* Auto-downloads [ruby-advisory-db] on first run if not present.
* TTY detection for ANSI color output and JSON pretty-printing.

#### Output Formats

* Text format with ANSI color highlighting for criticality levels.
* JSON format with gem info, advisory details, and CVSS scores.

[bundler-audit]: https://github.com/rubysec/bundler-audit
[ruby-advisory-db]: https://github.com/rubysec/ruby-advisory-db
