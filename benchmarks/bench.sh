#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# bundler-audit benchmark: Rust vs Ruby
# Requires: hyperfine, ruby, bundle-audit (gem), cargo
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RUST_BIN="$PROJECT_DIR/target/release/bundler-audit"
FIXTURE_DIR="$PROJECT_DIR/tests/fixtures"
WARMUP=3
RUNS=20

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
RESET='\033[0m'

info()  { echo -e "${GREEN}[INFO]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET} $*"; }
error() { echo -e "${RED}[ERROR]${RESET} $*"; exit 1; }

# ── Pre-flight checks ────────────────────────────────────────

command -v hyperfine >/dev/null 2>&1 || error "hyperfine not found. Install with: brew install hyperfine"

if [ ! -f "$RUST_BIN" ]; then
    info "Building Rust release binary ..."
    cargo build --release --manifest-path "$PROJECT_DIR/Cargo.toml"
fi

HAS_RUBY=false
if command -v bundle-audit >/dev/null 2>&1; then
    HAS_RUBY=true
    RUBY_VERSION=$(ruby --version | head -1)
    info "Ruby found: $RUBY_VERSION"
    info "bundle-audit: $(bundle-audit version 2>/dev/null || echo 'unknown')"
else
    warn "bundle-audit (Ruby) not found, running Rust-only benchmarks"
fi

RUST_VERSION=$("$RUST_BIN" version)
info "Rust binary: $RUST_VERSION"
echo

# ── Benchmark 1: check (unpatched gems — many advisories) ─────

echo -e "${BOLD}━━━ Benchmark 1: check (unpatched_gems fixture) ━━━${RESET}"
echo

if [ "$HAS_RUBY" = true ]; then
    hyperfine \
        --warmup "$WARMUP" \
        --runs "$RUNS" \
        --ignore-failure \
        --export-markdown "$PROJECT_DIR/benchmarks/results-unpatched.md" \
        -n "Rust"  "$RUST_BIN check $FIXTURE_DIR/unpatched_gems --quiet" \
        -n "Ruby"  "bundle-audit check $FIXTURE_DIR/unpatched_gems --quiet"
else
    hyperfine \
        --warmup "$WARMUP" \
        --runs "$RUNS" \
        --ignore-failure \
        -n "Rust"  "$RUST_BIN check $FIXTURE_DIR/unpatched_gems --quiet"
fi

echo

# ── Benchmark 2: check (secure — no vulnerabilities) ──────────

echo -e "${BOLD}━━━ Benchmark 2: check (secure fixture) ━━━${RESET}"
echo

if [ "$HAS_RUBY" = true ]; then
    hyperfine \
        --warmup "$WARMUP" \
        --runs "$RUNS" \
        --ignore-failure \
        --export-markdown "$PROJECT_DIR/benchmarks/results-secure.md" \
        -n "Rust"  "$RUST_BIN check $FIXTURE_DIR/secure --quiet" \
        -n "Ruby"  "bundle-audit check $FIXTURE_DIR/secure --quiet"
else
    hyperfine \
        --warmup "$WARMUP" \
        --runs "$RUNS" \
        --ignore-failure \
        -n "Rust"  "$RUST_BIN check $FIXTURE_DIR/secure --quiet"
fi

echo

# ── Benchmark 3: check with JSON output ───────────────────────

echo -e "${BOLD}━━━ Benchmark 3: check --format json (unpatched_gems) ━━━${RESET}"
echo

if [ "$HAS_RUBY" = true ]; then
    hyperfine \
        --warmup "$WARMUP" \
        --runs "$RUNS" \
        --ignore-failure \
        --export-markdown "$PROJECT_DIR/benchmarks/results-json.md" \
        -n "Rust"  "$RUST_BIN check $FIXTURE_DIR/unpatched_gems --quiet --format json --output /dev/null" \
        -n "Ruby"  "bundle-audit check $FIXTURE_DIR/unpatched_gems --quiet --format json --output /dev/null"
else
    hyperfine \
        --warmup "$WARMUP" \
        --runs "$RUNS" \
        --ignore-failure \
        -n "Rust"  "$RUST_BIN check $FIXTURE_DIR/unpatched_gems --quiet --format json --output /dev/null"
fi

echo

# ── Benchmark 4: startup time (version) ───────────────────────

echo -e "${BOLD}━━━ Benchmark 4: startup time (version) ━━━${RESET}"
echo

if [ "$HAS_RUBY" = true ]; then
    hyperfine \
        --warmup "$WARMUP" \
        --runs "$RUNS" \
        --export-markdown "$PROJECT_DIR/benchmarks/results-startup.md" \
        -n "Rust"  "$RUST_BIN version" \
        -n "Ruby"  "bundle-audit version"
else
    hyperfine \
        --warmup "$WARMUP" \
        --runs "$RUNS" \
        -n "Rust"  "$RUST_BIN version"
fi

echo
echo -e "${GREEN}${BOLD}Done!${RESET} Results saved to $PROJECT_DIR/benchmarks/results-*.md"
