#![allow(deprecated)] // Command::cargo_bin — replacement macro is unstable

use std::path::PathBuf;

use assert_cmd::Command;
use predicates::prelude::*;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn mock_db() -> PathBuf {
    fixtures_dir().join("mock_db")
}

/// Returns the real ruby-advisory-db path if it exists locally.
fn real_db_path() -> Option<PathBuf> {
    let path = std::env::var("GEM_AUDIT_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|_| dirs().unwrap_or_else(|| PathBuf::from(".")));
    if path.join("gems").is_dir() {
        Some(path)
    } else {
        None
    }
}

fn dirs() -> Option<PathBuf> {
    // Mirror Database::default_path() logic
    let home = std::env::var("HOME").ok()?;
    let path = PathBuf::from(home).join(".local/share/ruby-advisory-db");
    Some(path)
}

// ==================== version ====================

#[test]
fn version_subcommand() {
    Command::cargo_bin("gem-audit")
        .unwrap()
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("gem-audit "));
}

// ==================== check — secure lockfile ====================

#[test]
fn check_secure_lockfile() {
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            fixtures_dir().join("secure/Gemfile.lock").to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("No vulnerabilities found"));
}

// ==================== check — insecure sources ====================

#[test]
fn check_insecure_sources() {
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            fixtures_dir()
                .join("insecure_sources/Gemfile.lock")
                .to_str()
                .unwrap(),
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("Insecure Source URI found"));
}

// ==================== check — unpatched gems (real DB) ====================

#[test]
fn check_unpatched_gems() {
    let Some(db) = real_db_path() else { return };

    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--database",
            db.to_str().unwrap(),
            "--gemfile-lock",
            fixtures_dir()
                .join("unpatched_gems/Gemfile.lock")
                .to_str()
                .unwrap(),
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("Vulnerabilities found!"));
}

// ==================== check --quiet ====================

#[test]
fn check_quiet_secure() {
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--quiet",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            fixtures_dir().join("secure/Gemfile.lock").to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

// ==================== check --format json ====================

#[test]
fn check_json_secure() {
    let output = Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--format",
            "json",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            fixtures_dir().join("secure/Gemfile.lock").to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(parsed["results"].as_array().unwrap().len(), 0);
}

#[test]
fn check_json_insecure_sources() {
    let output = Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--format",
            "json",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            fixtures_dir()
                .join("insecure_sources/Gemfile.lock")
                .to_str()
                .unwrap(),
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let results = parsed["results"].as_array().unwrap();
    assert!(results.iter().any(|r| r["type"] == "insecure_source"));
}

// ==================== check --output <file> ====================

#[test]
fn check_output_to_file() {
    let tmp = std::env::temp_dir().join("gem-audit-cli-test-output.txt");

    // Clean up from prior runs
    let _ = std::fs::remove_file(&tmp);

    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            fixtures_dir().join("secure/Gemfile.lock").to_str().unwrap(),
            "--output",
            tmp.to_str().unwrap(),
        ])
        .assert()
        .success();

    let content = std::fs::read_to_string(&tmp).unwrap();
    assert!(content.contains("No vulnerabilities found"));

    let _ = std::fs::remove_file(&tmp);
}

// ==================== check --ignore (real DB) ====================

#[test]
fn check_ignore_advisory() {
    let Some(db) = real_db_path() else { return };

    // First run without ignore to confirm vulnerabilities exist
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--database",
            db.to_str().unwrap(),
            "--gemfile-lock",
            fixtures_dir()
                .join("unpatched_gems/Gemfile.lock")
                .to_str()
                .unwrap(),
        ])
        .assert()
        .failure();

    // Run with --ignore for a known CVE — should still find others but the ignored one is absent
    let output = Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--database",
            db.to_str().unwrap(),
            "--gemfile-lock",
            fixtures_dir()
                .join("unpatched_gems/Gemfile.lock")
                .to_str()
                .unwrap(),
            "--ignore",
            "CVE-2015-7577",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("CVE-2015-7577"));
}

// ==================== check --config (real DB) ====================

#[test]
fn check_with_config_ignore() {
    let Some(db) = real_db_path() else { return };

    let lockfile = fixtures_dir().join("unpatched_gems_with_config/Gemfile.lock");
    let config = fixtures_dir().join("unpatched_gems_with_config/.gem-audit.yml");

    // Without config: should find vulnerabilities
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--database",
            db.to_str().unwrap(),
            "--gemfile-lock",
            lockfile.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("Vulnerabilities found!"));

    // With config: the ignore list suppresses all known CVEs → clean result
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--database",
            db.to_str().unwrap(),
            "--gemfile-lock",
            lockfile.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("No vulnerabilities found"));
}

// ==================== check — missing Gemfile.lock ====================

#[test]
fn check_missing_gemfile_lock() {
    Command::cargo_bin("gem-audit")
        .unwrap()
        .args([
            "check",
            "--database",
            mock_db().to_str().unwrap(),
            "--gemfile-lock",
            "/nonexistent/path/Gemfile.lock",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::is_empty().not());
}

// ==================== stats (real DB) ====================

#[test]
fn stats_subcommand() {
    let Some(db) = real_db_path() else { return };

    Command::cargo_bin("gem-audit")
        .unwrap()
        .args(["stats", "--database", db.to_str().unwrap()])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("ruby-advisory-db:")
                .and(predicate::str::contains("advisories:")),
        );
}

// ==================== download — already exists (real DB) ====================

#[test]
fn download_already_exists() {
    let Some(db) = real_db_path() else { return };

    Command::cargo_bin("gem-audit")
        .unwrap()
        .args(["download", "--database", db.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("Database already exists"));
}
