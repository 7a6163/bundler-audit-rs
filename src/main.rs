use std::collections::HashSet;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::time::SystemTime;

use clap::{Parser, Subcommand};

use gem_audit::advisory::{Criticality, Database};
use gem_audit::configuration::Configuration;
use gem_audit::fixer::{self, FixResult};
use gem_audit::format::{self, OutputFormat};
use gem_audit::scanner::{ScanOptions, Scanner};
use gem_audit::util::format_timestamp;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const EXIT_SUCCESS: i32 = 0;
const EXIT_VULNERABLE: i32 = 1;
const EXIT_ERROR: i32 = 2;
const EXIT_STALE: i32 = 3;

#[derive(Parser)]
#[command(
    name = "gem-audit",
    about = "Patch-level verification for Ruby Bundler dependencies",
    version = VERSION,
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Check the Gemfile.lock for insecure dependencies (default)
    Check {
        /// Project directory to audit
        #[arg(default_value = ".")]
        dir: String,

        /// Suppress output
        #[arg(short, long)]
        quiet: bool,

        /// Show detailed descriptions
        #[arg(short, long)]
        verbose: bool,

        /// Advisory IDs to ignore
        #[arg(short, long, num_args = 1..)]
        ignore: Vec<String>,

        /// Update the advisory database before checking
        #[arg(short, long)]
        update: bool,

        /// Path to the advisory database
        #[arg(short = 'D', long)]
        database: Option<String>,

        /// Output format
        #[arg(short = 'F', long, value_enum, default_value = "text")]
        format: OutputFormat,

        /// Path to the Gemfile.lock file
        #[arg(short = 'G', long, default_value = "Gemfile.lock")]
        gemfile_lock: String,

        /// Path to the configuration file
        #[arg(short, long, default_value = ".gem-audit.yml")]
        config: String,

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<String>,

        /// Minimum severity level to report (none, low, medium, high, critical)
        #[arg(short = 'S', long, value_enum)]
        severity: Option<Criticality>,

        /// Maximum advisory database age in days before warning
        #[arg(long)]
        max_db_age: Option<u64>,

        /// Exit with code 3 if the advisory database is stale
        #[arg(long)]
        fail_on_stale: bool,

        /// Treat parse/load warnings as errors (exit code 2)
        #[arg(long)]
        strict: bool,

        /// Fix vulnerable gem versions in Gemfile.lock
        #[arg(long)]
        fix: bool,

        /// Preview fix changes without writing (use with --fix)
        #[arg(long)]
        dry_run: bool,

        /// Write all detected advisory IDs to the config file's ignore list
        #[arg(long)]
        write_ignore: bool,
    },

    /// Update the ruby-advisory-db
    Update {
        /// Suppress output
        #[arg(short, long)]
        quiet: bool,

        /// Path to the advisory database
        #[arg(short = 'D', long)]
        database: Option<String>,
    },

    /// Download the ruby-advisory-db
    Download {
        /// Suppress output
        #[arg(short, long)]
        quiet: bool,

        /// Path to the advisory database
        #[arg(short = 'D', long)]
        database: Option<String>,
    },

    /// Print ruby-advisory-db statistics
    Stats {
        /// Path to the advisory database
        #[arg(short = 'D', long)]
        database: Option<String>,
    },

    /// Print the gem-audit version
    Version,
}

fn main() {
    let cli = Cli::parse();

    let code = match cli.command {
        Some(Commands::Check {
            dir,
            quiet,
            verbose,
            ignore,
            update,
            database,
            format,
            gemfile_lock,
            config,
            output,
            severity,
            max_db_age,
            fail_on_stale,
            strict,
            fix,
            dry_run,
            write_ignore,
        }) => cmd_check(
            &dir,
            quiet,
            verbose,
            &ignore,
            update,
            database.as_deref(),
            format,
            &gemfile_lock,
            &config,
            output.as_deref(),
            severity,
            max_db_age,
            fail_on_stale,
            strict,
            fix,
            dry_run,
            write_ignore,
        ),
        Some(Commands::Update { quiet, database }) => cmd_update(quiet, database.as_deref()),
        Some(Commands::Download { quiet, database }) => cmd_download(quiet, database.as_deref()),
        Some(Commands::Stats { database }) => cmd_stats(database.as_deref()),
        Some(Commands::Version) => {
            println!("gem-audit {}", VERSION);
            EXIT_SUCCESS
        }
        None => {
            // Default command is check (like Ruby bundler-audit's behavior)
            cmd_check(
                ".",
                false,
                false,
                &[],
                false,
                None,
                OutputFormat::Text,
                "Gemfile.lock",
                Configuration::DEFAULT_FILE,
                None,
                None,
                None,
                false,
                false,
                false,
                false,
                false,
            )
        }
    };

    if code != EXIT_SUCCESS {
        process::exit(code);
    }
}

fn resolve_db_path(database: Option<&str>) -> PathBuf {
    database
        .map(PathBuf::from)
        .unwrap_or_else(Database::default_path)
}

#[allow(clippy::too_many_arguments)]
fn cmd_check(
    dir: &str,
    quiet: bool,
    verbose: bool,
    ignore: &[String],
    update: bool,
    database: Option<&str>,
    output_format: OutputFormat,
    gemfile_lock: &str,
    config_file: &str,
    output_file: Option<&str>,
    severity: Option<Criticality>,
    max_db_age: Option<u64>,
    fail_on_stale: bool,
    strict: bool,
    fix: bool,
    dry_run: bool,
    write_ignore: bool,
) -> i32 {
    let dir = Path::new(dir);
    if !dir.is_dir() {
        eprintln!("No such file or directory: {}", dir.display());
        return EXIT_ERROR;
    }

    // Load configuration file (relative to project dir)
    let config_path = if Path::new(config_file).is_absolute() {
        PathBuf::from(config_file)
    } else {
        dir.join(config_file)
    };
    let config = match Configuration::load_or_default(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", e);
            return EXIT_ERROR;
        }
    };

    let db_path = resolve_db_path(database);

    // Download or update advisory database
    if !db_path.is_dir() || !db_path.join("gems").is_dir() {
        if !quiet {
            eprintln!("Downloading ruby-advisory-db ...");
        }
        match Database::download(&db_path, quiet) {
            Ok(_) => {
                if !quiet {
                    eprintln!("Downloaded ruby-advisory-db");
                }
            }
            Err(e) => {
                eprintln!("Failed to download advisory database: {}", e);
                return EXIT_ERROR;
            }
        }
    } else if update {
        if !quiet {
            eprintln!("Updating ruby-advisory-db ...");
        }
        let db = Database::open(&db_path).unwrap();
        match db.update() {
            Ok(true) => {
                if !quiet {
                    eprintln!("Updated ruby-advisory-db");
                }
            }
            Ok(false) => {
                if !quiet {
                    eprintln!("Skipping update, ruby-advisory-db is not a git repository");
                }
            }
            Err(e) => {
                // Update failed but the existing DB is still usable — warn and continue.
                eprintln!("warning: Failed to update advisory database: {}", e);
            }
        }
    }

    let db = match Database::open(&db_path) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("Failed to open advisory database: {}", e);
            return EXIT_ERROR;
        }
    };

    // Check database staleness (CLI --max-db-age overrides config)
    let effective_max_age = max_db_age.or(config.max_db_age_days);
    let mut stale = false;
    if let Some(max_days) = effective_max_age
        && let Some(last_updated) = db.last_updated_at()
    {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let age_days = (now - last_updated) / 86400;
        if age_days > max_days as i64 {
            stale = true;
            eprintln!(
                "warning: advisory database is {} days old (max: {} days)",
                age_days, max_days
            );
        }
    }

    let lockfile_path = dir.join(gemfile_lock);
    let scanner = match Scanner::new(&lockfile_path, db) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", e);
            return EXIT_ERROR;
        }
    };

    // CLI --ignore takes precedence; otherwise use config file
    let ignore_set = if !ignore.is_empty() {
        ignore.iter().cloned().collect::<HashSet<String>>()
    } else {
        config.ignore.clone()
    };

    let options = ScanOptions {
        ignore: ignore_set,
        severity,
        strict,
    };

    let report = scanner.scan(&options);

    // Output
    let stdout = io::stdout();
    let is_tty = stdout.is_terminal();
    let mut output_handle: Box<dyn Write> = if let Some(path) = output_file {
        match std::fs::File::create(path) {
            Ok(f) => Box::new(f),
            Err(e) => {
                eprintln!("Failed to open output file {}: {}", path, e);
                return EXIT_ERROR;
            }
        }
    } else {
        Box::new(stdout.lock())
    };

    // Resolve fixes if --fix is requested
    let fix_results = if fix && !report.unpatched_gems.is_empty() {
        let remediations = report.remediations();
        Some(fixer::resolve_fixes(&remediations))
    } else {
        None
    };

    match output_format {
        OutputFormat::Text => {
            let use_color = output_file.is_none() && is_tty;
            format::print_text(
                &report,
                &mut output_handle,
                verbose,
                quiet,
                use_color,
                fix,
                fix_results.as_deref(),
            );
        }
        OutputFormat::Json => {
            format::print_json(
                &report,
                &mut output_handle,
                is_tty && output_file.is_none(),
                fix,
                fix_results.as_deref(),
            );
        }
    }

    // Apply fixes to Gemfile.lock
    if fix
        && !dry_run
        && let Some(ref results) = fix_results
    {
        let fixes: Vec<&fixer::FixSuggestion> = results
            .iter()
            .filter_map(|r| match r {
                FixResult::Fixed(f) => Some(f),
                _ => None,
            })
            .collect();

        if !fixes.is_empty() {
            let owned_fixes: Vec<fixer::FixSuggestion> = fixes
                .iter()
                .map(|f| fixer::FixSuggestion {
                    name: f.name.clone(),
                    current_version: f.current_version.clone(),
                    resolved_version: f.resolved_version.clone(),
                    advisory_ids: f.advisory_ids.clone(),
                })
                .collect();

            match std::fs::read_to_string(&lockfile_path) {
                Ok(content) => {
                    let (patched, patched_names) = fixer::patch_lockfile(&content, &owned_fixes);
                    if !patched_names.is_empty() {
                        // Atomic write: write to tmp file then rename
                        let tmp_path = lockfile_path.with_extension("lock.tmp");
                        match std::fs::write(&tmp_path, &patched) {
                            Ok(()) => {
                                if let Err(e) = std::fs::rename(&tmp_path, &lockfile_path) {
                                    eprintln!("error: failed to write Gemfile.lock: {}", e);
                                    let _ = std::fs::remove_file(&tmp_path);
                                } else {
                                    eprintln!(
                                        "\nFixed {} gem(s) in {}. Run `bundle install` to install the updated versions.",
                                        patched_names.len(),
                                        lockfile_path.display()
                                    );
                                }
                            }
                            Err(e) => {
                                eprintln!("error: failed to write temporary file: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("error: failed to read {}: {}", lockfile_path.display(), e);
                }
            }
        }
    }

    // Write all detected advisory IDs to the config ignore list
    if write_ignore && report.vulnerable() {
        let mut new_ignore = config.ignore.clone();
        let mut comments = std::collections::HashMap::new();

        for gem in &report.unpatched_gems {
            let criticality = gem
                .advisory
                .criticality()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "Unknown".to_string());
            let title = gem.advisory.title.as_deref().unwrap_or("N/A");
            let comment = format!("{} {} ({}) - {}", gem.name, gem.version, criticality, title);
            for id in gem.advisory.identifiers() {
                comments
                    .entry(id.clone())
                    .or_insert_with(|| comment.clone());
                new_ignore.insert(id);
            }
        }
        for ruby in &report.vulnerable_rubies {
            let criticality = ruby
                .advisory
                .criticality()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "Unknown".to_string());
            let title = ruby.advisory.title.as_deref().unwrap_or("N/A");
            let comment = format!(
                "{} {} ({}) - {}",
                ruby.engine, ruby.version, criticality, title
            );
            for id in ruby.advisory.identifiers() {
                comments
                    .entry(id.clone())
                    .or_insert_with(|| comment.clone());
                new_ignore.insert(id);
            }
        }

        let updated_config = Configuration {
            ignore: new_ignore,
            max_db_age_days: config.max_db_age_days,
        };

        match updated_config.save(&config_path, Some(&comments)) {
            Ok(()) => {
                let count = updated_config.ignore.len() - config.ignore.len();
                eprintln!(
                    "Added {} advisory ID(s) to {}",
                    count,
                    config_path.display()
                );
            }
            Err(e) => {
                eprintln!("Failed to write config: {}", e);
                return EXIT_ERROR;
            }
        }

        return EXIT_SUCCESS;
    }

    if report.vulnerable() {
        return EXIT_VULNERABLE;
    }

    if strict && (report.version_parse_errors > 0 || report.advisory_load_errors > 0) {
        return EXIT_ERROR;
    }

    if stale && fail_on_stale {
        return EXIT_STALE;
    }

    EXIT_SUCCESS
}

fn cmd_update(quiet: bool, database: Option<&str>) -> i32 {
    let db_path = resolve_db_path(database);

    if !db_path.is_dir() || !db_path.join("gems").is_dir() {
        return cmd_download(quiet, database);
    }

    if !quiet {
        eprintln!("Updating ruby-advisory-db ...");
    }

    let db = match Database::open(&db_path) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("Failed to open advisory database: {}", e);
            return EXIT_ERROR;
        }
    };

    match db.update() {
        Ok(true) => {
            if !quiet {
                eprintln!("Updated ruby-advisory-db");
            }
        }
        Ok(false) => {
            if !quiet {
                eprintln!("Skipping update, ruby-advisory-db is not a git repository");
            }
        }
        Err(e) => {
            eprintln!("Failed to update: {}", e);
            return EXIT_ERROR;
        }
    }

    if !quiet {
        print_stats(&db);
    }

    EXIT_SUCCESS
}

fn cmd_download(quiet: bool, database: Option<&str>) -> i32 {
    let db_path = resolve_db_path(database);

    if db_path.is_dir() && db_path.join("gems").is_dir() {
        eprintln!("Database already exists");
        return EXIT_SUCCESS;
    }

    if !quiet {
        eprintln!("Downloading ruby-advisory-db ...");
    }

    match Database::download(&db_path, quiet) {
        Ok(db) => {
            if !quiet {
                print_stats(&db);
            }
            EXIT_SUCCESS
        }
        Err(e) => {
            eprintln!("Failed to download: {}", e);
            EXIT_ERROR
        }
    }
}

fn cmd_stats(database: Option<&str>) -> i32 {
    let db_path = resolve_db_path(database);

    let db = match Database::open(&db_path) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("Failed to open advisory database: {}", e);
            return EXIT_ERROR;
        }
    };

    print_stats(&db);
    EXIT_SUCCESS
}

fn print_stats(db: &Database) {
    let gems = db.size();
    let rubies = db.rubies_size();

    println!("ruby-advisory-db:");
    println!("  advisories:\t{} advisories", gems + rubies);

    if rubies > 0 {
        println!("  gems:\t\t{}", gems);
        println!("  rubies:\t{}", rubies);
    }

    if let Some(ts) = db.last_updated_at() {
        println!("  last updated:\t{}", format_timestamp(ts));
    }

    if let Some(commit) = db.commit_id() {
        println!("  commit:\t{}", commit);
    }
}
