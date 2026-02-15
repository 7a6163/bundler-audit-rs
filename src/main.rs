use std::collections::HashSet;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::time::SystemTime;

use clap::{Parser, Subcommand};

use gem_audit::advisory::{Criticality, Database};
use gem_audit::configuration::Configuration;
use gem_audit::format::{self, OutputFormat};
use gem_audit::scanner::{ScanOptions, Scanner};

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
                eprintln!("Failed to update advisory database: {}", e);
                return EXIT_ERROR;
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
        config.ignore
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

    match output_format {
        OutputFormat::Text => {
            let use_color = output_file.is_none() && is_tty;
            format::print_text(&report, &mut output_handle, verbose, quiet, use_color);
        }
        OutputFormat::Json => {
            format::print_json(&report, &mut output_handle, is_tty && output_file.is_none());
        }
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
    println!("ruby-advisory-db:");
    println!("  advisories:\t{} advisories", db.size());

    if let Some(ts) = db.last_updated_at() {
        println!("  last updated:\t{}", format_timestamp(ts));
    }

    if let Some(commit) = db.commit_id() {
        println!("  commit:\t{}", commit);
    }
}

fn format_timestamp(seconds: i64) -> String {
    // Simple UTC formatting without external deps
    let days_since_epoch = seconds / 86400;
    let time_of_day = seconds % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let secs = time_of_day % 60;

    // Calculate date from days since epoch (1970-01-01)
    let (year, month, day) = days_to_date(days_since_epoch);

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        year, month, day, hours, minutes, secs
    )
}

fn days_to_date(days: i64) -> (i64, u32, u32) {
    // Algorithm from https://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
