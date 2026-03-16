use std::collections::HashSet;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process;

use clap::{Parser, Subcommand};

use gem_audit::advisory::{Criticality, Database};
use gem_audit::check;
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

#[derive(clap::Args)]
struct CheckOptions {
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
}

#[derive(Subcommand)]
enum Commands {
    /// Check the Gemfile.lock for insecure dependencies (default)
    Check(CheckOptions),

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
        Some(Commands::Check(opts)) => cmd_check(opts),
        Some(Commands::Update { quiet, database }) => cmd_update(quiet, database.as_deref()),
        Some(Commands::Download { quiet, database }) => cmd_download(quiet, database.as_deref()),
        Some(Commands::Stats { database }) => cmd_stats(database.as_deref()),
        Some(Commands::Version) => {
            println!("gem-audit {}", VERSION);
            EXIT_SUCCESS
        }
        None => cmd_check(CheckOptions::default()),
    };

    if code != EXIT_SUCCESS {
        process::exit(code);
    }
}

impl Default for CheckOptions {
    fn default() -> Self {
        Self {
            dir: ".".to_string(),
            quiet: false,
            verbose: false,
            ignore: Vec::new(),
            update: false,
            database: None,
            format: OutputFormat::Text,
            gemfile_lock: "Gemfile.lock".to_string(),
            config: Configuration::DEFAULT_FILE.to_string(),
            output: None,
            severity: None,
            max_db_age: None,
            fail_on_stale: false,
            strict: false,
            fix: false,
            dry_run: false,
            write_ignore: false,
        }
    }
}

fn resolve_db_path(database: Option<&str>) -> PathBuf {
    database
        .map(PathBuf::from)
        .unwrap_or_else(Database::default_path)
}

fn ensure_database(db_path: &Path, update: bool, quiet: bool) -> Result<Database, i32> {
    if !db_path.is_dir() || !db_path.join("gems").is_dir() {
        if !quiet {
            eprintln!("Downloading ruby-advisory-db ...");
        }
        match Database::download(db_path, quiet) {
            Ok(_) => {
                if !quiet {
                    eprintln!("Downloaded ruby-advisory-db");
                }
            }
            Err(e) => {
                eprintln!("Failed to download advisory database: {}", e);
                return Err(EXIT_ERROR);
            }
        }
    } else if update {
        if !quiet {
            eprintln!("Updating ruby-advisory-db ...");
        }
        let db = Database::open(db_path).map_err(|e| {
            eprintln!("Failed to open advisory database: {}", e);
            EXIT_ERROR
        })?;
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
                eprintln!("warning: Failed to update advisory database: {}", e);
            }
        }
    }

    Database::open(db_path).map_err(|e| {
        eprintln!("Failed to open advisory database: {}", e);
        EXIT_ERROR
    })
}

fn apply_fixes(lockfile_path: &Path, fix_results: &[FixResult]) {
    let fixes: Vec<fixer::FixSuggestion> = fix_results
        .iter()
        .filter_map(|r| match r {
            FixResult::Fixed(f) => Some(f.clone()),
            _ => None,
        })
        .collect();

    if fixes.is_empty() {
        return;
    }

    match std::fs::read_to_string(lockfile_path) {
        Ok(content) => {
            let (patched, patched_names) = fixer::patch_lockfile(&content, &fixes);
            if !patched_names.is_empty() {
                let tmp_path = lockfile_path.with_extension("lock.tmp");
                match std::fs::write(&tmp_path, &patched) {
                    Ok(()) => {
                        if let Err(e) = std::fs::rename(&tmp_path, lockfile_path) {
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

fn write_ignore_list(
    report: &gem_audit::scanner::Report,
    config: &Configuration,
    config_path: &Path,
) -> i32 {
    let (new_ids, comments) = check::build_ignore_comments(report);
    let merged_ignore: HashSet<String> = config.ignore.union(&new_ids).cloned().collect();

    let updated_config = Configuration {
        ignore: merged_ignore,
        max_db_age_days: config.max_db_age_days,
    };

    match updated_config.save(config_path, Some(&comments)) {
        Ok(()) => {
            let count = updated_config.ignore.len() - config.ignore.len();
            eprintln!(
                "Added {} advisory ID(s) to {}",
                count,
                config_path.display()
            );
            EXIT_SUCCESS
        }
        Err(e) => {
            eprintln!("Failed to write config: {}", e);
            EXIT_ERROR
        }
    }
}

fn cmd_check(opts: CheckOptions) -> i32 {
    let dir = Path::new(&opts.dir);
    if !dir.is_dir() {
        eprintln!("No such file or directory: {}", dir.display());
        return EXIT_ERROR;
    }

    let config_path = if Path::new(&opts.config).is_absolute() {
        PathBuf::from(&opts.config)
    } else {
        dir.join(&opts.config)
    };
    let config = match Configuration::load_or_default(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", e);
            return EXIT_ERROR;
        }
    };

    let db_path = resolve_db_path(opts.database.as_deref());

    let db = match ensure_database(&db_path, opts.update, opts.quiet) {
        Ok(db) => db,
        Err(code) => return code,
    };

    let stale = check::check_staleness(&db, opts.max_db_age, config.max_db_age_days);

    let lockfile_path = dir.join(&opts.gemfile_lock);
    let scanner = match Scanner::new(&lockfile_path, db) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", e);
            return EXIT_ERROR;
        }
    };

    let ignore_set = if !opts.ignore.is_empty() {
        opts.ignore.iter().cloned().collect::<HashSet<String>>()
    } else {
        config.ignore.clone()
    };

    let scan_options = ScanOptions {
        ignore: ignore_set,
        severity: opts.severity,
        strict: opts.strict,
    };

    let report = scanner.scan(&scan_options);

    // Output
    let stdout = io::stdout();
    let is_tty = stdout.is_terminal();
    let mut output_handle: Box<dyn Write> = if let Some(ref path) = opts.output {
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

    let fix_results = if opts.fix && !report.unpatched_gems.is_empty() {
        let remediations = report.remediations();
        Some(fixer::resolve_fixes(&remediations))
    } else {
        None
    };

    let print_result = match opts.format {
        OutputFormat::Text => {
            let use_color = opts.output.is_none() && is_tty;
            format::print_text(
                &report,
                &mut output_handle,
                opts.verbose,
                opts.quiet,
                use_color,
                opts.fix,
                fix_results.as_deref(),
            )
        }
        OutputFormat::Json => format::print_json(
            &report,
            &mut output_handle,
            is_tty && opts.output.is_none(),
            opts.fix,
            fix_results.as_deref(),
        ),
    };

    if let Err(e) = print_result
        && e.kind() != io::ErrorKind::BrokenPipe
    {
        eprintln!("error: write failed: {}", e);
        return EXIT_ERROR;
    }

    if opts.fix
        && !opts.dry_run
        && let Some(ref results) = fix_results
    {
        apply_fixes(&lockfile_path, results);
    }

    if opts.write_ignore && report.vulnerable() {
        return write_ignore_list(&report, &config, &config_path);
    }

    if report.vulnerable() {
        return EXIT_VULNERABLE;
    }

    if opts.strict && (report.version_parse_errors > 0 || report.advisory_load_errors > 0) {
        return EXIT_ERROR;
    }

    if stale && opts.fail_on_stale {
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
