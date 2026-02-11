mod json;
mod text;

pub use json::print_json;
pub use text::print_text;

/// Supported output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}
