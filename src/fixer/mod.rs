mod lockfile_patcher;
mod version_resolver;

pub use lockfile_patcher::{patch_lockfile, PatchError};
pub use version_resolver::{resolve_fixes, FixResult, FixSuggestion};
