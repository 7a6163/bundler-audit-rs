mod lockfile_patcher;
mod version_resolver;

pub use lockfile_patcher::{PatchError, patch_lockfile};
pub use version_resolver::{FixResult, FixSuggestion, resolve_fixes};
