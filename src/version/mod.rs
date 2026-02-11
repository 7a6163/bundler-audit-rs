mod gem_version;
mod requirement;

pub use gem_version::Version;
pub use requirement::{Operator, Requirement, VersionConstraint};
