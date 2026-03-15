use crate::scanner::Remediation;
use crate::version::Version;

/// A fix suggestion for a single gem: the resolved minimum safe version.
#[derive(Debug)]
pub struct FixSuggestion {
    pub name: String,
    pub current_version: String,
    pub resolved_version: Version,
    pub advisory_ids: Vec<String>,
}

/// Result of attempting to resolve a fix for a gem.
#[derive(Debug)]
pub enum FixResult {
    /// A safe version was found.
    Fixed(FixSuggestion),
    /// No safe version could be computed.
    Unresolvable {
        name: String,
        current_version: String,
        advisory_ids: Vec<String>,
    },
}

impl FixResult {
    pub fn name(&self) -> &str {
        match self {
            FixResult::Fixed(f) => &f.name,
            FixResult::Unresolvable { name, .. } => name,
        }
    }
}

/// Resolve minimum safe versions for all remediations.
///
/// For each gem, collects all advisory `patched_versions` and finds the smallest
/// version that satisfies ALL advisories simultaneously.
///
/// Each advisory's `patched_versions` are OR'd (any one suffices for that advisory).
/// Multiple advisories for the same gem are AND'd (must satisfy all).
pub fn resolve_fixes(remediations: &[Remediation]) -> Vec<FixResult> {
    remediations.iter().map(resolve_single).collect()
}

fn resolve_single(remediation: &Remediation) -> FixResult {
    let advisory_ids: Vec<String> = remediation
        .advisories
        .iter()
        .flat_map(|a| a.identifiers())
        .collect();

    // Collect candidate minimum versions from all advisories' patched_versions.
    // Each advisory's patched_versions are OR'd, so we take the minimum from each.
    let mut candidates: Vec<Version> = Vec::new();
    for adv in &remediation.advisories {
        for req in &adv.patched_versions {
            if let Some(v) = req.minimum_version() {
                candidates.push(v);
            }
        }
    }

    if candidates.is_empty() {
        return FixResult::Unresolvable {
            name: remediation.name.clone(),
            current_version: remediation.version.clone(),
            advisory_ids,
        };
    }

    // Sort candidates ascending — try smallest first
    candidates.sort();
    candidates.dedup();

    // Find the smallest candidate that satisfies ALL advisories
    for candidate in &candidates {
        if all_advisories_patched(remediation, candidate) {
            return FixResult::Fixed(FixSuggestion {
                name: remediation.name.clone(),
                current_version: remediation.version.clone(),
                resolved_version: candidate.clone(),
                advisory_ids,
            });
        }
    }

    // None of the exact candidates worked — try the largest candidate, which should
    // satisfy the most constraints
    FixResult::Unresolvable {
        name: remediation.name.clone(),
        current_version: remediation.version.clone(),
        advisory_ids,
    }
}

/// Check if a version is patched against ALL advisories for a gem.
fn all_advisories_patched(remediation: &Remediation, version: &Version) -> bool {
    remediation
        .advisories
        .iter()
        .all(|adv| adv.patched(version))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisory::Advisory;
    use std::path::Path;

    fn make_advisory(yaml: &str) -> Advisory {
        Advisory::from_yaml(yaml, Path::new("test.yml")).unwrap()
    }

    fn make_remediation(name: &str, version: &str, advisories: Vec<Advisory>) -> Remediation {
        Remediation {
            name: name.to_string(),
            version: version.to_string(),
            advisories,
        }
    }

    #[test]
    fn single_advisory_gte() {
        let adv =
            make_advisory("---\ngem: test\ncve: 2020-0001\npatched_versions:\n  - \">= 1.0.0\"\n");
        let rem = make_remediation("test", "0.5.0", vec![adv]);
        let results = resolve_fixes(&[rem]);
        assert_eq!(results.len(), 1);
        match &results[0] {
            FixResult::Fixed(f) => {
                assert_eq!(f.resolved_version, Version::parse("1.0.0").unwrap());
            }
            _ => panic!("expected Fixed"),
        }
    }

    #[test]
    fn single_advisory_pessimistic() {
        let adv =
            make_advisory("---\ngem: test\ncve: 2020-0001\npatched_versions:\n  - \"~> 1.18.7\"\n");
        let rem = make_remediation("test", "1.18.0", vec![adv]);
        let results = resolve_fixes(&[rem]);
        match &results[0] {
            FixResult::Fixed(f) => {
                assert_eq!(f.resolved_version, Version::parse("1.18.7").unwrap());
            }
            _ => panic!("expected Fixed"),
        }
    }

    #[test]
    fn single_advisory_gt() {
        let adv =
            make_advisory("---\ngem: test\ncve: 2020-0001\npatched_versions:\n  - \"> 1.0.0\"\n");
        let rem = make_remediation("test", "0.5.0", vec![adv]);
        let results = resolve_fixes(&[rem]);
        match &results[0] {
            FixResult::Fixed(f) => {
                assert_eq!(f.resolved_version, Version::parse("1.0.1").unwrap());
            }
            _ => panic!("expected Fixed"),
        }
    }

    #[test]
    fn multiple_patched_versions_or_picks_smallest() {
        // patched_versions: ["~> 1.18.7", ">= 1.19.1"] — OR, pick smallest
        let adv = make_advisory(
            "---\ngem: test\ncve: 2020-0001\npatched_versions:\n  - \"~> 1.18.7\"\n  - \">= 1.19.1\"\n",
        );
        let rem = make_remediation("test", "1.18.0", vec![adv]);
        let results = resolve_fixes(&[rem]);
        match &results[0] {
            FixResult::Fixed(f) => {
                assert_eq!(f.resolved_version, Version::parse("1.18.7").unwrap());
            }
            _ => panic!("expected Fixed"),
        }
    }

    #[test]
    fn two_advisories_and_takes_intersection() {
        // advisory1: patched >= 1.5
        // advisory2: patched >= 2.0
        // AND → need >= 2.0
        let adv1 =
            make_advisory("---\ngem: test\ncve: 2020-0001\npatched_versions:\n  - \">= 1.5\"\n");
        let adv2 =
            make_advisory("---\ngem: test\ncve: 2020-0002\npatched_versions:\n  - \">= 2.0\"\n");
        let rem = make_remediation("test", "1.0.0", vec![adv1, adv2]);
        let results = resolve_fixes(&[rem]);
        match &results[0] {
            FixResult::Fixed(f) => {
                assert_eq!(f.resolved_version, Version::parse("2.0").unwrap());
            }
            _ => panic!("expected Fixed"),
        }
    }

    #[test]
    fn no_patched_versions_is_unresolvable() {
        let adv = make_advisory("---\ngem: test\ncve: 2020-0001\npatched_versions: []\n");
        let rem = make_remediation("test", "1.0.0", vec![adv]);
        let results = resolve_fixes(&[rem]);
        assert!(matches!(&results[0], FixResult::Unresolvable { .. }));
    }

    #[test]
    fn empty_remediations() {
        let results = resolve_fixes(&[]);
        assert!(results.is_empty());
    }

    #[test]
    fn complex_multi_advisory_multi_patched() {
        // advisory1: patched by ~> 4.2.5 OR >= 5.0.0
        // advisory2: patched by >= 5.0.1
        // The smallest ~> 4.2.5 is 4.2.5 but that doesn't satisfy advisory2 (>= 5.0.1)
        // The smallest >= 5.0.0 is 5.0.0 but that doesn't satisfy advisory2 (>= 5.0.1)
        // So answer is 5.0.1
        let adv1 = make_advisory(
            "---\ngem: test\ncve: 2020-0001\npatched_versions:\n  - \"~> 4.2.5\"\n  - \">= 5.0.0\"\n",
        );
        let adv2 =
            make_advisory("---\ngem: test\ncve: 2020-0002\npatched_versions:\n  - \">= 5.0.1\"\n");
        let rem = make_remediation("test", "4.2.0", vec![adv1, adv2]);
        let results = resolve_fixes(&[rem]);
        match &results[0] {
            FixResult::Fixed(f) => {
                assert_eq!(f.resolved_version, Version::parse("5.0.1").unwrap());
            }
            _ => panic!("expected Fixed"),
        }
    }
}
