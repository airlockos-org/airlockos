//! Follow local Cargo dependencies while retaining the manifests needed to resolve the workspace.
//! Target-specific dependencies are conservatively included; development dependencies are excluded.

use std::{
    collections::BTreeMap,
    path::{Component, Path},
    sync::OnceLock,
};
use toml::Value;

#[cfg(test)]
use std::collections::BTreeSet;

mod lowering;

/// One local package, including vendored authoring libraries outside the application workspace.
struct Package {
    // Workspace-relative directory, also used to resolve path dependencies without filesystem I/O.
    directory: &'static str,
    // Cargo's declarations, embedded so source generation needs neither Cargo nor checkout access.
    manifest: Value,
}

/// Embed declarations rather than maintain a second dependency graph beside Cargo.
macro_rules! manifests {
    ($($directory:literal),+ $(,)?) => {
        &[$(($directory, include_str!(concat!("../../../../", $directory, "/Cargo.toml")))),+]
    };
}

const MANIFESTS: &[(&str, &str)] = manifests![
    "airlock-clipboard-core",
    "airlock-sys-clipboard",
    "airlock-config",
    "airlock-tests",
    "airlock-common/nix",
    "airlock-store-packer",
    "airlock-common/machine",
    "airlock-common/deployment",
    "airlock-common/diagnostics",
    "airlock-common/machine-planning",
    "airlock-common/provisioning",
    "airlock-common/build",
    "airlock-common/build-plan",
    "airlock-common/desktop",
    "airlock-common/qubes",
    "airlock-qubes-python",
    "airlock-cli",
    "airlock-image",
    "airlock-dev",
    "airlock-dom0/service",
    "airlock-sys-ctrl/gui",
    "airlock-sys-ctrl/service",
    "airlock-sys-gui/service",
    "airlock-sys-gui/setup",
    "airlock-vm/service",
    "airlock-vm/init",
    "vendor/rusix/crates/rusix",
    "vendor/rusix/crates/rusix-derive",
];

/// Parse each embedded manifest once, independently of the application source path supplied to Nix.
fn packages() -> &'static BTreeMap<String, Package> {
    static PACKAGES: OnceLock<BTreeMap<String, Package>> = OnceLock::new();
    PACKAGES.get_or_init(|| {
        let packages: BTreeMap<_, _> = MANIFESTS
            .iter()
            .map(|&(directory, contents)| {
                let manifest: Value =
                    toml::from_str(contents).expect("Cargo already parsed this manifest");
                let name = manifest["package"]["name"].as_str().unwrap().to_owned();
                (
                    name,
                    Package {
                        directory,
                        manifest,
                    },
                )
            })
            .collect();
        assert_eq!(
            packages.len(),
            MANIFESTS.len(),
            "duplicate package identity in source inventory"
        );
        let workspace: Value = toml::from_str(include_str!("../../../../Cargo.toml")).unwrap();
        for member in workspace["workspace"]["members"]
            .as_array()
            .expect("explicit workspace membership")
        {
            let member = member.as_str().expect("explicit workspace member path");
            assert!(
                packages.values().any(|package| package.directory == member),
                "workspace member absent from source inventory: {member}"
            );
        }
        packages
    })
}

/// Resolve an internal path lexically; generation must not inspect the caller's checkout.
fn relative(directory: &str, dependency: &str) -> String {
    let mut parts = Vec::new();
    let path = Path::new(directory).join(dependency);
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_str().unwrap()),
            Component::ParentDir => {
                parts
                    .pop()
                    .expect("local dependency stays inside the workspace");
            }
            Component::CurDir => {}
            _ => panic!("local dependency path must be relative"),
        }
    }
    parts.join("/")
}

/// Include normal and build edges for every platform supported by the same source tree.
fn dependencies(manifest: &Value) -> Vec<(&str, &Value)> {
    let sections = std::iter::once(manifest).chain(
        manifest
            .get("target")
            .and_then(Value::as_table)
            .into_iter()
            .flat_map(|targets| targets.values()),
    );
    sections
        .flat_map(|section| {
            ["dependencies", "build-dependencies"]
                .into_iter()
                .filter_map(move |kind| section.get(kind).and_then(Value::as_table))
                .flat_map(|table| table.iter().map(|(name, value)| (name.as_str(), value)))
        })
        .collect()
}

/// Interpret declarations outside the proof boundary, then use the verified solver and projection.
pub(super) fn checked(
    package: &str,
    default_features: bool,
    features: &[&str],
) -> airlock_build_plan::CheckedPackageSource {
    lowering::checked(packages(), package, default_features, features)
}

/// Materialize exactly the production-selected paths for isolated Cargo tests.
#[cfg(test)]
fn sources(package: &str, defaults: bool, features: &[&str]) -> BTreeSet<String> {
    let plan = checked(package, defaults, features);
    (0..plan.file_count())
        .map(|i| plan.file(i).unwrap().path.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Production profiles and distinct minimal/authoring feature configurations share the same checks.
    fn profiles() -> Vec<(&'static str, bool, Vec<&'static str>)> {
        packages()
            .keys()
            .map(|name| (name.as_str(), true, Vec::new()))
            .chain([
                ("airlock-image", false, vec![]),
                ("airlock-dom0-service", false, vec![]),
                ("airlock-tests", false, vec![]),
                ("airlock-sys-gui-service", false, vec!["authoring"]),
                ("airlock-nix-core", true, vec!["artifacts"]),
                ("airlock-diagnostics", true, vec!["runtime"]),
            ])
            .collect()
    }

    /// Materialize exactly the chosen file set; do not supply omitted implementation entry points.
    fn copy_input(source: &Path, destination: &Path) -> std::io::Result<()> {
        if source.is_dir() {
            std::fs::create_dir_all(destination)?;
            for entry in std::fs::read_dir(source)? {
                let entry = entry?;
                copy_input(&entry.path(), &destination.join(entry.file_name()))?;
            }
        } else if source.is_file() {
            std::fs::create_dir_all(destination.parent().unwrap())?;
            std::fs::copy(source, destination)?;
        }
        Ok(())
    }

    /// Every workspace member must remain resolvable when unrelated implementations are omitted.
    #[test]
    fn inventory_covers_workspace_members() {
        let original = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for (package, defaults, features) in profiles() {
            let filtered = tempfile::tempdir().unwrap();
            for relative in sources(package, defaults, &features) {
                copy_input(&original.join(&relative), &filtered.path().join(&relative)).unwrap();
            }
            let output = std::process::Command::new(env!("CARGO"))
                .args([
                    "metadata",
                    "--offline",
                    "--locked",
                    "--no-deps",
                    "--format-version",
                    "1",
                    "--manifest-path",
                ])
                .arg(filtered.path().join("Cargo.toml"))
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "filtered workspace for {package} failed Cargo resolution: {error}",
                error = String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    /// Compare local closures with Cargo's actual normal/build dependency resolution, including feature boundaries.
    #[test]
    fn local_feature_closures_match_cargo() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
        for (name, defaults, features) in profiles() {
            let mut command = std::process::Command::new(env!("CARGO"));
            command
                .args(["tree", "--locked", "--offline", "--manifest-path"])
                .arg(&root)
                .args([
                    "-p",
                    name,
                    "--prefix",
                    "none",
                    "--format",
                    "{p}",
                    "--edges",
                    "normal,build",
                    "--target",
                    "all",
                ]);
            if !defaults {
                command.arg("--no-default-features");
            }
            if !features.is_empty() {
                command.args(["--features", &features.join(",")]);
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "{error}",
                error = String::from_utf8_lossy(&output.stderr)
            );
            let actual: BTreeSet<_> = String::from_utf8(output.stdout)
                .unwrap()
                .lines()
                .filter_map(|line| line.split_whitespace().next())
                .filter(|name| packages().contains_key(*name))
                .map(str::to_owned)
                .collect();
            let plan = checked(name, defaults, &features);
            let expected: BTreeSet<_> = packages()
                .keys()
                .enumerate()
                .filter(|(index, _)| plan.includes(*index))
                .map(|(_, name)| name.clone())
                .collect();
            assert_eq!(
                actual, expected,
                "{name}: defaults={defaults}, features={features:?}"
            );
        }
    }
}
