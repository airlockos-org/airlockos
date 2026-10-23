//! Follow local Cargo dependencies while retaining the manifests needed to resolve the workspace.
//! Target-specific dependencies are conservatively included; development dependencies are excluded.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path},
    sync::OnceLock,
};
use toml::Value;

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
    "airlock-config",
    "airlock-tests",
    "airlock-common/nix",
    "airlock-common/machine",
    "airlock-common/deployment",
    "airlock-common/diagnostics",
    "airlock-common/machine-planning",
    "airlock-common/provisioning",
    "airlock-common/build",
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
        MANIFESTS
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
            .collect()
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

/// Expand named feature aliases, preserving dependency activation and forwarding tokens.
fn expanded(manifest: &Value, requested: &BTreeSet<String>) -> BTreeSet<String> {
    let mut result = requested.clone();
    loop {
        let previous = result.clone();
        for name in &previous {
            if let Some(values) = manifest
                .get("features")
                .and_then(|features| features.get(name))
                .and_then(Value::as_array)
            {
                result.extend(
                    values
                        .iter()
                        .map(|value| value.as_str().unwrap().to_owned()),
                );
            }
        }
        if result == previous {
            return result;
        }
    }
}

/// Match Cargo's optional-dependency activation, including implicit and explicitly suppressed features.
fn enabled(manifest: &Value, name: &str, dependency: &Value, features: &BTreeSet<String>) -> bool {
    if dependency.get("optional").and_then(Value::as_bool) != Some(true)
        || features.contains(&format!("dep:{name}"))
        || features.iter().any(|feature| {
            feature
                .strip_prefix(name)
                .is_some_and(|tail| tail.starts_with('/'))
        })
    {
        return true;
    }

    let definitions = manifest.get("features").and_then(Value::as_table);
    let suppressed = definitions.is_some_and(|definitions| {
        definitions.contains_key(name)
            || definitions
                .values()
                .filter_map(Value::as_array)
                .flatten()
                .any(|value| value.as_str() == Some(&format!("dep:{name}")))
    });
    !suppressed && features.contains(name)
}

/// Unify requested local features until no newly activated dependency adds implementation sources.
fn closure(
    packages: &BTreeMap<String, Package>,
    package: &str,
    default_features: bool,
    features: &[&str],
) -> BTreeMap<String, BTreeSet<String>> {
    assert!(
        packages.contains_key(package),
        "package belongs to the source inventory"
    );

    let mut requested: BTreeSet<String> = features
        .iter()
        .map(|feature| (*feature).to_owned())
        .collect();
    if default_features {
        requested.insert("default".into());
    }
    let mut selected = BTreeMap::from([(package.to_owned(), requested)]);

    loop {
        let previous = selected.clone();
        for (name, requested) in &previous {
            let package = &packages[name];
            let features = expanded(&package.manifest, requested);
            for (alias, dependency) in dependencies(&package.manifest) {
                if dependency.get("workspace").and_then(Value::as_bool) == Some(true) {
                    let contents = if package.directory.starts_with("vendor/rusix/") {
                        include_str!("../../../../vendor/rusix/Cargo.toml")
                    } else {
                        include_str!("../../../../Cargo.toml")
                    };
                    let workspace: Value = toml::from_str(contents).unwrap();
                    assert!(
                        workspace["workspace"]
                            .get("dependencies")
                            .and_then(|dependencies| dependencies.get(alias))
                            .and_then(|dependency| dependency.get("path"))
                            .is_none(),
                        "inherited local dependencies require source inventory support"
                    );
                }
                let Some(path) = dependency.get("path").and_then(Value::as_str) else {
                    continue;
                };
                if !enabled(&package.manifest, alias, dependency, &features) {
                    continue;
                }

                let directory = relative(package.directory, path);
                let target = packages
                    .iter()
                    .find(|(_, package)| package.directory == directory)
                    .expect("local dependency belongs to the source inventory")
                    .0;
                let requested = selected.entry(target.clone()).or_default();
                if dependency.get("default-features").and_then(Value::as_bool) != Some(false) {
                    requested.insert("default".into());
                }
                if let Some(values) = dependency.get("features").and_then(Value::as_array) {
                    requested.extend(
                        values
                            .iter()
                            .map(|value| value.as_str().unwrap().to_owned()),
                    );
                }
                for feature in &features {
                    if let Some((name, feature)) = feature.split_once('/')
                        && (name == alias || name.strip_suffix('?') == Some(alias))
                    {
                        requested.insert(feature.to_owned());
                    }
                }
            }
        }
        if selected == previous {
            return selected;
        }
    }
}

/// Return resolution inputs plus the implementation and explicit embedded assets of selected crates.
pub(super) fn sources(
    package: &str,
    default_features: bool,
    features: &[&str],
) -> BTreeSet<String> {
    let packages = packages();
    let selected = closure(packages, package, default_features, features);
    let mut files = BTreeSet::from([
        "Cargo.toml".into(),
        "Cargo.lock".into(),
        "vendor/rusix/Cargo.toml".into(),
        // Cargo discovers these library targets even when resolving an unrelated workspace member.
        // Retaining the entry files avoids fabricated sources or edits to vendored manifests.
        "vendor/rusix/crates/rusix/src/lib.rs".into(),
        "vendor/rusix/crates/rusix-derive/src/lib.rs".into(),
    ]);
    files.extend(
        packages
            .values()
            .map(|package| format!("{directory}/Cargo.toml", directory = package.directory)),
    );

    for name in selected.keys() {
        let package = &packages[name];
        let directory = package.directory;
        files.insert(format!("{directory}/src"));
        if package.manifest["package"]
            .get("build")
            .and_then(Value::as_bool)
            != Some(false)
        {
            let build = package.manifest["package"]
                .get("build")
                .and_then(Value::as_str)
                .unwrap_or("build.rs");
            files.insert(format!("{directory}/{build}"));
        }
        match name.as_str() {
            "airlock-build" => {
                files.insert("airlock-tests/fixtures/memory_accounting.c".into());
            }
            "airlock-config" => {
                files.insert("verus.json".into());
            }
            "airlock-sys-ctrl-gui" => {
                files.insert(format!("{directory}/examples"));
            }
            "airlock-desktop" => {
                files.insert(format!("{directory}/assets"));
            }
            "airlock-tests" => {
                files.insert(format!("{directory}/fixtures/memory_accounting.c"));
                files.insert(format!("{directory}/fixtures/gui"));
            }
            _ => {}
        }
    }
    files
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let root: Value = toml::from_str(include_str!("../../../../Cargo.toml")).unwrap();
        for member in root["workspace"]["members"].as_array().unwrap() {
            assert!(
                packages()
                    .values()
                    .any(|package| Some(package.directory) == member.as_str())
            );
        }

        let original = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let filtered = tempfile::tempdir().unwrap();
        for relative in sources("airlock-diagnostics", true, &[]) {
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
            "filtered workspace failed Cargo resolution: {error}",
            error = String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Compare local closures with Cargo's actual normal/build dependency resolution, including feature boundaries.
    #[test]
    fn local_feature_closures_match_cargo() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
        let cases = packages()
            .keys()
            .map(|name| (name.as_str(), true, Vec::new()))
            .chain([
                ("airlock-image", false, vec![]),
                ("airlock-dom0-service", false, vec![]),
                ("airlock-tests", false, vec![]),
                ("airlock-sys-gui-service", false, vec!["authoring"]),
                ("airlock-nix-core", true, vec!["artifacts"]),
            ]);
        for (name, defaults, features) in cases {
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
            let expected: BTreeSet<_> = closure(packages(), name, defaults, &features)
                .into_keys()
                .collect();
            assert_eq!(
                actual, expected,
                "{name}: defaults={defaults}, features={features:?}"
            );
        }
    }
}
