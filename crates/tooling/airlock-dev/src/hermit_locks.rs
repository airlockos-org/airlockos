//! Let Cargo regenerate the exact projected application workspaces. TOML is
//! decoded/encoded by the existing library; Nix's vendor catalog is a union of
//! locked source identities, not a second dependency resolver.

use crate::support;
use anyhow::{Context, Result, ensure};
use std::{collections::BTreeMap, fs, path::Path, process::Command};

/// Read a source-owned lock/manifest through the maintained TOML implementation.
fn read(path: &Path) -> Result<toml::Value> {
    Ok(toml::from_str(&fs::read_to_string(path)?)?)
}

/// Patch only an exact reviewed transport source to the same local path as Nix.
fn dependencies(table: &mut toml::Value, revision: &str) -> Result<()> {
    if let Some(dependency) = table.get_mut("xen-transport") {
        ensure!(
            dependency.get("git").and_then(toml::Value::as_str)
                == Some("https://github.com/airlockos-org/hermit-xen")
                && dependency.get("rev").and_then(toml::Value::as_str) == Some(revision),
            "transport differs from the committed integration revision"
        );
        let dependency = dependency
            .as_table_mut()
            .context("transport dependency table")?;
        dependency.remove("git");
        dependency.remove("rev");
        dependency.insert(
            "path".into(),
            "../../../.hermit-xen/crates/xen-transport".into(),
        );
    }
    Ok(())
}

/// Export the same manifest changes used by the production source projection.
fn manifest(path: &Path, revision: &str) -> Result<()> {
    let mut value = read(path)?;
    if let Some(table) = value.get_mut("dependencies") {
        dependencies(table, revision)?;
    }
    if let Some(targets) = value.get_mut("target").and_then(toml::Value::as_table_mut) {
        for (_, target) in targets.iter_mut() {
            if let Some(table) = target.get_mut("dependencies") {
                dependencies(table, revision)?;
            }
        }
    }
    fs::write(path, toml::to_string(&value)?)?;
    Ok(())
}

/// Collect unique registry/Git identities. Cargo owns the actual application
/// graph in lab.lock; this catalog only tells fetchCargoVendor which exact source
/// trees/checksums to retain, including the separately pinned Rust standard library.
fn catalog(kernel: &toml::Value, application: &toml::Value) -> Result<String> {
    let mut packages = BTreeMap::new();
    for lock in [kernel, application] {
        for package in lock
            .get("package")
            .and_then(toml::Value::as_array)
            .context("lock packages")?
        {
            let Some(source) = package.get("source").and_then(toml::Value::as_str) else {
                continue;
            };
            let key = (
                package
                    .get("name")
                    .and_then(toml::Value::as_str)
                    .context("package name")?
                    .to_owned(),
                package
                    .get("version")
                    .and_then(toml::Value::as_str)
                    .context("package version")?
                    .to_owned(),
                source.to_owned(),
            );
            let mut package = package.clone();
            package
                .as_table_mut()
                .context("package record")?
                .remove("dependencies");
            if let Some(previous) = packages.insert(key, package.clone()) {
                ensure!(previous == package, "conflicting locked source checksums");
            }
        }
    }
    Ok(toml::to_string(
        &serde_json::json!({"version":4, "package":packages.into_values().collect::<Vec<_>>()}),
    )?)
}

/// Regenerate source-owned locks only; no image evaluation, build, test or deployment occurs.
pub(crate) fn run(root: &Path, integration: &Path) -> Result<u8> {
    ensure!(
        support::git(
            integration,
            &["status", "--porcelain", "--untracked-files=no"]
        )?
        .is_empty(),
        "integration must match its committed pins"
    );
    let revision = support::git(integration, &["rev-parse", "HEAD"])?;
    let kernel = read(&integration.join("nix/hermit-deps.lock"))?;
    for source in airlock_build::hermit::APPLICATIONS {
        let temporary = tempfile::tempdir()?;
        let directory = temporary.path();
        for member in source.members {
            let target = directory.join("crates").join(member);
            fs::create_dir_all(target.parent().context("member parent")?)?;
            support::output(
                Command::new("cp")
                    .args(["-a", "--"])
                    .arg(root.join("crates").join(member))
                    .arg(&target),
            )?;
            manifest(&target.join("Cargo.toml"), &revision)?;
        }
        fs::create_dir_all(directory.join(".hermit-xen/crates"))?;
        support::output(
            Command::new("cp")
                .args(["-a", "--"])
                .arg(integration.join("crates/xen-transport"))
                .arg(directory.join(".hermit-xen/crates")),
        )?;
        fs::copy(root.join("crates/Cargo.lock"), directory.join("Cargo.lock"))?;
        let workspace = serde_json::json!({
            "workspace":{"resolver":"3", "members":source.members.iter().map(|member| format!("crates/{member}")).collect::<Vec<_>>(), "exclude":[".hermit-xen/crates/xen-transport"]},
            "profile":{"release":{"debug":2,"strip":false}}
        });
        fs::write(directory.join("Cargo.toml"), toml::to_string(&workspace)?)?;
        support::output(
            Command::new("cargo")
                .args(["update", "--workspace", "--offline"])
                .current_dir(directory),
        )?;
        let destination = root
            .join("crates/runtime")
            .join(format!("airlock-{binary}", binary = source.binary));
        let lock = read(&directory.join("Cargo.lock"))?;
        fs::copy(directory.join("Cargo.lock"), destination.join("lab.lock"))?;
        fs::write(destination.join("build.lock"), catalog(&kernel, &lock)?)?;
    }
    Ok(0)
}
