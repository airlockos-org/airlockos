//! Reuse an image-built machine compiler only while its actual source inputs still match.
//! The binary still snapshots the new approved checkout and emits fresh configuration.

use super::{Result, digest};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

/// Build-time evidence shipped beside the immutable executable.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    /// Exact admitted application source tree used to link the compiler.
    applications: PathBuf,
    /// Machine inputs, including explicit absence of optional Cargo configuration.
    inputs: BTreeMap<String, Option<String>>,
    /// Custom build scripts can discover inputs outside rustc's dep-info; use Cargo for those machines.
    reusable: bool,
}

/// Split rustc's Make dep-info prerequisites, including escaped whitespace and continuation lines.
fn dependencies(text: &str) -> Result<Vec<PathBuf>> {
    let first = text.split("\n\n").next().ok_or("empty compiler dep-info")?;
    let (_, inputs) = first.split_once(": ").ok_or("invalid compiler dep-info")?;
    let mut paths = Vec::new();
    let mut word = String::new();
    let mut escaped = false;
    for character in inputs.chars() {
        if escaped {
            if character != '\n' {
                word.push(character);
            }
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character.is_whitespace() {
            if !word.is_empty() {
                paths.push(PathBuf::from(std::mem::take(&mut word)));
            }
        } else {
            word.push(character);
        }
    }
    if escaped {
        return Err("truncated compiler dep-info".into());
    }
    if !word.is_empty() {
        paths.push(PathBuf::from(word));
    }
    Ok(paths)
}

/// Hash a present source input while distinguishing a missing optional input from an I/O error.
fn optional_digest(path: &Path) -> Result<Option<String>> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(Some(digest(path)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Copy the just-built executable and record rustc's source dependencies, never its build directory.
pub(super) fn install(source: &Path, destination: &Path, metadata: &Path) -> Result<()> {
    let source = fs::canonicalize(source)?;
    let executable = std::env::current_exe()?;
    let dep_info = fs::read_to_string(executable.with_extension("d"))?;
    let metadata: serde_json::Value = serde_json::from_slice(&fs::read(metadata)?)?;
    let mut reusable = !metadata["packages"]
        .as_array()
        .ok_or("missing Cargo package metadata")?
        .iter()
        .flat_map(|package| package["targets"].as_array().into_iter().flatten())
        .any(|target| {
            target["kind"]
                .as_array()
                .is_some_and(|kinds| kinds.iter().any(|kind| kind == "custom-build"))
        });
    let mut inputs = BTreeMap::new();
    for dependency in dependencies(&dep_info)? {
        let original = source.join(dependency);
        // A mutable symlink could change the resolved input without changing its old target.
        for ancestor in original
            .ancestors()
            .take_while(|path| path.starts_with(&source))
        {
            if fs::symlink_metadata(ancestor)?.file_type().is_symlink() {
                reusable = false;
            }
        }
        let path = fs::canonicalize(original)?;
        if let Ok(relative) = path.strip_prefix(&source) {
            inputs.insert(
                relative
                    .to_str()
                    .ok_or("non-UTF-8 compiler input")?
                    .to_owned(),
                Some(digest(&path)?),
            );
        }
    }
    for package in metadata["packages"]
        .as_array()
        .ok_or("missing Cargo package metadata")?
    {
        let path = Path::new(
            package["manifest_path"]
                .as_str()
                .ok_or("missing Cargo manifest path")?,
        );
        if let Ok(relative) = path.strip_prefix(&source) {
            inputs.insert(
                relative
                    .to_str()
                    .ok_or("non-UTF-8 Cargo manifest")?
                    .to_owned(),
                Some(digest(path)?),
            );
            let script = relative
                .parent()
                .ok_or("Cargo package directory")?
                .join("build.rs");
            inputs.insert(
                script.to_str().ok_or("non-UTF-8 build script")?.to_owned(),
                optional_digest(&source.join(&script))?,
            );
        }
    }
    // Cargo may discover these files without rustc listing them. Detect newly added overrides too.
    for name in [
        "Cargo.toml",
        "Cargo.lock",
        "application-revision",
        "Makefile",
        "build.rs",
        ".cargo/config",
        ".cargo/config.toml",
    ] {
        inputs.insert(name.into(), optional_digest(&source.join(name))?);
    }
    if !inputs.contains_key("src/main.rs") {
        return Err("compiler dep-info omitted the machine entry point".into());
    }
    let manifest = Manifest {
        applications: PathBuf::from(
            std::env::var_os("AIRLOCK_ADMITTED_APPS")
                .ok_or("missing admitted application source")?,
        ),
        inputs,
        reusable,
    };
    fs::create_dir_all(destination)?;
    fs::copy(executable, destination.join("airlock-machine-config"))?;
    fs::write(
        destination.join("compiler.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(())
}

/// Capture stable compiler inputs separately from runtime Nix modules and Git provenance.
/// rustc dep-info preserves explicitly embedded modules. Unknown dependency evidence,
/// custom build scripts and symlinks conservatively retain the complete source.
/// This filters build inputs only: Cargo compiles this captured source again, and
/// the packaged compiler still snapshots and validates the full reviewed checkout.
pub(super) fn source(source: &Path, destination: &Path) -> Result<()> {
    let executable = std::env::current_exe()?;
    let package = executable.parent().ok_or("compiler package directory")?;
    let receipt = package.join("compiler.json");
    let inputs = if receipt.is_file() {
        let manifest: Manifest = serde_json::from_slice(&fs::read(receipt)?)?;
        manifest.reusable.then(|| {
            manifest
                .inputs
                .into_keys()
                .collect::<std::collections::BTreeSet<_>>()
        })
    } else if executable.with_extension("d").is_file() {
        let root = fs::canonicalize(
            std::env::var_os("AIRLOCK_MACHINE_COMPILER_SOURCE")
                .map(PathBuf::from)
                .unwrap_or(std::env::current_dir()?),
        )?;
        Some(
            dependencies(&fs::read_to_string(executable.with_extension("d"))?)?
                .into_iter()
                .filter_map(|path| {
                    root.join(path)
                        .strip_prefix(&root)
                        .ok()
                        .map(|path| path.to_string_lossy().into_owned())
                })
                .collect(),
        )
    } else {
        None
    };
    let mut files = BTreeMap::new();
    super::inventory(source, source, &mut files)?;
    capture(source, destination, &files, inputs.as_ref())
}

/// Preserve Cargo controls and arbitrary assets; omit only known runtime inputs
/// when compiler dependency evidence establishes that Rust did not embed them.
fn capture(
    source: &Path,
    destination: &Path,
    files: &BTreeMap<String, String>,
    embedded: Option<&std::collections::BTreeSet<String>>,
) -> Result<()> {
    let embedded = embedded.filter(|_| {
        !files.keys().any(|name| {
            Path::new(name)
                .file_name()
                .is_some_and(|name| name == "build.rs")
                || fs::symlink_metadata(source.join(name))
                    .is_ok_and(|metadata| metadata.file_type().is_symlink())
        })
    });
    for name in files.keys() {
        let runtime = name == "airlock-source.json"
            || name == "flake.lock"
            || (name.starts_with("vms/")
                && Path::new(name)
                    .extension()
                    .is_some_and(|extension| extension == "nix"));
        if embedded.is_some_and(|inputs| runtime && !inputs.contains(name)) {
            continue;
        }
        let from = source.join(name);
        let to = destination.join(name);
        fs::create_dir_all(to.parent().ok_or("compiler input parent")?)?;
        if fs::symlink_metadata(&from)?.file_type().is_symlink() {
            std::os::unix::fs::symlink(fs::read_link(from)?, to)?;
        } else {
            fs::copy(from, to)?;
        }
    }
    Ok(())
}

/// Reject a changed Rust input, lock, build script, Cargo override or admitted application tree.
/// User Nix modules remain runtime inputs unless rustc explicitly embedded one in the executable.
pub(super) fn matches(source: &Path, package: &Path) -> Result<bool> {
    let manifest: Manifest = serde_json::from_slice(&fs::read(package.join("compiler.json"))?)?;
    let applications = std::env::var_os("AIRLOCK_APPS")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/airlock/config-inputs/airlock-apps"));
    if !manifest.reusable || fs::canonicalize(applications)? != manifest.applications {
        return Ok(false);
    }
    unchanged(source, &manifest.inputs)
}

/// Compare every recorded input, retaining absence checks for newly introduced Cargo overrides.
fn unchanged(source: &Path, inputs: &BTreeMap<String, Option<String>>) -> Result<bool> {
    for (name, expected) in inputs {
        if !Path::new(&name)
            .components()
            .all(|part| matches!(part, std::path::Component::Normal(_)))
        {
            return Err("invalid packaged compiler input path".into());
        }
        if optional_digest(&source.join(name))?.as_ref() != expected.as_ref() {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Embedded files and paths with spaces survive dep-info decoding; phony targets do not become inputs.
    #[test]
    fn dep_info_keeps_embedded_inputs() -> Result<()> {
        assert_eq!(
            dependencies(
                "/build/target/compiler: /build/src/main.rs /build/vms/my\\ file.nix \\\n/build/src/machine.rs\n\n/build/src/main.rs:\n"
            )?,
            vec![
                PathBuf::from("/build/src/main.rs"),
                PathBuf::from("/build/vms/my file.nix"),
                PathBuf::from("/build/src/machine.rs")
            ]
        );
        Ok(())
    }
    /// Package edits reuse the compiler, while Rust changes, embedded files and new build scripts invalidate it.
    #[test]
    fn compiler_reuse_tracks_compile_inputs() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let source = temporary.path();
        fs::create_dir(source.join("src"))?;
        fs::create_dir(source.join("vms"))?;
        fs::write(source.join("src/main.rs"), "fn main() {}")?;
        fs::write(source.join("vms/usr-home.nix"), "{}")?;
        let mut inputs = BTreeMap::from([
            (
                "src/main.rs".into(),
                optional_digest(&source.join("src/main.rs"))?,
            ),
            ("build.rs".into(), None),
        ]);
        fs::write(
            source.join("vms/usr-home.nix"),
            "{ environment.systemPackages = [ pkgs.firefox ]; }",
        )?;
        assert!(unchanged(source, &inputs)?);

        inputs.insert(
            "vms/usr-home.nix".into(),
            optional_digest(&source.join("vms/usr-home.nix"))?,
        );
        fs::write(source.join("vms/usr-home.nix"), "{}")?;
        assert!(!unchanged(source, &inputs)?);
        inputs.remove("vms/usr-home.nix");
        fs::write(source.join("build.rs"), "fn main() {}")?;
        assert!(!unchanged(source, &inputs)?);
        fs::remove_file(source.join("build.rs"))?;
        fs::write(source.join("src/main.rs"), "fn main() { panic!(); }")?;
        assert!(!unchanged(source, &inputs)?);
        Ok(())
    }

    /// Runtime module/provenance edits preserve compiler inputs; embedded Nix
    /// and Cargo controls remain inputs, and custom build scripts disable filtering.
    #[test]
    fn compiler_source_separates_runtime_modules_and_preserves_embedded_inputs() -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let source = fixture.path().join("source");
        fs::create_dir_all(source.join("vms"))?;
        fs::write(source.join("Cargo.toml"), "manifest")?;
        fs::write(source.join("vms/app.nix"), "runtime module")?;
        fs::write(source.join("vms/embedded.nix"), "embedded module")?;
        fs::write(source.join("airlock-source.json"), "revision one")?;
        let embedded = std::collections::BTreeSet::from(["vms/embedded.nix".to_owned()]);
        let snapshot = |name: &str| -> Result<BTreeMap<String, String>> {
            let mut inputs = BTreeMap::new();
            super::super::inventory(&source, &source, &mut inputs)?;
            let destination = fixture.path().join(name);
            capture(&source, &destination, &inputs, Some(&embedded))?;
            let mut output = BTreeMap::new();
            super::super::inventory(&destination, &destination, &mut output)?;
            Ok(output)
        };
        let first = snapshot("first")?;
        assert!(first.contains_key("Cargo.toml"));
        assert!(first.contains_key("vms/embedded.nix"));
        assert!(!first.contains_key("vms/app.nix"));
        fs::write(source.join("vms/app.nix"), "changed packages")?;
        fs::write(source.join("airlock-source.json"), "revision two")?;
        assert_eq!(first, snapshot("runtime-edit")?);
        fs::write(source.join("vms/embedded.nix"), "changed embedded input")?;
        assert_ne!(first, snapshot("embedded-edit")?);
        fs::write(source.join("Cargo.toml"), "changed compiler options")?;
        assert_ne!(first, snapshot("cargo-edit")?);
        fs::write(source.join("build.rs"), "dynamic inputs")?;
        assert!(snapshot("custom-build")?.contains_key("vms/app.nix"));
        Ok(())
    }
}
