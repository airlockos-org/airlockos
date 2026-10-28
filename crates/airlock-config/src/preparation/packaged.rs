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
}
