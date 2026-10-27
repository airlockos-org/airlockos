//! Prepare and build isolated clipboard lab artifacts from two local worktrees.
//! Generated Nix and the reduced Cargo workspace remain outside version control.
use anyhow::{Context, Result, bail, ensure};
use std::{fs, path::Path, process::Command};

/// Copy explicitly selected source directories, rejecting symlinks and special files.
fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let target = to.join(entry.file_name());
        if kind.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else if kind.is_file() {
            fs::copy(entry.path(), target)?;
        } else {
            bail!(
                "source must contain ordinary files: {path}",
                path = entry.path().display()
            );
        }
    }
    Ok(())
}

/// Execute a build command and propagate failure without claiming a verified guest.
fn checked(command: &mut Command) -> Result<()> {
    let status = command
        .status()
        .with_context(|| format!("launch {command:?}"))?;
    ensure!(status.success(), "command failed: {command:?}: {status}");
    Ok(())
}

/// Quote an external path for generated Nix; prevent interpolation in path text.
fn nix_string(value: &str) -> String {
    serde_json::to_string(value).unwrap().replace("${", "\\${")
}

/// Replace the reviewed Git transport with the same local source in the lab projection.
/// Native builds keep the portable Git pin; isolated Nix builds use only copied files.
fn local_manifest(contents: &str, revision: &str) -> Result<String> {
    let mut manifest: toml::Value = toml::from_str(contents)?;
    let replace = |section: &mut toml::Value| -> Result<()> {
        let Some(dependency) = section
            .get_mut("dependencies")
            .and_then(|table| table.get_mut("xen-transport"))
        else {
            return Ok(());
        };
        let table = dependency
            .as_table_mut()
            .context("transport dependency table")?;
        ensure!(
            table.get("git").and_then(toml::Value::as_str)
                == Some("https://github.com/airlockos-org/hermit-xen"),
            "unexpected transport source"
        );
        ensure!(
            table.get("rev").and_then(toml::Value::as_str) == Some(revision),
            "local Hermit HEAD must match the committed Cargo transport pin"
        );
        table.remove("git");
        table.remove("rev");
        table.insert(
            "path".into(),
            toml::Value::String("../../../.hermit-xen/crates/xen-transport".into()),
        );
        Ok(())
    };
    replace(&mut manifest)?;
    if let Some(targets) = manifest
        .get_mut("target")
        .and_then(toml::Value::as_table_mut)
    {
        for (_, target) in targets.iter_mut() {
            replace(target)?;
        }
    }
    Ok(toml::to_string_pretty(&manifest)?)
}

/// Prepare only the clipboard crates, matching transport and pinned lab lock.
/// The command deliberately has no physical-machine deployment path.
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 3,
        "usage: clipboard-lab HERMIT_XEN_WORKTREE prepare|build|test|peer-failure"
    );
    ensure!(
        matches!(
            args[2].as_str(),
            "prepare" | "build" | "test" | "peer-failure"
        ),
        "unknown command"
    );

    let hermit = fs::canonicalize(&args[1])?;
    ensure!(
        hermit.join("nix/application.nix").is_file(),
        "expected local hermit-xen checkout"
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    ensure!(
        fs::canonicalize(root.join(".hermit-xen"))? == hermit,
        "the .hermit-xen dependency link must select the same local worktree as the builder"
    );

    let revision = Command::new("git")
        .current_dir(&hermit)
        .args(["rev-parse", "HEAD"])
        .output()?;
    ensure!(revision.status.success(), "read local Hermit revision");
    let revision = String::from_utf8(revision.stdout)?;
    checked(Command::new("git").current_dir(&hermit).args([
        "diff",
        "--exit-code",
        "HEAD",
        "--",
        "crates/xen-transport",
    ]))?;

    let output = root.join(".airlock-logs/clipboard");
    fs::create_dir_all(&output)?;
    let source = output.join("source");
    // This directory contains only this tool's generated source projection.
    if source.exists() {
        fs::remove_dir_all(&source)?;
    }
    fs::create_dir_all(source.join("crates"))?;
    for name in ["airlock-common/clipboard", "runtime/airlock-sys-clipboard"] {
        let from = root.join("crates").join(name);
        let to = source.join("crates").join(name);
        copy_tree(&from.join("src"), &to.join("src"))?;
        let manifest = fs::read_to_string(from.join("Cargo.toml"))?;
        fs::write(
            to.join("Cargo.toml"),
            local_manifest(&manifest, revision.trim())?,
        )?;
    }
    let transport = source.join(".hermit-xen/crates/xen-transport");
    copy_tree(
        &hermit.join("crates/xen-transport/src"),
        &transport.join("src"),
    )?;
    fs::copy(
        hermit.join("crates/xen-transport/Cargo.toml"),
        transport.join("Cargo.toml"),
    )?;
    fs::write(
        source.join("Cargo.toml"),
        r#"[workspace]
resolver = "3"
members = ["crates/airlock-common/clipboard", "crates/runtime/airlock-sys-clipboard"]
exclude = [".hermit-xen/crates/xen-transport"]

[profile.release]
debug = 2
strip = false
"#,
    )?;
    fs::copy(
        root.join("crates/runtime/airlock-sys-clipboard/lab.lock"),
        source.join("Cargo.lock"),
    )?;
    // Source selection is local and explicit. Nix's Git source includes the pinned
    // locally checked-out submodules; there is no published-repository fallback.
    let input = nix_string(&format!(
        "git+file://{path}?submodules=1",
        path = hermit.display()
    ));
    fs::write(
        output.join("flake.nix"),
        format!(
            r#"{{
  inputs.hermit-xen.url = {input};
  outputs = {{ self, hermit-xen }}:
    let source = builtins.path {{ path = ./source; name = "clipboard-source"; }};
    in {{
    packages.x86_64-linux = {{
      service = hermit-xen.lib.x86_64-linux.buildHermitApplication {{
        src = source;
        bin = "sys-clipboard";
        features = [ "lab-authority" ];
      }};
      peer = hermit-xen.lib.x86_64-linux.buildLinuxApplication {{
        src = source;
        bin = "clipboard-peer";
        features = [ "linux-peer" ];
      }};
    }};
  }};
}}
"#
        ),
    )?;
    // Record both source revisions and exact local diffs alongside content-addressed
    // build provenance. Logs are outside Git; local edits must never look published.
    for (name, directory) in [("airlock", root), ("hermit-xen", hermit.as_path())] {
        for (suffix, arguments) in [
            ("revision", vec!["rev-parse", "HEAD"]),
            ("diff", vec!["diff", "HEAD"]),
        ] {
            let result = Command::new("git")
                .current_dir(directory)
                .args(arguments)
                .output()?;
            ensure!(result.status.success(), "record {name} {suffix}");
            fs::write(output.join(format!("{name}-{suffix}.txt")), result.stdout)?;
        }
    }
    if args[2] == "prepare" {
        println!("{path}", path = output.display());
        return Ok(());
    }
    // Refresh only the local input; other pins come from hermit-xen's committed lock.
    checked(Command::new("nix").current_dir(&output).args([
        "flake",
        "update",
        "hermit-xen",
        "--flake",
        &format!("path:{path}", path = output.display()),
    ]))?;
    for package in ["service", "peer"] {
        checked(Command::new("nix").current_dir(&output).args([
            "build",
            "-L",
            &format!("path:{path}#{package}", path = output.display()),
            "-o",
            package,
        ]))?;
    }
    if args[2] != "build" {
        let service = output.join("service/kernel.elf");
        let peer = output.join("peer/bin/clipboard-peer");
        checked(
            Command::new("nix")
                .current_dir(&hermit)
                .args([
                    "develop", "-c", "cargo", "run", "--locked", "--", "test", "--guest",
                    "service", "--kernel",
                ])
                .arg(service)
                .arg("--peer")
                .arg(peer)
                .args([
                    "--expect",
                    "AIRLOCK_CLIPBOARD_PASS",
                    "--peer-expect",
                    "AIRLOCK_CLIPBOARD_PEER_PASS",
                    "--cycles",
                    "2",
                    "--ipc-case",
                    if args[2] == "peer-failure" {
                        "peer-failure"
                    } else {
                        "normal"
                    },
                ]),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_projection_rejects_links_outside_the_selected_tree() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("ordinary"), "content").unwrap();
        let destination = temporary.path().join("destination");
        copy_tree(&source, &destination).unwrap();
        assert_eq!(
            fs::read_to_string(destination.join("ordinary")).unwrap(),
            "content"
        );

        std::os::unix::fs::symlink("/outside", source.join("link")).unwrap();
        assert!(copy_tree(&source, &destination).is_err());
        assert!(!destination.join("link").exists());
    }

    #[test]
    fn local_projection_preserves_features_and_rejects_wrong_revisions() {
        let source = r#"[package]
name = "consumer"
[dependencies]
xen-transport = { git = "https://github.com/airlockos-org/hermit-xen", rev = "reviewed", features = ["linux"] }
"#;
        let manifest: toml::Value =
            toml::from_str(&local_manifest(source, "reviewed").unwrap()).unwrap();
        assert_eq!(
            manifest["dependencies"]["xen-transport"]["features"][0].as_str(),
            Some("linux")
        );
        assert!(
            manifest["dependencies"]["xen-transport"]
                .get("git")
                .is_none()
        );
        assert!(local_manifest(source, "different").is_err());
    }

    #[test]
    fn generated_paths_cannot_interpolate_nix_expressions() {
        assert_eq!(nix_string("${untrusted}"), r#""\${untrusted}""#);
        assert_eq!(nix_string("quote\""), r#""quote\"""#);
    }
}
