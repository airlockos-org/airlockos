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

/// Prepare only the clipboard crates, matching transport and pinned lab lock.
/// The command deliberately has no physical-machine deployment path.
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 3,
        "usage: clipboard-lab HERMIT_XEN_WORKTREE prepare|build|test|peer-failure"
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
        .unwrap();
    let output = root.join(".airlock-logs/clipboard");
    fs::create_dir_all(&output)?;
    let source = output.join("source");
    // This directory contains only this tool's generated source projection.
    if source.exists() {
        fs::remove_dir_all(&source)?;
    }
    fs::create_dir_all(source.join("crates"))?;
    for name in ["airlock-clipboard-core", "airlock-sys-clipboard"] {
        let from = root.join("crates").join(name);
        let to = source.join("crates").join(name);
        copy_tree(&from.join("src"), &to.join("src"))?;
        fs::copy(from.join("Cargo.toml"), to.join("Cargo.toml"))?;
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
members = ["crates/airlock-clipboard-core", "crates/airlock-sys-clipboard"]
exclude = [".hermit-xen/crates/xen-transport"]

[profile.release]
debug = 2
strip = false
"#,
    )?;
    fs::copy(
        root.join("crates/airlock-sys-clipboard/lab.lock"),
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
  outputs = {{ self, hermit-xen }}: {{
    packages.x86_64-linux = {{
      service = hermit-xen.lib.x86_64-linux.buildHermitApplication {{
        src = ./source;
        bin = "sys-clipboard";
        features = [ "lab-authority" ];
      }};
      peer = hermit-xen.lib.x86_64-linux.buildLinuxApplication {{
        src = ./source;
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
    ensure!(
        matches!(args[2].as_str(), "build" | "test" | "peer-failure"),
        "unknown command"
    );
    // Refresh only the local input; other pins come from hermit-xen's committed lock.
    checked(
        Command::new("nix")
            .current_dir(&output)
            .args(["flake", "update", "hermit-xen"]),
    )?;
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
