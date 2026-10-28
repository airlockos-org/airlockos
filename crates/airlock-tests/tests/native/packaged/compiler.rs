//! Exercise the image-built compiler against a fresh checkout with no Cargo target directory.

use super::*;
use airlock_tests::repository::git;

/// Package-only edits prepare fresh source without Cargo; changed Rust selects the compilation fallback.
#[test]
#[ignore = "explicit guarded-store machine compiler build"]
fn package_machine_compiler_reuses_only_matching_rust_inputs() -> Result<()> {
    let packages = Packages::new("machine-compiler")?;
    let reference = format!(
        "path:{source}/airlock-machine#airlock-machine-compiler",
        source = packages.source.display()
    );
    let applications = format!("path:{source}/crates", source = packages.source.display());
    let qubes = format!(
        "path:{source}/crates/vendor/nixos-qubes",
        source = packages.source.display()
    );
    let built: Value = serde_json::from_slice(&packages.nix(
        "build",
        &[
            "build",
            &reference,
            "--override-input",
            "airlock-apps",
            &applications,
            "--override-input",
            "nixos-qubes",
            &qubes,
            "--no-write-lock-file",
            "--no-link",
            "--json",
        ],
    )?)?;
    let output = built[0]["outputs"]["out"]
        .as_str()
        .context("compiler output")?;
    let manifest: Value =
        serde_json::from_slice(&fs::read(packages.physical(output)?.join("compiler.json"))?)?;
    ensure!(
        manifest["reusable"] == true,
        "baseline compiler must be reusable"
    );

    let temporary = tempfile::tempdir()?;
    let checkout = temporary.path().join("machine");
    common::run(
        Command::new("git")
            .args(["clone", "--quiet", "--no-hardlinks"])
            .arg(common::root().join("airlock-machine"))
            .arg(&checkout),
        None,
    )?
    .checked()?;
    git(&checkout, &["config", "user.name", "Fixture"])?;
    git(
        &checkout,
        &["config", "user.email", "fixture@example.invalid"],
    )?;
    let module = checkout.join("vms/usr-home.nix");
    let content = format!(
        "{}\n# package-only change captured by the prepared source\n",
        fs::read_to_string(&module)?
    );
    fs::write(&module, &content)?;
    git(&checkout, &["commit", "-qam", "Change user VM module"])?;

    let execute = || -> Result<airlock_vm_service::support::Output> {
        common::run(
            packages
                .runtime(&format!("{output}/airlock-machine-config"))
                .current_dir(&checkout)
                .env(
                    "AIRLOCK_APPS",
                    manifest["applications"]
                        .as_str()
                        .context("admitted applications")?,
                )
                .arg("prepare-installed")
                .arg(temporary.path().join("prepared")),
            None,
        )
    };
    let start = std::time::Instant::now();
    let reply = String::from_utf8(execute()?.checked()?)?;
    let prepared = PathBuf::from(
        reply
            .trim()
            .strip_prefix("path:")
            .context("installed compiler cache miss")?,
    );
    assert_eq!(
        fs::read_to_string(prepared.join("vms/usr-home.nix"))?,
        content
    );
    assert!(
        !checkout.join("target").exists(),
        "installed path must not invoke Cargo"
    );
    fs::write(
        packages.logs.join("preparation-seconds.json"),
        serde_json::to_vec(&json!({"seconds":start.elapsed().as_secs_f64()}))?,
    )?;

    fs::write(checkout.join("src/main.rs"), "// changed compiler source\n")?;
    assert!(
        execute()?.checked()?.is_empty(),
        "changed Rust must return a cache miss"
    );
    Ok(())
}
