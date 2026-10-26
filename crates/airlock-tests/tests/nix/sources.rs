//! Filtered source trees preserve cache identities across unrelated edits and compile in isolation.

use super::*;
use std::io::Write;

/// Append a harmless comment so source hashing changes without changing compiled behavior.
fn change(path: &Path) -> Result<()> {
    writeln!(
        fs::OpenOptions::new().append(true).open(path)?,
        "\n// source input regression"
    )?;
    Ok(())
}

/// Evaluate source sets and actual package derivations using explicitly pinned local Nix inputs.
fn inspect(root: &Path, workspace: &Path, label: &str, cases: &Value) -> Result<Value> {
    let sources: Value = serde_json::from_slice(&fs::read(
        std::env::var_os("AIRLOCK_RUSIX_SOURCES").context("prepared upstream sources")?,
    )?)?;
    evaluate_fixture(
        root,
        label,
        "workspace/sources",
        json!({
            "workspace":workspace, "nixpkgs":sources["nixpkgsSource"], "cases":cases,
        }),
    )?
    .value()
}

/// Excluded implementation edits retain derivations, required dependencies/assets invalidate them, and all source profiles compile.
#[test]
#[ignore = "explicit offline Nix evaluation and Cargo checks; prepare native libraries and AIRLOCK_FILTERED_CARGO_TARGET_DIR"]
fn filtered_sources_preserve_cache_keys_and_compile() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let workspace = root.join("workspace");
    let original = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    copy_tree(original, &workspace)?;
    let metadata: Value = serde_json::from_slice(
        &common::run(
            Command::new("cargo")
                .args([
                    "metadata",
                    "--offline",
                    "--locked",
                    "--no-deps",
                    "--format-version",
                    "1",
                    "--manifest-path",
                ])
                .arg(workspace.join("Cargo.toml")),
            None,
        )?
        .checked()?,
    )?;
    let mut cases: Vec<_> = metadata["packages"].as_array().unwrap().iter().map(|package| {
        json!({"name":package["name"], "label":package["name"], "defaults":true, "features":[]})
    }).collect();
    for name in ["airlock-image", "airlock-dom0-service", "airlock-tests"] {
        cases.push(json!({"name":name, "label":format!("{name}-minimal"), "defaults":false, "features":[]}));
    }
    cases.push(json!({"name":"airlock-sys-gui-service", "label":"authoring", "defaults":false, "features":["authoring"]}));
    cases.push(json!({"name":"airlock-nix-core", "label":"artifacts", "defaults":true, "features":["artifacts"]}));
    let cases = json!(cases);
    let baseline = inspect(root, &workspace, "source-baseline", &cases)?;

    // Shell extensions are packaged directly, so their edits must not rebuild native applications.
    change(&workspace.join("airlock-sys-gui/gnome/startup-progress-extension/extension.js"))?;
    assert_eq!(
        baseline,
        inspect(root, &workspace, "source-extension-change", &cases)?
    );

    // Packaging reads these files independently; neither belongs to native compiler inputs.
    change(&workspace.join("patches/qubes-linux-utils/memory-accounting.h"))?;
    writeln!(
        fs::OpenOptions::new()
            .append(true)
            .open(workspace.join("airlock-qubes-python/assets/amd-vbios.xml"))?,
        "{{# source input regression #}}"
    )?;
    assert_eq!(
        baseline,
        inspect(root, &workspace, "source-integration-assets-change", &cases)?
    );

    change(&workspace.join("airlock-config/assets/usr-assistant/AGENTS.md"))?;
    change(&workspace.join("airlock-config/templates/initial-runtime-config/src/machine.rs"))?;
    assert_eq!(
        baseline,
        inspect(
            root,
            &workspace,
            "source-guidance-and-template-change",
            &cases
        )?
    );

    let relocated = root.join("relocated/workspace");
    copy_tree(&workspace, &relocated)?;
    assert_eq!(
        baseline,
        inspect(root, &relocated, "source-relocated", &cases)?
    );
    change(&workspace.join("vendor/rusix/README.md"))?;
    writeln!(
        fs::OpenOptions::new()
            .append(true)
            .open(workspace.join("vendor/nixos-qubes/pkgs/top-level/overlay.nix"))?,
        "# source input regression"
    )?;
    assert_eq!(
        baseline,
        inspect(root, &workspace, "source-vendor-doc-change", &cases)?
    );

    change(&workspace.join("airlock-common/build/src/script.rs"))?;
    let authoring = inspect(root, &workspace, "source-authoring-change", &cases)?;
    assert_eq!(baseline["derivations"], authoring["derivations"]);
    assert_eq!(
        baseline["sources"]["airlock-sys-gui-service"],
        authoring["sources"]["airlock-sys-gui-service"]
    );
    assert_ne!(
        baseline["sources"]["authoring"],
        authoring["sources"]["authoring"]
    );

    change(&workspace.join("vendor/rusix/crates/rusix/src/compiler.rs"))?;
    let vendor = inspect(root, &workspace, "source-vendor-change", &cases)?;
    assert_eq!(authoring["derivations"], vendor["derivations"]);
    assert_eq!(
        authoring["sources"]["airlock-sys-gui-service"],
        vendor["sources"]["airlock-sys-gui-service"]
    );
    assert_ne!(
        authoring["sources"]["airlock-image"],
        vendor["sources"]["airlock-image"]
    );

    change(&workspace.join("airlock-common/machine-planning/src/lib.rs"))?;
    let dependency = inspect(root, &workspace, "source-required-change", &cases)?;
    assert_ne!(
        vendor["derivations"]["cli"],
        dependency["derivations"]["cli"]
    );
    assert_eq!(
        vendor["derivations"]["init"],
        dependency["derivations"]["init"]
    );

    change(&workspace.join("airlock-sys-ctrl/gui/examples/diff-context/usr-home.before.rs"))?;
    let asset = inspect(root, &workspace, "source-asset-change", &cases)?;
    assert_ne!(
        dependency["derivations"]["gui"],
        asset["derivations"]["gui"]
    );
    assert_eq!(
        dependency["derivations"]["cli"],
        asset["derivations"]["cli"]
    );

    // Embedded binary assets must invalidate the owning package independently of Rust examples.
    let font = workspace.join("airlock-sys-ctrl/gui/assets/fonts/Inter-Regular.ttf");
    let mut bytes = fs::read(&font)?;
    *bytes.last_mut().context("nonempty embedded font")? ^= 1;
    fs::write(font, bytes)?;
    let font = inspect(root, &workspace, "source-font-change", &cases)?;
    assert_ne!(asset["derivations"]["gui"], font["derivations"]["gui"]);
    assert_eq!(asset["derivations"]["cli"], font["derivations"]["cli"]);

    let target = PathBuf::from(
        std::env::var_os("AIRLOCK_FILTERED_CARGO_TARGET_DIR")
            .context("explicit Cargo target directory for isolated source checks")?,
    );
    ensure!(
        target.is_absolute(),
        "filtered Cargo target must be absolute"
    );
    let logs =
        PathBuf::from(std::env::var_os("AIRLOCK_RUSIX_LOG_DIR").context("source check logs")?);
    let work = root.join("filtered");
    for case in cases.as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let source = baseline["sources"][label]
            .as_str()
            .context("filtered source path")?;
        let source = root.join("evaluation-store").join(
            source
                .strip_prefix('/')
                .context("absolute Nix source path")?,
        );
        ensure!(
            source.is_dir(),
            "filtered source missing from evaluation store: {path}",
            path = source.display()
        );
        if work.exists() {
            fs::remove_dir_all(&work)?;
        }
        copy_tree(&source, &work)?;

        let mut command = Command::new("cargo");
        command
            .args(["check", "--offline", "--locked", "--manifest-path"])
            .arg(work.join("Cargo.toml"))
            .args(["-p", case["name"].as_str().unwrap(), "--target-dir"])
            .arg(&target)
            .env("CARGO_INCREMENTAL", "0");
        if case["defaults"] == false {
            command.arg("--no-default-features");
        }
        let features: Vec<_> = case["features"]
            .as_array()
            .unwrap()
            .iter()
            .map(|feature| feature.as_str().unwrap())
            .collect();
        if !features.is_empty() {
            command.args(["--features", &features.join(",")]);
        }
        let output = support::run(&mut command, None, Duration::from_secs(180))?;
        fs::write(logs.join(format!("compile-{label}.stdout")), &output.stdout)?;
        fs::write(logs.join(format!("compile-{label}.stderr")), &output.stderr)?;
        output
            .checked()
            .with_context(|| format!("compile filtered profile {label}"))?;
        eprintln!("Filtered source profile compiled: {label}");
    }
    Ok(())
}
