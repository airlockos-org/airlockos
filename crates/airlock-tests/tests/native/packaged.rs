//! Explicit packaged tests build in the guarded Airlock store; normal Cargo execution never provisions these artifacts.

#[path = "packaged/interfaces.rs"]
mod interfaces;

#[path = "packaged/terminal.rs"]
mod terminal;

#[path = "packaged/early_init.rs"]
mod early_init;

use crate::common;
use airlock_tests::system;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

/// Bind package assertions to an explicitly prepared source and the existing guarded Nix wrapper.
struct Packages {
    // Generated source tree selected before the test, never authored or rebuilt by test execution.
    source: PathBuf,
    // Distinct complete command logs for expensive build/evaluation requests.
    logs: PathBuf,
}

impl Packages {
    /// Require explicit source preparation and preserve command evidence under the configured test log directory.
    fn new(name: &str) -> Result<Self> {
        let source = std::env::var("AIRLOCK_PREPARED_SOURCE")
            .context("set AIRLOCK_PREPARED_SOURCE to the explicitly prepared tree")?;
        let source = PathBuf::from(source.strip_prefix("path:").unwrap_or(&source));
        ensure!(source.join("flake.nix").is_file(), "prepared flake missing");
        Ok(Self {
            source,
            logs: system::logs(&common::root(), &format!("packaged/{name}"))?,
        })
    }

    /// Run one explicitly selected Nix operation, retaining all build output on disk under a finite deadline.
    fn nix(&self, name: &str, args: &[&str]) -> Result<Vec<u8>> {
        let logs = self.logs.join(name);
        let mut command = Command::new(common::binary("AIRLOCK_DEV_BIN", "airlock-dev"));
        command
            .args(["with-environment", "--", "nix", "--"])
            .args(args)
            .current_dir(common::root());
        system::run(&mut command, &logs, Duration::from_secs(7200))?;
        Ok(fs::read(logs.join("stdout.log"))?)
    }

    /// Build a selected machine attribute without creating an ambient result link.
    fn build(&self, name: &str, attribute: &str) -> Result<String> {
        let reference = format!(
            "path:{source}/airlock-machine#{attribute}",
            source = self.source.display()
        );
        let reply: Value = serde_json::from_slice(&self.nix(
            name,
            &[
                "build",
                &reference,
                "--no-write-lock-file",
                "--no-link",
                "--json",
                "--print-build-logs",
                "--show-trace",
            ],
        )?)?;
        Ok(reply[0]["outputs"]["out"]
            .as_str()
            .context("package output")?
            .to_owned())
    }

    /// Map logical store paths through the explicitly configured guarded store.
    fn physical(&self, logical: &str) -> Result<PathBuf> {
        if std::env::var("AIRLOCK_USE_HOST_NIX_STORE").as_deref() == Ok("1") {
            return Ok(PathBuf::from(logical));
        }
        Ok(PathBuf::from(
            std::env::var_os("AIRLOCK_NIX_ROOT").context("guarded Airlock store root")?,
        )
        .join(logical.trim_start_matches('/')))
    }

    /// Evaluate package-backed interfaces in this explicit build lane, preserving required upstream derivation context.
    fn inspect(&self, fixture: &str, inputs: Value) -> Result<Value> {
        let expression = String::from_utf8(
            common::run(
                Command::new(common::binary(
                    "AIRLOCK_TEST_FIXTURES_BIN",
                    "examples/test_fixtures",
                ))
                .arg(fixture)
                .arg(serde_json::to_string(&inputs)?),
                None,
            )?
            .checked()?,
        )?;
        Ok(serde_json::from_slice(&self.nix(
            &format!(
                "interfaces-{digest:x}",
                digest = Sha256::digest(expression.as_bytes())
            ),
            &[
                "eval",
                "--impure",
                "--json",
                "--option",
                "allow-import-from-derivation",
                "true",
                "--expr",
                &expression,
            ],
        )?)?)
    }

    /// Execute a realized store program through the existing guarded-store runtime wrapper.
    fn runtime(&self, logical: &str) -> Command {
        let mut command = Command::new("bash");
        command
            .args([
                "-c",
                "source \"$1\"; shift; airlock_run_store_path \"$@\"",
                "packaged",
            ])
            .arg(common::root().join("crates/tooling/airlock-dev/scripts/lib/airlock-env.sh"))
            .arg(logical);
        command
    }

    /// Build a Rust-authored fixture expression against the captured source, keeping caller data out of executable text.
    fn fixture(&self, name: &str, fixture: &str, inputs: Value) -> Result<PathBuf> {
        let expression = String::from_utf8(
            common::run(
                Command::new(common::binary(
                    "AIRLOCK_TEST_FIXTURES_BIN",
                    "examples/test_fixtures",
                ))
                .arg(fixture)
                .arg(serde_json::to_string(&inputs)?),
                None,
            )?
            .checked()?,
        )?;
        let reply: Value = serde_json::from_slice(&self.nix(
            name,
            &[
                "build",
                "--impure",
                "--no-link",
                "--json",
                "--expr",
                &expression,
            ],
        )?)?;
        self.physical(
            reply[0]["outputs"]["out"]
                .as_str()
                .context("fixture output")?,
        )
    }
}

/// Packaged public entry points and module contracts remain buildable after moving their authoring and test orchestration into Rust.
#[test]
#[ignore = "explicit guarded-store package builds"]
fn package_machine_entry_points() -> Result<()> {
    let packages = Packages::new("entry-points")?;
    for name in [
        "module-contract",
        "airlock-config-apply",
        "airlock-config-archive-candidate",
        "airlock-config-boot-verify",
        "airlock-config-status",
        "airlock-config-inputs-import",
        "airlock-config-vms-smoke",
        "airlock-config-bootstrap-current",
        "airlock-observe-dom0",
        "airlock-setup-config",
        "airlock-start-network-providers",
        "airlock-dom0-service",
    ] {
        let attribute = if name == "module-contract" {
            "checks.x86_64-linux.module-contract".to_owned()
        } else {
            format!("packages.x86_64-linux.{name}")
        };
        packages.build(name, &attribute)?;
    }
    let reference = format!(
        "path:{source}/airlock-machine",
        source = packages.source.display()
    );
    packages.nix(
        "flake-check",
        &[
            "flake",
            "check",
            &reference,
            "--no-build",
            "--no-write-lock-file",
            "--show-trace",
        ],
    )?;
    Ok(())
}

/// Root disk contents omit package payloads and keep root ownership even when image construction runs unprivileged.
#[test]
#[ignore = "explicit root image package build and debugfs inspection"]
fn package_vm_root_image_contains_only_bootstrap_files() -> Result<()> {
    let packages = Packages::new("root-image")?;
    let logical = packages.build("build", "airlock-nix-closure-root-image-test")?;
    let output = packages.physical(&logical)?;
    let manifest: Value = serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    assert_eq!(manifest["schema"], "airlock.nix-closure-root-image.v1");
    assert_eq!(manifest["contains_store"], false);
    assert_eq!(manifest["store_mountpoint"], "/nix/store");
    assert_eq!(manifest["store_device_default"], "/dev/xvde");
    let files = fs::read_to_string(output.join("root-files.txt"))?;
    assert!(files.lines().any(|name| name == "./sbin/init"));
    assert!(files.lines().any(|name| name == "./nix/store"));
    assert!(!files.lines().any(|name| name.starts_with("./nix/store/")));
    let image = output.join("root.img");
    let debugfs = common::tool("debugfs")?;
    let init = packages.logs.join("init");
    common::run(
        Command::new(&debugfs)
            .args([
                "-R",
                &format!("dump /sbin/init {init}", init = init.display()),
            ])
            .arg(&image),
        None,
    )?
    .checked()?;
    let readelf = common::tool("readelf")?;
    for option in ["--program-headers", "--dynamic"] {
        let headers =
            common::run(Command::new(&readelf).arg(option).arg(&init), None)?.checked()?;
        let headers = String::from_utf8(headers)?;
        assert!(
            !headers.contains("INTERP"),
            "bootstrap init needs a dynamic interpreter"
        );
        assert!(
            !headers.contains("(NEEDED)"),
            "bootstrap init needs shared libraries"
        );
    }

    let listing = String::from_utf8(
        common::run(
            Command::new(&debugfs)
                .args(["-R", "ls -p /nix/store"])
                .arg(&image),
            None,
        )?
        .checked()?,
    )?;
    assert!(!listing.split('/').any(|part| part.len() > 32
        && part.as_bytes()[32] == b'-'
        && part.as_bytes()[..32].iter().all(u8::is_ascii_alphanumeric)));
    for path in std::iter::once("/")
        .chain(std::iter::once("/lost+found"))
        .chain(
            files
                .lines()
                .map(|name| name.strip_prefix('.').unwrap_or(name)),
        )
    {
        let stat = String::from_utf8(
            common::run(
                Command::new(&debugfs)
                    .args(["-R", &format!("stat {path}")])
                    .arg(&image),
                None,
            )?
            .checked()?,
        )?;
        let user = stat
            .split_once("User:")
            .and_then(|(_, value)| value.split_whitespace().next());
        let group = stat
            .split_once("Group:")
            .and_then(|(_, value)| value.split_whitespace().next());
        assert_eq!((user, group), (Some("0"), Some("0")), "{path}: {stat}");
    }
    Ok(())
}

/// A packaged Qubes session requires explicit session selection and successfully executes that selection without an implicit desktop.
#[test]
#[ignore = "explicit upstream Qubes GUI agent package build"]
fn package_qubes_session_requires_explicit_xsession() -> Result<()> {
    let packages = Packages::new("session")?;
    let logical = packages.build("build", "qubes-gui-agent-linux")?;
    let closure =
        String::from_utf8(packages.nix("closure", &["path-info", "--recursive", &logical])?)?;
    assert!(!closure.contains("-xfce4-session-"));
    let script = fs::read_to_string(packages.physical(&logical)?.join("bin/qubes-session"))?;
    assert!(!script.contains("xfce4-session"));
    let mut replaced = 0;
    let script = script
        .lines()
        .map(|line| {
            if line.starts_with(". /nix/store/") && line.ends_with("/lib/qubes/init/functions") {
                replaced += 1;
                "qsvc() { return 0; }"
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(replaced, 1);
    let temporary = tempfile::tempdir()?;
    let result = common::run(
        Command::new("bash")
            .args(["-c", &script])
            .env("HOME", temporary.path())
            .env_remove("XSESSION"),
        None,
    )?;
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("requires an explicit XSESSION"));
    let mut peers = common::peers::Peers::new()?;
    peers.rules(
        "selected-session",
        json!([{"stdout": "explicit-session-started\n"}]),
    )?;
    let mut command = peers.command("bash")?;
    command
        .args(["-c", &script])
        .env("HOME", temporary.path())
        .env("XSESSION", peers.path("bin/selected-session"));
    assert_eq!(
        String::from_utf8(common::run(&mut command, None)?.checked()?)?.trim(),
        "explicit-session-started"
    );
    Ok(())
}

/// Bitmap selection and complex SVG rendering produce bounded, complete RGBA frames through the actual packaged icon RPC.
#[test]
#[ignore = "explicit packaged image/icon fixture builds"]
fn package_icon_rpc_selects_and_renders_application_assets() -> Result<()> {
    let packages = Packages::new("icons")?;
    for fixture in ["bitmap_icons", "svg_icons"] {
        let output = packages.fixture(
            fixture,
            &format!("live_vm_interfaces/{fixture}"),
            json!({"root": packages.source.join("airlock-machine")}),
        )?;
        let paths = if fixture == "bitmap_icons" {
            vec![output]
        } else {
            [
                "contacts",
                "logs",
                "fonts",
                "airlock",
                "airlock-symbolic",
                "setup",
                "control",
            ]
            .into_iter()
            .map(|name| output.join(format!("{name}.rgba")))
            .collect()
        };
        for path in paths {
            let name = path
                .file_stem()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            let bytes = fs::read(&path)?;
            let index = bytes
                .iter()
                .position(|byte| *byte == b'\n')
                .context("RGBA header")?;
            let dimensions = std::str::from_utf8(&bytes[..index])?
                .split_whitespace()
                .map(str::parse::<usize>)
                .collect::<std::result::Result<Vec<_>, _>>()?;
            assert_eq!(dimensions.len(), 2);
            assert!(dimensions.iter().all(|size| (1..=512).contains(size)));
            if fixture == "bitmap_icons" {
                assert_eq!(dimensions, [128, 128]);
            }
            assert_eq!(bytes.len() - index - 1, dimensions[0] * dimensions[1] * 4);
            if matches!(name, "airlock" | "setup" | "control") {
                assert!(
                    bytes[index + 1..]
                        .chunks_exact(4)
                        .any(|pixel| pixel[0] > 180
                            && pixel[1] < 150
                            && pixel[2] < 130
                            && pixel[3] > 200),
                    "{name}: themed lookup must return the red emblem rather than a fallback"
                );
            }
        }
    }
    Ok(())
}

/// The real USB runtime closure omits VM-only payload/root packages while retaining their independent descriptors and kernels.
#[test]
#[ignore = "explicit complete prepared USB image runtime build and closure accounting"]
fn package_prepared_usb_runtime_avoids_duplicate_vm_closures() -> Result<()> {
    let packages = Packages::new("usb-closure")?;
    let prefix = "nixosConfigurations.usb-dev.config";
    let reference = |attribute: &str| {
        format!(
            "path:{source}#{prefix}.{attribute}",
            source = packages.source.display()
        )
    };
    packages.nix(
        "build",
        &[
            "build",
            &reference("system.build.toplevel"),
            &reference("system.build.usbPreparedGuestStore"),
            "--no-link",
        ],
    )?;
    let eval = |name: &str, attribute: &str| -> Result<Value> {
        Ok(serde_json::from_slice(
            &packages.nix(name, &["eval", "--json", &reference(attribute)])?,
        )?)
    };
    let system = eval("system", "system.build.toplevel.outPath")?;
    let payload = eval("payload", "system.build.usbPreparedGuestStore.outPath")?;
    let descriptors = eval(
        "descriptors",
        "system.build.usbPreparedGuestStore.descriptors.outPath",
    )?;
    let topology = eval("topology", "airlock.qubes.topology")?;
    let runtime: Value = serde_json::from_slice(&packages.nix(
        "runtime",
        &[
            "path-info",
            "--recursive",
            "--json",
            system.as_str().unwrap(),
        ],
    )?)?;
    let paths: BTreeSet<String> = if let Some(items) = runtime.as_array() {
        items
            .iter()
            .map(|item| item["path"].as_str().unwrap().to_owned())
            .collect()
    } else {
        runtime.as_object().unwrap().keys().cloned().collect()
    };
    assert!(!paths.contains(payload.as_str().unwrap()));
    assert!(paths.contains(descriptors.as_str().unwrap()));
    let mut vm_paths = BTreeSet::new();
    for entry in fs::read_dir(packages.physical(descriptors.as_str().unwrap())?)? {
        let directory = entry?.path();
        if !directory.join("prepared.json").is_file() {
            continue;
        }
        let descriptor: Value =
            serde_json::from_slice(&fs::read(directory.join("prepared.json"))?)?;
        assert!(!paths.contains(descriptor["system"].as_str().unwrap()));
        vm_paths.extend(
            fs::read_to_string(directory.join("store-paths"))?
                .lines()
                .map(str::to_owned),
        );
    }
    assert!(!vm_paths.is_empty());
    let domain = &topology["domains"]["sys-gui"];
    let root = domain["backend"]["root"]["source"]
        .as_str()
        .unwrap()
        .trim_end_matches("/root.img");
    assert!(!paths.contains(root));
    assert!(!paths.contains(domain["backend"]["system"]["source"].as_str().unwrap()));
    for kernel in topology["kernels"].as_object().unwrap().values() {
        assert!(paths.contains(kernel["source"].as_str().unwrap()));
    }
    for item in [&payload, &descriptors] {
        let info: Value = serde_json::from_slice(&packages.nix(
            if item == &payload {
                "payload-info"
            } else {
                "descriptor-info"
            },
            &["path-info", "--json", item.as_str().unwrap()],
        )?)?;
        let record = if info.is_array() {
            &info[0]
        } else {
            &info[item.as_str().unwrap()]
        };
        assert_eq!(record["references"], json!([]));
    }
    let omitted = vm_paths.difference(&paths).count();
    assert!(omitted > 0);
    fs::write(
        packages.logs.join("accounting.json"),
        serde_json::to_vec_pretty(
            &json!({"system": system, "payload": payload, "descriptors": descriptors,
        "vm_objects": vm_paths.len(), "vm_only_objects_omitted": omitted, "objects_also_needed_by_dom0": vm_paths.intersection(&paths).count()}),
        )?,
    )?;
    Ok(())
}

/// The disposable NixOS test VM executes native uplink assertions against real kernel interfaces, udev and systemd.
#[test]
#[ignore = "explicit isolated NixOS systemd/udev test VM build"]
fn vm_uplink_hotplug() -> Result<()> {
    let packages = Packages::new("uplink-hotplug")?;
    let output = packages.fixture(
        "vm",
        "network_uplink_vm/uplink_hotplug",
        json!({"root": packages.source.join("airlock-machine")}),
    )?;
    assert!(output.is_dir());
    Ok(())
}

/// Installed RPCs register input devices and deliver real evdev events in a closure-isolated disposable VM.
#[test]
#[ignore = "explicit isolated input receiver VM and boot-preflight build"]
fn vm_installed_input_receivers() -> Result<()> {
    let packages = Packages::new("input-receiver")?;
    let output = packages.fixture(
        "build",
        "network_uplink_vm/input_receiver",
        json!({"root":packages.source.join("airlock-machine")}),
    )?;
    let vm = fs::read_link(output.join("vm"))?;
    let physical = packages.physical(vm.to_str().context("VM store path")?)?;
    let runners = fs::read_dir(physical.join("bin"))?.collect::<std::io::Result<Vec<_>>>()?;
    ensure!(runners.len() == 1, "expected one disposable VM runner");
    let runner = vm.join("bin").join(runners[0].file_name());
    let temporary = tempfile::tempdir()?;
    let mut command = packages.runtime(runner.to_str().context("VM runner")?);
    command
        .current_dir(temporary.path())
        .env("QEMU_OPTS", "-display none");
    let logs = packages.logs.join("boot");
    system::run(&mut command, &logs, Duration::from_secs(180))?;
    let console = fs::read_to_string(logs.join("stdout.log"))?;
    ensure!(
        console.contains(r#""schema":"airlock.input-smoke.v1""#)
            && console.contains(r#""status":"passed""#),
        "installed input RPC smoke failed; inspect {}",
        logs.display()
    );
    Ok(())
}

/// A VM policy probe uses live QubesDB role/name observations while keeping its configured safe fallback.
#[test]
#[ignore = "explicit packaged Qubes PolicyProbe RPC build"]
fn package_policy_probe_observes_role_then_vm_identity() -> Result<()> {
    let packages = Packages::new("policy-probe")?;
    let logical = packages.build("build", "nixosConfigurations.airlock-domain-sys-ctrl.config.environment.etc.\"qubes-rpc/airlock.PolicyProbe\".source")?;
    for (role, name, expected) in [
        (None, "sys-ctrl", "sys-ctrl"),
        (Some("usr-assistant"), "other-name", "usr-assistant"),
    ] {
        let mut peers = common::peers::Peers::new()?;
        peers.rules("qubesdb-read", json!([
            {"args": ["/features/airlock-role"], "stdout": role.unwrap_or(""), "exit": if role.is_some() {0} else {1}},
            {"args": ["/name"], "stdout": name}
        ]))?;
        // The package owns its interpreter/tools; the override replaces only its QubesDB boundary.
        let mut command = packages.runtime(&logical);
        peers.environment(&mut command)?;
        command.env("AIRLOCK_QUBESDB_READ", peers.path("bin/qubesdb-read"));
        let output = common::run(&mut command, None)?.checked()?;
        let text = String::from_utf8(output)?;
        assert!(
            text.trim()
                .starts_with(&format!("airlock-policy-probe role={expected} user=")),
            "{text}"
        );
    }
    Ok(())
}

/// Inspect a configuration whose report reads realized package files; callers must select the explicit package lane.
pub(crate) fn inspect_configuration(fixture: &str, relative_root: &str) -> Result<Value> {
    let packages = Packages::new(&fixture.replace('/', "-"))?;
    packages.inspect(
        fixture,
        json!({"root": packages.source.join(relative_root)}),
    )
}

/// Inspect the actual independently admitted candidate profile rather than relying only on its evaluated source reference.
pub(crate) fn validate_candidate_profile(candidate: &Path) -> Result<()> {
    let packages = Packages::new("candidate-profile")?;
    let reference = format!(
        "path:{source}#airlock-dom0-profile",
        source = candidate.display()
    );
    let result: Value = serde_json::from_slice(
        &packages.nix("build", &["build", "--no-link", "--json", &reference])?,
    )?;
    let output = packages.physical(
        result[0]["outputs"]["out"]
            .as_str()
            .context("candidate profile")?,
    )?;
    let metadata: Value =
        serde_json::from_slice(&fs::read(output.join("share/airlock/profile.json"))?)?;
    assert_eq!(metadata["message"], "initial");
    assert_eq!(metadata["built_by"], "sys-ctrl");
    assert!(output.join("bin/airlock-dom0-profile-activate").is_file());
    Ok(())
}

/// Copy a prepared standalone workspace for a negative flake-boundary test without carrying build artifacts or Git state.
fn copy_workspace(source: &Path, target: &Path) -> Result<()> {
    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        if [".git", "target"].iter().any(|ignored| name == *ignored) {
            continue;
        }
        let target = target.join(name);
        if entry.file_type()?.is_dir() {
            copy_workspace(&entry.path(), &target)?;
        } else if entry.file_type()?.is_symlink() {
            std::os::unix::fs::symlink(fs::read_link(entry.path())?, target)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

/// Compile the runtime preparer from its filtered source and exercise the installed command boundary.
#[test]
#[ignore = "explicit runtime-preparation package build with archived Nix sources"]
fn package_runtime_preparer_builds_from_filtered_workspace() -> Result<()> {
    let packages = Packages::new("runtime-preparer")?;
    let reference = format!(
        "path:{source}#packages.x86_64-linux.airlock-prepare-runtime",
        source = packages.source.display(),
    );
    let reply: Value = serde_json::from_slice(&packages.nix(
        "build",
        &[
            "build",
            &reference,
            "--no-link",
            "--json",
            "--print-build-logs",
        ],
    )?)?;
    let output = reply[0]["outputs"]["out"]
        .as_str()
        .context("runtime preparer output")?;
    let help = common::run(
        packages
            .runtime(&format!("{output}/bin/airlock-prepare-runtime"))
            .arg("--help"),
        None,
    )?
    .checked()?;
    let help = String::from_utf8(help)?;
    for argument in ["<TOPOLOGY>", "<POOL>", "<OUTPUT>"] {
        assert!(
            help.contains(argument),
            "missing runtime argument {argument}"
        );
    }
    Ok(())
}

/// Standalone application evaluation ignores an unavailable machine gitlink and a deliberately unusable parent flake.
#[test]
#[ignore = "explicit standalone application package evaluation with archived Nix sources"]
fn package_standalone_application_does_not_fetch_machine_source() -> Result<()> {
    use airlock_tests::repository::git;
    let packages = Packages::new("standalone")?;
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("checkout");
    fs::create_dir(&root)?;
    copy_workspace(&packages.source.join("crates"), &root.join("crates"))?;
    let forbidden = common::run(
        Command::new(common::binary(
            "AIRLOCK_TEST_FIXTURES_BIN",
            "examples/test_fixtures",
        ))
        .args(["source/forbidden-root", "{}"]),
        None,
    )?
    .checked()?;
    fs::write(root.join("flake.nix"), forbidden)?;
    let lock: Value = serde_json::from_slice(&fs::read(
        packages.source.join("airlock-machine/flake.lock"),
    )?)?;
    fs::write(
        root.join("crates/flake.lock"),
        serde_json::to_vec(&json!({"version": 7, "root": "root", "nodes": {
            "root": {"inputs": {"nixpkgs": "nixpkgs"}}, "nixpkgs": lock["nodes"]["nixpkgs"]
        }}))?,
    )?;
    fs::write(
        root.join(".gitmodules"),
        format!(
            r#"[submodule "airlock-machine"]
    path = airlock-machine
    url = file://{missing}
"#,
            missing = temporary.path().join("unavailable.git").display()
        ),
    )?;
    git(&root, &["init", "-q", "-b", "main"])?;
    git(&root, &["config", "user.name", "Fixture"])?;
    git(&root, &["config", "user.email", "fixture@example.invalid"])?;
    git(&root, &["add", "."])?;
    git(
        &root,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{hash},airlock-machine", hash = "1".repeat(40)),
        ],
    )?;
    git(&root, &["commit", "-qm", "Standalone source boundary"])?;
    let reference = format!(
        "git+file://{root}?dir=crates#packages.x86_64-linux.airlock-sys-ctrl-gui.drvPath",
        root = root.display()
    );
    let result = String::from_utf8(packages.nix(
        "evaluate",
        &["eval", "--raw", "--no-write-lock-file", &reference],
    )?)?;
    assert!(result.trim().ends_with("-airlock-sys-ctrl-gui-0.1.0.drv"));
    Ok(())
}
