//! Generated USB images preserve source provenance, independent recovery and narrow development control paths.

use super::{
    configuration::{inspect, text},
    *,
};

/// Check list membership or a generated command fragment without imposing unrelated order.
fn includes(value: &Value, expected: &str) {
    assert!(
        match value {
            Value::String(value) => value.contains(expected),
            Value::Array(value) => value.contains(&json!(expected)),
            _ => false,
        },
        "missing {expected}: {value}"
    );
}

/// Real upstream publication renames an output-staged sparse file and rejects changed staging hooks.
#[test]
#[ignore = "requires explicitly prepared offline Nix sources; evaluates hooks without building an image"]
fn raw_image_publication_preserves_inode_and_sparse_allocation() -> Result<()> {
    use std::{
        fs::File,
        io::{Read, Seek, SeekFrom, Write},
        os::unix::fs::MetadataExt,
    };

    let temporary = tempfile::tempdir()?;
    let report = raw_disk_hooks(temporary.path(), false)?.value()?;
    assert_eq!(
        report["checkedBuilder"]["builder"],
        "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-native/bin/airlock-dom0-service"
    );
    assert_eq!(
        report["checkedBuilder"]["args"],
        json!([
            "storage",
            "image",
            "assemble-host",
            "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-seed",
            "/nix/store/cccccccccccccccccccccccccccccccc-topology",
            "--profile",
            "normal",
            "--host",
            "/nix/store/dddddddddddddddddddddddddddddddd-host",
            "--",
            "/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-builder",
            "-e",
            "upstream.sh"
        ])
    );
    // Run only the staging assignment from preVM; actual partitioning, installation
    // and the assembly VM are outside this host-side publication regression.
    let assignment = text(&report["preVM"])
        .lines()
        .find(|line| line.trim_start().starts_with("diskImage="))
        .context("upstream preparation has no disk image assignment")?;
    let work = temporary.path().join("scratch");
    let output = temporary.path().join("output");
    fs::create_dir(&work)?;
    fs::create_dir(&output)?;
    let assignment = format!(
        r#"
        {assignment}
        printf '%s' "$diskImage"
    "#
    );
    let staged = PathBuf::from(String::from_utf8(
        common::run(
            Command::new("bash")
                .args(["-e", "-c", &assignment])
                .env("out", &output)
                .current_dir(&work),
            None,
        )?
        .checked()?,
    )?);
    assert_eq!(staged.parent(), Some(output.as_path()));

    let mut image = File::create_new(&staged)?;
    image.set_len(16 * 1024 * 1024)?;
    image.write_all(b"image header")?;
    image.seek(SeekFrom::End(-10))?;
    image.write_all(b"image tail")?;
    image.sync_all()?;
    let before = image.metadata()?;
    drop(image);
    assert!(before.blocks() * 512 < before.len() / 2);

    common::run(
        Command::new("bash")
            .args(["-e", "-c", text(&report["postVM"])])
            .env("out", &output)
            .env("diskImage", &staged)
            .current_dir(&work),
        None,
    )?
    .checked()?;
    let published = output.join("airlock-staging-fixture.img");
    let after = fs::metadata(&published)?;
    assert_eq!(
        (after.dev(), after.ino(), after.len(), after.blocks()),
        (before.dev(), before.ino(), before.len(), before.blocks())
    );
    assert!(!staged.exists());
    assert_eq!(fs::read_dir(&work)?.count(), 0);
    assert!(output.join("nix-support/hydra-build-products").is_file());
    let mut image = File::open(published)?;
    let mut header = [0; 12];
    image.read_exact(&mut header)?;
    assert_eq!(&header, b"image header");
    image.seek(SeekFrom::End(-10))?;
    let mut tail = [0; 10];
    image.read_exact(&mut tail)?;
    assert_eq!(&tail, b"image tail");

    let changed = raw_disk_hooks(temporary.path(), true)?;
    assert!(!changed.success);
    assert!(
        changed
            .stderr
            .contains("Upstream raw disk assembly no longer exposes")
    );
    Ok(())
}

/// Inspect upstream's host hooks without generating unrelated machine exports or realizing closures.
fn raw_disk_hooks(root: &Path, changed: bool) -> Result<Reply> {
    let sources: Value = serde_json::from_slice(&fs::read(
        std::env::var_os("AIRLOCK_RUSIX_SOURCES").context("prepared upstream sources")?,
    )?)?;
    evaluate_fixture(
        root,
        &format!("raw-hooks-{changed}"),
        "prepared_store/raw_disk_hooks",
        json!({"nixpkgs":sources["nixpkgsSource"], "changedUpstream":changed}),
    )
}

/// Nix's actual scanner retains derived host roots while detaching guest payload and build tools.
#[test]
#[ignore = "explicit tiny Nix builds using the already Cargo-built native requirement tool"]
fn package_detached_topology_retains_only_derived_host_objects() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let sources: Value = serde_json::from_slice(&fs::read(
        std::env::var_os("AIRLOCK_RUSIX_SOURCES").context("prepared Nix source")?,
    )?)?;
    let store = PathBuf::from(std::env::var_os("AIRLOCK_NIX_ROOT").context("guarded store")?);
    ensure!(
        store.is_absolute() && store != Path::new("/"),
        "select the guarded Airlock store"
    );
    let driver = root.join("retention.nix");
    fs::write(&driver, common::run(Command::new(common::binary("AIRLOCK_TEST_FIXTURES_BIN", "examples/test_fixtures"))
        .arg("prepared_store/retention").arg(serde_json::to_string(&json!({
            "nixpkgs":sources["nixpkgsSource"], "native":common::binary("AIRLOCK_DOM0_BIN","airlock-dom0-service")
        }))?), None)?.checked()?)?;
    let command = || {
        let mut command = Command::new("nix");
        command
            .arg("--store")
            .arg(&store)
            .args([
                "--extra-experimental-features",
                "nix-command flakes",
                "--option",
                "builders",
                "",
                "--option",
                "build-users-group",
                "",
                "--option",
                "substituters",
                "",
                "--offline",
            ])
            .env_remove("NIX_REMOTE")
            .env("NIX_CONFIG", "")
            .env("NIX_PATH", "");
        command
    };
    let mut build = command();
    build
        .args(["build", "--impure", "--no-link", "--json", "--file"])
        .arg(&driver)
        .arg("system");
    let built = support::run(&mut build, None, Duration::from_secs(180))?;
    let logs = PathBuf::from(std::env::var_os("AIRLOCK_RUSIX_LOG_DIR").context("test logs")?);
    fs::create_dir_all(&logs)?;
    fs::write(logs.join("retention-build.stderr"), &built.stderr)?;
    let built: Value = serde_json::from_slice(&built.checked()?)?;
    let mut inspect = command();
    inspect
        .args(["eval", "--impure", "--json", "--file"])
        .arg(&driver)
        .arg("report");
    let report: Value = serde_json::from_slice(&common::run(&mut inspect, None)?.checked()?)?;
    let mut query = command();
    query.args([
        "path-info",
        "--recursive",
        text(&built[0]["outputs"]["out"]),
    ]);
    let closure = String::from_utf8(common::run(&mut query, None)?.checked()?)?;
    let paths = closure.lines().collect::<Vec<_>>();
    for field in ["executable", "kernel", "requirements"] {
        assert!(
            paths.contains(&text(&report[field])),
            "host closure omitted {field}: {closure}"
        );
    }
    for field in ["guest", "detached", "native"] {
        assert!(
            !paths.contains(&text(&report[field])),
            "host closure retained {field}: {closure}"
        );
    }
    fs::write(
        logs.join("retention-closure.json"),
        serde_json::to_vec_pretty(&json!({"report":report,"closure":paths}))?,
    )?;
    Ok(())
}

/// Changing one package rebuilds only its fragment and affected index; another closure reuses both outputs.
#[test]
#[ignore = "explicit tiny Nix builds: prepares the store-cache executable, fragments and real EROFS indexes"]
fn package_store_cache_reuses_unchanged_fragments_and_indexes() -> Result<()> {
    let nix = context()?;
    let apps = nix.temporary.path().join("cache-apps");
    copy_tree(&nix.prepared.join("crates"), &apps)?;
    let trial = std::cell::Cell::new(0);

    let build = |variant: &str| -> Result<Value> {
        trial.set(trial.get() + 1);
        let input = nix
            .temporary
            .path()
            .join(format!("store-cache-{variant}.nix"));
        fs::write(&input, nix.fixture("prepared_store/cache", json!({
            "nixpkgs":nix.sources["nixpkgsSource"], "machine":nix.prepared.join("airlock-machine"),
            "apps":apps, "variant":variant,
        }))?)?;
        let mut command = Command::new("nix");
        nix.environment(&mut command);
        command
            .arg("--store")
            .arg(std::env::var_os("AIRLOCK_NIX_ROOT").context("guarded store")?)
            .arg("--cores")
            .arg(std::thread::available_parallelism()?.get().to_string())
            .args([
                "--extra-experimental-features",
                "nix-command flakes",
                "--option",
                "builders",
                "",
                "--option",
                "build-users-group",
                "",
                "--offline",
                "build",
                "--impure",
                "--no-link",
                "--json",
                "--file",
            ])
            .arg(input);
        let output = support::run(&mut command, None, Duration::from_secs(600))?;
        fs::write(
            nix.logs.join(format!(
                "store-cache-{trial}-{variant}.stderr",
                trial = trial.get()
            )),
            &output.stderr,
        )?;
        let result: Value = serde_json::from_slice(&output.checked()?)?;
        let manifest = Path::new(result[0]["outputs"]["out"].as_str().unwrap());
        let physical = PathBuf::from(std::env::var_os("AIRLOCK_NIX_ROOT").unwrap())
            .join(manifest.strip_prefix("/")?);
        let manifest_value: Value = serde_json::from_slice(&fs::read(physical)?)?;
        let mut references = Command::new("nix-store");
        nix.environment(&mut references);
        references
            .arg("--store")
            .arg(std::env::var_os("AIRLOCK_NIX_ROOT").unwrap())
            .args(["--query", "--requisites"])
            .arg(manifest);
        let references = String::from_utf8(common::run(&mut references, None)?.checked()?)?;
        for artifact in manifest_value["fragments"]
            .as_object()
            .unwrap()
            .values()
            .chain(manifest_value["indexes"].as_array().unwrap())
        {
            assert!(
                references
                    .lines()
                    .any(|path| path == artifact.as_str().unwrap()),
                "cache manifest failed to retain {artifact}"
            );
        }
        for package in manifest_value["fragments"].as_object().unwrap().keys() {
            assert!(
                !references.lines().any(|path| path == package),
                "cache manifest retained source package {package}"
            );
        }
        fs::write(
            nix.logs.join(format!(
                "store-cache-{trial}-{variant}.json",
                trial = trial.get()
            )),
            serde_json::to_vec_pretty(&manifest_value)?,
        )?;
        Ok(manifest_value)
    };
    let first = build("first")?;
    let second = build("second")?;
    let fragments = |value: &Value, suffix: &str| -> (String, String) {
        let (package, artifact) = value["fragments"]
            .as_object()
            .unwrap()
            .iter()
            .find(|(path, _)| path.ends_with(suffix))
            .unwrap();
        (package.clone(), artifact.as_str().unwrap().to_owned())
    };
    assert_eq!(
        fragments(&first, "-airlock-cache-left"),
        fragments(&second, "-airlock-cache-left")
    );
    assert_ne!(
        fragments(&first, "-airlock-cache-right"),
        fragments(&second, "-airlock-cache-right")
    );
    assert_eq!(first["indexes"][0], second["indexes"][0]);
    assert_ne!(first["indexes"][1], second["indexes"][1]);
    let service = apps.join("runtime/airlock-dom0/service/src/lib.rs");
    let mut body = fs::read_to_string(&service)?;
    body.push_str("\n// Unrelated service edit must not invalidate package packing.\n");
    fs::write(service, body)?;
    assert_eq!(build("second")?, second);
    Ok(())
}

/// Check ordering edges after the caller has selected one machine's evaluated unit graph.
fn startup_units_are_acyclic(units: &serde_json::Map<String, Value>) -> Result<()> {
    use std::collections::{BTreeMap, BTreeSet};

    let mut edges: BTreeMap<&str, BTreeSet<&str>> = units
        .keys()
        .map(|name| (name.as_str(), BTreeSet::new()))
        .collect();
    for (name, unit) in units {
        for dependency in unit["after"].as_array().unwrap() {
            let dependency = dependency.as_str().unwrap();
            if units.contains_key(dependency) {
                edges.get_mut(name.as_str()).unwrap().insert(dependency);
            }
        }
        for successor in unit["before"].as_array().unwrap() {
            let successor = successor.as_str().unwrap();
            if let Some(dependencies) = edges.get_mut(successor) {
                dependencies.insert(name);
            }
        }
    }
    while !edges.is_empty() {
        let ready: BTreeSet<_> = edges
            .iter()
            .filter(|(_, dependencies)| dependencies.is_empty())
            .map(|(name, _)| *name)
            .collect();
        ensure!(!ready.is_empty(), "startup ordering cycle: {edges:?}");
        edges.retain(|name, _| !ready.contains(name));
        for dependencies in edges.values_mut() {
            dependencies.retain(|name| !ready.contains(name));
        }
    }
    Ok(())
}

/// The real unit graph keeps transient input jobs outside boot prerequisites and gates completion on health.
#[test]
#[ignore = "requires explicitly prepared offline Nix sources"]
fn usb_startup_gates_are_acyclic_and_preserve_health_budgets() -> Result<()> {
    use std::collections::BTreeSet;

    let nix = context()?;
    let report = inspect(
        &nix,
        "usb_lab/startup_contract",
        json!({"root":nix.prepared}),
    )?;
    assert_eq!(
        report["readiness"],
        json!({
            "schema":"airlock.boot-readiness.v1", "desktop":true, "input_target":"sys-gui"
        })
    );
    let units = report["units"].as_object().unwrap();
    let guest = &units["airlock-boot-guest@.service"];
    assert_eq!(guest["type"], "oneshot");
    assert_eq!(guest["remain"], true);
    assert_eq!(guest["wantedBy"], json!([]));
    assert_eq!(guest["failure"], json!([]));
    includes(
        &guest["start"],
        "airlock-start-qube-ready %i /run/airlock/startup/topology.json",
    );
    assert!(guest["timeout"].as_u64().unwrap() >= airlock_machine_core::boot::GUEST_HELPER_SECONDS);
    includes(
        &guest["condition"][0],
        "test ! -e /run/airlock/boot-supervisor/recovery-required.json",
    );
    startup_units_are_acyclic(units)?;
    let gui_units = report["guiUnits"].as_object().unwrap();
    startup_units_are_acyclic(gui_units)?;
    let login_gate = &gui_units["airlock-input-login-ready.service"];
    includes(
        &gui_units["display-manager.service"]["requires"],
        "airlock-input-login-ready.service",
    );
    includes(
        &gui_units["display-manager.service"]["after"],
        "airlock-input-login-ready.service",
    );
    includes(&login_gate["before"], "display-manager.service");
    includes(&login_gate["start"], "airlock-wait-input-login");
    assert!(
        !login_gate["after"]
            .as_array()
            .unwrap()
            .contains(&json!("display-manager.service"))
    );
    assert!(
        !login_gate["after"]
            .as_array()
            .unwrap()
            .contains(&json!("graphical.target"))
    );
    assert!(
        login_gate["timeout"].as_u64().unwrap() > airlock_machine_core::input::LOGIN_WAIT_SECONDS
    );
    assert_eq!(report["guiConsoleLogin"], false);
    assert!(
        !units["airlock-gui-input-connect.service"]["after"]
            .as_array()
            .unwrap()
            .contains(&json!("airlock-foreground-ready.service"))
    );
    includes(
        &units["airlock-foreground-ready.service"]["after"],
        "airlock-start-gui-gpu.service",
    );
    includes(
        &units["airlock-desktop-ready.service"]["requires"],
        "airlock-foreground-ready.service",
    );

    let mut pending = vec!["airlock-machine-autostart.service"];
    let mut required = BTreeSet::new();
    while let Some(name) = pending.pop() {
        if required.insert(name)
            && let Some(unit) = units.get(name)
        {
            pending.extend(
                unit["requires"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|name| name.as_str().unwrap()),
            );
        }
    }
    assert!(required.contains("airlock-gui-input-boot-ready.service"));
    assert!(required.contains("airlock-desktop-ready.service"));
    assert!(!required.contains("airlock-gui-input-connect.service"));
    includes(
        &units["airlock-gui-input-boot-ready.service"]["start"],
        "input boot-ready --target sys-gui",
    );
    includes(
        &units["airlock-desktop-ready.service"]["start"],
        "wait-desktop-ready",
    );
    includes(
        &units["airlock-desktop-ready.service"]["post"],
        "boot-supervisor desktop-ready",
    );
    includes(
        &units["airlock-desktop-ready.service"]["failure"],
        "airlock-boot-failure@%n.service",
    );
    includes(
        &units["airlock-foreground-ready.service"]["start"],
        "boot-foreground --topology /run/airlock/startup/topology.json",
    );
    includes(
        &units["airlock-setup-config.service"]["start"],
        "boot-setup --gui",
    );
    includes(
        &units["airlock-start-gui-gpu.service"]["requires"],
        "airlock-setup-config.service",
    );
    includes(
        &units["airlock-start-gui-gpu.service"]["after"],
        "airlock-setup-config.service",
    );
    includes(
        &units["airlock-start-gui-gpu.service"]["start"],
        "airlock-start-qube-ready sys-gui /run/airlock/startup/topology.json",
    );
    assert!(
        !units["airlock-setup-config-deferred.service"]["pre"]
            .to_string()
            .contains("desktop-ready")
    );

    let guest_budget = units["airlock-foreground-ready.service"]["timeout"]
        .as_u64()
        .unwrap();
    let guests = report["domains"].as_array().unwrap().len() as u64;
    assert!(
        guest_budget
            >= guests
                * (airlock_machine_core::boot::GUEST_HELPER_SECONDS
                    + 2 * airlock_machine_core::boot::GUI_OBSERVATION_SECONDS)
                + airlock_machine_core::boot::GUI_OBSERVATION_SECONDS
                + airlock_machine_core::boot::BOOT_UNIT_OVERHEAD_SECONDS
    );
    assert!(
        units["airlock-start-gui-gpu.service"]["timeout"]
            .as_u64()
            .unwrap()
            >= airlock_machine_core::boot::GUEST_HELPER_SECONDS
                + airlock_machine_core::boot::BOOT_UNIT_OVERHEAD_SECONDS
    );
    for name in [
        "airlock-foreground-ready.service",
        "airlock-start-network-providers.service",
        "airlock-machine-autostart.service",
    ] {
        assert!(
            units[name]["timeout"].as_u64().unwrap()
                >= report["domains"].as_array().unwrap().len() as u64 * (240 + 180)
        );
    }
    Ok(())
}

/// Image validation runs before assembly, recovery logging survives failure and the runtime closure does not retain its pool payload twice.
#[test]
#[ignore = "explicit image input builds: cache discovery realizes the host and guest closure lists"]
fn prepared_image_validates_sealed_pool_before_assembly() -> Result<()> {
    let nix = context()?;
    let report = inspect(
        &nix,
        "prepared_store/sealed_store",
        json!({"root": nix.prepared, "realizeImageInputs": true}),
    )?;
    assert_eq!(report["mode"], "go-rwx");
    includes(&report["hostOrdering"], "airlock-host-store.service");
    includes(&report["earlyLogs"], "airlock-boot-journal");
    assert_eq!(report["recoveryLogs"], true);
    includes(&report["recoveryRecorder"], "airlock-boot-journal");
    assert_eq!(report["journalConfig"]["Storage"], "persistent");
    assert_eq!(report["journalConfig"]["SyncIntervalSec"], "1s");
    assert!(text(&report["daemonConfig"]).starts_with("store = local-overlay://?"));
    includes(&report["daemonConfig"], "local%%3Froot%%3D");
    let dependencies = report["dependencies"].as_array().unwrap();
    assert!(!dependencies.contains(&report["runtimeSeed"]));
    assert!(dependencies.contains(&report["validation"]));
    let executables = report["hermitExecutables"].as_array().unwrap();
    assert!(
        report["bootDependencies"]
            .as_array()
            .unwrap()
            .contains(&report["requiredBootArtifacts"])
    );
    assert!(
        !executables.is_empty(),
        "normal USB boot must exercise Hermit retention"
    );
    for executable in executables {
        assert!(
            report["bootArtifactReport"]["host_roots"]
                .as_array()
                .unwrap()
                .contains(executable),
            "Hermit executable omitted from dom0: {executable}"
        );
    }
    let command = text(&report["imageCommand"]);
    let mut previous = 0;
    for token in [
        "mount $rootDisk $mountPoint",
        "USB image: installing prepared Qubes runtime state",
        "switch-to-configuration boot",
        "chown -R root:qubes /var/lib/qubes",
        "umount -R /mnt",
    ] {
        let index = command
            .find(token)
            .with_context(|| format!("image command missing {token}"))?;
        assert!(index >= previous);
        previous = index;
    }
    includes(
        &report["imageCommand"],
        "env NIX_REMOTE=local NIX_CONFIG='store = local'",
    );
    crate::image_seed::validation_hook(text(&report["preVM"]), text(&report["checkCommand"]))
}

/// The lab keeps a single firewall chain, explicit controller authority and boot supervision without host networking services.
#[test]
#[ignore = "explicit package builds: report reads realized RPC and policy scripts"]
fn package_usb_lab_keeps_network_dependencies_and_development_authority_explicit() -> Result<()> {
    let report =
        crate::packaged::inspect_configuration("usb_lab/network_and_development_access", ".")?;
    for prerequisite in [
        "airlock-setup-config.service",
        "airlock-start-gui-gpu.service",
        "airlock-start-network-providers.service",
    ] {
        includes(&report["autostart"]["after"], prerequisite);
        includes(&report["autostart"]["requires"], prerequisite);
    }
    assert_eq!(
        report["autostart"]["wantedBy"],
        json!(["multi-user.target"])
    );
    assert!(
        text(&report["autostart"]["command"]).ends_with("boot-start --require-running sys-gui")
    );
    includes(
        &report["autostart"]["sync"][0],
        "airlock-dom0-service boot-supervisor complete",
    );
    assert_eq!(report["retireDomains"], json!([]));
    assert_eq!(report["trashRetentionDays"], 30);
    includes(
        &report["retiredPolicy"],
        "* * @anyvm @tag:airlock-retired deny",
    );
    let supervisor = &report["bootSupervisor"];
    assert_eq!(supervisor["enabled"], true);
    includes(&supervisor["prepare"]["wantedBy"], "multi-user.target");
    for dependency in ["xenconsoled.service", "qubesd.service"] {
        includes(&supervisor["prepare"]["before"], dependency);
    }
    assert!(text(&supervisor["recoveryCondition"]).ends_with("/recovery-required.json"));
    includes(
        &supervisor["failureCapture"],
        "airlock-dom0-service boot-supervisor fail",
    );
    includes(
        &supervisor["failureFinally"],
        "airlock-boot-failure-console.service",
    );
    assert_eq!(supervisor["tty1"], false);
    assert_eq!(supervisor["autoTty1"], false);
    assert_eq!(supervisor["failureConsole"]["TTYPath"], "/dev/tty1");
    for (service, timeout) in [("network", 4080), ("gui", 780), ("autostart", 4080)] {
        assert_eq!(
            supervisor[service]["serviceConfig"]["TimeoutStartSec"],
            timeout
        );
        includes(
            &supervisor[service]["serviceConfig"]["ExecCondition"][0],
            "test ! -e /run/airlock/boot-supervisor/recovery-required.json",
        );
        assert_eq!(
            supervisor[service]["unitConfig"]["OnFailure"],
            json!([if service == "gui" {
                "airlock-boot-failure@%n.service"
            } else {
                "airlock-boot-background-failure.service"
            }])
        );
    }
    for key in ["default_netvm", "devNetvm", "ctrlNetvm", "homeNetvm"] {
        assert_eq!(report[key], "sys-firewall");
    }
    assert_eq!(report["firewallNetvm"], "sys-net");
    assert!(report["netNetvm"].is_null());
    for key in [
        "devProvider",
        "hostNetworkManager",
        "hostTailscale",
        "hostSsh",
        "labGuiHasDom0Terminal",
    ] {
        assert_eq!(report[key], false);
    }
    for key in ["netProvider", "firewallProvider"] {
        assert_eq!(report[key], true);
    }
    for key in ["devMemory", "devMaxmem", "ctrlMemory", "ctrlMaxmem"] {
        assert_eq!(report[key], 8192);
    }
    assert_eq!(report["ctrlBuildJobs"], 1);
    assert_eq!(report["devAutoPci"], "0");
    assert_eq!(report["netAutoPci"], "1");
    assert_eq!(report["devPci"], json!([]));
    assert_eq!(report["netPci"], json!([]));
    assert_eq!(report["callers"], json!(["usr-assistant"]));
    includes(
        &report["policy"],
        "airlock.DevDom0Shell + usr-assistant dom0 allow",
    );
    assert!(!text(&report["policy"]).contains("airlock.DevDom0Shell + sys-gui dom0 allow"));
    for service in ["airlock.CaptureImport", "airlock.CaptureOpen"] {
        includes(
            &report["capturePolicy"],
            &format!("{service} * @anyvm @anyvm deny"),
        );
    }
    includes(
        &report["tailscalePolicy"],
        "airlock.DevTailscaleUp + sys-gui usr-assistant allow user=root",
    );
    includes(
        &report["tailscalePolicy"],
        "airlock.DevTailscaleUp * @anyvm @anyvm deny",
    );
    includes(
        &report["tailscaleAssistantDesktop"],
        "Name=Connect Tailscale",
    );
    includes(
        &report["tailscaleAssistantDesktop"],
        "/bin/airlock-connect-tailscale",
    );
    includes(
        &report["tailscaleAssistantDesktop"],
        "Icon=org.airlockos.Airlock",
    );
    includes(
        &report["tailscaleAssistantDesktop"],
        "StartupWMClass=org.airlockos.Tailscale",
    );

    let helper = text(&report["tailscaleLocalHelper"]);
    assert_eq!(
        report["tailscaleLocalEnrollment"]["args"],
        json!(["runtime", "tailscale-up-local"])
    );
    let sudo_command = format!(r#"{helper} """#);
    let sudo_rule = report["tailscaleSudo"]
        .as_array()
        .unwrap()
        .iter()
        .find(|rule| {
            rule["commands"]
                .as_array()
                .unwrap()
                .iter()
                .any(|command| command["command"] == sudo_command)
        })
        .context("missing local enrollment sudo rule")?;
    assert_eq!(sudo_rule["users"], json!(["user"]));
    assert_eq!(sudo_rule["runAs"], "root");
    assert_eq!(
        sudo_rule["commands"],
        json!([{"command":sudo_command,"options":["NOPASSWD"]}])
    );

    // Run the authored window contract with an inert terminal; sudo stays inside the VM window.
    let temporary = tempfile::tempdir()?;
    let mut window = report["tailscaleWindow"].clone();
    assert!(text(&window["program"]).ends_with("/bin/xterm"));
    let mut peers = common::peers::Peers::new()?;
    peers.rules("enrollment-terminal", json!([{}]))?;
    window["program"] = json!(peers.path("bin/enrollment-terminal"));
    let mut launch = common::launcher(temporary.path(), &window)?;
    peers.environment(&mut launch)?;

    common::run(&mut launch, None)?.checked()?;

    let calls = peers.calls()?;
    let args = calls[0]["args"].as_array().unwrap();
    let class = args.iter().position(|arg| arg == "-class").unwrap();
    assert_eq!(args[class + 1], "org.airlockos.Tailscale");
    let terminal_command = args.iter().position(|arg| arg == "-e").unwrap();
    assert_eq!(
        &args[terminal_command + 1..],
        &[json!("/run/wrappers/bin/sudo"), json!("-n"), json!(helper)]
    );

    let mut enrollment = report["tailscaleHandler"].clone();
    assert_eq!(enrollment["args"], json!(["runtime", "tailscale-up"]));
    // Execute the actual native guard with an untrusted caller or service argument.
    enrollment["program"] = json!(common::binary(
        "AIRLOCK_VM_SERVICE_BIN",
        "airlock-vm-service"
    ));
    for (source, argument) in [("usr-browser", ""), ("sys-gui", "unexpected")] {
        let output = common::run(
            common::launcher(temporary.path(), &enrollment)?
                .env("QREXEC_REMOTE_DOMAIN", source)
                .env("QREXEC_SERVICE_ARGUMENT", argument),
            None,
        )?;
        assert_eq!(output.status.code(), Some(1));
    }
    assert_eq!(report["poolAdmission"]["caller"], "sys-ctrl");
    for target in report["poolAdmission"]["targets"].as_array().unwrap() {
        includes(
            &report["poolAdmissionPolicy"],
            &format!(
                "airlock.Pool.Admit +{target} sys-ctrl dom0 allow",
                target = text(target)
            ),
        );
    }
    assert_eq!(report["poolAdmissionMode"], "symlink");
    assert_eq!(
        report["dev"]["configNixStoreRoot"],
        "/rw/airlock-builder/merged"
    );
    assert_eq!(report["dev"]["providesNetwork"], false);
    assert_eq!(report["dev"]["networkManager"], false);
    assert_eq!(report["dev"]["dom0Shell"], true);
    assert_eq!(report["dev"]["tailscaleSsh"], json!(["--ssh"]));
    Ok(())
}

/// Parent and standalone machine images preserve machine lock identity independently from their own boot-source labels.
#[test]
#[ignore = "requires explicitly prepared offline Nix sources"]
fn usb_image_source_and_boot_provenance_are_distinct() -> Result<()> {
    let nix = context()?;
    let identity: Value = serde_json::from_slice(&fs::read(
        nix.prepared.join("airlock-machine/airlock-source.json"),
    )?)?;
    let lock_hash = format!(
        "{hash:x}",
        hash = Sha256::digest(fs::read(nix.prepared.join("airlock-machine/flake.lock"))?)
    );
    for (flake, configuration) in [
        (nix.prepared.clone(), "usb-dev"),
        (nix.prepared.join("airlock-machine"), "machine"),
    ] {
        let report = inspect(
            &nix,
            "usb_lab/source_metadata",
            json!({"flake": flake, "configuration": configuration}),
        )?;
        assert_eq!(
            report["source"],
            json!({"schema": "airlock.machine-source.v1", "revision": identity["revision"], "lockHash": lock_hash})
        );
        let boot = inspect(
            &nix,
            "usb_lab/boot_source_metadata",
            json!({"repo": flake, "configuration": configuration}),
        )?;
        assert_eq!(boot["normal"], boot["recovery"]);
        let source: Value = serde_json::from_slice(&fs::read(flake.join("airlock-source.json"))?)?;
        assert_eq!(
            boot["normal"],
            json!({"revision": source["revision"], "timestamp": source["timestamp"]})
        );
        assert_eq!(boot["consoleMode"], "1");
    }
    Ok(())
}
