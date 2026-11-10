//! Packaged Qubes policy retains its upstream parser with Rust-owned authority assertions.

use super::*;

/// Shared lazy applications preserve recipe identities, including override and source boundaries.
#[test]
#[ignore = "explicit prepared-source Nix evaluation; no package build"]
fn package_sharing_preserves_recipes_and_input_boundaries() -> Result<()> {
    let packages = Packages::new("package-sharing")?;
    let report = packages.inspect(
        "packages/sharing",
        json!({
            "root": packages.source.join("airlock-machine"),
            "apps": packages.source.join("crates"),
        }),
    )?;
    assert_eq!(report["original"], report["shared"]);
    assert_eq!(report["original"], report["mismatch"]);
    assert_eq!(report["extendedOriginal"], report["extendedShared"]);
    assert_ne!(report["original"], report["extendedShared"]);
    Ok(())
}

/// Require a textual field from the packaged interface report.
fn text(value: &Value) -> &str {
    value.as_str().expect("interface text")
}

/// The installed icon receiver imports its own Python dependencies before parsing arguments.
#[test]
#[ignore = "explicit real GUI launcher package build"]
fn package_icon_receiver_has_complete_python_environment() -> Result<()> {
    let packages = Packages::new("icon-receiver")?;
    let output = packages.fixture(
        "build",
        "native_etc/icon_receiver",
        json!({"root": packages.source.join("airlock-machine")}),
    )?;
    let launcher = fs::read_link(output.join("launcher"))?;
    let mut command = packages.runtime(launcher.to_str().context("icon receiver launcher")?);
    command
        .arg("--help")
        .env_remove("PYTHONPATH")
        .env_remove("DISPLAY");
    let output = common::run(&mut command, None)?.checked()?;
    assert!(String::from_utf8(output)?.contains("--force"));
    Ok(())
}

/// Native /etc entry points keep their package identity and adjacent JSON in NixOS's real artifacts.
#[test]
#[ignore = "explicit small NixOS /etc artifact builds with prepared sources"]
fn package_native_etc_preserves_launcher_contracts() -> Result<()> {
    let packages = Packages::new("native-etc")?;
    let fixture = tempfile::tempdir()?;
    let bin = fixture.path().join("bin");
    fs::create_dir(&bin)?;
    fs::copy(
        common::binary("AIRLOCK_EXEC_BIN", "airlock-exec"),
        bin.join("airlock-test-operation"),
    )?;
    fs::write(
        bin.join("airlock-test-operation.json"),
        serde_json::to_vec(&json!({"program":"/unused", "inherit_args":false}))?,
    )?;

    let output = packages.fixture(
        "installation",
        "native_etc/installation",
        json!({"root":packages.source, "fixture":fixture.path()}),
    )?;
    let resolve = |name: &str| -> Result<PathBuf> {
        packages.physical(
            fs::read_link(output.join(name))?
                .to_str()
                .context("store path")?,
        )
    };
    let etc = resolve("etc")?.join("etc");
    let basedir = resolve("basedir")?;
    let installed_fixture = resolve("fixture")?;
    let entries: Vec<Value> = serde_json::from_slice(&fs::read(resolve("entries.json")?)?)?;
    ensure!(!entries.is_empty(), "native entry inventory is empty");
    let mut scopes = BTreeSet::new();

    for entry in entries {
        let scope = text(&entry["scope"]);
        scopes.insert(scope.to_owned());
        let relative = format!("{scope}/{target}", target = text(&entry["target"]));
        let alias = etc.join(&relative);
        let target = fs::read_link(&alias)
            .with_context(|| format!("native /etc entry is not a symlink: {relative}"))?;
        assert_eq!(
            packages.physical(target.to_str().context("launcher path")?)?,
            installed_fixture.join("bin/airlock-test-operation")
        );
        assert_eq!(text(&entry["mode"]), "symlink", "{relative}");
        assert!(
            !etc.join(format!("{relative}.mode")).exists(),
            "{relative} requests a copy"
        );
        assert!(
            !basedir.join(&relative).exists(),
            "{relative} was copied into the overlay data layer"
        );
    }

    assert!(scopes.contains("dom0"));
    assert!(scopes.contains("airlock-domain-sys-gui"));
    assert!(scopes.contains("airlock-domain-sys-net"));
    assert!(
        installed_fixture
            .join("bin/airlock-test-operation.json")
            .is_file()
    );
    Ok(())
}

/// The real upstream RPC join retains executable clients and relocated notification symlinks.
#[test]
#[ignore = "explicit host RPC package builds and exact-closure preflight"]
fn package_host_rpc_join_has_resolvable_commands() -> Result<()> {
    let packages = Packages::new("host-rpc-preflight")?;
    let output = packages.fixture(
        "build",
        "native_etc/host_rpcs",
        json!({"root":packages.source}),
    )?;
    let system = fs::read_link(output.join("system"))?;
    let closure = fs::read_link(output.join("closure"))?;
    let paths = packages
        .physical(closure.to_str().context("closure path")?)?
        .join("store-paths");
    let store = if std::env::var("AIRLOCK_USE_HOST_NIX_STORE").as_deref() == Ok("1") {
        PathBuf::from("/nix/store")
    } else {
        PathBuf::from(std::env::var_os("AIRLOCK_NIX_ROOT").context("guarded Airlock store root")?)
            .join("nix/store")
    };
    let logs = packages.logs.join("preflight");
    system::run(
        Command::new(common::binary(
            "AIRLOCK_PREPARE_BOOT_BIN",
            "airlock-prepare-boot",
        ))
        .arg("preflight")
        .arg("--system")
        .arg(system)
        .arg("--paths")
        .arg(paths)
        .arg("--store-root")
        .arg(store)
        .arg("--launcher")
        .arg(common::binary("AIRLOCK_EXEC_BIN", "airlock-exec"))
        .arg("--readelf")
        .arg(common::tool("readelf")?)
        .arg("--report")
        .arg(packages.logs.join("preflight.json")),
        &logs,
        Duration::from_secs(120),
    )?;
    Ok(())
}

/// Invoke only the upstream Python interface fragment; all queries, temporary data and assertions stay in Rust.
fn upstream(request: Value) -> Result<Value> {
    common::json(
        Command::new(common::binary(
            "AIRLOCK_QUBES_PROBE_BIN",
            "airlock-qubes-probe",
        ))
        .arg("policy")
        .env(
            "PYTHONPATH",
            request["python_path"].as_str().expect("policy Python path"),
        ),
        Some(serde_json::to_vec(&request)?),
    )
}

/// Policy evaluation permits only the declared screen-capture routes.
#[test]
#[ignore = "explicit packaged Qubes interface builds"]
fn package_interfaces_preserve_narrow_policy() -> Result<()> {
    let packages = Packages::new("interfaces")?;
    let report = packages.inspect(
        "live_vm_interfaces/interfaces",
        json!({"root": packages.source.join("airlock-machine")}),
    )?;
    let path = text(&report["qrexecPythonPath"]);
    let physical = packages.physical(path)?;
    let mut queries = Vec::new();
    let mut expected = Vec::new();
    for service in ["airlock.CaptureImport", "airlock.CaptureOpen"] {
        for argument in ["+image", "+video"] {
            queries.push(json!([service, argument, "sys-gui", "usr-home"]));
            expected.push(true);
        }
        for (argument, source, target) in [
            ("+other", "sys-gui", "usr-home"),
            ("+image", "sys-gui", "usr-other"),
            ("+image", "usr-other", "usr-home"),
            ("+image", "sys-gui", "dom0"),
        ] {
            queries.push(json!([service, argument, source, target]));
            expected.push(false);
        }
    }
    assert_eq!(
        upstream(
            json!({"operation": "policy", "python_path": physical, "policy": report["policy"], "domains": ["dom0", "sys-gui", "usr-home", "usr-other"], "queries": queries})
        )?,
        json!(expected)
    );
    Ok(())
}

/// New VM menu sync waits for readiness, clears the inherited caller identity and refuses undeclared control callers.
#[test]
#[ignore = "explicit packaged Qubes interface builds"]
fn package_interface_shells_preserve_session_and_caller_barriers() -> Result<()> {
    let packages = Packages::new("interfaces")?;
    let report = packages.inspect(
        "live_vm_interfaces/interfaces",
        json!({"root": packages.source.join("airlock-machine")}),
    )?;
    assert_eq!(report["sync"]["args"], json!(["sync-appmenus"]));
    assert_eq!(report["sync"]["argument_count"], 1);
    assert!(text(&report["sync"]["program"]).ends_with("/bin/airlock-sys-gui-service"));
    assert!(
        text(&report["policy"])
            .contains("airlock.AppSessionReady + sys-gui @tag:guivm-sys-gui allow")
    );
    assert!(text(&report["policy"]).contains("airlock.AppSessionReady * @anyvm @anyvm deny"));
    assert!(text(&report["receiverUser"]).contains("force-user='user'"));
    let temporary = tempfile::tempdir()?;
    let mut receiver = report["receiver"].clone();
    assert_eq!(receiver["empty_service_argument"], true);
    receiver["program"] = json!(common::tool("true")?);
    receiver["args"] = json!([]);
    assert!(
        !common::run(
            common::launcher(temporary.path(), &receiver)?
                .env("QREXEC_SERVICE_ARGUMENT", "unexpected"),
            None
        )?
        .status
        .success()
    );
    for service in ["airlock.Ctrl.MachinePrepare", "airlock.Pool.AdmitCandidate"] {
        assert!(
            text(&report["controlPolicy"]).contains(&format!("{service} * @anyvm @anyvm deny"))
        );
    }
    for handler in ["prepare", "candidate"] {
        for caller in ["usr-new", "sys-gui", "usr-assistant", ""] {
            assert_eq!(
                common::run(
                    Command::new("bash")
                        .args(["-c", text(&report[handler])])
                        .env("QREXEC_REMOTE_DOMAIN", caller),
                    None
                )?
                .status
                .code(),
                Some(1)
            );
        }
    }
    Ok(())
}
