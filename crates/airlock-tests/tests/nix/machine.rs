//! Complete authoring, evaluation, inspection and runtime authorization boundaries.

use super::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Compare unordered VM names while preserving explicit ordering checks where dependencies matter.
fn names(value: &Value) -> BTreeSet<&str> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|name| name.as_str().unwrap())
        .collect()
}

/// Run offline planning through the actual dom0 service without coordinator state.
fn plan(
    nix: &Nix,
    before: &Value,
    after: &Value,
    label: &str,
    running: &[&str],
) -> Result<(Reply, PathBuf)> {
    let directory = nix.logs.join(label);
    fs::create_dir_all(&directory)?;
    let before_path = directory.join("before.json");
    let after_path = directory.join("after.json");
    fs::write(&before_path, serde_json::to_vec(before)?)?;
    fs::write(&after_path, serde_json::to_vec(after)?)?;
    let output = directory.join("plan");
    let result = common::run(
        Command::new(&nix.compiler)
            .arg("plan")
            .arg(common::binary("AIRLOCK_DOM0_BIN", "airlock-dom0-service"))
            .arg(&before_path)
            .arg(&after_path)
            .arg(&output)
            .args(running),
        None,
    )?;
    assert!(!output.join("unused-state").exists());
    let diagnostics = directory.join("stderr.log");
    fs::write(&diagnostics, &result.stderr)?;
    Ok((
        Reply {
            success: result.status.success(),
            stdout: String::from_utf8(result.stdout)?,
            stderr: String::from_utf8(result.stderr)?,
            diagnostics,
        },
        output,
    ))
}

/// Authored bootstrap modules retain worker inputs and preserve the existing VM build contract.
#[test]
#[ignore = "requires explicitly prepared offline Nix sources"]
fn bootstrap_and_machine_exports_preserve_vm_definitions() -> Result<()> {
    let nix = context()?;
    assert_eq!(
        nix.evaluate(
            "export-bootstrap",
            "export/bootstrap",
            json!({
                "output": nix.generated.join("bootstrap-fixture"),
                "nixpkgs": nix.nixpkgs()?,
                "machine": nix.prepared.join("airlock-machine"),
                "root": nix.prepared
            })
        )?
        .value()?,
        json!({"token":"kept","moduleExists":true})
    );
    let original = nix
        .machine("original-whole", "original", json!({"wholeMachine":true}))?
        .value()?;
    let bootstrap = nix
        .machine("bootstrap-whole", "bootstrap", json!({"wholeMachine":true}))?
        .value()?;
    for key in ["vms", "topology"] {
        assert_eq!(bootstrap[key], original[key], "{key}");
    }
    assert_eq!(
        bootstrap["host"]["admission"],
        original["host"]["admission"]
    );
    assert_eq!(
        bootstrap["topology"]["domains"].as_object().unwrap().len(),
        7
    );
    assert!(
        bootstrap["host"]["system"]["drv"]
            .as_str()
            .unwrap()
            .ends_with(".drv")
    );
    assert!(
        bootstrap["host"]["release"]["drv"]
            .as_str()
            .unwrap()
            .ends_with(".drv")
    );

    let before = nix
        .machine("usb-lab-reference", "usb-lab-reference", json!({}))?
        .value()?;
    let after = nix.machine("complete", "complete", json!({}))?.value()?;
    let old = before["vms"].as_object().unwrap();
    let new = after["vms"].as_object().unwrap();
    assert_eq!(
        old.keys().collect::<Vec<_>>(),
        new.keys().collect::<Vec<_>>()
    );
    assert_eq!(new.len(), 6);
    for name in old.keys() {
        assert_eq!(new[name]["root"], old[name]["root"]);
        if name != "sys-gui" && name != "usr-home" {
            assert_eq!(new[name], old[name]);
            assert_eq!(
                after["topology"]["domains"][name],
                before["topology"]["domains"][name]
            );
        }
        assert_eq!(
            after["topology"]["domains"][name]["netvm"],
            before["topology"]["domains"][name]["netvm"]
        );
    }

    let mut settings = Vec::new();
    for (variant, snapshot) in [("usb-lab-reference", &before), ("complete", &after)] {
        let mut value = nix
            .machine(
                &format!("{variant}-settings"),
                variant,
                json!({"projection":"vm-settings"}),
            )?
            .value()?;
        for (name, vm) in value.as_object_mut().unwrap() {
            let system = snapshot["vms"][name]["system"]["out"].as_str().unwrap();
            vm["prefs"]["kernelopts"] = json!(vm["prefs"]["kernelopts"].as_str().unwrap().replace(
                &format!("airlock.system={system}"),
                "airlock.system=<system>"
            ));
        }
        settings.push(value);
    }
    assert_eq!(settings[0], settings[1]);
    let comparison = nix.logs.join("bootstrap-comparison");
    fs::create_dir_all(&comparison)?;
    let old = comparison.join("before.json");
    let new = comparison.join("after.json");
    fs::write(&old, serde_json::to_vec(&before)?)?;
    fs::write(&new, serde_json::to_vec(&after)?)?;
    let review = common::json(
        Command::new(&nix.compiler).arg("diff").arg(old).arg(new),
        None,
    )?;
    assert_eq!(review["addedVMs"], json!({}));
    assert_eq!(review["removedVMs"], json!([]));
    assert_eq!(review["changedVMs"], json!({}));
    Ok(())
}

/// Equivalent snapshots need no staging, while a firewall closure change reaches dependent VMs.
#[test]
#[ignore = "requires explicitly prepared offline Nix sources and dom0 planner"]
fn real_dependency_planner_preserves_runtime_and_rejection_boundaries() -> Result<()> {
    let nix = context()?;
    let before = nix
        .machine("complete-whole", "complete", json!({"wholeMachine":true}))?
        .value()?;
    let after = nix
        .machine(
            "firewall-whole",
            "firewall-diagnostics",
            json!({"wholeMachine":true}),
        )?
        .value()?;
    let all: Vec<_> = before["vms"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let (unchanged, _) = plan(&nix, &before, &before, "unchanged", &all)?;
    let unchanged = unchanged.value()?;
    assert_eq!(unchanged["authority"], "local-inspection-only");
    for key in ["changed", "stage", "stop", "affected"] {
        assert_eq!(unchanged["plan"][key], json!([]));
    }
    assert_eq!(unchanged["plan"]["host_reboot_required"], false);

    for name in &all {
        if *name != "sys-firewall" {
            assert_eq!(after["vms"][*name], before["vms"][*name]);
        }
    }
    assert_ne!(
        after["vms"]["sys-firewall"]["system"],
        before["vms"]["sys-firewall"]["system"]
    );
    for assistant_running in [false, true] {
        let running: Vec<_> = all
            .iter()
            .copied()
            .filter(|name| assistant_running || *name != "usr-assistant")
            .collect();
        let label = format!("firewall-plan-{assistant_running}");
        let (reply, output) = plan(&nix, &before, &after, &label, &running)?;
        let value = reply.value()?;
        let direct = common::json(
            Command::new(&nix.compiler)
                .arg("inspect")
                .arg(output.parent().unwrap().join("before.json"))
                .arg(output.parent().unwrap().join("after.json"))
                .args(&running),
            None,
        )?;
        assert_eq!(value, direct);
        let plan = &value["plan"];
        for key in ["changed", "stage"] {
            assert_eq!(plan[key], json!(["sys-firewall"]));
        }
        let affected = BTreeSet::from(["sys-ctrl", "usr-assistant", "usr-home", "sys-firewall"]);
        assert_eq!(names(&plan["affected"]), affected);
        let running_set: BTreeSet<_> = running.iter().copied().collect();
        assert_eq!(
            names(&plan["stop"]),
            affected.intersection(&running_set).copied().collect()
        );
        assert_eq!(
            plan["stop"].as_array().unwrap().last().unwrap(),
            "sys-firewall"
        );
        assert_eq!(
            names(&plan["start"]),
            running_set
                .union(&BTreeSet::from(["usr-assistant"]))
                .copied()
                .collect()
        );
        let starts = plan["start"].as_array().unwrap();
        let index = |name| starts.iter().position(|value| value == name).unwrap();
        assert!(index("sys-net") < index("sys-firewall"));
        for consumer in ["sys-ctrl", "usr-assistant", "usr-home"] {
            if running.contains(&consumer) {
                assert!(index("sys-firewall") < index(consumer));
                assert!(index("sys-gui") < index(consumer));
            }
        }
        assert_eq!(plan["retire"], json!([]));
        assert_eq!(
            plan["host_reboot_required"],
            before["manifest"]["host"] != after["manifest"]["host"]
        );
    }

    let (valid, output) = plan(&nix, &before, &before, "rejected", &[])?;
    valid.value()?;
    assert!(output.join("plan.json").is_file());
    let (rejected, output) = plan(&nix, &before, &before, "rejected", &["missing-vm"])?;
    assert!(!rejected.success);
    assert!(rejected.stderr.contains("unknown running guest"));
    assert!(!output.join("plan.json").exists());
    Ok(())
}

/// Actual NixOS conflicts retain their Rust component origins and the original module diagnostic.
#[test]
#[ignore = "requires explicitly prepared offline Nix sources"]
fn overrides_and_conflict_diagnostics_retain_rust_provenance() -> Result<()> {
    let nix = context()?;
    assert_eq!(
        nix.machine(
            "scale-override",
            "complete",
            json!({"scale":2,"projection":"scale"})
        )?
        .value()?,
        2
    );
    for (variant, overrides, vm, expected) in [
        (
            "source-conflict",
            json!({"conflict":true,"projection":"workspace"}),
            "usr-assistant",
            vec!["authoring_boundary.rs", "AIRLOCK_WORKSPACE", "nixos-merge"],
        ),
        (
            "complete",
            json!({"desktopConflict":true,"projection":"desktop-session"}),
            "sys-gui",
            vec![
                "src/components/desktop/session.rs",
                "services.displayManager.defaultSession",
                "conflicting definition",
                "nixos-merge",
            ],
        ),
    ] {
        let label = format!("{variant}-conflict");
        let result = nix.machine(&label, variant, overrides)?;
        assert!(!result.success);
        let export = nix.generated.join(variant);
        let mapped = common::run(
            Command::new(&nix.compiler)
                .arg("diagnose")
                .arg(export.join(format!("{vm}.json")))
                .arg(export.join(format!("{vm}.nix")))
                .arg(nix.nixpkgs()?)
                .arg(&result.diagnostics),
            None,
        )?
        .checked()?;
        let mapped = String::from_utf8(mapped)?;
        fs::write(nix.logs.join(format!("{label}.txt")), &mapped)?;
        for text in expected {
            assert!(mapped.contains(text), "missing {text}: {mapped}");
        }
    }
    Ok(())
}

/// Installed capture contracts, qrexec policy and runtime authorization follow typed connections.
#[test]
#[ignore = "requires explicitly prepared offline Nix sources and VM binaries"]
fn capture_connections_control_contracts_policy_and_authorization() -> Result<()> {
    let nix = context()?;
    let installed = nix
        .machine(
            "capture-complete",
            "complete",
            json!({"projection":"capture-implementation"}),
        )?
        .value()?;
    assert_eq!(
        installed["desktop"],
        json!({
            "session": "gnome",
            "defaultSession": "gnome",
            "gnome": true,
            "xfce": false,
            "hasDesktopOptions": false
        })
    );
    assert_eq!(installed["hasSenderOptions"], false);
    assert_eq!(installed["hasReceiverOptions"], false);
    let temporary = tempfile::tempdir()?;
    let config = temporary.path().join("sender.json");
    fs::write(
        &config,
        installed["sender"]["airlock/capture-sender.json"]["text"]
            .as_str()
            .unwrap(),
    )?;
    assert_eq!(
        common::json(
            Command::new(common::binary(
                "AIRLOCK_SYS_GUI_BIN",
                "airlock-sys-gui-service"
            ))
            .args(["screen-capture", "check-config", "--config"])
            .arg(&config),
            None
        )?,
        json!({"target":"usr-home"})
    );
    assert_eq!(
        serde_json::from_str::<Value>(
            installed["receiver"]["airlock/capture-receiver.json"]["text"]
                .as_str()
                .unwrap()
        )?,
        json!({"sources":["sys-gui"]})
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(
            nix.generated.join("complete/connections.json")
        )?)?,
        json!({"screenCapture":[{"source":"sys-gui","target":"usr-home"}]})
    );

    for (index, overrides) in [
        json!({"captureTarget":"usr-other"}),
        json!({"senderContract":"{\"target\":\"usr-other\"}"}),
        json!({"receiverContract":"{\"sources\":[\"other-gui\"]}"}),
        json!({"desktopSession":"xfce"}),
        json!({"gnomeEnabled":false}),
    ]
    .into_iter()
    .enumerate()
    {
        let mut overrides = overrides;
        overrides["projection"] = json!("capture-implementation");
        let reply = nix.machine(&format!("capture-rejected-{index}"), "complete", overrides)?;
        assert!(!reply.success);
        assert!(
            [
                "does not exist",
                "typed screen-capture connection",
                "requires the GNOME completion adapter",
                "requires an enabled GNOME session"
            ]
            .iter()
            .any(|text| reply.stderr.contains(text)),
            "{}",
            reply.stderr
        );
    }

    for (variant, source, target, sources) in [
        (
            "capture-renamed",
            "capture-display",
            "personal-files",
            vec!["capture-display"],
        ),
        (
            "capture-shared",
            "sys-gui",
            "usr-home",
            vec!["sys-gui", "capture-display"],
        ),
    ] {
        let installed = nix
            .machine(
                variant,
                variant,
                json!({
                    "projection": "capture-implementation",
                    "captureSource": source,
                    "captureDestination": target
                }),
            )?
            .value()?;
        assert_eq!(
            serde_json::from_str::<Value>(
                installed["sender"]["airlock/capture-sender.json"]["text"]
                    .as_str()
                    .unwrap()
            )?,
            json!({"target":target})
        );
        let receiver = installed["receiver"]["airlock/capture-receiver.json"]["text"]
            .as_str()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(receiver)?,
            json!({"sources":sources})
        );
        for service in ["airlock.CaptureImport", "airlock.CaptureOpen"] {
            assert!(
                installed["receiver"][format!("qubes-rpc/{service}")]["script"]
                    .as_str()
                    .unwrap()
                    .contains("--config /etc/airlock/capture-receiver.json")
            );
        }
        let policy = nix
            .machine(
                &format!("{variant}-policy"),
                variant,
                json!({"projection":"capture-policy"}),
            )?
            .value()?;
        assert!(!policy["gui"].as_str().unwrap().contains("airlock.Capture"));
        let lines: Vec<_> = policy["capture"].as_str().unwrap().lines().collect();
        let allows: Vec<_> = lines
            .iter()
            .filter(|line| line.ends_with(" allow"))
            .map(|line| (*line).to_owned())
            .collect();
        let mut expected = Vec::new();
        for caller in &sources {
            for service in ["airlock.CaptureImport", "airlock.CaptureOpen"] {
                for kind in ["image", "video"] {
                    expected.push(format!("{service} +{kind} {caller} {target} allow"));
                }
            }
        }
        assert_eq!(allows, expected);
        assert_eq!(
            &lines[lines.len() - 2..],
            [
                "airlock.CaptureImport * @anyvm @anyvm deny",
                "airlock.CaptureOpen * @anyvm @anyvm deny"
            ]
        );
        if variant == "capture-renamed" {
            assert!(
                allows
                    .iter()
                    .all(|line| !line.contains("sys-gui") && !line.contains("usr-home"))
            );
        }

        let temporary = tempfile::tempdir()?;
        let config = temporary.path().join("receiver.json");
        fs::write(&config, receiver)?;
        let xdg = common::peer_link(temporary.path(), "xdg-user-dir")?;
        let vm = common::binary("AIRLOCK_VM_BIN", "airlock-vm-service");
        let data = b"completed screenshot";
        let header = json!({
            "schema": "airlock.capture.v1",
            "id": "a".repeat(64),
            "name": "screen.png",
            "size": data.len(),
            "sha256": format!("{hash:x}", hash = Sha256::digest(data))
        });
        let mut wire = serde_json::to_vec(&header)?;
        wire.push(b'\n');
        wire.extend_from_slice(data);
        let command = |operation: &str, caller: &str| {
            let mut command = Command::new(&vm);
            command
                .args([operation, "image", "--config"])
                .arg(&config)
                .env("HOME", temporary.path())
                .env("XDG_STATE_HOME", temporary.path().join("state"))
                .env("AIRLOCK_XDG_USER_DIR", &xdg)
                .env("QREXEC_REMOTE_DOMAIN", caller);
            command
        };
        for caller in &sources {
            let reply = common::json(&mut command("capture-receive", caller), Some(wire.clone()))?;
            assert_eq!(fs::read(reply["path"].as_str().unwrap())?, data);
        }
        for caller in ["sys-gui", "unrelated-vm", "dom0"]
            .into_iter()
            .filter(|caller| !sources.contains(caller))
        {
            for operation in ["capture-receive", "capture-open"] {
                let reply = common::run(&mut command(operation, caller), Some(Vec::new()))?;
                assert!(!reply.status.success());
                assert!(
                    String::from_utf8_lossy(&reply.stderr)
                        .contains("capture caller is not authorized")
                );
            }
        }
    }

    let installed = nix
        .machine(
            "capture-none",
            "capture-none",
            json!({"projection":"capture-implementation"}),
        )?
        .value()?;
    assert_eq!(installed["sender"], json!({}));
    assert_eq!(installed["receiver"], json!({}));
    assert_eq!(installed["hasSenderOptions"], false);
    assert_eq!(installed["hasReceiverOptions"], false);
    let policy = nix
        .machine(
            "capture-none-policy",
            "capture-none",
            json!({"projection":"capture-policy"}),
        )?
        .value()?;
    assert!(!policy["capture"].as_str().unwrap().contains(" allow"));
    assert!(!policy["gui"].as_str().unwrap().contains("airlock.Capture"));
    let rejected = nix.machine(
        "capture-none-session",
        "capture-none",
        json!({"projection":"capture-implementation","desktopSession":"xfce"}),
    )?;
    assert!(!rejected.success);
    assert!(
        rejected
            .stderr
            .contains("requires an enabled GNOME session")
    );
    Ok(())
}

/// GNOME's connected and standalone profiles retain login, forwarding and setup behavior.
#[test]
#[ignore = "requires explicitly prepared offline Nix sources"]
fn desktop_profiles_preserve_services_extensions_and_startup() -> Result<()> {
    let nix = context()?;
    assert_eq!(
        nix.machine(
            "desktop-consumer",
            "complete",
            json!({"projection":"desktop-consumer"})
        )?
        .value()?,
        json!({
            "session": "gnome",
            "defaultSession": "gnome",
            "gnome": true,
            "capture": true,
            "captureOptions": false,
            "desktopOptions": false
        })
    );
    let desktops = nix
        .machine(
            "desktop-implementation",
            "complete",
            json!({"projection":"desktop-implementation"}),
        )?
        .value()?;
    for (profile, application, core_apps) in [
        ("connected", json!("usr-home"), false),
        ("standalone", Value::Null, true),
    ] {
        let desktop = &desktops[profile];
        assert_eq!(
            desktop["session"],
            json!({
                "default": "gnome",
                "gnome": true,
                "gdm": true,
                "autoSuspend": false,
                "coreApps": core_apps,
                "defaultApplication": application,
                "xfce": false
            })
        );
        assert!(
            desktop["disabledServices"]
                .as_object()
                .unwrap()
                .values()
                .all(|value| value == false)
        );
        assert_eq!(
            desktop["launcher"]["args"],
            json!(["launch", "--workspace"])
        );
        assert!(
            desktop["launcher"]["program"]
                .as_str()
                .unwrap()
                .ends_with("/bin/airlock-sys-gui-service")
        );
        assert!(desktop["system"].as_str().unwrap().ends_with(".drv"));
        let identities = &desktop["identities"];
        let setup = identities["org.airlockos.Setup.desktop"].as_str().unwrap();
        assert!(setup.contains("Icon=org.airlockos.Setup\n"));
        assert!(setup.contains("StartupWMClass=org.airlockos.Setup\n"));
        let notifications = identities["org.airlockos.Desktop.desktop"]
            .as_str()
            .unwrap();
        assert!(notifications.contains("Icon=org.airlockos.Desktop\n"));
        assert!(notifications.contains("NoDisplay=true\n"));
        let review = identities["org.airlock.ctrl.desktop"].as_str().unwrap();
        assert!(review.contains("StartupWMClass=sys-ctrl:org.airlock.ctrl\n"));
        assert!(review.contains("Icon=org.airlock.ctrl\n") && review.contains("NoDisplay=true\n"));
        assert!(
            review
                .lines()
                .any(|line| line.starts_with("Exec=") && line.ends_with("/bin/true"))
        );
    }

    let desktop = &desktops["connected"];
    let enabled = desktop["gsettings"]
        .as_str()
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("enabled-extensions="))
        .unwrap();
    // GSettings prints a flat GVariant array of quoted UUIDs; inspect its values, not quote style.
    let enabled: BTreeSet<_> = enabled
        .trim_matches(['[', ']'])
        .split(',')
        .map(|uuid| uuid.trim().trim_matches(['\'', '"']))
        .collect();
    let mut installed = BTreeSet::new();
    for extension in desktop["extensions"].as_object().unwrap().values() {
        // Extension sources are independent store snapshots held by the private evaluation store.
        let source = Path::new(extension["source"].as_str().unwrap());
        let source = nix
            .temporary
            .path()
            .join("store")
            .join(source.strip_prefix("/")?);
        let metadata: Value = serde_json::from_slice(&fs::read(source.join("metadata.json"))?)?;
        installed.insert(metadata["uuid"].as_str().unwrap().to_owned());
        let phase = extension["installPhase"].as_str().unwrap();
        assert!(
            !phase.contains("@identityReader@") || phase.contains("@identityReader@' '/nix/store/")
        );
    }
    assert_eq!(enabled, installed.iter().map(String::as_str).collect());
    let phase = desktop["extensions"]["airlock-gnome-vm-workspaces"]["installPhase"]
        .as_str()
        .unwrap();
    for (suffix, destination) in [("-state.js", "identity.js"), ("-model.js", "inventory.js")] {
        assert!(phase.lines().any(|line| line.starts_with("cp /nix/store/")
            && line.ends_with(&format!("{suffix} \"$extension_dir/{destination}\""))));
    }
    let watcher = &desktop["watcher"];
    assert!(
        watcher["serviceConfig"]["ExecStart"]
            .as_str()
            .unwrap()
            .ends_with("/bin/qvm-start-daemon --all --watch")
    );
    assert_eq!(watcher["serviceConfig"]["Restart"], "always");
    assert_eq!(watcher["unitConfig"]["StartLimitIntervalSec"], 0);
    for key in ["wantedBy", "partOf"] {
        assert!(
            watcher[key]
                .as_array()
                .unwrap()
                .contains(&json!("graphical-session.target"))
        );
    }
    assert!(
        desktop["startup"]["xdg/autostart/qvm-start-daemon.desktop"]
            .as_str()
            .unwrap()
            .contains("Hidden=true")
    );
    assert!(
        desktop["style"]["requires"]
            .as_array()
            .unwrap()
            .contains(&json!("airlock-qubes-rw-init.service"))
    );
    assert!(
        desktop["style"]["before"]
            .as_array()
            .unwrap()
            .contains(&json!("display-manager.service"))
    );
    assert!(
        desktop["style"]["script"]
            .as_str()
            .unwrap()
            .contains(" gui-style --boot < /nix/store/")
    );
    assert!(
        desktop["guiDaemon"]["postInstall"]
            .as_str()
            .unwrap()
            .contains("gui-border-reload-v1")
    );
    for (filename, command) in [
        (
            "org.airlockos.Setup.desktop",
            "/bin/airlock-sys-gui-setup --auto\n",
        ),
        (
            "airlock-boot-notification.desktop",
            "/bin/airlock-sys-gui-service boot-notification\n",
        ),
    ] {
        let entry = desktop["startup"][format!("xdg/autostart/{filename}")]
            .as_str()
            .unwrap();
        assert!(entry.contains(command) && entry.contains("OnlyShowIn=GNOME;\n"));
    }
    Ok(())
}

/// Physical boot, release artifacts and recovery retain the whole-machine deployment boundaries.
#[test]
#[ignore = "requires explicitly prepared offline Nix sources"]
fn physical_machine_preserves_boot_release_and_recovery() -> Result<()> {
    let nix = context()?;
    let value = nix
        .machine(
            "physical-host",
            "complete",
            json!({"projection":"physical-host"}),
        )?
        .value()?;
    let normal = &value["normal"];
    let recovery = &value["recovery"];
    let standalone = &value["standalone"];
    assert_eq!(value["carrierSetup"], false);
    assert_eq!(
        value["specialisations"],
        json!(["usb-lab", "usb-text-recovery"])
    );
    assert_eq!(normal["profile"], "usb-lab");
    assert_eq!(normal["stores"], normal["prepared"]);
    assert!(
        normal["seed"]
            .as_str()
            .unwrap()
            .contains("/bin/airlock-machine-seed")
    );
    assert_eq!(normal["device"]["bdf"], "0000:09:03.0");
    assert_eq!(
        normal["assignment"],
        json!([
            {
                "backend": "dom0",
                "id": "00_03.1-00_00.0",
                "mode": "required",
                "match": "port",
                "options": {}
            }
        ])
    );
    assert!(
        normal["capturePolicy"]
            .as_str()
            .unwrap()
            .contains("airlock.CaptureImport +image sys-gui usr-home allow")
    );
    assert!(
        normal["diagnosticPolicy"]
            .as_str()
            .unwrap()
            .contains("airlock.Diagnostics.Self + usr-assistant dom0 allow user=root autostart=no")
    );
    assert_eq!(normal["policyDirectoryConflicts"], json!([]));
    assert!(
        normal["release"]
            .as_str()
            .unwrap()
            .ends_with("-airlock-machine-release.drv")
    );
    assert!(
        normal["transport"]
            .as_str()
            .unwrap()
            .ends_with("-airlock-machine-transport.drv")
    );
    assert!(
        normal["releaseTopology"]["domains"]
            .as_object()
            .unwrap()
            .values()
            .all(|domain| domain["backend"]["store"]["source"]
                .as_str()
                .unwrap()
                .starts_with("/nix/store/"))
    );
    assert!(
        normal["hostOrdering"]
            .as_array()
            .unwrap()
            .contains(&json!("airlock-host-store.service"))
    );
    assert!(
        normal["daemonStore"]
            .as_str()
            .unwrap()
            .starts_with("store = local-overlay://")
    );

    assert_eq!(recovery["role"], "recovery\n");
    for key in ["nixEnabled", "hasTopology", "hasHostStore"] {
        assert_eq!(recovery[key], false);
    }
    assert_eq!(recovery["mounts"], json!(["/", "/boot", "/nix/store"]));
    assert_eq!(
        recovery["store"]["device"],
        "/var/lib/airlock/recovery-store"
    );
    for option in ["bind", "ro"] {
        assert!(
            recovery["store"]["options"]
                .as_array()
                .unwrap()
                .contains(&json!(option))
        );
    }
    assert_eq!(recovery["sameKernel"], true);
    assert_eq!(recovery["sameXen"], true);
    assert_eq!(recovery["source"], normal["bootSource"]);
    assert_eq!(recovery["source"]["revision"], normal["source"]["revision"]);
    assert!(recovery["system"].as_str().unwrap().ends_with(".drv"));
    assert_eq!(standalone["profile"], "usb-gui-lab");
    assert_eq!(standalone["domains"], json!(["sys-gui"]));
    assert_eq!(standalone["assignment"][0]["id"], "00_08.1-00_00.0");
    assert!(standalone["system"].as_str().unwrap().ends_with(".drv"));
    Ok(())
}

/// Review distinguishes missing from null and escapes special JSON Pointer characters.
#[test]
fn review_preserves_absence_and_pointer_escaping() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let before = temporary.path().join("before.json");
    let after = temporary.path().join("after.json");
    fs::write(
        &before,
        serde_json::to_vec(
            &json!({"topology":{"domains":{"usr-home":{"prefs":{"a/b~c":null}},"usr-retired":{}}}}),
        )?,
    )?;
    fs::write(
        &after,
        serde_json::to_vec(&json!({"topology":{"domains":{"usr-home":{"prefs":{}}}}}))?,
    )?;
    let review = common::json(
        Command::new(common::binary("AIRLOCK_RUSIX_BIN", "airlock-config"))
            .arg("diff")
            .arg(before)
            .arg(after),
        None,
    )?;
    assert_eq!(review["removedVMs"], json!(["usr-retired"]));
    assert_eq!(
        review["changedVMs"]["usr-home"],
        json!([
            {
                "path": "/prefs/a~1b~0c",
                "before": null,
                "after": null,
                "beforePresent": true,
                "afterPresent": false
            }
        ])
    );
    Ok(())
}

/// Source-owned machine authoring reproduces the prepared artifacts exactly.
#[test]
#[ignore = "requires explicitly prepared authoring binaries and source artifacts"]
fn machine_entry_points_are_current() -> Result<()> {
    let nix = context()?;
    let temporary = tempfile::tempdir()?;
    common::run(
        Command::new(common::binary(
            "AIRLOCK_MACHINE_CONFIG_BIN",
            "airlock-machine-config",
        ))
        .arg("--emit")
        .arg(temporary.path()),
        None,
    )?
    .checked()?;

    /// Compare generated Nix recursively without treating it as an authored Git input.
    fn compare(directory: &Path, relative: &Path, expected: &Path) -> Result<()> {
        for entry in fs::read_dir(directory.join(relative))? {
            let entry = entry?;
            let path = relative.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                compare(directory, &path, expected)?;
            } else if entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "nix")
            {
                assert_eq!(
                    fs::read(entry.path())?,
                    fs::read(expected.join(&path))?,
                    "{path:?}"
                );
            }
        }
        Ok(())
    }
    compare(
        temporary.path(),
        Path::new(""),
        &nix.prepared.join("airlock-machine"),
    )?;

    // The installed adapter also prepares its own Git checkout without a parent source checkout.
    let output = common::run(
        Command::new(common::binary(
            "AIRLOCK_MACHINE_CONFIG_BIN",
            "airlock-machine-config",
        ))
        .arg("prepare")
        .arg(temporary.path().join("cache"))
        .current_dir(nix.root.join("airlock-machine")),
        None,
    )?
    .checked()?;
    let output = String::from_utf8(output)?;
    let prepared = Path::new(
        output
            .trim()
            .strip_prefix("path:")
            .context("prepared machine reference")?,
    );
    assert!(prepared.join("airlock-prepared.json").is_file());
    assert_eq!(
        fs::read(temporary.path().join("flake.nix"))?,
        fs::read(prepared.join("flake.nix"))?
    );
    compare(temporary.path(), Path::new("generated"), prepared)
}
