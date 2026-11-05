//! Authoring stays independent of runtime X11 dependencies and preserves literal command arguments.

use super::*;

/// Real NixOS units bind notification readiness, cleanup and toolkit discovery to the graphical user.
#[test]
#[ignore = "requires explicitly prepared offline Nix sources"]
fn preferences_installation_follows_gui_sessions() -> Result<()> {
    let nix = context()?;
    let report = super::configuration::inspect(&nix, "preferences/installation", json!({}))?;
    assert!(report["sys-net"]["unit"].is_null());
    assert!(report["sys-net"]["binding"].is_null());
    let publisher = &report["sys-gui"];
    assert!(publisher["binding"].is_null());
    assert_eq!(
        publisher["unit"]["wantedBy"],
        json!(["gnome-session.target"])
    );
    assert!(
        publisher["unit"]["serviceConfig"]["ExecStart"]
            .as_str()
            .unwrap()
            .ends_with(" preferences publish")
    );
    assert_eq!(
        publisher["rpc"]["text"],
        format!(
            "force-user='{user}'\n",
            user = publisher["user"].as_str().unwrap()
        )
    );
    for name in ["usr-home", "usr-assistant", "sys-ctrl"] {
        let guest = &report[name];
        let binding: Value = serde_json::from_str(guest["binding"]["text"].as_str().unwrap())?;
        assert_eq!(binding["enabled"], true);
        assert_eq!(binding["gui_domain"], "sys-gui");
        assert!((1..=4).contains(&binding["window_scale"].as_u64().unwrap()));
        assert_eq!(guest["binding"]["mode"], "0444");
        assert!(guest["rpc"].is_null());
        assert_eq!(guest["portal"], true);
        let unit = &guest["unit"];
        assert_eq!(unit["wantedBy"], json!(["qubes-graphical-session.target"]));
        assert!(
            unit["partOf"]
                .as_array()
                .unwrap()
                .contains(&json!("qubes-graphical-session.target"))
        );
        assert_eq!(unit["serviceConfig"]["Type"], "notify");
        assert_eq!(unit["serviceConfig"]["KillMode"], "control-group");
        assert_eq!(unit["serviceConfig"]["TimeoutStopSec"], "15s");
        assert!(
            unit["serviceConfig"]["ExecStopPost"]
                .as_str()
                .unwrap()
                .ends_with(" preferences restore")
        );
        assert!(
            unit["environment"]["GIO_EXTRA_MODULES"]
                .as_str()
                .unwrap()
                .ends_with("/lib/gio/modules")
        );
        assert!(
            guest["environment"]["XDG_DATA_DIRS"]
                .to_string()
                .contains("gsettings-schemas")
        );
    }
    Ok(())
}

/// Resolve feature graphs without compiling or provisioning either side of the service boundary.
#[test]
fn authoring_does_not_require_runtime_dependencies() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let tree = |authoring: bool| -> Result<String> {
        let mut command = Command::new("cargo");
        command
            .args(["tree", "--locked", "--offline", "--manifest-path"])
            .arg(root.join("Cargo.toml"))
            .args([
                "-p",
                "airlock-sys-gui-service",
                "--prefix",
                "none",
                "--format",
                "{p}",
                "--edges",
                "normal",
            ]);
        if authoring {
            command.args(["--no-default-features", "--features", "authoring"]);
        }
        Ok(String::from_utf8(
            common::run(&mut command, None)?.checked()?,
        )?)
    };
    let runtime = tree(false)?;
    let authoring = tree(true)?;
    assert!(!runtime.lines().any(|line| line.starts_with("rusix ")));
    assert!(authoring.lines().any(|line| line.starts_with("rusix ")));
    for dependency in ["x11rb ", "airlock-vm-service "] {
        assert!(!authoring.lines().any(|line| line.starts_with(dependency)));
        assert!(runtime.lines().any(|line| line.starts_with(dependency)));
    }
    Ok(())
}

/// Execute rendered commands and preserve upstream behavior when extending capture build hooks.
#[test]
#[ignore = "requires explicitly prepared offline Nix sources and gio"]
fn rendered_commands_preserve_literal_arguments() -> Result<()> {
    let nix = context()?;
    let temporary = tempfile::tempdir()?;
    let package = temporary.path().join("package");
    fs::create_dir_all(package.join("bin"))?;
    common::peer_link(&package.join("bin"), "airlock-sys-gui-service")?;
    let argument = "/tmp/a \"quote\" \\ slash $dollar `tick` ; %field\nnew\ttab.json";
    let commands = nix
        .evaluate(
            "gui-command-rendering",
            "gui/render-command",
            json!({"package":package,"library":nix.nixpkgs()?.join("lib"),"argument":argument,"apps":nix.prepared.join("crates")}),
        )?
        .value()?;
    for mode in ["shell", "desktop"] {
        let receipt = temporary.path().join(format!("{mode}.json"));
        let mut command = if mode == "shell" {
            let mut command = Command::new("sh");
            command.args(["-c", commands[mode].as_str().unwrap()]);
            command
        } else {
            let desktop = temporary.path().join("arguments.desktop");
            fs::write(
                &desktop,
                format!(
                    r#"[Desktop Entry]
Type=Application
Name=Argument test
Exec={exec}
"#,
                    exec = commands[mode].as_str().unwrap()
                ),
            )?;
            let mut command = Command::new("gio");
            command.arg("launch").arg(desktop);
            command
        };
        nix.environment(&mut command);
        common::run(command.env("AIRLOCK_ARGS_RECEIPT", &receipt), None)?.checked()?;
        common::until(|| Ok(receipt.exists()))?;
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(receipt)?)?,
            json!(["screen-capture", "check-config", "--config", argument])
        );
    }

    let capture = &commands["capture"];
    let patches = capture["patches"].as_array().unwrap();
    assert_eq!(patches[0], "upstream.patch");
    assert!(
        patches
            .last()
            .unwrap()
            .as_str()
            .unwrap()
            .ends_with("-0001-completed-capture-handoff.patch")
    );

    let script = format!(
        r#"
            substituteInPlace() {{ printf '%s\n' substitution; }}
            {hook}
        "#,
        hook = capture["postPatch"].as_str().unwrap(),
    );
    let output = common::run(Command::new("sh").args(["-eu", "-c", &script]), None)?.checked()?;
    assert_eq!(
        String::from_utf8(output)?.lines().collect::<Vec<_>>(),
        ["upstream", "substitution", "substitution"]
    );
    Ok(())
}
