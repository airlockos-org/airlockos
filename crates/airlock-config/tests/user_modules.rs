//! Evaluate user-owned module imports through generated VM factories and upstream NixOS merging.
//! Nix and its pinned library must be prepared explicitly; this test never builds a VM.

use airlock_config::rusix::{
    self,
    interop::{
        NixPath,
        raw::{NixRepresentation, NixValue},
    },
    nix_record,
};
use std::{fs, path::Path, process::Command};

/// Represent an existing absolute fixture path without embedding its contents in Rust-generated Nix.
fn path(path: &Path) -> NixValue {
    NixPath::from_source_text(path.to_string_lossy().into_owned()).as_expression()
}

/// Local imports, settings overrides and data files compose only into the selected VM.
#[test]
#[ignore = "requires explicitly prepared Nix and AIRLOCK_TEST_NIXPKGS/AIRLOCK_NIX_ROOT"]
fn external_tool_user_modules_compose_and_track_local_inputs()
-> Result<(), Box<dyn std::error::Error>> {
    let nixpkgs = std::env::var("AIRLOCK_TEST_NIXPKGS")?;
    let store = std::env::var("AIRLOCK_NIX_ROOT")?;
    assert!(Path::new(&store).is_absolute() && store != "/");
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let directory = root.join("vms");
    fs::create_dir(&directory)?;
    fs::write(
        directory.join("usr-home.nix"),
        r#"
        { pkgs, ... }: {
          imports = [ ./shared.nix ];
          environment.systemPackages = [ pkgs.firefox ];
          services.example.enable = false;
          test.payload = builtins.readFile ./payload.txt;
        }
    "#,
    )?;
    fs::write(directory.join("shared.nix"), "{ test.shared = true; }")?;
    fs::write(directory.join("payload.txt"), "original")?;

    let machine = airlock_config::profiles::usb_lab::machine(false)?;
    let generated = root.join("machine.nix");
    fs::write(&generated, airlock_config::generate(&machine)?.source)?;
    let lib = NixValue::builtin("import").call(path(&Path::new(&nixpkgs).join("lib")));
    let builder = NixValue::builtin("import")
        .call(path(&generated))
        .select("builders");
    let arguments = nix_record! {
        "lib":lib.clone(),
        "mkAirlockQubeBuilders":NixValue::function(|_| nix_record! {
            "mkNixNativeDomain":NixValue::function(|args| args),
        }),
        "airlockQubesVmKernelName":"fixture-kernel",
        "airlockSupport":path(root),
    };
    let plain = builder.clone().call(arguments.clone());
    let factories = builder.call(arguments.merge_attrs(nix_record! {
        "userModulesDirectory":path(&directory),
    }));
    let evaluated = |factories: &NixValue, name: &str| {
        let modules = factories
            .clone()
            .select(name)
            .call("x86_64-linux")
            .select("modules");
        // The builder receives implementation modules followed by the user import.
        let user = lib.clone().select("last").call(modules);
        let string_list = lib
            .clone()
            .select("types.listOf")
            .call(lib.clone().select("types.str"));
        let option = |kind: NixValue, default: NixValue| {
            lib.clone()
                .select("mkOption")
                .call(nix_record! { "type":kind, "default":default })
        };
        lib.clone().select("evalModules").call(nix_record! {
            "specialArgs":nix_record! { "pkgs":nix_record! { "firefox":"fixture-browser" } },
            "modules":NixValue::list([nix_record! {
                "options":nix_record! {
                    "environment":nix_record! { "systemPackages":option(string_list, NixValue::list([])) },
                    "services":nix_record! { "example":nix_record! { "enable":option(lib.clone().select("types.bool"), true.into()) } },
                    "test":nix_record! {
                        "shared":option(lib.clone().select("types.bool"), false.into()),
                        "payload":option(lib.clone().select("types.str"), "default".into()),
                    },
                },
                "config":nix_record! { "environment":nix_record! { "systemPackages":NixValue::list(["base".into()]) } },
            },user]),
        }).select("config")
    };
    let driver = root.join("driver.nix");
    fs::write(
        &driver,
        rusix::compile(rusix::Config::new().set_dynamic(
            "result",
            nix_record! {
                "home":evaluated(&factories, "usr-home"), "network":evaluated(&factories, "sys-net"),
                "plain":evaluated(&plain, "usr-home"),
            },
        ))
        .map_err(|error| error.render(root))?
        .source,
    )?;
    let evaluate = || -> Result<std::process::Output, std::io::Error> {
        Command::new("nix")
            .args([
                "--store",
                &store,
                "--extra-experimental-features",
                "nix-command",
                "--option",
                "build-users-group",
                "",
                "--option",
                "substituters",
                "",
                "--offline",
                "eval",
                "--impure",
                "--json",
                "--eval-store",
            ])
            .arg(root.join("eval-store"))
            .arg("--file")
            .arg(&driver)
            .arg("result")
            .output()
    };
    let output = evaluate()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let packages = value["home"]["environment"]["systemPackages"]
        .as_array()
        .unwrap();
    assert!(
        packages.contains(&serde_json::json!("fixture-browser"))
            && packages.contains(&serde_json::json!("base"))
    );
    assert_eq!(value["home"]["services"]["example"]["enable"], false);
    assert_eq!(value["home"]["test"]["shared"], true);
    assert_eq!(value["home"]["test"]["payload"], "original");
    assert_eq!(
        value["network"]["environment"]["systemPackages"],
        serde_json::json!(["base"])
    );
    assert_eq!(value["plain"]["test"]["payload"], "default");
    fs::write(directory.join("payload.txt"), "changed")?;
    let output = evaluate()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(value["home"]["test"]["payload"], "changed");
    fs::write(
        directory.join("usr-home.nix"),
        "{ services.example.enable = 123; }",
    )?;
    assert!(!evaluate()?.status.success());
    Ok(())
}
