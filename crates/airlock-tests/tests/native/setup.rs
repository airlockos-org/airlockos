//! Exercise the production setup command with native property reads and inert Qubes command peers.

#[path = "setup/image_handoff.rs"]
mod image_handoff;

use crate::common::{self, peers::Peers};
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    process::Command,
};

/// A topology, observed Qubes state and private policy/log paths for one setup scenario.
struct Setup {
    // Owns command peers and all mutable files without touching a live Qubes installation.
    peers: Peers,
    // Desired declaration serialized again before each operation.
    topology: Value,
}

/// Match Qubes' command-line rendering of primitive preference and service values.
fn text(value: &Value) -> String {
    match value {
        Value::Null => "none".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::String(value) => value.clone(),
        value => value.to_string(),
    }
}

/// An otherwise empty topology makes each scenario's policy decisions explicit.
fn topology() -> Value {
    json!({"schema":"airlock.qubes-topology.v1","templates":{},"kernels":{},
        "domains":{},"prefs":{},"qrexec_policy":{"rules":[]}})
}

/// Declare an ordinary VM without changing the architecture or selecting another VM by accident.
fn domain(label: &str, netvm: Value) -> Value {
    json!({"class":"StandaloneVM","template":null,"label":label,"netvm":netvm,
        "prefs":{"autostart":false},"features":{},"services":{},"devices":{"pci":[]}})
}

impl Setup {
    /// Configure literal upstream command replies and isolate every writable setup path.
    fn new(topology: Value, live: Value, globals: Value) -> Result<Self> {
        let mut peers = Peers::new()?;
        peers.native_dom0();
        for name in ["logs", "policy.d", "state", "vm-kernels"] {
            fs::create_dir(peers.path(name))?;
        }
        fs::write(peers.path("capabilities"), "control_d\n")?;
        fs::write(
            peers.path("qubes.xml"),
            "<qubes><properties/><domains/></qubes>",
        )?;

        let mut names = String::from("dom0\n");
        let mut states = String::from("dom0|Running\n");
        let mut classes = String::from("dom0|AdminVM\n");
        let mut preferences = Vec::new();
        let mut features = Vec::new();
        let mut services = Vec::new();
        for (name, vm) in live.as_object().context("observed domains")? {
            names.push_str(&format!("{name}\n"));
            states.push_str(&format!(
                "{name}|{state}\n",
                state = vm["state"].as_str().unwrap_or("Halted")
            ));
            classes.push_str(&format!(
                "{name}|{class}\n",
                class = vm["class"].as_str().unwrap_or("StandaloneVM")
            ));
            for (field, rules, service) in [
                ("prefs", &mut preferences, false),
                ("features", &mut features, false),
                ("services", &mut services, true),
            ] {
                if let Some(values) = vm[field].as_object() {
                    for (key, value) in values {
                        let value = if service {
                            if value == true {
                                "on".into()
                            } else {
                                "off".into()
                            }
                        } else {
                            text(value)
                        };
                        rules.push(json!({"args":[name,key],"stdout":format!("{value}\n")}));
                    }
                }
            }
        }
        for (file, contents) in [("names", names), ("states", states), ("classes", classes)] {
            fs::write(peers.path(file), contents)?;
        }
        peers.rules(
            "qvm-ls",
            json!([
                {"args":["--raw-data","--fields","NAME","--no-spinner"],"stdout_file":"names"},
                {"args":["--raw-data","--fields","NAME,STATE","--no-spinner"],"stdout_file":"states"},
                {"args":["--raw-data","--fields","NAME,CLASS","--no-spinner"],"stdout_file":"classes"}
            ]),
        )?;
        for (name, mut rules) in [
            ("qvm-prefs", preferences),
            ("qvm-features", features),
            ("qvm-service", services),
        ] {
            rules.push(json!({"argc":2,"exit":1}));
            rules.push(json!({"argc":3}));
            peers.rules(name, json!(rules))?;
        }
        let mut rules = Vec::new();
        for (key, value) in globals.as_object().context("observed global preferences")? {
            rules.push(json!({"args":[key],"stdout":format!("{value}\n", value=text(value))}));
        }
        rules.extend([json!({"argc":1,"exit":1}), json!({"argc":2})]);
        peers.rules("qubes-prefs", json!(rules))?;
        for name in [
            "qvm-create",
            "qvm-template-postprocess",
            "qvm-volume",
            "qvm-device",
            "systemctl",
            "airlock-dom0-service",
            // Recovery-route observation belongs to this fixture, never the workstation's NIC.
            "ip",
        ] {
            peers.rules(name, json!([{}]))?;
        }
        let launcher = peers.path("bin/airlock-setup-config");
        fs::copy(
            common::binary("AIRLOCK_EXEC_BIN", "airlock-exec"),
            &launcher,
        )?;
        fs::write(
            peers.path("bin/airlock-setup-config.json"),
            serde_json::to_vec(&json!({
                "program": common::binary("AIRLOCK_DOM0_BIN", "airlock-dom0-service"),
                "args": ["setup-config", "run", "--script", "@self@"]
            }))?,
        )?;
        Ok(Self { peers, topology })
    }

    /// Build a native command using only fixture-local state and explicitly supplied native tools.
    fn command(&self, mode: &str) -> Result<Command> {
        fs::write(
            self.peers.path("topology.json"),
            serde_json::to_vec(&self.topology)?,
        )?;
        let mut command = self
            .peers
            .command(self.peers.path("bin/airlock-setup-config"))?;
        command
            .arg(mode)
            .arg("--topology")
            .arg(self.peers.path("topology.json"))
            .env(
                "AIRLOCK_DOM0_SERVICE",
                self.peers.path("bin/airlock-dom0-service"),
            )
            .env("AIRLOCK_LOG_DIR", self.peers.path("logs"))
            .env("AIRLOCK_QUBES_POLICY_DIR", self.peers.path("policy.d"))
            .env("AIRLOCK_XEN_CAPABILITIES", self.peers.path("capabilities"))
            .env("AIRLOCK_QUBES_XML", self.peers.path("qubes.xml"))
            .env("AIRLOCK_SYSTEM_STATE_DIR", self.peers.path("state"))
            .env("AIRLOCK_QUBES_KERNEL_BASE", self.peers.path("vm-kernels"))
            .env("AIRLOCK_DOM0_NETWORK_PCI_DEVICES", "")
            .env("AIRLOCK_DOM0_DEFAULT_ROUTE_PCI_DEVICES", "")
            .env_remove("AIRLOCK_STAGED_GENERATIONS")
            .env_remove("AIRLOCK_SETUP_CONFIG_STATUS_DEVICE");
        Ok(command)
    }

    /// Invoke the local Rust reconciler with the same isolated paths as its setup adapter.
    fn domain_command(&self, name: &str) -> Result<Command> {
        let setup = self.command("--apply")?;
        let mut command = self.peers.command("airlock-dom0-service")?;
        for (name, value) in setup.get_envs() {
            if let Some(value) = value {
                command.env(name, value);
            } else {
                command.env_remove(name);
            }
        }
        command
            .args(["setup-config", "configure-domain", "--topology"])
            .arg(self.peers.path("topology.json"))
            .arg("--script")
            .arg(self.peers.path("bin/airlock-setup-config"))
            .args([name, "--apply"]);
        Ok(command)
    }

    /// Require successful setup and read its public result rather than matching implementation text.
    fn run(&self, mode: &str) -> Result<Value> {
        self.peers.run(&mut self.command(mode)?)?;
        self.result()
    }

    /// Read the same result consumed by startup and deployment verification.
    fn result(&self) -> Result<Value> {
        self.peers.read("logs/setup-config.json")
    }
}

/// Split setup refuses missing task evidence even when the helper invocation log is empty.
#[test]
fn setup_completion_requires_every_configured_vm_task() -> Result<()> {
    let mut desired = topology();
    desired["domains"]["app"] = domain("green", Value::Null);
    let setup = Setup::new(desired, json!({}), json!({}))?;
    let mut prepare = setup.command("--apply")?;
    prepare
        .arg("--prepare-only")
        .env("AIRLOCK_SETUP_RUN_ID", "123");
    setup.peers.run(&mut prepare)?;
    let mut configure = setup.domain_command("app")?;
    configure.env("AIRLOCK_SETUP_RUN_ID", "123");
    setup.peers.run(&mut configure)?;
    // Independent task snapshots retain all three per-VM outcomes without the helper list.
    fs::write(setup.peers.path("logs/rust-setup-helpers.jsonl"), "")?;
    let mut finish = setup.command("--apply")?;
    finish
        .arg("--finish-only")
        .env("AIRLOCK_SETUP_RUN_ID", "123");
    setup.peers.run(&mut finish)?;
    assert_eq!(setup.result()?["task_results"].as_array().unwrap().len(), 4);

    fs::remove_file(setup.peers.path("logs/task-app-devices.json"))?;
    let mut finish = setup.command("--apply")?;
    finish
        .arg("--finish-only")
        .env("AIRLOCK_SETUP_RUN_ID", "123");
    let result = finish.output()?;
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("setup task"));
    // The failed finish cannot reuse the earlier finalized success.
    assert!(setup.result()?["rust_reconciled"].is_null());
    Ok(())
}

/// Empty global settings must be made explicit even if the observed default is already empty.
#[test]
fn empty_global_defaults_become_explicit() -> Result<()> {
    let mut desired = topology();
    desired["prefs"] = json!({"default_kernel":""});
    let setup = Setup::new(desired, json!({}), json!({"default_kernel":""}))?;
    assert_eq!(setup.run("--apply")?["prefs_changed"], 1);
    assert!(
        setup
            .peers
            .calls()?
            .iter()
            .any(|call| call["command"] == "qubes-prefs"
                && call["args"] == json!(["default_kernel", ""]))
    );

    fs::write(
        setup.peers.path("qubes.xml"),
        r#"<qubes><properties><property name="default_kernel"/></properties></qubes>"#,
    )?;
    let result = setup.run("--apply")?;
    assert_eq!(result["prefs_changed"], 0);
    assert_eq!(result["restart_required"], false);
    Ok(())
}

/// A missing external NetVM is deferred while other safe settings are still reconciled.
#[test]
fn missing_external_network_provider_is_not_assigned() -> Result<()> {
    let mut desired = topology();
    desired["domains"]["dev"] = domain("green", json!("sys-firewall"));
    let setup = Setup::new(
        desired,
        json!({"dev":{"prefs":{"label":"green","autostart":false}}}),
        json!({}),
    )?;
    let result = setup.run("--apply")?;
    assert_eq!(result["domains_changed"], 0);
    assert!(
        result["live_actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|action| action["action"] == "defer"
                && action["domain"] == "dev"
                && action["field"] == "netvm")
    );
    assert!(
        !setup
            .peers
            .calls()?
            .iter()
            .any(|call| call["args"] == json!(["dev", "netvm", "sys-firewall"]))
    );
    Ok(())
}

/// Memory precedes maxmem, and running VMs report the changes requiring a restart.
#[test]
fn preference_order_and_restart_receipts_are_preserved() -> Result<()> {
    let mut desired = topology();
    let mut vm = domain("gray", Value::Null);
    vm["prefs"] = json!({"autostart":false,"maxmem":4096,"memory":2048,"vcpus":2});
    vm["services"] = json!({"network-manager":false});
    desired["domains"]["usr-home"] = vm;
    let setup = Setup::new(
        desired,
        json!({"usr-home":{"state":"Running","prefs":{
        "label":"gray","autostart":false,"netvm":null,"memory":4096,"maxmem":8192,"vcpus":4},
        "services":{"network-manager":true}}}),
        json!({}),
    )?;
    let result = setup.run("--apply")?;
    assert_eq!(result["restart_required"], true);
    let calls = setup.peers.calls()?;
    let position = |args: Value| calls.iter().position(|call| call["args"] == args).unwrap();
    assert!(
        position(json!(["usr-home", "memory", "2048"]))
            < position(json!(["usr-home", "maxmem", "4096"]))
    );
    for (field, value) in [("memory", "2048"), ("network-manager", "off")] {
        assert!(result["restart_actions"].as_array().unwrap().iter().any(
            |action| action["domain"] == "usr-home"
                && action["field"] == field
                && action["value"] == value
                && action["state"] == "Running"
        ));
    }
    assert_eq!(
        setup.peers.read("state/current-setup.json")?["restart_required"],
        true
    );
    Ok(())
}

/// Generation-linked configuration is readable and identical observed state produces no mutations on repeat setup.
#[test]
fn reconciled_topology_is_idempotent() -> Result<()> {
    let mut desired = topology();
    let mut vm = domain("green", Value::Null);
    vm["prefs"]["memory"] = json!(1024);
    vm["features"] = json!({"airlock-role":"usr-home"});
    vm["services"] = json!({"network-manager":false});
    desired["domains"]["usr-home"] = vm;
    let setup = Setup::new(
        desired,
        json!({"usr-home":{"prefs":{"label":"green","netvm":null,"autostart":false,"memory":1024},
        "features":{"airlock-role":"usr-home"},"services":{"network-manager":false}}}),
        json!({}),
    )?;
    fs::create_dir(setup.peers.path("generation"))?;
    fs::create_dir(setup.peers.path("etc"))?;
    symlink("../generation", setup.peers.path("etc/static"))?;
    symlink(
        "etc/static/topology.json",
        setup.peers.path("topology.json"),
    )?;
    fs::write(
        setup.peers.path("qubes.xml"),
        r#"<qubes><domains><domain><properties>
      <property name="name">usr-home</property><property name="netvm"/>
    </properties></domain></domains></qubes>"#,
    )?;
    setup.run("--apply")?;
    fs::write(setup.peers.path("calls.jsonl"), "")?;
    let result = setup.run("--apply")?;
    for key in [
        "domains_changed",
        "prefs_changed",
        "features_changed",
        "services_changed",
        "qrexec_policy_changed",
    ] {
        assert_eq!(result[key], 0, "{key}");
    }
    assert_eq!(result["restart_required"], false);
    assert_eq!(result["restart_actions"], json!([]));
    assert!(!setup.peers.calls()?.iter().any(|call| matches!(
        call["command"].as_str(),
        Some("qvm-prefs" | "qvm-features" | "qvm-service")
    ) && call["args"].as_array().unwrap().len()
        == 3));
    Ok(())
}

/// Policy refresh retries the fixed service even when a previous publication left matching bytes.
#[test]
fn policy_reconciliation_has_a_reload_fallback_and_is_idempotent() -> Result<()> {
    let mut desired = topology();
    desired["qrexec_policy"]["rules"] = json!([
        {"service":"airlock.PolicyProbe","argument":"*","source":"dom0","target":"sys-config-vault","action":"allow"},
        {"service":"airlock.PolicyProbe","argument":"*","source":"@anyvm","target":"@anyvm","action":"deny"}
    ]);
    let mut setup = Setup::new(desired, json!({}), json!({}))?;
    setup.peers.rules(
        "systemctl",
        json!([
            {"args":["reload","qubes-qrexec-policy-daemon.service"],"exit":1},
            {"prefix":["is-active"]},
            {"args":["try-restart","qubes-qrexec-policy-daemon.service"]}
        ]),
    )?;
    assert_eq!(setup.run("--apply")?["qrexec_policy_changed"], 1);
    let policy = fs::read_to_string(setup.peers.path("policy.d/90-airlock.policy"))?;
    assert!(policy.contains("airlock.PolicyProbe * dom0 sys-config-vault allow\n"));
    assert!(policy.contains("airlock.PolicyProbe * @anyvm @anyvm deny\n"));
    assert!(
        setup.peers.calls()?.iter().any(
            |call| call["args"] == json!(["try-restart", "qubes-qrexec-policy-daemon.service"])
        )
    );

    fs::write(setup.peers.path("calls.jsonl"), "")?;
    assert_eq!(setup.run("--apply")?["qrexec_policy_changed"], 0);
    assert!(
        setup
            .peers
            .calls()?
            .iter()
            .any(|call| call["args"] == json!(["reload", "qubes-qrexec-policy-daemon.service"]))
    );
    Ok(())
}

/// The direct policy CLI cannot skip a failed refresh, acknowledge an inactive daemon or substitute a target.
#[test]
fn policy_cli_retries_published_bytes_and_binds_the_configured_target() -> Result<()> {
    let mut peers = Peers::new()?;
    let directory = peers.path("policy.d");
    fs::create_dir(&directory)?;
    let target = directory.join("90-airlock.policy");
    let source = peers.path("topology.json");
    let mut desired = topology();
    desired["qrexec_policy"]["rules"] = json!([
        {"service":"airlock.Probe","argument":"+one","source":"dom0","target":"usr-home","action":"allow"}
    ]);
    fs::write(&source, serde_json::to_vec(&desired)?)?;
    let call =
        |peers: &Peers, target: &std::path::Path| -> Result<airlock_vm_service::support::Output> {
            common::run(
                peers
                    .command(common::binary("AIRLOCK_DOM0_BIN", "airlock-dom0-service"))?
                    .args(["setup-config", "policy", "--apply", "--topology"])
                    .arg(&source)
                    .arg("--rendered")
                    .arg(peers.path("preview"))
                    .arg("--target")
                    .arg(target)
                    .env("AIRLOCK_QUBES_POLICY_DIR", &directory),
                None,
            )
        };
    peers.rules(
        "systemctl",
        json!([
            {"args":["reload","qubes-qrexec-policy-daemon.service"],"exit":1},
            {"args":["try-restart","qubes-qrexec-policy-daemon.service"],"exit":1}
        ]),
    )?;
    assert!(!call(&peers, &target)?.status.success());
    let published = fs::read_to_string(&target)?;
    assert!(published.contains("airlock.Probe +one dom0 usr-home allow\n"));

    peers.rules(
        "systemctl",
        json!([
            {"args":["reload","qubes-qrexec-policy-daemon.service"],"exit":1},
            {"args":["try-restart","qubes-qrexec-policy-daemon.service"]},
            {"args":["is-active","--quiet","qubes-qrexec-policy-daemon.service"]}
        ]),
    )?;
    let output = call(&peers, &target)?;
    assert!(
        output.status.success(),
        "{error}",
        error = String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8(output.stdout)?.trim(), "false");
    assert_eq!(fs::read_to_string(&target)?, published);

    peers.rules(
        "systemctl",
        json!([
            {"args":["reload","qubes-qrexec-policy-daemon.service"],"exit":1},
            {"args":["try-restart","qubes-qrexec-policy-daemon.service"]},
            {"args":["is-active","--quiet","qubes-qrexec-policy-daemon.service"],"exit":1}
        ]),
    )?;
    assert!(!call(&peers, &target)?.status.success());
    fs::write(peers.path("calls.jsonl"), "")?;
    let wrong = directory.join("10-other.policy");
    assert!(!call(&peers, &wrong)?.status.success());
    assert!(!wrong.exists());
    assert!(peers.calls()?.is_empty());
    Ok(())
}

/// Scope selection keeps providers and GUI setup before deferred personal VMs.
#[test]
fn startup_scope_preserves_network_device_and_gui_order() -> Result<()> {
    let mut desired = topology();
    for (name, label, netvm) in [
        ("sys-net", "red", Value::Null),
        ("sys-firewall", "green", json!("sys-net")),
        ("sys-gui", "black", Value::Null),
        ("sys-config-staging", "gray", Value::Null),
        ("dev", "green", json!("sys-firewall")),
    ] {
        desired["domains"][name] = domain(label, netvm);
    }
    for name in ["sys-net", "sys-firewall", "sys-gui"] {
        desired["domains"][name]["prefs"]["autostart"] = json!(true);
        desired["domains"][name]["features"]["airlock-role"] = json!(name);
        desired["domains"][name]["prefs"]["guivm"] = if name == "sys-gui" {
            json!("dom0")
        } else {
            Value::Null
        };
    }
    desired["domains"]["sys-net"]["prefs"]["provides_network"] = json!(true);
    desired["domains"]["sys-firewall"]["prefs"]["provides_network"] = json!(true);
    desired["prefs"] = json!({"default_guivm":"sys-gui","default_netvm":"sys-firewall"});
    let mut setup = Setup::new(desired, json!({}), json!({}))?;
    // Publish each created VM to subsequent upstream inventory reads.
    let mut names = String::from("dom0\n");
    let mut states = String::from("dom0|Running\n");
    let mut classes = String::from("dom0|AdminVM\n");
    let mut creates = Vec::new();
    for (name, label) in [
        ("sys-net", "red"),
        ("sys-firewall", "green"),
        ("sys-gui", "black"),
        ("sys-config-staging", "gray"),
        ("dev", "green"),
    ] {
        names.push_str(&format!("{name}\n"));
        states.push_str(&format!("{name}|Halted\n"));
        classes.push_str(&format!("{name}|StandaloneVM\n"));
        creates.push(
            json!({"args": ["--class", "StandaloneVM", "--label", label, name],
            "write": {"names": names, "states": states, "classes": classes}}),
        );
    }
    for (file, initial) in [
        ("names", "dom0\n"),
        ("states", "dom0|Running\n"),
        ("classes", "dom0|AdminVM\n"),
    ] {
        fs::write(setup.peers.path(file), initial)?;
    }
    setup.peers.rules("qvm-create", json!(creates))?;
    setup.peers.rules("qvm-ls", json!([
        {"args": ["--raw-data", "--fields", "NAME", "--no-spinner"], "stdout_file": "names"},
        {"args": ["--raw-data", "--fields", "NAME,STATE", "--no-spinner"], "stdout_file": "states"},
        {"args": ["--raw-data", "--fields", "NAME,CLASS", "--no-spinner"], "stdout_file": "classes"}
    ]))?;

    let mut command = setup.command("--apply")?;
    command
        .arg("--boot-critical")
        .env("AIRLOCK_DOM0_NETWORK_PCI_DEVICES", "00_1f.6")
        .env(
            "AIRLOCK_SETUP_CONFIG_STATUS_DEVICE",
            setup.peers.path("status"),
        );
    fs::write(setup.peers.path("status"), "")?;
    let output = common::run(&mut command, None)?;
    anyhow::ensure!(
        output.status.success(),
        "startup setup: {log}",
        log = fs::read_to_string(setup.peers.path("logs/setup-config.commands.log"))?
    );
    let output = fs::read_to_string(setup.peers.path("status"))?;
    let result = setup.result()?;
    assert_eq!(result["scope"], "boot-critical");
    assert_eq!(result["domains_changed"], 3);
    let calls = setup.peers.calls()?;
    let before = |first: &str, first_args: Value, second: &str, second_args: Value| {
        let position = |command: &str, arguments: &Value| {
            calls
                .iter()
                .position(|call| call["command"] == command && call["args"] == *arguments)
        };
        assert!(
            position(first, &first_args)
                .is_some_and(|a| position(second, &second_args).is_some_and(|b| a < b)),
            "{first} {first_args} must precede {second} {second_args}: {calls:?}"
        );
    };
    before(
        "qvm-create",
        json!(["--class", "StandaloneVM", "--label", "red", "sys-net"]),
        "qvm-create",
        json!([
            "--class",
            "StandaloneVM",
            "--label",
            "green",
            "sys-firewall"
        ]),
    );
    before(
        "qvm-prefs",
        json!(["sys-net", "netvm", "none"]),
        "qvm-device",
        json!([
            "pci",
            "assign",
            "--required",
            "--port",
            "sys-net",
            "dom0:00_1f.6"
        ]),
    );
    before(
        "qvm-device",
        json!([
            "pci",
            "assign",
            "--required",
            "--port",
            "sys-net",
            "dom0:00_1f.6"
        ]),
        "qvm-prefs",
        json!(["sys-firewall", "netvm", "sys-net"]),
    );
    before(
        "qvm-prefs",
        json!(["sys-gui", "netvm", "none"]),
        "qubes-prefs",
        json!(["default_guivm", "sys-gui"]),
    );
    assert!(!calls.iter().any(|call| call["command"] == "qvm-create"
        && matches!(call["args"].as_array().and_then(|args| args.last()).and_then(Value::as_str),
            Some("dev" | "sys-config-staging"))));
    assert!(output.contains("Topology configured; verifying required VMs next"));

    let output = common::run(setup.command("--apply")?.arg("--deferred"), None)?;
    anyhow::ensure!(
        output.status.success(),
        "deferred setup: {log}",
        log = fs::read_to_string(setup.peers.path("logs/setup-config.commands.log"))?
    );
    let result = setup.result()?;
    assert_eq!(result["scope"], "deferred");
    assert_eq!(result["domains_changed"], 2);
    assert_eq!(result["devices_changed"], 0);
    Ok(())
}

/// Automatic NIC assignment excludes recovery routes for sys-net while allowing its replacement VM.
#[test]
fn automatic_pci_assignment_preserves_recovery_exclusions() -> Result<()> {
    for (name, route, exclusions, expected) in [
        ("sys-net", "00_1f.6", "", vec!["00_1c.0-00_00.0"]),
        ("sys-net", "", "00_1c.0-00_00.0", vec!["00_1f.6"]),
        (
            "usr-assistant",
            "00_1f.6",
            "",
            vec!["00_1f.6", "00_1c.0-00_00.0"],
        ),
    ] {
        let mut desired = topology();
        desired["domains"][name] = domain("red", Value::Null);
        desired["domains"][name]["prefs"]["provides_network"] = json!(true);
        desired["domains"][name]["features"] =
            json!({"airlock-role":name,"airlock-auto-network-pci":"1"});
        let setup = Setup::new(desired, json!({}), json!({}))?;
        let mut command = setup.command("--plan")?;
        command
            .env(
                "AIRLOCK_DOM0_NETWORK_PCI_DEVICES",
                "00_1f.6\n00_1c.0-00_00.0\n00_1c.0-00_00.0\n",
            )
            .env("AIRLOCK_DOM0_DEFAULT_ROUTE_PCI_DEVICES", route)
            .env("AIRLOCK_SYS_NET_PCI_EXCLUDE", exclusions);
        setup.peers.run(&mut command)?;
        let result = setup.result()?;
        let actual: Vec<_> = result["live_actions"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|action| action["type"] == "domain-device" && action["action"] == "assign")
            .map(|action| action["value"].as_str().unwrap())
            .collect();
        let expected: Vec<_> = expected
            .iter()
            .map(|port| format!("dom0:{port} mode=required match=port"))
            .collect();
        assert_eq!(actual, expected);
    }
    Ok(())
}

/// Provider startup follows dependency order and excludes disabled and ordinary application VMs.
#[test]
fn provider_startup_selects_autostart_network_providers() -> Result<()> {
    let mut peers = Peers::new()?;
    peers.rules("airlock-start-qube-ready", json!([{}]))?;
    let mut desired = topology();
    for (name, netvm, autostart, provider) in [
        ("sys-net", Value::Null, true, true),
        ("sys-firewall", json!("sys-net"), true, true),
        ("sys-vpn", Value::Null, false, true),
        ("dev", json!("sys-net"), true, false),
        ("sys-none", json!("none"), true, true),
    ] {
        desired["domains"][name] = json!({"backend":{"system":{"source":format!("/nix/store/{name}")}},
            "netvm":netvm,"prefs":{"autostart":autostart,"provides_network":provider}});
    }
    fs::write(peers.path("topology.json"), serde_json::to_vec(&desired)?)?;
    let mut command = peers.command(common::binary("AIRLOCK_DOM0_BIN", "airlock-dom0-service"))?;
    command
        .arg("start-network-providers")
        .env(
            "AIRLOCK_DOM0_SERVICE",
            common::binary("AIRLOCK_DOM0_BIN", "airlock-dom0-service"),
        )
        .env("AIRLOCK_QUBES_TOPOLOGY", peers.path("topology.json"))
        .env(
            "AIRLOCK_START_QUBE_READY",
            peers.path("bin/airlock-start-qube-ready"),
        )
        .env("AIRLOCK_LOG_DIR", peers.path("logs"));
    peers.run(&mut command)?;
    let result = peers.read("logs/start-network-providers.json")?;
    assert_eq!(
        result["providers"],
        json!(["sys-net", "sys-none", "sys-firewall"])
    );
    assert_eq!(result["started_or_running"], result["providers"]);
    assert_eq!(result["failed"], json!([]));
    let actual: Vec<_> = peers
        .calls()?
        .into_iter()
        .map(|call| call["args"][0].clone())
        .collect();
    assert_eq!(
        actual,
        vec![json!("sys-net"), json!("sys-none"), json!("sys-firewall")]
    );
    Ok(())
}

/// Planning imports and kernel setup must describe effects without executing mutating commands.
#[test]
fn template_and_kernel_planning_has_no_upstream_side_effects() -> Result<()> {
    let mut setup = Setup::new(topology(), json!({}), json!({}))?;
    for name in ["kernel", "template"] {
        fs::create_dir(setup.peers.path(name))?;
    }
    fs::write(setup.peers.path("template/root.img"), "root fixture")?;
    fs::write(
        setup.peers.path("template/template.conf"),
        "qrexec=1\nvirt-mode=pvh\n",
    )?;
    for name in ["vmlinuz", "initramfs", "modules.img"] {
        fs::write(setup.peers.path("kernel").join(name), name)?;
    }
    setup.topology["templates"] = json!({"fedora-44-xfce":{"import":true,"skip_start":true,"source":setup.peers.path("template")}});
    setup.topology["kernels"] = json!({"6.12.64-1.fc41":{"source":setup.peers.path("kernel")}});
    let mut vm = domain("green", Value::Null);
    vm["class"] = json!("AppVM");
    vm["template"] = json!("fedora-44-xfce");
    setup.topology["domains"]["usr-home"] = vm;
    let result = setup.run("--plan")?;
    for key in ["templates_changed", "kernels_changed", "domains_changed"] {
        assert_eq!(result[key], 1, "{key}");
    }
    assert!(!setup.peers.calls()?.iter().any(|call| matches!(
        call["command"].as_str(),
        Some("qvm-create" | "qvm-template-postprocess" | "qvm-volume")
    )));
    assert_eq!(fs::read_dir(setup.peers.path("vm-kernels"))?.count(), 0);
    Ok(())
}

/// Supply valid source descriptors while leaving actual volume mutation to an inert command peer.
fn native_vm(setup: &Setup, name: &str) -> Result<Value> {
    for directory in ["system", "root", "closure"] {
        fs::create_dir_all(setup.peers.path(directory))?;
    }
    fs::write(setup.peers.path("system/init"), "system fixture")?;
    fs::set_permissions(
        setup.peers.path("system/init"),
        fs::Permissions::from_mode(0o755),
    )?;
    fs::write(setup.peers.path("root/root.img"), "root fixture")?;
    fs::write(
        setup.peers.path("closure/store-paths"),
        format!("{system}\n", system = setup.peers.path("system").display()),
    )?;
    fs::write(
        setup.peers.path("closure/manifest.json"),
        serde_json::to_vec(&json!({
            "schema":"airlock.store-closure-manifest.v1","name":"fixture-store","read_only":true
        }))?,
    )?;
    let mut vm = domain("green", Value::Null);
    vm["prefs"] = json!({"autostart":false,"memory":1024,"virt_mode":"pvh"});
    vm["features"] = json!({"airlock-managed":"1","airlock-role":name,"qrexec":"1"});
    vm["backend"] = json!({"type":"nix-closure","template":null,
        "system":{"source":setup.peers.path("system")},
        "kernel":{"name":"6.12.64-1.fc41","source":null},
        "initrd":{"name":null,"source":null},"modules":{"name":null,"source":null},
        "root":{"mode":"qubes-root-image","source":setup.peers.path("root"),"read_only":false},
        "store":{"mode":"shared-closure","source":setup.peers.path("closure"),"read_only":true,
            "view_backend":"erofs-objectmap","blob_device":"/dev/xvdf","mountpoint":"/nix/store"},
        "state":{"persistent":format!("{name}-private"),"persistent_size":8589934592_u64,"volatile":null}});
    Ok(vm)
}

/// New native VMs import one root, enlarge private state and delegate exactly one store materialization.
#[test]
fn native_vm_setup_coordinates_root_private_and_shared_store() -> Result<()> {
    let mut setup = Setup::new(topology(), json!({}), json!({}))?;
    setup.topology["domains"]["usr-home"] = native_vm(&setup, "usr-home")?;
    setup.peers.rules(
        "qvm-create",
        json!([
            {"args":["--class","StandaloneVM","--label","green","usr-home"],
             "write":{"names":"dom0\nusr-home\n","states":"dom0|Running\nusr-home|Halted\n",
                      "classes":"dom0|AdminVM\nusr-home|StandaloneVM\n"}}
        ]),
    )?;
    let report = json!({"schema":"airlock.nix-domain-storage.v1","domain":"usr-home","volume":"store",
        "mode":"shared-closure","source":setup.peers.path("closure"),"read_only":true,
        "volume_created":true,"volumes_created":["store","store-data"],"view_created":true,
        "metadata_changed":true,"qubesd_restart_required":false,"qubesd_restarted":true,
        "generation":1,"closure_hash":"fixture","filesystem":"erofs","view_backend":"erofs-objectmap",
        "view_image":"/pool/view.erofs","metadata_image":"/pool/view.erofs",
        "blob_map":"/pool/view.blob-map.json","blob_volume":"store-data","blob_device":"/dev/xvdf","blob_logical_size":65536,
        "system":setup.topology["domains"]["usr-home"]["backend"]["system"]["source"],
        "root_source":setup.topology["domains"]["usr-home"]["backend"]["root"]["source"],
        "kernel_name":setup.topology["domains"]["usr-home"]["backend"]["kernel"]["name"],
        "device":"/dev/xvde", "mountpoint":"/nix/store"});
    setup.peers.rules(
        "airlock-dom0-service",
        json!([
            {"prefix":["storage","domain","ensure-store"],"stdout":format!("{report}\n")},
            {"prefix":["storage","domain","verify-native-volumes"]}
        ]),
    )?;
    setup.peers.rules("qvm-volume", json!([
        {"prefix":["info"],"stdout":"pool varlibqubes\nvid appvms/usr-home/private\nrw True\nsize 2147483648\nusage 0\n"},
        {}
    ]))?;
    for mode in ["--plan", "--apply"] {
        let result = setup.run(mode)?;
        for (key, expected) in [
            ("domains_changed", 1),
            ("root_images_changed", 1),
            ("store_volumes_changed", 2),
            ("state_volumes_changed", 1),
            ("store_views_changed", 1),
            ("unsupported_domains_count", 0),
        ] {
            assert_eq!(result[key], expected, "{mode} {key}");
        }
    }
    let calls = setup.peers.calls()?;
    assert_eq!(
        calls
            .iter()
            .filter(|call| call["command"] == "airlock-dom0-service"
                && call["args"][2] == "ensure-store")
            .count(),
        1
    );
    assert!(calls.iter().any(|call| call["command"] == "qvm-volume"
        && call["args"] == json!(["resize", "usr-home:private", "8589934592"])));

    // Publish the next boot identity only after root, private and shared-store work finishes.
    let root_import = calls
        .iter()
        .position(|call| call["command"] == "qvm-volume" && call["args"][0] == "import")
        .context("missing root import")?;
    let private_resize = calls
        .iter()
        .position(|call| call["command"] == "qvm-volume" && call["args"][0] == "resize")
        .context("missing private resize")?;
    let store_install = calls
        .iter()
        .position(|call| {
            call["command"] == "airlock-dom0-service" && call["args"][2] == "ensure-store"
        })
        .context("missing store installation")?;
    let boot_identity = calls
        .iter()
        .position(|call| {
            call["command"] == "qvm-features"
                && call["args"][1] == "airlock-system-source"
                && call["args"].as_array().is_some_and(|args| args.len() == 3)
        })
        .context("missing boot identity publication")?;
    assert!(root_import < private_resize);
    assert!(private_resize < store_install);
    assert!(store_install < boot_identity);

    // A halted VM with unavailable capacity must not acquire resizing permission.
    setup
        .peers
        .rules("qvm-volume", json!([{"prefix":["info"],"exit":1}, {}]))?;
    let output = common::run(&mut setup.command("--apply")?, None)?;
    assert!(!output.status.success());
    assert!(
        setup.result()?["reason"]
            .as_str()
            .unwrap()
            .contains("private capacity")
    );
    assert_eq!(
        setup
            .peers
            .calls()?
            .iter()
            .filter(|call| call["command"] == "qvm-volume" && call["args"][0] == "resize")
            .count(),
        1
    );
    Ok(())
}

/// Running native VMs defer root, store and boot identity changes together without partial mutation.
#[test]
fn running_vm_keeps_its_root_store_and_boot_identity_until_restart() -> Result<()> {
    let mut setup = Setup::new(topology(), json!({}), json!({}))?;
    let mut vm = native_vm(&setup, "usr-home")?;
    vm["features"]["airlock-system-source"] = vm["backend"]["system"]["source"].clone();
    vm["features"]["airlock-store-generation"] = json!("new-generation");
    setup.topology["domains"]["usr-home"] = vm;
    let system = setup.peers.path("old-system").display().to_string();
    let root = setup.peers.path("old-root").display().to_string();
    let closure = setup.peers.path("old-closure").display().to_string();
    setup.peers.rules("qvm-ls", json!([
        {"args":["--raw-data","--fields","NAME","--no-spinner"],"stdout":"usr-home\n"},
        {"args":["--raw-data","--fields","NAME,STATE","--no-spinner"],"stdout":"usr-home|Running\n"},
        {"args":["--raw-data","--fields","NAME,CLASS","--no-spinner"],"stdout":"usr-home|StandaloneVM\n"}
    ]))?;
    let mut prefs = Vec::new();
    for (key, value) in [
        ("label", "green"),
        ("netvm", "none"),
        ("autostart", "False"),
        ("memory", "1024"),
        ("virt_mode", "pvh"),
        ("kernel", "6.12.64-1.fc41"),
    ] {
        prefs.push(json!({"args":["usr-home",key],"stdout":format!("{value}\n")}));
    }
    prefs.push(json!({"args":["usr-home","kernelopts"],"stdout":format!("console=hvc0 init=/sbin/init airlock.system={system} airlock.storedev=/dev/xvde airlock.storefmt=erofs airlock.storeblobdev=/dev/xvdf\n")}));
    setup.peers.rules("qvm-prefs", json!(prefs))?;
    let mut features = Vec::new();
    for (key, value) in [
        ("airlock-system-source", system.as_str()),
        ("airlock-root-source", root.as_str()),
        ("airlock-store-source", closure.as_str()),
        ("airlock-backend", "nix-closure"),
        ("airlock-store-mode", "shared-closure"),
        ("airlock-managed", "1"),
        ("airlock-role", "usr-home"),
        ("qrexec", "1"),
    ] {
        features.push(json!({"args":["usr-home",key],"stdout":format!("{value}\n")}));
    }
    features.push(json!({"argc":2,"exit":1}));
    setup.peers.rules("qvm-features", json!(features))?;
    fs::write(
        setup.peers.path("qubes.xml"),
        r#"<qubes><domains><domain><properties>
      <property name="name">usr-home</property><property name="netvm"/>
    </properties></domain></domains></qubes>"#,
    )?;
    let result = setup.run("--apply")?;
    assert_eq!(result["restart_required"], true);
    for key in [
        "root_images_changed",
        "store_volumes_changed",
        "store_views_changed",
    ] {
        assert_eq!(result[key], 0, "{key}");
    }
    assert!(
        result["live_actions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|action| action["type"] == "qrexec-policy")
    );
    let actions = result["restart_actions"].as_array().unwrap();
    for kind in ["domain-root", "domain-store", "domain-system"] {
        assert!(
            actions.iter().any(|action| action["type"] == kind),
            "{kind}: {actions:?}"
        );
    }
    assert!(
        !setup
            .peers
            .calls()?
            .iter()
            .any(
                |call| (call["command"] == "qvm-volume" && call["args"][0] == "import")
                    || (call["command"] == "airlock-dom0-service"
                        && call["args"][2] == "ensure-store")
            )
    );
    Ok(())
}

/// Dom0 completion remains private, durable and idempotent, and damaged records are never overwritten.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_setup_completion_preserves_damaged_state() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let native = common::binary("AIRLOCK_DOM0_BIN", "airlock-dom0-service");
    let run = |action: &str| -> Result<airlock_vm_service::support::Output> {
        let mut command = Command::new(&native);
        command
            .args(["setup", action])
            .env("AIRLOCK_SETUP_STATE", "/var/lib/airlock/setup/state.json");
        common::run(&mut common::namespace(&command, temporary.path())?, None)
    };
    assert_eq!(run("status")?.checked()?, b"incomplete\n");
    let path = temporary.path().join("setup/state.json");
    assert!(!path.exists());
    assert_eq!(run("complete")?.checked()?, b"complete\n");
    let before = fs::read(&path)?;
    assert_eq!(
        serde_json::from_slice::<Value>(&before)?,
        json!({"schema":1,"completed":true})
    );
    assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
    assert_eq!(run("complete")?.checked()?, b"complete\n");
    assert_eq!(fs::read(&path)?, before);

    for damaged in [
        "corrupt",
        r#"{"schema":2,"completed":true}"#,
        r#"{"schema":1,"completed":false}"#,
        r#"{"schema":1,"completed":true,"completed":false}"#,
    ] {
        fs::write(&path, damaged)?;
        assert!(!run("complete")?.status.success());
        assert_eq!(fs::read_to_string(&path)?, damaged);
    }
    Ok(())
}

/// Physical GPU validation must stop setup before template imports or VM mutations can begin.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_gpu_guard_precedes_topology_mutation() -> Result<()> {
    let mut desired = topology();
    desired["domains"]["usr-home"] = domain("green", Value::Null);
    let mut setup = Setup::new(desired, json!({}), json!({}))?;
    fs::create_dir(setup.peers.path("etc"))?;
    fs::write(setup.peers.path("etc/gui-gpu.json"), r#"{"enable":true}"#)?;
    setup.peers.rules(
        "airlock-dom0-service",
        json!([{"prefix":["gpu","check"],"stdout":r#"{"error":"GPU identity refused"}"#,"exit":1}]),
    )?;
    let isolated = common::namespace(&setup.command("--apply")?, &setup.peers.path(""))?;
    let args: Vec<_> = isolated.get_args().collect();
    let index = args
        .iter()
        .position(|arg| *arg == "bash")
        .context("setup command in namespace")?;
    let mut command = Command::new(isolated.get_program());
    command
        .args(&args[..index])
        .args(["--tmpfs", "/etc", "--ro-bind"])
        .arg(setup.peers.path("etc"))
        .arg("/etc/airlock")
        .args(&args[index..]);
    for (key, value) in isolated.get_envs() {
        if let Some(value) = value {
            command.env(key, value);
        } else {
            command.env_remove(key);
        }
    }
    assert!(!common::run(&mut command, None)?.status.success());
    assert!(!setup.peers.calls()?.iter().any(|call| matches!(
        call["command"].as_str(),
        Some("qvm-create" | "qvm-template-postprocess")
    ) || (call["command"] == "qvm-prefs"
        && call["args"].as_array().unwrap().len() == 3)));
    Ok(())
}

/// A declared provider is an internal obligation even when only its client is reconciled.
#[test]
fn single_domain_setup_refuses_missing_declared_provider() -> Result<()> {
    let mut desired = topology();
    desired["domains"]["dev"] = domain("green", json!("provider"));
    desired["domains"]["provider"] = domain("red", Value::Null);
    let setup = Setup::new(
        desired,
        json!({"dev":{"prefs":{"label":"green","autostart":false}}}),
        json!({}),
    )?;
    let output = common::run(&mut setup.domain_command("dev")?, None)?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("declared NetVM is missing"));
    assert!(
        !setup
            .peers
            .calls()?
            .iter()
            .any(|call| call["command"] == "qvm-prefs"
                && call["args"] == json!(["dev", "netvm", "provider"]))
    );
    Ok(())
}

/// Split setup phases preserve preparation and VM changes without duplicate receipt aggregation.
#[test]
fn split_setup_preserves_global_and_vm_results() -> Result<()> {
    let mut desired = topology();
    desired["prefs"] = json!({"default_kernel":"test-kernel"});
    desired["domains"]["dev"] = domain("green", Value::Null);
    desired["domains"]["dev"]["prefs"]["memory"] = json!(1024);
    let setup = Setup::new(
        desired,
        json!({"dev":{"prefs":{"label":"green","netvm":null,"autostart":false,"memory":512}}}),
        json!({}),
    )?;
    fs::write(
        setup.peers.path("qubes.xml"),
        r#"<qubes><domains><domain><properties>
        <property name="name">dev</property><property name="netvm"/>
    </properties></domain></domains></qubes>"#,
    )?;
    setup.peers.run(
        setup
            .command("--apply")?
            .arg("--prepare-only")
            .env("AIRLOCK_SETUP_RUN_ID", "123"),
    )?;
    assert!(
        !setup
            .peers
            .calls()?
            .iter()
            .any(|call| call["command"] == "qvm-create")
    );
    setup.peers.run(
        setup
            .domain_command("dev")?
            .env("AIRLOCK_SETUP_RUN_ID", "123"),
    )?;
    setup.peers.run(
        setup
            .command("--apply")?
            .arg("--finish-only")
            .env("AIRLOCK_SETUP_RUN_ID", "123"),
    )?;
    let result = setup.result()?;
    assert_eq!(result["prefs_changed"], 2);
    assert_eq!(result["restart_required"], false);
    for (kind, field) in [("global-pref", "default_kernel"), ("domain-pref", "memory")] {
        assert_eq!(
            result["live_actions"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|action| action["type"] == kind && action["field"] == field)
                .count(),
            1
        );
    }
    Ok(())
}
