//! Explicit development-only warm tool import through the existing loopback SSH connection.

use super::*;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

/// Collect immutable store object roots from structured configuration, never grep command text.
fn roots(value: &Value, output: &mut BTreeSet<String>) {
    match value {
        Value::String(value) => {
            if let Some(relative) = value.strip_prefix("/nix/store/")
                && let Some(name) = relative.split('/').next().filter(|name| !name.is_empty())
            {
                output.insert(format!("/nix/store/{name}"));
            }
        }
        Value::Array(values) => {
            for value in values {
                roots(value, output);
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                roots(value, output);
            }
        }
        _ => {}
    }
}

/// Find one regular package directory without traversing symlinked subtrees.
fn site_packages(directory: &Path) -> Result<Option<PathBuf>> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            if entry.file_name() == "site-packages" {
                return Ok(Some(entry.path()));
            }
            if let Some(path) = site_packages(&entry.path())? {
                return Ok(Some(path));
            }
        }
    }
    Ok(None)
}

/// Evaluate a declared JSON attribute and preserve the exact decoded input in evidence.
fn evaluate(context: &Context, attribute: &str, output: &str) -> Result<Value> {
    let value = serde_json::from_str(&support::text(&mut context.nix(&[
        "eval",
        "--impure",
        "--json",
        &format!("{root}#{attribute}", root = context.root.display()),
    ])?)?)?;
    context.save(output, &value)?;
    Ok(value)
}

/// Install one file with a separate data transfer; remote shells only parse quoted argv.
fn install(context: &Context, source: &Path, destination: &str) -> Result<()> {
    let temporary = format!(
        "/tmp/airlock-warm-{nonce}",
        nonce = crate::transport::nonce()?
    );
    context.send(source, &temporary)?;
    let result = context.remote(&[
        "sudo",
        "-n",
        "install",
        "-m",
        "0644",
        &temporary,
        destination,
    ]);
    let _ = context.remote(&["rm", "-f", &temporary]);
    result?;
    Ok(())
}

/// Import the selected tool/artifact closure and install transient guest overrides.
pub(super) fn execute(context: &Context) -> Result<()> {
    let topology_enabled = toggle("AIRLOCK_NESTED_WARM_SYNC_TOPOLOGY", true)?;
    let inputs_enabled = toggle("AIRLOCK_NESTED_WARM_SYNC_CONFIG_INPUTS", true)?;
    let restart = toggle("AIRLOCK_NESTED_WARM_RESTART_QUBESD", true)?;
    let mut tools = BTreeMap::new();
    for (key, attribute) in [
        ("setup_config", "airlock-setup-config"),
        ("config_inputs_import", "airlock-config-inputs-import"),
        ("config_vms_smoke", "airlock-config-vms-smoke"),
        ("nix_closure_smoke", "airlock-nix-closure-domain-smoke"),
        ("storage", "airlock-dom0-service"),
        ("adapter", "airlock-qubes-storage-adapter"),
    ] {
        tools.insert(
            key,
            context.build(&format!("packages.x86_64-linux.{attribute}"), None)?,
        );
    }
    let mut topology_sources = BTreeSet::new();
    let mut domains = Vec::new();
    if topology_enabled {
        let topology = evaluate(
            context,
            "nixosConfigurations.vm-gui-config-dev.config.airlock.qubes.topology",
            "vm-gui-current-qubes-topology.json",
        )?;
        ensure!(
            topology["schema"] == "airlock.qubes-topology.v1",
            "invalid topology schema"
        );
        roots(&topology, &mut topology_sources);
        topology_sources
            .insert(context.build("packages.x86_64-linux.airlock-qubes-vm-kernel", None)?);
        for domain in setting(
            "AIRLOCK_NESTED_WARM_NIX_DOMAINS",
            "sys-config-staging sys-config-validator sys-config-vault",
        )
        .split_whitespace()
        {
            ensure!(
                domain
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)),
                "invalid warm domain"
            );
            let system = context.build(
                &format!(
                    "nixosConfigurations.airlock-domain-{domain}.config.system.build.toplevel"
                ),
                None,
            )?;
            let root = context.build(
                &format!("packages.x86_64-linux.airlock-domain-{domain}-root-image"),
                None,
            )?;
            let store = context.build(
                &format!("packages.x86_64-linux.airlock-domain-{domain}-store-closure"),
                None,
            )?;
            topology_sources.extend([system.clone(), root.clone(), store.clone()]);
            domains.push(json!({"domain":domain,"system":system,"root":root,"store":store}));
        }
    }
    let mut inputs = BTreeMap::new();
    let mut input_sources = BTreeSet::new();
    if inputs_enabled {
        let evaluated = evaluate(
            context,
            "airlock.configInputs",
            "vm-gui-current-config-inputs.json",
        )?;
        for (name, key) in [
            ("nixpkgs", "nixpkgs"),
            ("nixpkgs-libvirt_10_5", "nixpkgsLibvirt105"),
            ("nixos-qubes", "nixosQubes"),
            ("airlock-support", "airlockSupport"),
        ] {
            let source = evaluated[key]
                .as_str()
                .filter(|value| value.starts_with("/nix/store/"))
                .context(format!("missing immutable input {key}"))?;
            inputs.insert(name.to_owned(), source.to_owned());
        }
        // Newer source manifests include the Rust authoring seed in addition to the legacy four roots.
        if let Some(source) = evaluated["airlockApps"].as_str() {
            ensure!(source.starts_with("/nix/store/"), "invalid authoring input");
            inputs.insert("airlock-apps".into(), source.into());
        }
        roots(&json!(inputs), &mut input_sources);
        context.save(
            "vm-gui-current-config-inputs-manifest.json",
            &json!({"schema":"airlock.config-inputs.v1","inputs":inputs}),
        )?;
    }
    let sources = tools
        .values()
        .chain(topology_sources.iter())
        .chain(input_sources.iter())
        .collect::<BTreeSet<_>>();
    let closure = support::text(Command::new("nix-store").arg("-qR").args(&sources))?;
    let closure = closure.lines().map(str::to_owned).collect::<BTreeSet<_>>();
    ensure!(
        closure
            .iter()
            .all(|path| path.starts_with("/nix/store/") && !path.chars().any(char::is_whitespace)),
        "invalid closure root"
    );
    let adapter = &tools["adapter"];
    let physical = environment::physical(Path::new(adapter));
    let site = site_packages(&physical.join("lib"))?
        .context("storage adapter has no Python site-packages")?;
    let site = PathBuf::from(adapter)
        .join(site.strip_prefix(&physical)?)
        .to_string_lossy()
        .into_owned();
    let mut bins = Vec::new();
    for program in ["dmsetup", "losetup", "mkfs.erofs"] {
        let source = closure
            .iter()
            .find(|source| {
                environment::physical(Path::new(source))
                    .join("bin")
                    .join(program)
                    .is_file()
            })
            .context(format!("closure omits {program}"))?;
        bins.push(format!("{source}/bin"));
    }
    let mut missing = Vec::new();
    for source in &closure {
        if context.remote(&["test", "-e", source]).is_err() {
            missing.push(source);
        }
    }
    if !missing.is_empty() {
        let export = context.logs.join("vm-gui-warm-export.nar");
        files(
            Command::new("nix-store").arg("--export").args(&missing),
            None,
            &export,
        )?;
        let mut import = context.connection(false)?;
        import.arg("sudo -n nix-store --import");
        files(
            &mut import,
            Some(&export),
            &context.logs.join("vm-gui-warm-import.log"),
        )?;
        fs::remove_file(export)?;
    }
    let old = context
        .remote(&[
            "systemctl",
            "show",
            "-p",
            "Environment",
            "--value",
            "qubesd.service",
        ])
        .unwrap_or_default();
    let old = old
        .split_whitespace()
        .find_map(|value| value.strip_prefix("PYTHONPATH="))
        .unwrap_or("");
    let python = if old.is_empty() {
        site.clone()
    } else {
        format!("{site}:{old}")
    };
    let program_path = format!(
        "{bins}:/run/wrappers/bin:/run/current-system/sw/bin",
        bins = bins.join(":")
    );
    ensure!(
        !python.contains(['\n', '\r', '"']) && !program_path.contains(['\n', '\r', '"']),
        "invalid systemd environment override"
    );
    let dropin = context.logs.join("vm-gui-sync-dom0-tools-qubesd.conf");
    fs::write(
        &dropin,
        format!("[Service]\nEnvironment=PYTHONPATH={python}\nEnvironment=PATH={program_path}\n"),
    )?;
    let bin = setting("AIRLOCK_NESTED_WARM_BIN_DIR", "/run/airlock-warm/bin");
    context.remote(&[
        "sudo",
        "-n",
        "mkdir",
        "-p",
        &bin,
        "/run/systemd/system/qubesd.service.d",
    ])?;
    for (key, program) in [
        ("setup_config", "airlock-setup-config"),
        ("config_inputs_import", "airlock-config-inputs-import"),
        ("config_vms_smoke", "airlock-config-vms-smoke"),
        ("nix_closure_smoke", "airlock-nix-closure-domain-smoke"),
        ("storage", "airlock-dom0-service"),
    ] {
        context.remote(&[
            "sudo",
            "-n",
            "ln",
            "-sfn",
            &format!("{source}/bin/{program}", source = tools[key]),
            &format!("{bin}/{program}"),
        ])?;
    }
    context.remote(&[
        "sudo",
        "-n",
        "rm",
        "-f",
        "/run/systemd/system/qubesd.service.d/90-airlock-warm-tools.conf",
    ])?;
    install(
        context,
        &dropin,
        "/run/systemd/system/qubesd.service.d/zz-airlock-warm-tools.conf",
    )?;
    context.remote(&["sudo", "-n", "systemctl", "daemon-reload"])?;
    let remote_topology = setting(
        "AIRLOCK_NESTED_WARM_TOPOLOGY_PATH",
        "/run/airlock-warm/current-qubes-topology.json",
    );
    if topology_enabled {
        context.remote(&[
            "sudo",
            "-n",
            "mkdir",
            "-p",
            Path::new(&remote_topology)
                .parent()
                .context("remote topology parent")?
                .to_str()
                .context("remote path")?,
        ])?;
        install(
            context,
            &context.logs.join("vm-gui-current-qubes-topology.json"),
            &remote_topology,
        )?;
    }
    let remote_inputs = setting(
        "AIRLOCK_NESTED_WARM_CONFIG_INPUTS_PATH",
        "/run/airlock-warm/config-inputs",
    );
    let system_inputs = setting(
        "AIRLOCK_NESTED_WARM_CONFIG_INPUTS_SYSTEM_PATH",
        "/etc/airlock/config-inputs",
    );
    if inputs_enabled {
        for directory in [&remote_inputs, &system_inputs] {
            context.remote(&["sudo", "-n", "mkdir", "-p", directory])?;
            install(
                context,
                &context
                    .logs
                    .join("vm-gui-current-config-inputs-manifest.json"),
                &format!("{directory}/manifest.json"),
            )?;
            for (name, source) in &inputs {
                let destination = format!("{directory}/{name}");
                if context.remote(&["mountpoint", "-q", &destination]).is_ok() {
                    context.remote(&["sudo", "-n", "umount", &destination])?;
                }
                if context.remote(&["test", "-L", &destination]).is_ok()
                    || (context.remote(&["test", "-e", &destination]).is_ok()
                        && context.remote(&["test", "-d", &destination]).is_err())
                {
                    context.remote(&["sudo", "-n", "rm", "-f", &destination])?;
                }
                context.remote(&["sudo", "-n", "mkdir", "-p", &destination])?;
                context.remote(&["sudo", "-n", "mount", "--bind", source, &destination])?;
            }
        }
    }
    if restart {
        let _ = context.remote(&["sudo", "-n", "systemctl", "reset-failed", "qubesd.service"]);
        context.remote(&["sudo", "-n", "systemctl", "restart", "qubesd.service"])?;
    }
    let record = json!({"schema":"airlock.nested-dom0-tool-sync.v1","status":"passed","setup_config":tools["setup_config"],"config_inputs_import":tools["config_inputs_import"],"config_vms_smoke":tools["config_vms_smoke"],"nix_closure_smoke":tools["nix_closure_smoke"],"storage":tools["storage"],"topology":{"synced":topology_enabled,"remote_path":remote_topology,"sources":topology_sources,"domains":domains},"config_inputs":{"synced":inputs_enabled,"remote_path":remote_inputs,"system_path":system_inputs,"sources":input_sources,"inputs":inputs},"storage_site":site,"remote_bin_dir":bin,"qubesd":{"pythonpath":python,"path":program_path,"restarted":restart},"closure_paths_total":closure.len(),"imported_paths":missing.len()});
    context.save("vm-gui-sync-dom0-tools.json", &record)?;
    println!("{record}");
    Ok(())
}
