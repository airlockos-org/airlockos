//! Stateful Qubes command replies for native machine transaction scenarios in a disposable namespace.

use airlock_vm_service::support;
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    os::unix::{fs::symlink, process::CommandExt},
    path::Path,
    process::Command,
    time::Duration,
};

/// Read one named command argument without guessing a Qubes command's option order.
fn option<'a>(arguments: &'a [String], option: &str) -> Result<&'a str> {
    arguments
        .iter()
        .position(|value| value == option)
        .and_then(|index| arguments.get(index + 1))
        .map(String::as_str)
        .with_context(|| format!("missing argument {option}"))
}

/// Persist only fixture data and return supplied upstream replies; production code owns every decision.
pub fn execute(root: &Path, program: &str, original: &[String]) -> Result<()> {
    let path = root.join("data.json");
    let mut data: Value = serde_json::from_slice(&fs::read(&path)?)?;
    let mut program = program.to_owned();
    let mut arguments = original;
    if program == "airlock-dom0-service" {
        if arguments.first().map(String::as_str) != Some("storage") {
            return Err(Command::new(
                std::env::var_os("AIRLOCK_FIXTURE_DOM0_BINARY").context("native dom0 binary")?,
            )
            .args(arguments)
            .exec()
            .into());
        }
        program = format!(
            "storage-{action}",
            action = arguments.get(1).context("storage action")?
        );
        arguments = &arguments[2..];
    }
    let mut row = vec![json!(program)];
    row.extend(arguments.iter().map(|value| json!(value)));
    let mut calls = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("calls.jsonl"))?;
    let call = Value::Array(row);
    writeln!(calls, "{call}")?;
    if program == "airlock-setup-config" && arguments == ["--protocol"] {
        if data["native_setup"] == true {
            println!("airlock.setup.v4");
            return Ok(());
        }
        // Match the admitted legacy script's unsupported-option response without
        // applying staged generations or reporting configuration completion.
        eprintln!("Usage: airlock-setup-config (--plan|--apply)");
        std::process::exit(1);
    }
    if data["delay"] == program {
        std::thread::sleep(Duration::from_secs(2));
    }
    ensure!(data["fail"] != program, "simulated helper failure");

    let last = || {
        arguments
            .last()
            .map(String::as_str)
            .context("command target")
    };
    match program.as_str() {
        "qvm-check" => {
            ensure!(
                data["running"]
                    .as_array()
                    .unwrap()
                    .contains(&json!(last()?)),
                "fixture guest is not running"
            );
        }
        "qvm-ls" => {
            if arguments.iter().any(|value| value == "--raw-list") {
                println!("dom0");
                for name in data["selected"].as_object().unwrap().keys() {
                    println!("{name}");
                }
            } else {
                let selected = data["selected"].as_object().unwrap();
                let names: Vec<_> = if selected.contains_key(last()?) {
                    vec![last()?]
                } else {
                    selected.keys().map(String::as_str).collect()
                };
                for name in names {
                    let state = if let Some(state) = data["power_states"][name].as_str() {
                        state
                    } else if data["running"].as_array().unwrap().contains(&json!(name)) {
                        "Running"
                    } else {
                        "Halted"
                    };
                    match option(arguments, "--fields").unwrap_or("NAME,STATE") {
                        "NAME" => println!("{name}"),
                        "NAME,CLASS" => println!("{name}|StandaloneVM"),
                        _ => println!("{name}|{state}"),
                    }
                }
            }
        }
        "qvm-features" => {
            let name = &arguments[0];
            let key = &arguments[1];
            if arguments.len() == 3 {
                if data["features"].is_null() {
                    data["features"] = json!({});
                }
                if data["features"][name].is_null() {
                    data["features"][name] = json!({});
                }
                data["features"][name][key] = json!(arguments[2]);
            } else if let Some(value) = data["features"][name][key].as_str() {
                println!("{value}");
            } else {
                let generation = &data["selected"][name];
                let info = &data["generations"][format!("{name}:{generation}")];
                let value = match key.as_str() {
                    "airlock-store-generation" => generation.clone(),
                    "airlock-root-source" => info["root_source"].clone(),
                    "airlock-root-artifact" => info["root_artifact"]["sha256"].clone(),
                    "airlock-store-source" => info["closure_source"].clone(),
                    "airlock-store-mode" => json!("shared-closure"),
                    _ => info["system"].clone(),
                };
                println!(
                    "{value}",
                    value = value
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| value.to_string())
                );
            }
        }
        "qvm-volume" => {
            let name = arguments[1].split_once(':').context("volume target")?.0;
            match arguments[0].as_str() {
                "info" => println!(
                    "size  {size}",
                    size = data["private_sizes"][name].as_u64().unwrap_or(100)
                ),
                "resize" => {
                    if data["private_sizes"].is_null() {
                        data["private_sizes"] = json!({});
                    }
                    data["private_sizes"][name] = json!(arguments[2].parse::<u64>()?);
                    data["resize_count"] = json!(data["resize_count"].as_u64().unwrap_or(0) + 1);
                }
                "import" => {
                    data["root_import_count"] =
                        json!(data["root_import_count"].as_u64().unwrap_or(0) + 1);
                    if data["lose_root_reply"] == true {
                        fs::write(&path, serde_json::to_vec(&data)?)?;
                        bail!("simulated lost root-import reply");
                    }
                }
                _ => bail!("unexpected volume operation"),
            }
        }
        "storage-domain" => match arguments[0].as_str() {
            "verify-native-volumes" => println!("{}", json!({"native_volume_isolation":"passed"})),
            "ensure-store" => {
                let name = &arguments[1];
                let supplied = std::env::var_os("AIRLOCK_STAGED_GENERATIONS")
                    .map(|path| -> Result<Option<u64>> {
                        let staged: Value = serde_json::from_slice(&fs::read(path)?)?;
                        staged
                            .get(name)
                            .map(|value| {
                                value
                                    .as_u64()
                                    .or_else(|| value.as_str()?.parse().ok())
                                    .context("invalid fixture generation")
                            })
                            .transpose()
                    })
                    .transpose()?
                    .flatten();
                let explicit = arguments
                    .iter()
                    .position(|arg| arg == "--generation")
                    .map(|index| {
                        arguments
                            .get(index + 1)
                            .context("generation value")?
                            .parse::<u64>()
                            .context("invalid requested generation")
                    })
                    .transpose()?;
                if let (Some(expected), Some(supplied)) = (explicit, supplied) {
                    ensure!(
                        expected == supplied,
                        "staged generation differs from request"
                    );
                }
                let generation = json!(
                    explicit
                        .or(supplied)
                        .context("missing fixture generation")?
                );
                ensure!(!generation.is_null(), "missing staged fixture generation");
                let mut receipt = data["generations"][format!("{name}:{generation}")].clone();
                receipt["schema"] = json!("airlock.nix-domain-storage.v1");
                receipt["domain"] = json!(name);
                for key in [
                    "mode",
                    "device",
                    "blob_device",
                    "mountpoint",
                    "view_backend",
                ] {
                    receipt[key] = receipt["store"][key].clone();
                }
                data["selected"][name] = generation;
                data["store_install_count"] =
                    json!(data["store_install_count"].as_u64().unwrap_or(0) + 1);
                receipt["source"] = if data["wrong_store_receipt"] == true {
                    json!("/different-closure")
                } else {
                    receipt["closure_source"].clone()
                };
                receipt["qubesd_restart_required"] = json!(data["store_restart_required"] == true);
                receipt["qubesd_restarted"] = json!(false);
                receipt["closure_hash"] = receipt["store"]["closure_hash"].clone();
                receipt["view_image"] = json!("/var/lib/airlock/pool/metadata.img");
                if data["lose_store_reply"] == true {
                    fs::write(&path, serde_json::to_vec(&data)?)?;
                    bail!("simulated lost store-install reply");
                }
                println!("{receipt}");
            }
            _ => bail!("unexpected domain storage operation"),
        },
        "storage-pool" => match arguments.first().map(String::as_str) {
            Some("find-generation") => {
                let namespace = option(arguments, "--domain")?;
                let system = option(arguments, "--system")?;
                let source = option(arguments, "--closure-source")?;
                let root = option(arguments, "--root-source")?;
                let kernel = option(arguments, "--kernel-name")?;
                let approved_by = option(arguments, "--approved-by")?;
                let matches = data["generations"]
                    .as_object()
                    .context("fixture generations")?
                    .values()
                    .filter(|info| {
                        info["domain"] == namespace
                            && info["system"] == system
                            && info["closure_source"] == source
                            && info["root_source"] == root
                            && info["kernel_name"] == kernel
                            && info["approval"]["approved_by"] == approved_by
                    })
                    .max_by_key(|info| info["generation"].as_u64());
                let reply = match matches {
                    Some(info) => {
                        json!({"schema":"airlock.closure-store.generation-match.v1", "domain":namespace,
                        "status":"found", "generation":info["generation"], "manifest":info["manifest"],
                        "closure_hash":info["store"]["closure_hash"]})
                    }
                    None => {
                        json!({"schema":"airlock.closure-store.generation-match.v1", "domain":namespace, "status":"missing"})
                    }
                };
                println!("{reply}");
            }
            Some("describe-generation") => {
                let namespace = option(arguments, "--domain")?;
                let name = namespace
                    .strip_suffix("-runtime-store")
                    .context("runtime namespace required")?;
                let generation: u64 = option(arguments, "--generation")?.parse()?;
                let mut info = data["generations"][format!("{name}:{generation}")].clone();
                info["selected"] = json!(data["selected"][name] == generation);
                println!("{info}");
            }
            Some("resolve-root") => {
                let name = option(arguments, "--domain")?;
                let source = option(arguments, "--root-source")?;
                let generation = data["generations"]
                    .as_object()
                    .context("missing fixture generations")?
                    .values()
                    .find(|info| info["domain"] == name && info["root_source"] == source)
                    .context("missing root fixture")?;
                println!(
                    "{}",
                    json!({"domain":name, "root_source":source,
                    "image":"/var/lib/airlock/pool/root.img", "artifact":generation["root_artifact"]})
                );
            }
            Some("gc" | "retire-generation" | "set-retention" | "release-automatic") => {
                println!("{}", json!({"status": "passed"}))
            }
            _ => bail!("unexpected pool operation"),
        },
        "storage-host" => {
            if ["validate", "publish"].contains(&arguments[0].as_str()) {
                let count = data["host_validations"].as_u64().unwrap_or(0) + 1;
                data["host_validations"] = json!(count);
                let response = if count > 1 && !data["host_response_after_preflight"].is_null() {
                    &data["host_response_after_preflight"]
                } else {
                    &data["host_pool"]
                };
                println!("{response}");
            }
        }
        "storage-artifact" => {
            if data["artifact_error"] == true {
                println!(
                    "{}",
                    json!({"schema": "airlock.pool-artifact-error.v1", "error": "simulated storage rejection"})
                );
                std::process::exit(1);
            }
            println!(
                "{}",
                json!({"schema": "airlock.closure-store.admission.v1", "status": "passed", "activated": false})
            );
        }
        "nix-store" => {
            if arguments.iter().any(|value| value == "--add-root") {
                let link = Path::new(option(arguments, "--add-root")?);
                fs::create_dir_all(link.parent().context("GC root parent")?)?;
                if fs::symlink_metadata(link).is_ok() {
                    fs::remove_file(link)?;
                }
                symlink(last()?, link)?;
                println!("{target}", target = last()?);
            } else if arguments.iter().any(|value| value == "--print-live") {
                println!(
                    "{host}",
                    host = data["host_pool"]["system"].as_str().unwrap()
                );
            }
        }
        "qvm-shutdown" => {
            data["running"]
                .as_array_mut()
                .unwrap()
                .retain(|value| value != last().unwrap());
            // Model an independent administrator restarting the target before the next observation.
            if data["restart_after_shutdown"] == true {
                data["running"].as_array_mut().unwrap().push(json!(last()?));
            }
        }
        "qvm-start" => {
            let name = json!(last()?);
            let running = data["running"].as_array_mut().unwrap();
            if !running.contains(&name) {
                running.push(name);
            }
        }
        "qvm-prefs" => {
            if arguments.len() == 2 && arguments[1] == "uuid" {
                let suffix = if arguments[0] == "usr-home" { "0" } else { "1" };
                if let Some(uuid) = data["uuids"][&arguments[0]].as_str() {
                    println!("{uuid}");
                } else {
                    println!("123e4567-e89b-12d3-a456-42661417400{suffix}");
                }
            }
        }
        "qvm-tags" => {
            let name = &arguments[0];
            if data["tags"].is_null() {
                data["tags"] = json!({});
            }
            if data["tags"][name].is_null() {
                data["tags"][name] = json!([]);
            }
            let tags = data["tags"][name].as_array_mut().unwrap();
            match arguments[1].as_str() {
                "add" => {
                    let tag = json!(arguments[2]);
                    if !tags.contains(&tag) {
                        tags.push(tag);
                    }
                }
                "del" => tags.retain(|tag| tag != &arguments[2]),
                "list" => {
                    for tag in tags {
                        println!("{tag}", tag = tag.as_str().unwrap());
                    }
                }
                _ => bail!("unexpected tag operation"),
            }
        }
        "qvm-remove" => {
            data["selected"].as_object_mut().unwrap().remove(last()?);
        }
        "qrexec-client" => {
            let name = option(arguments, "-d")?;
            if arguments
                .last()
                .is_some_and(|command| command.contains("boot-health build-store"))
            {
                data["health_probes"] = json!(data["health_probes"].as_u64().unwrap_or(0) + 1);
                let failures = data["health_failures"].as_u64().unwrap_or(0);
                data["health_failures"] = json!(failures.saturating_sub(1));
                fs::write(&path, serde_json::to_vec(&data)?)?;
                ensure!(failures == 0, "worker build store not ready");
                return Ok(());
            }
            let generation = &data["selected"][name];
            println!(
                "{system}",
                system = data["generations"][format!("{name}:{generation}")]["system"]
                    .as_str()
                    .unwrap()
            );
        }
        "airlock-setup-config" => {
            if data["native_setup"] != true
                && let Some(staged) = std::env::var_os("AIRLOCK_STAGED_GENERATIONS")
            {
                let staged: Value = serde_json::from_slice(&fs::read(staged)?)?;
                data["selected"]
                    .as_object_mut()
                    .unwrap()
                    .extend(staged.as_object().unwrap().clone());
            }
            let output = std::env::var_os("AIRLOCK_LOG_DIR")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| root.join("log"));
            fs::create_dir_all(&output)?;
            let mut report = json!({"schema":"airlock.setup-config.v1", "status":"passed",
                "restart_required":false, "unsupported_domains_count":0});
            if data["native_setup"] == true {
                let topology: Value =
                    serde_json::from_slice(&fs::read(option(arguments, "--topology")?)?)?;
                let phase = if arguments.iter().any(|a| a == "--prepare-only") {
                    "prepare-only"
                } else {
                    "finish-only"
                };
                let run = std::env::var("AIRLOCK_SETUP_RUN_ID")?;
                if phase == "prepare-only" {
                    if let Some(mapping) = data["staged_after_prepare"].as_object() {
                        // Simulate a changed compatibility file after checked staging was captured.
                        fs::write(
                            output
                                .parent()
                                .context("transaction directory")?
                                .join("staged.json"),
                            serde_json::to_vec(mapping)?,
                        )?;
                    }
                    fs::write(output.join("rust-vm-actions.jsonl"), "")?;
                    fs::write(output.join("rust-setup-helpers.jsonl"), "")?;
                }
                let topology_hash = format!("{:x}", Sha256::digest(serde_json::to_vec(&topology)?));
                if phase == "prepare-only" {
                    fs::write(
                        output.join("task-preparation.json"),
                        serde_json::to_vec(&json!({
                            "task":"preparation", "run_id":run, "topology_hash":topology_hash,
                            "scope":"all", "mode":"apply", "status":"passed", "pending":false, "unsupported":0
                        }))?,
                    )?;
                }
                if phase == "finish-only"
                    && let Some(mapping) = data["selected_after_setup"].as_object().cloned()
                {
                    // External selection can drift after setup succeeded but before final verification.
                    for (name, generation) in mapping {
                        data["selected"][&name] = generation.clone();
                        data["features"][&name]["airlock-store-generation"] =
                            json!(generation.to_string());
                    }
                }

                report["topology"] = json!(option(arguments, "--topology")?);
                for (key, value) in json!({"mode":"apply", "scope":"all", "phase":phase,
                    "run_id":run, "topology_hash":format!("{:x}", Sha256::digest(serde_json::to_vec(&topology)?)),
                    "reason":"fixture completed", "live_actions":[], "restart_actions":[], "unsupported_domains":[]}).as_object().unwrap() {
                    report[key] = value.clone();
                }
                for counter in [
                    "templates_changed",
                    "kernels_changed",
                    "domains_changed",
                    "prefs_changed",
                    "features_changed",
                    "services_changed",
                    "devices_changed",
                    "qrexec_policy_changed",
                    "root_images_changed",
                    "store_volumes_changed",
                    "state_volumes_changed",
                    "store_views_changed",
                    "qubesd_restarts",
                ] {
                    report[counter] = json!(0);
                }
            }
            fs::write(
                output.join("setup-config.json"),
                serde_json::to_vec(&report)?,
            )?;
            if data["native_setup"] == true {
                let result = Command::new(
                    std::env::var_os("AIRLOCK_FIXTURE_DOM0_BINARY")
                        .context("native dom0 binary")?,
                )
                .args(["setup-config", "finalize", "--result"])
                .arg(output.join("setup-config.json"))
                .output()?;
                ensure!(
                    result.status.success(),
                    "native report finalization: {error}",
                    error = String::from_utf8_lossy(&result.stderr)
                );
                if let Some(overrides) = data["setup_report_override"].as_object() {
                    let path = output.join("setup-config.json");
                    let mut report: Value = serde_json::from_slice(&fs::read(&path)?)?;
                    for (key, value) in overrides {
                        report[key] = value.clone();
                    }
                    fs::write(path, serde_json::to_vec(&report)?)?;
                }
            }
        }
        "machine-lock-race" => {
            let binary =
                std::env::var_os("AIRLOCK_FIXTURE_DOM0_BINARY").context("native dom0 binary")?;
            let mut worker = Command::new(&binary)
                .args(["prepared-check", &arguments[0]])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()?;
            let result = (|| -> Result<()> {
                for _ in 0..100 {
                    if root.join("machine/lock.owner.json").exists() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                let mut replies = Vec::new();
                for operation in ["status", "check"] {
                    let mut request = json!({"op": operation, "request_id": arguments[1]});
                    if operation == "check" {
                        request["revision"] = json!("e".repeat(40));
                        request["lock_hash"] = json!("b".repeat(64));
                    }
                    let mut frame = serde_json::to_vec(&request)?;
                    frame.push(b'\n');
                    let output = support::run(
                        Command::new(&binary).arg("review-control"),
                        Some(support::Input::bytes(frame)),
                        Duration::from_secs(5),
                    )?;
                    replies.push(serde_json::from_slice::<Value>(&output.stdout)?);
                }
                println!("{}", Value::Array(replies));
                Ok(())
            })();
            if result.is_err() {
                worker.kill()?;
            }
            ensure!(worker.wait()?.success(), "prepared validation failed");
            result?;
        }
        "systemctl" => {
            if arguments.first().map(String::as_str) == Some("show")
                && let Some(name) = last()?
                    .strip_prefix("airlock-boot-guest@")
                    .and_then(|name| name.strip_suffix(".service"))
            {
                let states = data["boot_unit_states"][name]
                    .as_array_mut()
                    .context("supply boot unit states for the scoped boot fixture")?;
                let state = states
                    .first()
                    .and_then(Value::as_str)
                    .context("boot unit state")?
                    .to_owned();
                if states.len() > 1 {
                    states.remove(0);
                }
                println!("ActiveState={state}");
                // An inactive unit may still have its submitted start job queued.
                println!(
                    "Job={job}",
                    job = if state == "inactive" {
                        "1 /fixture/job/1"
                    } else {
                        ""
                    }
                );
                if state == "active" && !data["running"].as_array().unwrap().contains(&json!(name))
                {
                    data["running"].as_array_mut().unwrap().push(json!(name));
                }
            }
        }
        "nix-env" | "airlock-start-qube-ready" => {}
        _ => bail!("unexpected machine peer {program}"),
    }
    // The concurrent validation driver must not overwrite data its child updated.
    if program != "machine-lock-race" {
        fs::write(path, serde_json::to_vec(&data)?)?;
        // A fixed command/target prefix still identifies the interruption boundary
        // when production carries additional checked identity arguments.
        let matches = |key: &str| {
            data[key] == program
                || data[key] == call
                || data[key]
                    .as_array()
                    .is_some_and(|prefix| row_prefix(&call, prefix))
        };
        if matches("crash_after") {
            // The inert peer runs only in the disposable namespace. Kill the actual coordinator,
            // after the external outcome was saved but before its phase can be acknowledged.
            let parent = rustix::process::getppid().context("fixture coordinator PID")?;
            rustix::process::kill_process(parent, rustix::process::Signal::KILL)?;
            std::process::exit(86);
        }
        ensure!(!matches("fail_after"), "simulated uncertain helper outcome");
    }
    Ok(())
}

/// Match an explicit fault-injection command prefix, including the exact named target when supplied.
fn row_prefix(call: &Value, prefix: &[Value]) -> bool {
    !prefix.is_empty()
        && call
            .as_array()
            .is_some_and(|arguments| arguments.starts_with(prefix))
}
