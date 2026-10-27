//! Stable source-image binding for immutable baselines and two-boot activation tests.

use super::*;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;

/// Build a child runner invocation with exact per-phase environment values.
fn runner(context: &Context, overrides: &[(&str, String)]) -> Result<()> {
    let mut command =
        match std::env::var_os("AIRLOCK_NESTED_SMOKE_COMMAND").filter(|value| !value.is_empty()) {
            Some(program) => Command::new(program),
            None => context.native(&["nested", "smoke"])?,
        };
    let status = command
        .envs(overrides.iter().map(|(key, value)| (*key, value)))
        .status()?;
    ensure!(
        status.success(),
        "nested baseline/boot scenario failed ({status}); see retained evidence"
    );
    Ok(())
}

/// Common explicit switches keep unrelated live scenarios out of a baseline or boot-only run.
fn quiet() -> Vec<(&'static str, String)> {
    [
        "AIRLOCK_BOOTSTRAP_QUBES",
        "AIRLOCK_RUN_CONFIG_INPUTS_IMPORT",
        "AIRLOCK_RUN_CONFIG_VMS_SMOKE",
        "AIRLOCK_RUN_CONFIG_BOOT_VERIFY",
        "AIRLOCK_RUN_NIX_CLOSURE_SMOKE",
        "AIRLOCK_RUN_QUBES_SMOKE",
        "AIRLOCK_RUN_GUI_SMOKE",
    ]
    .into_iter()
    .map(|key| (key, "0".into()))
    .chain([
        ("AIRLOCK_SHUTDOWN_VM_ON_SUCCESS", "1".into()),
        ("AIRLOCK_VM_SKIP_BASE_BUILD", "1".into()),
        ("AIRLOCK_VM_DISPLAY", setting("AIRLOCK_VM_DISPLAY", "none")),
    ])
    .collect()
}

/// Reuse only a complete baseline whose image, paths and successful setup receipt still match.
pub(super) fn execute(context: &Context) -> Result<()> {
    let attribute = setting("AIRLOCK_VM_IMAGE_ATTR", "airlock-vm-gui-config-dev-image");
    ensure!(!attribute.contains('/'), "invalid baseline image attribute");
    let data = path("AIRLOCK_DATA_ROOT", context.root.join(".airlock"));
    let directory = path(
        "AIRLOCK_VM_BASELINE_DIR",
        data.join(format!("vm-baselines/{attribute}-setup")),
    );
    let logs = path(
        "AIRLOCK_VM_BASELINE_LOG_DIR",
        context.logs.join("vm-baseline"),
    );
    let links = path(
        "AIRLOCK_VM_BASELINE_RESULT_LINK_DIR",
        directory.join("result-links"),
    );
    let shared = path(
        "AIRLOCK_VM_SHARED_IMAGE_LINK",
        path("AIRLOCK_RESULT_LINK_DIR", data.join("result-links"))
            .join(format!("{attribute}-parallel-shared-result")),
    );
    let disk = path(
        "AIRLOCK_VM_BASELINE_DISK",
        directory.join(format!("{attribute}.qcow2")),
    );
    let variables = path(
        "AIRLOCK_VM_BASELINE_OVMF_VARS",
        directory.join(format!("{attribute}-OVMF_VARS.fd")),
    );
    let meta = directory.join("baseline.json");
    for directory in [&directory, &logs, &links] {
        fs::create_dir_all(directory)?;
    }
    let source = fs::canonicalize(&shared)
        .context("shared image result is missing; explicitly prebuild the parallel image first")?;
    ensure!(source.is_dir(), "shared image output is not a directory");
    link(&source, &directory.join(format!("{attribute}-result")))?;
    if !toggle("AIRLOCK_VM_BASELINE_FORCE", false)?
        && disk.is_file()
        && variables.is_file()
        && let Ok(mut record) = support::json(&meta)
        && record["schema"] == "airlock.vm-baseline.v1"
        && record["status"] == "passed"
        && record["image_attr"] == attribute
        && record["source_image_output"] == json!(source)
        && record["disk"] == json!(disk)
        && record["ovmf_vars"] == json!(variables)
        && record["setup_config"]["schema"] == "airlock.setup-config.v1"
        && record["setup_config"]["status"] == "passed"
    {
        record["reused"] = json!(true);
        support::atomic(
            &logs.join("vm-baseline.json"),
            &serde_json::to_vec_pretty(&record)?,
        )?;
        return Ok(());
    }
    // The runner's disk names are fixed by its image attribute; an alternate baseline path must not disguise another disk.
    ensure!(
        disk == directory.join(format!("{attribute}.qcow2"))
            && variables == directory.join(format!("{attribute}-OVMF_VARS.fd")),
        "baseline output overrides must match the configured runner paths"
    );
    let started = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let started_at = support::text(Command::new("date").args(["-u", "+%Y-%m-%dT%H:%M:%SZ"]))?;
    let mut overrides = quiet();
    overrides.extend([
        ("AIRLOCK_LOG_DIR", logs.to_string_lossy().into()),
        ("AIRLOCK_VM_DIR", directory.to_string_lossy().into()),
        ("AIRLOCK_RESULT_LINK_DIR", links.to_string_lossy().into()),
        ("AIRLOCK_VM_IMAGE_ATTR", attribute.clone()),
        (
            "AIRLOCK_VM_SSH_PORT",
            setting(
                "AIRLOCK_VM_BASELINE_SSH_PORT",
                &setting("AIRLOCK_VM_SSH_PORT", "2299"),
            ),
        ),
        ("AIRLOCK_VM_FRESH", "1".into()),
        ("AIRLOCK_AUTO_GC_AFTER_RUN", "0".into()),
        ("AIRLOCK_REQUIRE_CLEAN_SHUTDOWN", "1".into()),
        ("AIRLOCK_RUN_SETUP_CONFIG", "1".into()),
    ]);
    let result: Result<Value> = (|| {
        runner(context, &overrides)?;
        ensure!(
            disk.is_file() && variables.is_file(),
            "baseline disk/firmware variables were not created"
        );
        let setup = support::json(&logs.join("vm-gui-setup-config.json"))?;
        ensure!(
            setup["schema"] == "airlock.setup-config.v1" && setup["status"] == "passed",
            "baseline setup did not pass"
        );
        for file in [&disk, &variables] {
            let mut mode = fs::metadata(file)?.permissions();
            mode.set_mode(mode.mode() & !0o222);
            fs::set_permissions(file, mode)?;
        }
        Ok(setup)
    })();
    let finished = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let finished_at = support::text(Command::new("date").args(["-u", "+%Y-%m-%dT%H:%M:%SZ"]))?;
    let mut record = json!({"schema":"airlock.vm-baseline.v1","status":if result.is_ok(){"passed"}else{"failed"},"reason":if result.is_ok(){"baseline setup completed"}else{"baseline setup run failed"},"image_attr":attribute,"source_image_result_link":shared,"source_image_output":source,"disk":disk,"ovmf_vars":variables,"started_at":started_at,"finished_at":finished_at,"duration_seconds":finished.saturating_sub(started),"reused":false});
    match &result {
        Ok(setup) => record["setup_config"] = setup.clone(),
        Err(error) => {
            record["error"] = json!(format!("{error:#}"));
            record["exit_code"] = json!(1);
        }
    }
    support::atomic(
        &logs.join("vm-baseline.json"),
        &serde_json::to_vec_pretty(&record)?,
    )?;
    result?;
    support::atomic(&meta, &serde_json::to_vec_pretty(&record)?)?;
    println!("VM baseline ready: {disk}", disk = disk.display());
    Ok(())
}

/// Stage and boot the exact same overlay; a rebuilt base cannot erase the staged profile.
pub(super) fn boot_flow(context: &Context) -> Result<()> {
    let attribute = setting("AIRLOCK_VM_IMAGE_ATTR", "airlock-vm-gui-config-dev-image");
    let directory = path("AIRLOCK_VM_DIR", context.root.join(".airlock-vm"));
    fs::create_dir_all(&directory)?;
    let mut stage = Value::Null;
    let mut verify = Value::Null;
    let mut expected = String::new();
    let result: Result<()> = (|| {
        let source = super::image::resolve(
            context,
            Some(&attribute),
            Some(&directory.join(format!("{attribute}-result"))),
        )?;
        fs::write(
            context.logs.join("vm-config-boot-activate-image-path.txt"),
            format!("{source}\n", source = source.display()),
        )?;
        let mut common = quiet();
        common.extend([
            ("AIRLOCK_VM_IMAGE_ATTR", attribute.clone()),
            ("AIRLOCK_VM_DIR", directory.to_string_lossy().into()),
            ("AIRLOCK_REQUIRE_CLEAN_SHUTDOWN", "1".into()),
        ]);
        let mut first = common.clone();
        first.extend([
            ("AIRLOCK_AUTO_GC_AFTER_RUN", "0".into()),
            ("AIRLOCK_VM_FRESH", "1".into()),
            ("AIRLOCK_RUN_SETUP_CONFIG", "1".into()),
            ("AIRLOCK_RUN_CONFIG_VMS_SMOKE", "1".into()),
            ("AIRLOCK_CONFIG_DOM0_SYSTEM_SWITCH_ACTION", "boot".into()),
        ]);
        runner(context, &first)?;
        stage = support::json(&context.logs.join("vm-gui-config-vms-smoke.json"))?;
        context.save("vm-config-boot-activate-stage.json", &stage)?;
        expected = stage["dom0_system_apply"]["host_system_source"]
            .as_str()
            .filter(|s| !s.is_empty())
            .context("stage omitted host system source")?
            .into();
        let host = &stage["config_status"]["host_generation"];
        ensure!(
            stage["schema"] == "airlock.config-vms-smoke.v1"
                && stage["status"] == "passed"
                && stage["dom0_system_apply"]["status"] == "passed"
                && stage["dom0_system_apply"]["host_system_switch_action"] == "boot"
                && stage["dom0_system_apply"]["reboot_required"] == true
                && stage["config_status"]["pending_reboot"]["required"] == true
                && host["active"] == false
                && host["staged_source"] == expected
                && host["pending_reboot"]["required"] == true,
            "stage did not leave the expected pending boot generation"
        );
        let mut second = common;
        second.extend([
            ("AIRLOCK_AUTO_GC_AFTER_RUN", "1".into()),
            ("AIRLOCK_VM_FRESH", "0".into()),
            ("AIRLOCK_RUN_SETUP_CONFIG", "0".into()),
            ("AIRLOCK_RUN_CONFIG_BOOT_VERIFY", "1".into()),
            ("AIRLOCK_EXPECTED_HOST_SYSTEM_SOURCE", expected.clone()),
        ]);
        runner(context, &second)?;
        verify = support::json(&context.logs.join("vm-gui-config-boot-verify.json"))?;
        context.save("vm-config-boot-activate-verify.json", &verify)?;
        let host = &verify["status_json"]["host_generation"];
        ensure!(
            verify["schema"] == "airlock.config-boot-verify.v1"
                && verify["status"] == "passed"
                && verify["expected_host_system_source"] == expected
                && verify["host_system_profile_resolved_target"] == expected
                && verify["run_current_system_resolved_target"] == expected
                && verify["pending_reboot"]["required"] == false
                && host["active"] == true
                && host["current_source"] == expected
                && host["pending_reboot"]["required"] == false,
            "verify did not boot the staged generation"
        );
        Ok(())
    })();
    let record = json!({"schema":"airlock.config-boot-activate-flow.v1","status":if result.is_ok(){"passed"}else{"failed"},"reason":result.as_ref().map(|()|"staged dom0 generation became the running boot generation".to_owned()).unwrap_or_else(|e|format!("{e:#}")),"expected_host_system_source":expected,"stage":stage,"verify":verify});
    context.save("vm-config-boot-activate-flow.json", &record)?;
    println!("{record}");
    result
}
