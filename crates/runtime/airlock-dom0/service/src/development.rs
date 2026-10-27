//! Explicit development observations and disposable nested-machine validation.

use crate::{process::Runner, state};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    fs,
    path::Path,
    time::{Duration, Instant},
};

pub(crate) fn snapshot() -> Result<Value> {
    let selection = Path::new("/var/lib/airlock/machine/selection.json");
    let chosen: Option<Value> = if selection.try_exists()? {
        Some(state::read(selection)?)
    } else {
        None
    };
    let manifest: Option<Value> = chosen
        .as_ref()
        .map(|s| {
            state::read(
                &Path::new(s["release"].as_str().context("selected release")?).join("release.json"),
            )
        })
        .transpose()?;
    let topology: Value = state::read(Path::new("/var/lib/airlock/system/current-topology.json"))?;
    let topology_hash = state::digest(&topology)?;

    Ok(
        json!({"host":fs::canonicalize("/run/current-system")?,"profile":fs::read_to_string("/etc/airlock/machine-profile")?.trim(),"devMode":Path::new("/etc/airlock/dev-mode").exists(),"boot":state::configuration::<Value>(Path::new("/etc/airlock/boot-source.json"))?,"manifest":manifest,"topology":topology,"topologyHash":topology_hash}),
    )
}

fn text(runner: &Runner, args: &[&str], input: Option<Vec<u8>>, timeout: u64) -> Result<String> {
    let (program, words) = args.split_first().context("empty development command")?;
    if let Some(input) = input {
        let result = airlock_nix_core::runtime::process::run(
            std::process::Command::new(program).args(words),
            Some(input),
            Some(Duration::from_secs(timeout)),
        )?;
        Ok(String::from_utf8(result.checked("nested VM command")?)?
            .trim()
            .to_owned())
    } else {
        runner.run(
            program,
            &words
                .iter()
                .map(std::ffi::OsString::from)
                .collect::<Vec<_>>(),
            Duration::from_secs(timeout),
            &[],
        )
    }
}

fn final_json(text: &str) -> Result<Value> {
    for (offset, _) in text.match_indices('{') {
        if let Ok(value) = serde_json::from_str::<Value>(&text[offset..])
            && value.is_object()
        {
            return Ok(value);
        }
    }
    anyhow::bail!("command did not finish with a JSON object")
}

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn vm(runner: &Runner, script: &str, timeout: u64) -> Result<String> {
    let help = text(runner, &["qvm-run", "--help"], None, 30)?;
    let mut words = vec!["qvm-run", "--pass-io", "--user", "root"];
    if help.contains("--no-gui") {
        words.push("--no-gui");
    }
    words.extend(["usr-assistant", "bash -s"]);
    text(runner, &words, Some(script.as_bytes().to_vec()), timeout)
}

pub(crate) fn pool_smoke() -> Result<Value> {
    ensure!(
        rustix::process::geteuid().is_root(),
        "nested admission smoke requires root"
    );
    ensure!(
        Path::new("/etc/airlock/dev-mode").is_file()
            && fs::read_to_string("/etc/airlock/machine-profile")?.trim()
                == "vm-pool-admission-test",
        "pool smoke is restricted to the disposable vm-pool-admission-test profile"
    );
    let runner = Runner::default();
    if text(
        &runner,
        &["qvm-check", "--running", "usr-assistant"],
        None,
        30,
    )
    .is_err()
    {
        text(&runner, &["qvm-start", "usr-assistant"], None, 300)?;
    }
    let deadline = Instant::now() + Duration::from_secs(240);
    loop {
        if vm(&runner, "printf ready", 30).is_ok_and(|s| s == "ready") {
            break;
        }
        ensure!(
            Instant::now() < deadline,
            "usr-assistant qrexec did not become ready"
        );
        std::thread::sleep(Duration::from_secs(3));
    }
    let topology: Value = state::read(Path::new("/var/lib/airlock/system/current-topology.json"))?;
    let backend = &topology["domains"]["usr-assistant"]["backend"];
    let system = backend["system"]["source"]
        .as_str()
        .context("assistant system")?;
    let root = backend["root"]["source"]
        .as_str()
        .context("assistant root")?;
    let kernel = backend["kernel"]["name"]
        .as_str()
        .context("assistant kernel")?;
    let closure = "/home/user/.local/share/airlock/pool-admission-smoke/closure";
    let sentinel = "airlock-pool-admission-private-data";
    let script = format!(
        "set -eu\nmkdir -p {closure}\nprintf '%s\\n' {sentinel} > /home/user/.airlock-pool-admission-sentinel\nnix-store -qR {} > {closure}/store-paths\nairlock artifact send --domain usr-assistant --system {} --closure-source {closure} --root-source {} --kernel-name {} --source-revision {} --lock-hash {} --physical-store-root /nix/store --nix /run/current-system/sw/bin/nix --nix-store /",
        quote(system),
        quote(system),
        quote(root),
        quote(kernel),
        "1".repeat(40),
        "2".repeat(64)
    );
    let admission = final_json(&vm(&runner, &script, 3600)?)?;
    ensure!(
        admission["activated"] == false && admission["retained"] == true,
        "unexpected admission result"
    );
    let work = Path::new("/var/lib/airlock/pool-admission-smoke/release");
    fs::create_dir_all(work)?;
    let mut updated = topology.clone();
    updated["domains"]["usr-assistant"]["backend"]["store"]["source"] = json!(closure);
    state::save(&work.join("topology.json"), &updated)?;
    state::save(
        &work.join("release.json"),
        &json!({"schema":"airlock.machine-release.v1","profile":"vm-pool-admission-test","host":fs::canonicalize("/run/current-system")?,"setup":fs::canonicalize("/run/current-system/sw/bin/airlock-setup-config")?,"revision":"1".repeat(40),"lockHash":"2".repeat(64)}),
    )?;
    let executable = std::env::current_exe()?;
    let executable = executable.to_str().context("coordinator executable")?;
    let apply = final_json(&text(
        &runner,
        &[
            executable,
            "apply",
            work.to_str().context("smoke release")?,
            "--administrative",
        ],
        None,
        1800,
    )?)?;
    ensure!(
        vm(
            &runner,
            "cat /home/user/.airlock-pool-admission-sentinel",
            180
        )? == sentinel,
        "private sentinel did not survive coordinator apply"
    );
    let rollback = final_json(&text(&runner, &[executable, "rollback"], None, 1800)?)?;
    ensure!(
        vm(
            &runner,
            "cat /home/user/.airlock-pool-admission-sentinel",
            180
        )? == sentinel,
        "private sentinel did not survive coordinator rollback"
    );
    Ok(
        json!({"schema":"airlock.pool-admission-smoke.v1","status":"passed","admission":admission,"apply_phase":apply["phase"],"rollback_phase":rollback["phase"],"sentinel_preserved":true}),
    )
}
