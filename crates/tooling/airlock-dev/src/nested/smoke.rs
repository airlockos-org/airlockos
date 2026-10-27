//! Nested live smoke orchestration with Rust-owned deadlines, result checks and cleanup.

use super::*;
use serde_json::json;
use std::{
    collections::BTreeMap,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    thread,
};

/// Shared ownership serializes signal cleanup and status polling to prevent signalling a reused PID.
type ChildState = std::sync::Arc<std::sync::Mutex<Option<std::process::Child>>>;

/// Only the QEMU child started by this invocation is terminated on ordinary scope exit.
struct Vm {
    /// Owned timeout/QEMU child, shared only with the cancellation listener.
    child: ChildState,
    /// Explicit diagnostic choice to leave this invocation's VM running.
    keep: bool,
}

/// Terminate only a still-owned process group before reaping its reserved leader identity.
fn terminate(state: &ChildState) {
    if let Ok(mut state) = state.lock()
        && let Some(mut child) = state.take()
        && child.try_wait().ok().flatten().is_none()
    {
        if let Ok(pid) = i32::try_from(child.id())
            && let Some(pid) = rustix::process::Pid::from_raw(pid)
        {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::TERM);
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}

impl Vm {
    /// Observe only this invocation's child while holding the cancellation ownership lock.
    fn exited(&self) -> Result<bool> {
        Ok(self
            .child
            .lock()
            .map_err(|_| anyhow::anyhow!("VM owner lock poisoned"))?
            .as_mut()
            .context("VM child no longer owned")?
            .try_wait()?
            .is_some())
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        if !self.keep {
            terminate(&self.child);
        }
    }
}

/// An owned signal listener; closing it prevents a lingering thread after ordinary completion.
struct Cancellation {
    /// Registration handle used to wake and close the listener on normal return.
    handle: signal_hook::iterator::Handle,
    /// Joined before returning from the runner, keeping registrations local to this invocation.
    worker: Option<thread::JoinHandle<()>>,
}

impl Cancellation {
    /// Preserve the shell runner's INT/TERM cleanup even during a blocking SSH or build command.
    fn new(child: ChildState, keep: bool) -> Result<Self> {
        let mut signals = signal_hook::iterator::Signals::new([
            signal_hook::consts::SIGINT,
            signal_hook::consts::SIGTERM,
        ])?;
        let handle = signals.handle();
        let worker = thread::spawn(move || {
            if let Some(signal) = signals.forever().next() {
                if !keep {
                    terminate(&child);
                }
                std::process::exit(128 + signal);
            }
        });
        Ok(Self {
            handle,
            worker: Some(worker),
        })
    }
}

impl Drop for Cancellation {
    fn drop(&mut self) {
        self.handle.close();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// Download into the explicit workstation cache, publishing only a complete transfer.
fn download(context: &Context, url: &str) -> Result<PathBuf> {
    let name = url
        .split('?')
        .next()
        .unwrap_or(url)
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty() && ![".", ".."].contains(name))
        .context("URL has no filename")?;
    let directory = path(
        "AIRLOCK_QUBES_CACHE_DIR",
        context.root.join(".airlock-cache/rpms"),
    );
    fs::create_dir_all(&directory)?;
    let destination = directory.join(name);
    if destination
        .metadata()
        .is_ok_and(|metadata| metadata.len() > 0)
    {
        return Ok(destination);
    }
    let partial = destination.with_file_name(format!("{name}.part"));
    let mut command = Command::new("curl");
    command.args(["--fail", "--location", "--silent", "--show-error"]);
    if partial.metadata().is_ok_and(|metadata| metadata.len() > 0) {
        command.args(["--continue-at", "-"]);
    }
    support::output(command.arg("--output").arg(&partial).arg(url))?;
    fs::set_permissions(&partial, fs::Permissions::from_mode(0o644))?;
    fs::rename(partial, &destination)?;
    Ok(destination)
}

/// Cache only missing explicitly selected bootstrap assets; downloaded content is still verified in dom0.
fn assets(context: &Context) -> Result<BTreeMap<String, String>> {
    let mut overrides = BTreeMap::new();
    if !toggle("AIRLOCK_BOOTSTRAP_QUBES", true)? || !toggle("AIRLOCK_CACHE_QUBES_ASSETS", true)? {
        return Ok(overrides);
    }
    let kernel = std::env::var_os("AIRLOCK_QUBES_KERNEL_RPM").filter(|v| !v.is_empty());
    let modules = std::env::var_os("AIRLOCK_QUBES_KERNEL_MODULES_RPM").filter(|v| !v.is_empty());
    ensure!(
        kernel.is_some() == modules.is_some(),
        "kernel RPM and modules RPM must be set together"
    );
    let mut selected = Vec::new();
    if toggle("AIRLOCK_QUBES_VERIFY_RPMS", true)? && setting("AIRLOCK_QUBES_GPG_KEY", "").is_empty()
    {
        selected.push((
            "AIRLOCK_QUBES_GPG_KEY",
            "AIRLOCK_QUBES_GPG_KEY_URL",
            "https://keys.qubes-os.org/keys/qubes-release-4.3-signing-key.asc",
        ));
    }
    if kernel.is_none() {
        selected.extend([("AIRLOCK_QUBES_KERNEL_RPM","AIRLOCK_QUBES_KERNEL_URL","https://ftp.qubes-os.org/repo/yum/r4.3/current/dom0/fc41/rpm/kernel-qubes-vm-6.12.64-1.qubes.fc41.x86_64.rpm"),("AIRLOCK_QUBES_KERNEL_MODULES_RPM","AIRLOCK_QUBES_KERNEL_MODULES_URL","https://ftp.qubes-os.org/repo/yum/r4.3/current/dom0/fc41/rpm/kernel-modules-6.12.64-1.qubes.fc41.x86_64.rpm")]);
    }
    if setting("AIRLOCK_QUBES_TEMPLATE_RPM", "").is_empty() {
        selected.push(("AIRLOCK_QUBES_TEMPLATE_RPM","AIRLOCK_QUBES_TEMPLATE_URL","https://ftp.qubes-os.org/repo/yum/r4.3/templates-itl/rpm/qubes-template-fedora-43-xfce-4.3.0-202601041226.noarch.rpm"));
    }
    for (key, url, default) in selected {
        let source = download(context, &setting(url, default))?;
        let guest = format!(
            "/var/cache/airlock/qubes-rpms/{name}",
            name = source
                .file_name()
                .context("cached filename")?
                .to_string_lossy()
        );
        let size = fs::metadata(&source)?.len().to_string();
        if context
            .remote(&["stat", "-c", "%s", &guest])
            .ok()
            .as_deref()
            != Some(&size)
        {
            context.remote(&[
                "sudo",
                "-n",
                "install",
                "-d",
                "-m",
                "0755",
                "/var/cache/airlock/qubes-rpms",
            ])?;
            let temporary = format!("{guest}.part");
            files(
                context.connection(false)?.arg(support::join(&[
                    "sudo",
                    "-n",
                    "dd",
                    &format!("of={temporary}"),
                    "status=none",
                ])),
                Some(&source),
                &context.logs.join("vm-gui-cache-transfer.log"),
            )?;
            context.remote(&["sudo", "-n", "chmod", "0644", &temporary])?;
            context.remote(&["sudo", "-n", "mv", &temporary, &guest])?;
        }
        overrides.insert(key.into(), guest);
    }
    Ok(overrides)
}

/// Copy diagnostics without replacing a meaningful skipped result with a stale previous receipt.
fn diagnostics(context: &Context) {
    for (args, name) in [
        (
            vec!["systemctl", "--failed", "--no-legend"],
            "vm-gui-failed-units.log",
        ),
        (
            vec![
                "journalctl",
                "-b",
                "--no-pager",
                "-n",
                "320",
                "-u",
                "qubesd",
                "-u",
                "qubes-core",
                "-u",
                "libvirtd",
                "-u",
                "qubes-db-dom0",
                "-u",
                "qubes-qrexec-policy-daemon",
                "-u",
                "airlock-qubes-store-init",
                "-u",
                "airlock-setup-config",
            ],
            "vm-gui-journal.log",
        ),
        (vec!["qvm-ls"], "vm-gui-qvm-ls.log"),
    ] {
        if let Ok(output) = context.remote(&args) {
            let _ = fs::write(context.logs.join(name), output);
        }
    }
    for (source, name) in super::evidence::DIAGNOSTICS {
        if !context.logs.join(name).exists() || !name.ends_with(".json") {
            context.collect(source, name);
        }
    }
    // Enumerate diagnostic files with an upstream primitive; selection and concatenation stay native.
    if let Ok(paths) = context.remote(&[
        "sudo",
        "-n",
        "find",
        "/var/log/airlock",
        "-maxdepth",
        "1",
        "-type",
        "f",
        "-name",
        "config-apply-*-build-*.log",
        "-o",
        "-type",
        "f",
        "-name",
        "nix-closure-domain-*",
    ]) {
        let mut details = String::new();
        for path in paths
            .lines()
            .filter(|path| path.starts_with("/var/log/airlock/") && !path.contains('\0'))
        {
            if let Ok(text) = context.remote(&["sudo", "-n", "cat", path]) {
                details.push_str(&format!("== {path} ==\n{text}\n"));
            }
        }
        let _ = fs::write(
            context.logs.join("vm-gui-build-and-closure-details.log"),
            details,
        );
    }
}

/// Refuse to apply while a boot setup job is still mutating the machine.
fn boot_setup(context: &Context, warm: bool) -> Result<()> {
    if !warm
        && context
            .remote(&["systemctl", "cat", "airlock-setup-config.service"])
            .is_ok()
    {
        let deadline = Instant::now()
            + Duration::from_secs(number("AIRLOCK_SETUP_CONFIG_BOOT_WAIT_SECONDS", 900)?);
        loop {
            let state = context.remote(&[
                "systemctl",
                "show",
                "-p",
                "ActiveState",
                "--value",
                "airlock-setup-config.service",
            ])?;
            if state != "activating" {
                ensure!(state != "failed", "boot setup-config failed");
                break;
            }
            ensure!(Instant::now() < deadline, "boot setup-config timed out");
            thread::sleep(Duration::from_secs(2));
        }
    }
    context.collect(
        "/var/log/airlock/setup-config.json",
        "vm-gui-setup-config-boot.json",
    );
    context.collect(
        "/var/log/airlock/setup-config.commands.log",
        "vm-gui-setup-config-boot.commands.log",
    );
    if warm {
        let _ = context.remote(&[
            "sudo",
            "-n",
            "systemctl",
            "reset-failed",
            "airlock-setup-config.service",
        ]);
        context.save("vm-gui-setup-config-boot.json",&json!({"schema":"airlock.setup-config.v1","status":"skipped","reason":"warm tool sync uses explicit setup-config"}))?;
    }
    Ok(())
}

/// Shut down explicit warm targets, waiting for observed Halted before storage reconfiguration.
fn stop_warm(context: &Context) -> Result<()> {
    if !toggle("AIRLOCK_NESTED_WARM_STOP_NIX_DOMAINS", false)? {
        return Ok(());
    }
    for domain in setting(
        "AIRLOCK_NESTED_WARM_NIX_DOMAINS",
        "sys-config-staging sys-config-validator sys-config-vault",
    )
    .split_whitespace()
    {
        let state = || -> Result<Option<String>> {
            Ok(context
                .remote(&[
                    "sudo",
                    "-n",
                    "qvm-ls",
                    "--raw-data",
                    "--fields",
                    "NAME,STATE",
                    "--no-spinner",
                ])?
                .lines()
                .find_map(|line| {
                    line.split_once('|')
                        .filter(|(name, _)| *name == domain)
                        .map(|(_, state)| state.split('|').next().unwrap_or("").into())
                }))
        };
        match state()?.as_deref() {
            None | Some("Halted") => continue,
            Some("Running") => {
                if context
                    .remote(&[
                        "sudo",
                        "-n",
                        "qvm-shutdown",
                        "--wait",
                        "--timeout",
                        "120",
                        domain,
                    ])
                    .is_err()
                {
                    context.remote(&["sudo", "-n", "qvm-kill", domain])?;
                }
            }
            _ => {
                let _ = context.remote(&["sudo", "-n", "qvm-kill", domain]);
            }
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        while state()?.as_deref() != Some("Halted") {
            ensure!(
                Instant::now() < deadline,
                "warm target {domain} did not halt"
            );
            thread::sleep(Duration::from_secs(1));
        }
    }
    Ok(())
}

/// Execute one remote scenario and extract its schema-bound report, preserving both streams on failure.
fn scenario(
    context: &Context,
    spec: (&str, &str, &str),
    program: &str,
    args: &[&str],
    environment: &BTreeMap<String, String>,
) -> Result<()> {
    let (prefix, schema, remote_report) = spec;
    let mut words = vec![
        "sudo".to_owned(),
        "-n".into(),
        "env".into(),
        "AIRLOCK_LOG_DIR=/var/log/airlock".into(),
    ];
    words.extend(
        environment
            .iter()
            .map(|(key, value)| format!("{key}={value}")),
    );
    words.push(program.into());
    words.extend(args.iter().map(|arg| (*arg).into()));
    let mut command = context.connection(false)?;
    command.arg(
        words
            .iter()
            .map(|word| support::quote(word))
            .collect::<Vec<_>>()
            .join(" "),
    );
    let captured = process::run(
        &mut command,
        None,
        Some(Duration::from_secs(number(
            "AIRLOCK_VM_RUN_TIMEOUT",
            14400,
        )?)),
    )?;
    let stdout = context.logs.join(format!("{prefix}.stdout.log"));
    fs::write(&stdout, &captured.stdout)?;
    fs::write(
        context.logs.join(format!("{prefix}.stderr.log")),
        &captured.stderr,
    )?;
    let output = context.logs.join(format!("{prefix}.json"));
    let reporter = path(
        "AIRLOCK_TEST_REPORT_BIN",
        context.root.join("crates/target/debug/airlock-test-report"),
    );
    let extracted = support::output(
        Command::new(reporter)
            .arg("extract")
            .arg(schema)
            .arg(&stdout)
            .arg(&output),
    );
    if extracted.is_err() {
        context.collect(remote_report, &format!("{prefix}.json"));
    }
    ensure!(
        captured.status.success(),
        "{prefix} failed; see retained stdout/stderr"
    );
    let record = support::json(&output)?;
    ensure!(
        record["schema"] == schema && record["status"] == "passed",
        "{prefix} did not report a passing {schema} result"
    );
    Ok(())
}

/// Forward only the explicitly enumerated knobs of each remote command.
fn forwarded(keys: &[&str], overrides: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    keys.iter()
        .filter_map(|key| {
            overrides
                .get(*key)
                .cloned()
                .or_else(|| std::env::var(key).ok())
                .map(|value| ((*key).into(), value))
        })
        .collect()
}

/// Launch or reuse a disposable VM, run the selected scenarios, and retain failed evidence.
pub(super) fn execute(context: &Context) -> Result<()> {
    let keep = toggle("AIRLOCK_KEEP_VM", false)?;
    let warm = toggle("AIRLOCK_SYNC_DOM0_TOOLS", false)?;
    let child: ChildState = Default::default();
    let _cancellation = Cancellation::new(child.clone(), keep)?;
    let mut vm = None;
    // Clear only this runner's known result files; unrelated evidence remains untouched.
    for name in [
        "observe",
        "bootstrap",
        "setup-config-boot",
        "setup-config",
        "config-inputs-import",
        "config-vms-smoke",
        "config-boot-verify",
        "nix-closure-domain-smoke",
        "sync-dom0-tools",
        "qrexec-smoke",
        "window-smoke",
    ] {
        for suffix in ["json", "stdout.log", "stderr.log"] {
            let path = context.logs.join(format!("vm-gui-{name}.{suffix}"));
            if path.is_file() {
                fs::remove_file(path)?;
            }
        }
    }
    let result: Result<()> = (|| {
        let reuse = toggle("AIRLOCK_REUSE_WARM_VM", false)?
            && context.remote(&["echo", "ssh-ready"]).is_ok();
        if !reuse {
            let log = context.logs.join("vm-gui-smoke-qemu.log");
            let output = File::create(&log)?;
            let mut command = Command::new("timeout");
            command
                .args([
                    "-k",
                    "20s",
                    &number("AIRLOCK_VM_RUN_TIMEOUT", 14400)?.to_string(),
                ])
                .arg(std::env::current_exe()?)
                .arg("--repository-root")
                .arg(&context.root)
                .args(["nested", "run"])
                .env(
                    "AIRLOCK_VM_IMAGE_ATTR",
                    setting("AIRLOCK_VM_IMAGE_ATTR", "airlock-vm-gui-dev-image"),
                )
                .env("AIRLOCK_VM_DISPLAY", setting("AIRLOCK_VM_DISPLAY", "gtk"))
                .stdin(Stdio::null())
                .stdout(output.try_clone()?)
                .stderr(output)
                .process_group(0);
            {
                let mut state = child
                    .lock()
                    .map_err(|_| anyhow::anyhow!("VM owner lock poisoned"))?;
                *state = Some(command.spawn()?);
            }
            vm = Some(Vm {
                child: child.clone(),
                keep,
            });
            let deadline = Instant::now()
                + Duration::from_secs(number(
                    "AIRLOCK_VM_START_WAIT_SECONDS",
                    number("AIRLOCK_VM_RUN_TIMEOUT", 14400)?,
                )?);
            while !fs::read_to_string(&log)
                .unwrap_or_default()
                .lines()
                .any(|line| line == "starting VM")
            {
                ensure!(
                    !vm.as_ref().unwrap().exited()?,
                    "VM launcher exited; see QEMU log"
                );
                ensure!(
                    Instant::now() < deadline,
                    "VM did not start before deadline"
                );
                thread::sleep(Duration::from_secs(3));
            }
        }
        let deadline =
            Instant::now() + Duration::from_secs(number("AIRLOCK_VM_SSH_WAIT_SECONDS", 240)?);
        while context.remote(&["echo", "ssh-ready"]).is_err() {
            ensure!(Instant::now() < deadline, "nested SSH did not become ready");
            if let Some(vm) = &mut vm {
                ensure!(!vm.exited()?, "VM exited before SSH readiness");
            }
            thread::sleep(Duration::from_secs(3));
        }
        fs::write(
            context.logs.join("vm-gui-observe.json"),
            context.remote(&["airlock-observe-dom0"])?,
        )?;
        fs::write(
            context.logs.join("vm-gui-services.log"),
            context.remote(&[
                "systemctl",
                "is-active",
                "libvirtd",
                "qubesd",
                "qubes-db-dom0",
                "qubes-qrexec-policy-daemon",
            ])?,
        )?;
        boot_setup(context, warm)?;
        let mut overrides = BTreeMap::new();
        if warm {
            super::warm::execute(context)?;
            let bin = setting("AIRLOCK_NESTED_WARM_BIN_DIR", "/run/airlock-warm/bin");
            overrides.insert(
                "AIRLOCK_SETUP_CONFIG_COMMAND".into(),
                format!("{bin}/airlock-setup-config"),
            );
            overrides.insert(
                "AIRLOCK_DOM0_SERVICE".into(),
                format!("{bin}/airlock-dom0-service"),
            );
            overrides.insert(
                "AIRLOCK_CONFIG_INPUTS_SOURCE".into(),
                setting(
                    "AIRLOCK_CONFIG_INPUTS_SOURCE",
                    &setting(
                        "AIRLOCK_NESTED_WARM_CONFIG_INPUTS_PATH",
                        "/run/airlock-warm/config-inputs",
                    ),
                ),
            );
        } else {
            context.save("vm-gui-sync-dom0-tools.json",&json!({"schema":"airlock.nested-dom0-tool-sync.v1","status":"skipped","reason":"AIRLOCK_SYNC_DOM0_TOOLS=0"}))?;
        }
        let bootstrap = assets(context)?;
        if toggle("AIRLOCK_BOOTSTRAP_QUBES", true)? {
            scenario(
                context,
                (
                    "vm-gui-bootstrap",
                    "airlock.qubes-bootstrap.v1",
                    "/var/log/airlock/qubes-bootstrap.json",
                ),
                "airlock-qube-bootstrap",
                &[],
                &forwarded(super::evidence::BOOTSTRAP, &bootstrap),
            )?;
        } else {
            context.save("vm-gui-bootstrap.json", &json!({"schema":"airlock.qubes-bootstrap.v1","status":"skipped","reason":"AIRLOCK_BOOTSTRAP_QUBES=0"}))?;
        }

        let setup_program = overrides
            .get("AIRLOCK_SETUP_CONFIG_COMMAND")
            .cloned()
            .unwrap_or_else(|| setting("AIRLOCK_SETUP_CONFIG_COMMAND", "airlock-setup-config"));
        if toggle("AIRLOCK_RUN_SETUP_CONFIG", false)? {
            stop_warm(context)?;
            let topology = if warm {
                setting(
                    "AIRLOCK_NESTED_WARM_TOPOLOGY_PATH",
                    "/run/airlock-warm/current-qubes-topology.json",
                )
            } else {
                setting("AIRLOCK_SETUP_CONFIG_TOPOLOGY", "")
            };
            let args = if topology.is_empty() {
                vec!["--apply"]
            } else {
                vec!["--apply", "--topology", topology.as_str()]
            };
            scenario(
                context,
                (
                    "vm-gui-setup-config",
                    "airlock.setup-config.v1",
                    "/var/log/airlock/setup-config.json",
                ),
                &setup_program,
                &args,
                &BTreeMap::new(),
            )?;
        } else if let Ok(record) =
            support::json(&context.logs.join("vm-gui-setup-config-boot.json"))
        {
            context.save("vm-gui-setup-config.json", &record)?;
        } else {
            context.save("vm-gui-setup-config.json",&json!({"schema":"airlock.setup-config.v1","status":"skipped","reason":"AIRLOCK_RUN_SETUP_CONFIG=0"}))?;
        }
        for (flag, default, prefix, schema, command, remote, keys) in [
            (
                "AIRLOCK_RUN_CONFIG_INPUTS_IMPORT",
                false,
                "config-inputs-import",
                "airlock.config-inputs-import.v1",
                "airlock-config-inputs-import",
                "config-inputs-import.json",
                super::evidence::INPUTS,
            ),
            (
                "AIRLOCK_RUN_CONFIG_VMS_SMOKE",
                false,
                "config-vms-smoke",
                "airlock.config-vms-smoke.v1",
                "airlock-config-vms-smoke",
                "config-vms-smoke.json",
                super::evidence::CONFIG,
            ),
            (
                "AIRLOCK_RUN_CONFIG_BOOT_VERIFY",
                false,
                "config-boot-verify",
                "airlock.config-boot-verify.v1",
                "airlock-config-boot-verify",
                "config-boot-verify.json",
                super::evidence::BOOT,
            ),
            (
                "AIRLOCK_RUN_NIX_CLOSURE_SMOKE",
                false,
                "nix-closure-domain-smoke",
                "airlock.nix-closure-domain-smoke.v1",
                "airlock-nix-closure-domain-smoke",
                "nix-closure-domain-smoke.json",
                super::evidence::CLOSURE,
            ),
            (
                "AIRLOCK_RUN_QUBES_SMOKE",
                true,
                "qrexec-smoke",
                "airlock.qubes-smoke.v1",
                "airlock-qubes-smoke",
                "qubes-smoke.json",
                &[][..],
            ),
            (
                "AIRLOCK_RUN_GUI_SMOKE",
                true,
                "window-smoke",
                "airlock.qubes-gui-smoke.v1",
                "airlock-qube-gui-smoke",
                "qube-gui-smoke.json",
                &[][..],
            ),
        ] {
            let prefix = format!("vm-gui-{prefix}");
            if toggle(flag, default)? {
                let mut env = forwarded(
                    keys,
                    if flag == "AIRLOCK_BOOTSTRAP_QUBES" {
                        &bootstrap
                    } else {
                        &overrides
                    },
                );
                if flag == "AIRLOCK_RUN_QUBES_SMOKE" {
                    env.extend([
                        (
                            "AIRLOCK_TEST_TEMPLATE".into(),
                            setting("AIRLOCK_QUBES_TEMPLATE", "fedora-43-xfce"),
                        ),
                        (
                            "AIRLOCK_TEST_QUBE".into(),
                            setting("AIRLOCK_TEST_QUBE", "test-airlock-smoke"),
                        ),
                        ("AIRLOCK_TEST_CLEANUP".into(), "0".into()),
                    ]);
                }
                if flag == "AIRLOCK_RUN_GUI_SMOKE" {
                    env.extend([
                        (
                            "AIRLOCK_TEST_QUBE".into(),
                            setting("AIRLOCK_TEST_QUBE", "test-airlock-smoke"),
                        ),
                        ("AIRLOCK_GUI_DISPLAY".into(), ":0".into()),
                    ]);
                }
                let variable = match flag {
                    "AIRLOCK_RUN_CONFIG_INPUTS_IMPORT" => "AIRLOCK_CONFIG_INPUTS_IMPORT_COMMAND",
                    "AIRLOCK_RUN_CONFIG_VMS_SMOKE" => "AIRLOCK_CONFIG_VMS_SMOKE_COMMAND",
                    "AIRLOCK_RUN_NIX_CLOSURE_SMOKE" => "AIRLOCK_NIX_CLOSURE_DOMAIN_SMOKE_COMMAND",
                    _ => "",
                };
                let program = if warm && !variable.is_empty() {
                    format!(
                        "{bin}/{command}",
                        bin = setting("AIRLOCK_NESTED_WARM_BIN_DIR", "/run/airlock-warm/bin")
                    )
                } else {
                    setting(variable, command)
                };
                scenario(
                    context,
                    (&prefix, schema, &format!("/var/log/airlock/{remote}")),
                    &program,
                    &[],
                    &env,
                )?;
            } else {
                context.save(
                    &format!("{prefix}.json"),
                    &json!({"schema":schema,"status":"skipped","reason":format!("{flag}=0")}),
                )?;
            }
        }
        if toggle("AIRLOCK_SHUTDOWN_VM_ON_SUCCESS", false)?
            && !keep
            && let Some(vm) = &mut vm
        {
            let _ = context.remote(&["sudo", "-n", "systemctl", "poweroff"]);
            let deadline = Instant::now()
                + Duration::from_secs(number("AIRLOCK_VM_SHUTDOWN_WAIT_SECONDS", 180)?);
            while !vm.exited()? && Instant::now() < deadline {
                thread::sleep(Duration::from_secs(2));
            }
            ensure!(
                !toggle("AIRLOCK_REQUIRE_CLEAN_SHUTDOWN", false)? || vm.exited()?,
                "VM did not shut down cleanly"
            );
        }
        Ok(())
    })();
    diagnostics(context);
    drop(vm);
    if !keep
        && toggle("AIRLOCK_AUTO_GC_AFTER_RUN", false)?
        && let Err(error) = crate::gc::execute(&context.root, crate::gc::Mode::Auto)
    {
        eprintln!("automatic Airlock GC: {error:#}");
    }
    result?;
    println!(
        "nested GUI smoke completed; evidence: {directory}",
        directory = context.logs.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Scope cleanup cancels the process it owns while an explicit keep request leaves it alive.
    #[test]
    fn vm_cleanup_respects_owned_and_kept_processes() -> Result<()> {
        for keep in [false, true] {
            let child = Command::new("sleep").arg("60").process_group(0).spawn()?;
            let pid = rustix::process::Pid::from_child(&child);
            let state: ChildState = std::sync::Arc::new(std::sync::Mutex::new(Some(child)));
            let vm = Vm {
                child: state.clone(),
                keep,
            };
            assert!(!vm.exited()?);
            drop(vm);
            if keep {
                assert!(rustix::process::test_kill_process(pid).is_ok());
                terminate(&state);
            } else {
                assert!(state.lock().unwrap().is_none());
            }
        }
        Ok(())
    }
}
