//! Boot-time VM readiness and declared network-provider startup through existing Qubes tools.
//! These local boot commands retain their own policy, separate from reviewed deployment execution.

use crate::{
    boot::{self, GuestState},
    process::{Captured, Runner},
};
use airlock_machine_core::boot::{GUEST_READY_SECONDS, GUEST_START_SECONDS};
use airlock_nix_core::identity::GuestName;
use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::Write,
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

/// Start one declared VM and wait for its exact generation and provider services.
#[derive(Args)]
pub(crate) struct Ready {
    /// Exact declared guest identity; also used as one log filename component.
    domain: GuestName,
    /// Desired topology; the environment override applies when omitted.
    topology: Option<PathBuf>,
}

/// Observe a graphical login on the declared GUI generation before publishing desktop readiness.
#[derive(Args)]
pub(crate) struct Desktop {
    /// Full selected topology published by setup before GPU handoff.
    #[arg(long, default_value = "/run/airlock/startup/topology.json")]
    topology: PathBuf,
    /// Complete polling budget; shorter values support bounded local diagnostics.
    #[arg(long, default_value_t = 180, value_parser = clap::value_parser!(u64).range(1..=180))]
    timeout: u64,
}

/// Select only installed worker roles; topology values never become arbitrary remote commands.
pub(crate) fn worker_probe(role: Option<&str>) -> Option<String> {
    match role {
        Some(role @ ("sys-ctrl" | "usr-assistant")) => Some(format!(
            "root:/run/current-system/sw/bin/airlock-vm-service boot-health build-store --domain {role}"
        )),
        _ => None,
    }
}

/// Require a running GUI, its exact generation and a local graphical login on the same Xen instance.
pub(crate) fn desktop(request: Desktop) -> Result<()> {
    let raw = crate::state::configuration(&request.topology)?;
    let inputs = airlock_machine_core::boot::BootInputs::new(raw)?;
    let gui = inputs
        .topology()
        .domains
        .get(&"sys-gui".parse()?)
        .context("desktop topology has no sys-gui")?;
    let expected = gui.backend.system.source.as_str();
    let deadline = Instant::now() + Duration::from_secs(request.timeout);
    let runner = Runner::default();
    let mut error = "graphical login is not ready".to_owned();
    let mut instance = None;
    while Instant::now() < deadline {
        let result = (|| -> Result<()> {
            let run = |program: &str, args: &[&str]| {
                runner.run(
                    program,
                    &args.iter().map(OsString::from).collect::<Vec<_>>(),
                    deadline
                        .saturating_duration_since(Instant::now())
                        .min(Duration::from_secs(15)),
                    &[],
                )
            };
            run("qvm-check", &["--running", "sys-gui"])?;
            let before = run("qvm-ls", &["--raw-data", "--fields", "XID", "sys-gui"])?;
            ensure!(
                !before.is_empty()
                    && before.bytes().all(|byte| byte.is_ascii_digit())
                    && before.parse::<u32>().is_ok_and(|xid| xid > 0),
                "invalid GUI Xen identity"
            );
            let initial = instance.get_or_insert_with(|| before.clone());
            ensure!(*initial == before, "GUI restarted during desktop readiness");
            ensure!(
                run(
                    "qrexec-client",
                    &["-d", "sys-gui", "user:readlink -f /run/current-system"]
                )? == expected,
                "GUI running generation differs from topology"
            );
            run(
                "qrexec-client",
                &[
                    "-d",
                    "sys-gui",
                    "root:/run/current-system/sw/bin/airlock-vm-service boot-health desktop",
                ],
            )?;
            ensure!(
                run("qvm-ls", &["--raw-data", "--fields", "XID", "sys-gui"])? == before,
                "GUI restarted during graphical readiness"
            );
            run("qvm-check", &["--running", "sys-gui"])?;
            Ok(())
        })();
        match result {
            Ok(()) => return Ok(()),
            Err(failure) => error = failure.to_string(),
        }
        thread::sleep(
            Duration::from_millis(250).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
    bail!("desktop did not become ready: {error}")
}

/// Read a path override without requiring its bytes to be UTF-8.
fn path(key: &str, default: &str) -> PathBuf {
    std::env::var_os(key).map_or_else(|| default.into(), PathBuf::from)
}

/// Read a finite whole-second command deadline, including zero for immediate expiry.
fn seconds(key: &str, default: u64) -> Result<Duration> {
    let seconds = match std::env::var(key) {
        Ok(value) => value.parse().with_context(|| format!("invalid {key}"))?,
        Err(std::env::VarError::NotPresent) => default,
        Err(error) => return Err(error.into()),
    };
    // Refuse unrepresentable Instant deadlines before requesting external effects.
    let duration = Duration::from_secs(seconds);
    ensure!(
        Instant::now().checked_add(duration).is_some(),
        "{key} is too large"
    );
    Ok(duration)
}

/// Run a bounded peer and retain both successful output and failed diagnostics.
fn capture(
    log: &mut File,
    key: &str,
    default: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<Captured> {
    let program = path(key, default);
    writeln!(log, "+ {program} {args:?}", program = program.display())?;
    let output = Runner::default().capture(
        program.as_os_str(),
        &args.iter().map(OsString::from).collect::<Vec<_>>(),
        timeout,
        &[],
    )?;
    log.write_all(&output.stdout)?;
    log.write_all(&output.stderr)?;
    Ok(output)
}

/// Publish progress locally; fixture overrides retain the existing transport seam.
fn supervise(phase: GuestState, domain: &GuestName, detail: &str) -> Result<()> {
    if let Some(program) = std::env::var_os("AIRLOCK_BOOT_SERVICE") {
        Runner::default().run(
            program,
            &[
                "boot-supervisor".into(),
                "guest".into(),
                domain.as_str().into(),
                match phase {
                    GuestState::Waiting => "waiting",
                    GuestState::Starting => "starting",
                    GuestState::Ready => "ready",
                    GuestState::Failed => "failed",
                }
                .into(),
                detail.into(),
            ],
            Duration::from_secs(60),
            &[],
        )?;
        return Ok(());
    }

    boot::guest_checkpoint(domain, phase, detail)
}

/// Match the existing guest probe; each forwarding unit must independently be active.
pub(crate) const PROVIDER_HEALTH: &str = r#"root:for unit in qubes-antispoof qubes-iptables qubes-firewall qubes-network; do systemctl is-active --quiet "$unit.service" || { echo "Network provider unhealthy: $unit.service" >&2; exit 1; }; done; if test -e /run/qubes-service/network-manager; then systemctl is-active --quiet NetworkManager.service; fi"#;

/// Start and poll after the supervisor has recorded the expected generation.
fn wait(
    log: &mut File,
    domain: &str,
    expected: &str,
    health: Option<&str>,
    artifact: Option<&airlock_nix_core::hermit_artifact::Descriptor>,
    start: Duration,
    ready: Duration,
) -> Result<()> {
    let output = capture(
        log,
        "AIRLOCK_QVM_START",
        "qvm-start",
        &["--skip-if-running", "--", domain],
        start,
    )?;
    ensure!(
        !output.limited && output.status.success(),
        "{domain} startup failed or timed out"
    );

    let deadline = Instant::now() + ready;
    let mut attempt = 0;
    while Instant::now() < deadline {
        attempt += 1;
        writeln!(log, "readiness attempt={attempt}")?;
        let _ = capture(
            log,
            "AIRLOCK_QVM_CHECK",
            "qvm-check",
            &["--running", domain],
            Duration::from_secs(15),
        )?;
        let _ = capture(
            log,
            "AIRLOCK_QVM_LS",
            "qvm-ls",
            &["--raw-data", "--fields", "NAME,STATE,XID", domain],
            Duration::from_secs(15),
        )?;
        if let Some(artifact) = artifact {
            let observation = (|| -> Result<()> {
                let output = capture(
                    log,
                    "AIRLOCK_QVM_LS",
                    "qvm-ls",
                    &["--raw-data", "--fields", "XID", domain],
                    Duration::from_secs(10),
                )?;
                ensure!(
                    !output.limited && output.status.success(),
                    "Hermit Xen identity unavailable"
                );
                let xid: u32 = std::str::from_utf8(&output.stdout)?.trim().parse()?;
                crate::hermit::ready(domain, artifact, xid)?;
                let after = capture(
                    log,
                    "AIRLOCK_QVM_LS",
                    "qvm-ls",
                    &["--raw-data", "--fields", "XID", domain],
                    Duration::from_secs(10),
                )?;
                ensure!(
                    !after.limited && after.status.success() && output.stdout == after.stdout,
                    "Hermit restarted during readiness"
                );
                Ok(())
            })();
            match observation {
                Ok(()) => {
                    return supervise(
                        GuestState::Ready,
                        &domain.parse()?,
                        &format!(
                            "{domain} executes {expected}; clipboard authority {authority:?}",
                            authority = artifact.authority
                        ),
                    );
                }
                Err(error) => writeln!(log, "Hermit execution pending: {error}")?,
            }
            thread::sleep(
                Duration::from_millis(250).min(deadline.saturating_duration_since(Instant::now())),
            );
            continue;
        }
        let output = capture(
            log,
            "AIRLOCK_QREXEC_CLIENT",
            "qrexec-client",
            &["-d", domain, "user:readlink -f /run/current-system"],
            Duration::from_secs(15),
        )?;
        if !output.limited && output.status.success() {
            let actual = std::str::from_utf8(&output.stdout)?.trim_end_matches('\n');
            ensure!(
                actual == expected,
                "{domain} reported {actual}; expected {expected}"
            );
            let healthy = if let Some(command) = health {
                let output = capture(
                    log,
                    "AIRLOCK_QREXEC_CLIENT",
                    "qrexec-client",
                    &["-d", domain, command],
                    Duration::from_secs(15),
                )?;
                !output.limited && output.status.success()
            } else {
                true
            };
            if healthy {
                let output = capture(
                    log,
                    "AIRLOCK_QVM_CHECK",
                    "qvm-check",
                    &["--running", domain],
                    Duration::from_secs(15),
                )?;
                ensure!(
                    !output.limited && output.status.success(),
                    "{domain} stopped during readiness checks"
                );
                return supervise(
                    GuestState::Ready,
                    &domain.parse()?,
                    &format!("{domain} is qrexec-ready on {expected}"),
                );
            }
            writeln!(log, "Guest network or build-store services are not ready.")?;
        }
        thread::sleep(
            Duration::from_secs(3).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
    bail!(
        "{domain} did not report its expected application readiness within {seconds}s",
        seconds = ready.as_secs()
    )
}

/// Preserve per-VM boot evidence and report failures through the existing supervisor.
pub(crate) fn start(request: Ready) -> Result<()> {
    let topology = request.topology.unwrap_or_else(|| {
        path(
            "AIRLOCK_QUBES_TOPOLOGY",
            "/var/lib/airlock/system/current-topology.json",
        )
    });
    let raw: Value = crate::state::configuration(&topology)?;
    let domain = request.domain.as_str();
    let definition = raw["domains"]
        .get(domain)
        .context("VM is not declared by topology")?;
    let hermit = if definition["backend"]["type"] == "hermit" {
        let inputs = airlock_machine_core::boot::BootInputs::new(raw.clone())?;
        inputs.topology().domains[&request.domain]
            .backend
            .hermit()
            .cloned()
    } else {
        None
    };
    let expected = definition["backend"]["system"]["source"]
        .as_str()
        .filter(|source| !source.is_empty())
        .context("missing expected system generation")?;
    let provider = definition["prefs"]["provides_network"] == true;
    let health = worker_probe(definition["features"]["airlock-role"].as_str())
        .or_else(|| provider.then(|| PROVIDER_HEALTH.to_owned()));
    let start = seconds("AIRLOCK_QUBE_START_TIMEOUT", GUEST_START_SECONDS)?;
    let ready = seconds("AIRLOCK_QUBE_READY_TIMEOUT", GUEST_READY_SECONDS)?;
    let boot_id = fs::read_to_string(path(
        "AIRLOCK_BOOT_ID_FILE",
        "/proc/sys/kernel/random/boot_id",
    ))?;
    let default = format!(
        "/var/log/airlock/boot-attempts/{boot_id}",
        boot_id = boot_id.trim()
    );
    let directory = path("AIRLOCK_BOOT_ATTEMPT_LOG_DIR", &default);
    fs::create_dir_all(&directory)?;
    let mut log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(directory.join(format!("start-{domain}.log")))?;
    let result = (|| {
        supervise(
            GuestState::Starting,
            &request.domain,
            &format!("starting {domain}; expecting {expected}"),
        )?;
        writeln!(
            log,
            "domain={domain} expected={expected} start_timeout={start:?} ready_timeout={ready:?}"
        )?;
        wait(
            &mut log,
            domain,
            expected,
            health.as_deref(),
            hermit.as_ref(),
            start,
            ready,
        )
    })();
    if let Err(error) = &result {
        writeln!(log, "{error:#}")?;
        let _ = supervise(GuestState::Failed, &request.domain, &format!("{error:#}"));
    }
    result
}

/// Select only autostart providers and order explicit local NetVM dependencies among them.
fn providers(topology: &Value) -> Result<Vec<String>> {
    let Some(domains) = topology.get("domains") else {
        return Ok(Vec::new());
    };
    let domains = domains
        .as_object()
        .context("topology domains must be an object")?;
    let mut pending = domains
        .iter()
        .filter(|(_, vm)| {
            vm["prefs"]["provides_network"] == true && vm["prefs"]["autostart"] == true
        })
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    for name in &pending {
        let _: GuestName = name.parse()?;
    }
    let selected: BTreeSet<_> = pending.iter().cloned().collect();
    let mut ordered = Vec::new();
    while !pending.is_empty() {
        let before = pending.len();
        let mut next = Vec::new();
        for name in pending {
            let dependency = domains[&name]["netvm"].as_str().filter(|target| {
                !target.is_empty()
                    && !target.eq_ignore_ascii_case("none")
                    && selected.contains(*target)
            });
            if dependency.is_none_or(|target| ordered.iter().any(|name| name == target)) {
                ordered.push(name);
            } else {
                next.push(name);
            }
        }
        ensure!(
            next.len() < before,
            "declared autostart network-provider NetVM dependency cycle: {next:?}"
        );
        pending = next;
    }
    Ok(ordered)
}

/// Start every selected provider, collecting failures without skipping independent providers.
pub(crate) fn start_providers() -> Result<()> {
    let topology = path("AIRLOCK_QUBES_TOPOLOGY", "/etc/airlock/qubes-topology.json");
    let directory = path("AIRLOCK_LOG_DIR", "/var/log/airlock");
    fs::create_dir_all(&directory)?;
    let command_log = directory.join("start-network-providers.commands.log");
    let mut log = File::create(&command_log)?;
    let raw: Value = crate::state::configuration(&topology)?;
    let providers = providers(&raw)?;
    let mut started = Vec::new();
    let mut failed = Vec::new();
    for name in &providers {
        let output = capture(
            &mut log,
            "AIRLOCK_START_QUBE_READY",
            "airlock-start-qube-ready",
            &[name, topology.to_str().context("non-UTF-8 topology path")?],
            seconds("AIRLOCK_QUBE_START_TIMEOUT", GUEST_START_SECONDS)?
                + seconds("AIRLOCK_QUBE_READY_TIMEOUT", GUEST_READY_SECONDS)?
                + Duration::from_secs(240),
        );
        match output {
            Ok(output) if !output.limited && output.status.success() => started.push(name),
            Ok(_) => failed.push(name),
            Err(error) => {
                writeln!(log, "{name}: {error:#}")?;
                failed.push(name);
            }
        }
    }
    let result = json!({"schema":"airlock.start-network-providers.v1", "status":if failed.is_empty() {"passed"} else {"failed"}, "topology":topology, "command_log":command_log, "providers":providers, "started_or_running":started, "failed":failed});
    crate::setup_config::report::save(&directory.join("start-network-providers.json"), &result)?;
    println!("{result}");
    ensure!(
        failed.is_empty(),
        "one or more network providers failed to start"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only selected providers participate in ordering; external and disabled peers stay excluded.
    #[test]
    fn provider_order_keeps_the_selected_subgraph() -> Result<()> {
        let topology = json!({"domains":{
            "a-child":{"prefs":{"autostart":true,"provides_network":true},"netvm":"z-parent"},
            "b-external":{"prefs":{"autostart":true,"provides_network":true},"netvm":"outside"},
            "disabled":{"prefs":{"autostart":false,"provides_network":true}},
            "z-parent":{"prefs":{"autostart":true,"provides_network":true},"netvm":"disabled"}
        }});
        assert_eq!(providers(&topology)?, ["b-external", "z-parent", "a-child"]);
        Ok(())
    }

    /// A cycle among selected providers must fail before any startup is attempted.
    #[test]
    fn provider_cycles_are_rejected() {
        let topology = json!({"domains":{
            "a":{"prefs":{"autostart":true,"provides_network":true},"netvm":"b"},
            "b":{"prefs":{"autostart":true,"provides_network":true},"netvm":"a"}
        }});
        assert!(providers(&topology).is_err());
    }
}
