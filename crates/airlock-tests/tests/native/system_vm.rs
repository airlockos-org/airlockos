//! Explicit nested-VM lanes serialize shared state and keep staged steps together in one failing transaction.

use crate::common;
use airlock_tests::system::{self, Job};
use airlock_vm_service::support;
use anyhow::{Context, Result, ensure};
use rustix::fs::{FlockOperation, flock};
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    net::TcpListener,
    os::unix::fs::symlink,
    path::PathBuf,
    process::Command,
    time::{Duration, Instant},
};

/// Protect global serial work and retain one exclusive VM slot for each concurrently executing parallel flow.
struct Lease {
    // Shared by parallel jobs and exclusively held by serial or staged jobs.
    _global: File,
    // Slot file remains locked until the complete flow ends.
    _slot: Option<File>,
    // Allocates mutable disk state, result links and SSH ports consistently.
    lane: usize,
}

impl Lease {
    /// Coordinate Cargo test threads with kernel locks, including separate runner processes.
    fn acquire(serial: bool) -> Result<Self> {
        let data = PathBuf::from(
            std::env::var_os("AIRLOCK_DATA_ROOT")
                .context("set AIRLOCK_DATA_ROOT before system tests")?,
        );
        let locks = data.join("test-locks");
        fs::create_dir_all(&locks)?;
        let open = |name: &str| -> Result<File> {
            Ok(File::options()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(locks.join(name))?)
        };
        let global = open("vm-global")?;
        flock(
            &global,
            if serial {
                FlockOperation::LockExclusive
            } else {
                FlockOperation::LockShared
            },
        )?;
        if serial {
            return Ok(Self {
                _global: global,
                _slot: None,
                lane: 0,
            });
        }
        let lanes = std::env::var("AIRLOCK_VM_PARALLEL_LANES")
            .unwrap_or_else(|_| "1".into())
            .parse::<usize>()?;
        ensure!(
            (1..=64).contains(&lanes),
            "VM lanes must be between 1 and 64"
        );
        let deadline = Instant::now() + Duration::from_secs(7200);
        loop {
            for lane in 0..lanes {
                let slot = open(&format!("vm-{lane}"))?;
                match flock(&slot, FlockOperation::NonBlockingLockExclusive) {
                    Ok(()) => {
                        return Ok(Self {
                            _global: global,
                            _slot: Some(slot),
                            lane,
                        });
                    }
                    Err(rustix::io::Errno::WOULDBLOCK) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            ensure!(Instant::now() < deadline, "all VM test lanes remained busy");
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// Require a prepared backing disk or firmware template instead of provisioning one during a test.
fn required(name: &str) -> Result<PathBuf> {
    let path = PathBuf::from(std::env::var_os(name).with_context(|| format!("set {name}"))?);
    ensure!(
        path.is_file(),
        "{name} must refer to a prepared file: {path:?}"
    );
    Ok(path)
}

/// Run an existing Make flow with lane-private writable state, prepared image links and durable evidence.
fn flow(name: &str, serial: bool, warm: bool, baseline: bool) -> Result<()> {
    ensure!(
        std::env::var("AIRLOCK_RUN_VM_TESTS").as_deref() == Ok("1"),
        "set AIRLOCK_RUN_VM_TESTS=1"
    );
    let lease = Lease::acquire(serial || warm)?;
    let lanes = std::env::var("AIRLOCK_VM_PARALLEL_LANES")
        .unwrap_or_else(|_| "1".into())
        .parse::<usize>()?;
    let root = common::root();
    let logs = system::logs(&format!("vm-lanes/{lane}/{name}", lane = lease.lane))?;
    let mut command = Command::new("make");
    command
        .arg("-C")
        .arg(&root)
        .arg(name)
        .env("AIRLOCK_LOG_DIR", &logs);
    command.env("AIRLOCK_SKIP_GC_AUTO", "1");
    if lanes > 1 && !serial && !warm {
        let data = PathBuf::from(std::env::var_os("AIRLOCK_DATA_ROOT").unwrap());
        let vm = data.join(format!("vm-lanes/{lane}", lane = lease.lane));
        let links = data.join(format!("result-links/vm-lanes/{lane}", lane = lease.lane));
        fs::create_dir_all(&vm)?;
        fs::create_dir_all(&links)?;
        let attr = std::env::var("AIRLOCK_VM_PARALLEL_IMAGE_ATTR")
            .unwrap_or_else(|_| "airlock-vm-gui-config-dev-image".into());
        ensure!(!attr.is_empty(), "parallel image attribute required");
        let shared = PathBuf::from(
            std::env::var_os("AIRLOCK_VM_PARALLEL_IMAGE_LINK")
                .context("explicitly prepare the shared VM image")?,
        );
        let image = fs::canonicalize(shared)?;
        ensure!(image.is_dir(), "prepared VM image output missing");
        let link = vm.join(format!("{attr}-result"));
        if link.is_symlink() {
            fs::remove_file(&link)?;
        } else {
            ensure!(!link.exists(), "refusing to replace VM result directory");
        }
        symlink(image, link)?;
        let port = std::env::var("AIRLOCK_VM_PARALLEL_SSH_BASE_PORT")
            .unwrap_or_else(|_| "2300".into())
            .parse::<u16>()?
            .checked_add(lease.lane.try_into()?)
            .context("VM port overflow")?;
        command
            .env("AIRLOCK_VM_DIR", vm)
            .env("AIRLOCK_RESULT_LINK_DIR", links)
            .env("AIRLOCK_VM_LANE", lease.lane.to_string())
            .env("AIRLOCK_VM_SSH_PORT", port.to_string())
            .env("AIRLOCK_VM_SKIP_BASE_BUILD", "1");
        if baseline {
            command
                .env(
                    "AIRLOCK_VM_BACKING_IMAGE",
                    required("AIRLOCK_VM_PARALLEL_BASELINE_DISK")?,
                )
                .env(
                    "AIRLOCK_VM_OVMF_VARS_TEMPLATE",
                    required("AIRLOCK_VM_PARALLEL_BASELINE_OVMF_VARS")?,
                )
                .env("VM_FLOW_RUN_SETUP_CONFIG", "0");
        }
    }
    system::run(&mut command, &logs, Duration::from_secs(7200))
}

/// Declare only explicit ignored system tests; normal Cargo runs never start or build a VM.
macro_rules! flows {
    ($($test:ident => ($name:literal, $serial:literal, $warm:literal, $baseline:literal)),+ $(,)?) => {
        $(
            /// Run the selected nested-VM flow with locked mutable state and complete per-flow evidence.
            #[test]
            #[ignore = "explicit nested Xen VM build and runtime validation"]
            fn $test() -> Result<()> {flow($name, $serial, $warm, $baseline)}
        )+
    };
}

flows! {
    vm_flow_vm_prebuild_shared => ("vm-prebuild-shared", true, false, false),
    vm_flow_vm_config_flow => ("vm-config-flow", false, false, true),
    vm_flow_vm_nix_closure_flow => ("vm-nix-closure-flow", false, false, true),
    vm_flow_vm_pool_admission_flow => ("vm-pool-admission-flow", true, false, false),
    vm_flow_vm_config_boot_flow => ("vm-config-boot-flow", false, false, true),
    vm_flow_vm_config_boot_activate_flow => ("vm-config-boot-activate-flow", true, false, false),
    vm_flow_vm_gui_smoke => ("vm-gui-smoke", true, false, false),
    vm_flow_vm_warm_start => ("vm-warm-start", true, true, false),
    vm_flow_vm_warm_sync => ("vm-warm-sync", true, true, false),
    vm_flow_vm_warm_apply => ("vm-warm-apply", true, true, false),
    vm_flow_vm_warm_test_config => ("vm-warm-test-config", true, true, false),
    vm_flow_vm_config_warm_flow => ("vm-config-warm-flow", true, true, false),
    vm_flow_vm_nix_closure_warm_flow => ("vm-nix-closure-warm-flow", true, true, false),
}

/// Keep ordered archive/resolve/setup/system/deploy steps in one test so a failure prevents every dependent step.
#[test]
#[ignore = "explicit staged nested Xen VM validation"]
fn staged_configuration() -> Result<()> {
    ensure!(
        std::env::var("AIRLOCK_RUN_VM_TESTS").as_deref() == Ok("1"),
        "set AIRLOCK_RUN_VM_TESTS=1"
    );
    let _lease = Lease::acquire(true)?;
    let root = common::root();
    let logs = system::logs("vm-staged")?;
    let message = std::env::var("AIRLOCK_CONFIG_APPLY_MESSAGE").unwrap_or_else(|_| {
        format!(
            "rust-staged-{timestamp}",
            timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        )
    });
    fs::write(logs.join("apply-message.txt"), &message)?;
    let selected = std::env::var("AIRLOCK_VM_STAGED_STEPS").unwrap_or_default();
    for step in [
        "warm-start",
        "warm-baseline",
        "config-vms-preflight",
        "config-apply-archive",
        "config-apply-resolve",
        "config-apply-setup",
        "config-apply-system",
        "config-apply-deploy",
        "config-vms-post-apply",
        "nix-closure-domain-smoke",
    ] {
        if !selected.is_empty() && !selected.split_whitespace().any(|name| name == step) {
            continue;
        }
        if selected.is_empty() && step == "nix-closure-domain-smoke" {
            continue;
        }
        let mut command = if ["warm-start", "warm-baseline"].contains(&step) {
            let mut command = Command::new("make");
            command.arg(if step == "warm-start" {
                "vm-warm-start"
            } else {
                "vm-warm-apply"
            });
            command
        } else {
            let mut command = Command::new(common::binary("AIRLOCK_DEV_BIN", "airlock-dev"));
            command.arg("--repository-root").arg(&root).args([
                "with-environment",
                "nested",
                "smoke",
            ]);
            for (key, value) in [
                ("AIRLOCK_KEEP_VM", "1"),
                ("AIRLOCK_REUSE_WARM_VM", "1"),
                ("AIRLOCK_SYNC_DOM0_TOOLS", "0"),
                ("AIRLOCK_NESTED_WARM_STOP_NIX_DOMAINS", "1"),
                ("AIRLOCK_VM_SKIP_BASE_BUILD", "1"),
                ("AIRLOCK_VM_IMAGE_ATTR", "airlock-vm-gui-config-dev-image"),
                ("AIRLOCK_VM_DISPLAY", "none"),
                ("AIRLOCK_VM_FRESH", "0"),
                ("AIRLOCK_BOOTSTRAP_QUBES", "0"),
                ("AIRLOCK_RUN_SETUP_CONFIG", "0"),
                ("AIRLOCK_RUN_CONFIG_INPUTS_IMPORT", "0"),
                ("AIRLOCK_RUN_CONFIG_VMS_SMOKE", "1"),
                ("AIRLOCK_RUN_NIX_CLOSURE_SMOKE", "0"),
                ("AIRLOCK_RUN_QUBES_SMOKE", "0"),
                ("AIRLOCK_RUN_GUI_SMOKE", "0"),
                (
                    "AIRLOCK_CONFIG_INPUTS_SOURCE",
                    "/run/airlock-warm/config-inputs",
                ),
                (
                    "AIRLOCK_CONFIG_VMS_SMOKE_COMMAND",
                    "/run/airlock-warm/bin/airlock-config-vms-smoke",
                ),
                (
                    "AIRLOCK_SETUP_CONFIG_COMMAND",
                    "/run/airlock-warm/bin/airlock-setup-config",
                ),
                (
                    "AIRLOCK_DOM0_SERVICE",
                    "/run/airlock-warm/bin/airlock-dom0-service",
                ),
            ] {
                command.env(key, value);
            }
            if let Some(stage) = step.strip_prefix("config-apply-") {
                command
                    .env("AIRLOCK_CONFIG_VMS_SMOKE_MODE", "apply-candidate")
                    .env("AIRLOCK_CONFIG_APPLY_STAGE", stage);
            } else {
                command.env(
                    "AIRLOCK_CONFIG_VMS_SMOKE_MODE",
                    if step == "config-vms-preflight" {
                        "preflight"
                    } else {
                        "post-apply"
                    },
                );
            }
            if step == "nix-closure-domain-smoke" {
                command
                    .env("AIRLOCK_RUN_CONFIG_VMS_SMOKE", "0")
                    .env("AIRLOCK_RUN_NIX_CLOSURE_SMOKE", "1")
                    .env(
                        "AIRLOCK_NIX_CLOSURE_DOMAIN_SMOKE_COMMAND",
                        "/run/airlock-warm/bin/airlock-nix-closure-domain-smoke",
                    );
            }
            command
        };
        command
            .current_dir(&root)
            .env("AIRLOCK_LOG_DIR", logs.join(step))
            .env("AIRLOCK_CONFIG_APPLY_MESSAGE", &message)
            .env("AIRLOCK_SKIP_GC_AUTO", "1");
        if let Err(error) = system::run(&mut command, &logs.join(step), Duration::from_secs(7200)) {
            fs::write(logs.join("failed-step.txt"), step)?;
            return Err(error);
        }
    }
    Ok(())
}

/// The isolated GPU lab verifies VM lifecycle and diagnostic transport while requiring no physical GPU.
#[test]
#[ignore = "explicit isolated nested Xen GPU lab"]
fn gpu_lab_vm() -> Result<()> {
    ensure!(
        std::env::var("AIRLOCK_RUN_GPU_LAB_TESTS").as_deref() == Ok("1"),
        "set AIRLOCK_RUN_GPU_LAB_TESTS=1"
    );
    let _lease = Lease::acquire(true)?;
    let root = common::root();
    let logs = system::logs("gpu-lab-vm")?;
    let data = PathBuf::from(std::env::var_os("AIRLOCK_DATA_ROOT").context("Airlock data root")?);
    fs::create_dir_all(data.join("gpu-lab-tests"))?;
    let vm = tempfile::Builder::new()
        .prefix("run-")
        .tempdir_in(data.join("gpu-lab-tests"))?
        .keep();
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    drop(listener);
    let configure = |command: &mut Command| {
        command
            .env("AIRLOCK_VM_DIR", &vm)
            .env("AIRLOCK_VM_SSH_PORT", port.to_string())
            .env("AIRLOCK_VM_IMAGE_ATTR", "airlock-vm-gpu-lab-image")
            .env("AIRLOCK_VM_DISPLAY", "none")
            .env("AIRLOCK_VM_MEMORY", "12288");
    };
    fs::write(
        logs.join("environment.json"),
        serde_json::to_vec_pretty(&json!({"vm_dir": vm, "ssh_port": port}))?,
    )?;
    let ssh = |script: &str| -> Result<support::Output> {
        let mut command = Command::new(common::binary("AIRLOCK_DEV_BIN", "airlock-dev"));
        command
            .arg("--repository-root")
            .arg(&root)
            .args(["with-environment", "nested", "ssh"]);
        command.arg(script);
        configure(&mut command);
        support::run(&mut command, None, Duration::from_secs(180))
    };
    let mut command = Command::new(common::binary("AIRLOCK_DEV_BIN", "airlock-dev"));
    command
        .arg("--repository-root")
        .arg(&root)
        .args(["with-environment", "nested", "run"]);
    command.current_dir(&root);
    configure(&mut command);
    let mut job = Job::spawn(&mut command, &logs.join("console"))?;
    let deadline = Instant::now() + Duration::from_secs(2400);
    loop {
        ensure!(job.running()?, "GPU lab exited; inspect console evidence");
        if ssh(
            "systemctl is-active --quiet airlock-setup-config-deferred && sudo qvm-check sys-gpu",
        )?
        .status
        .success()
        {
            break;
        }
        ensure!(Instant::now() < deadline, "sys-gpu was not created");
        std::thread::sleep(Duration::from_secs(5));
    }
    assert!(!ssh("sudo qvm-check --running sys-gpu")?.status.success());
    ssh("sudo qvm-start sys-gpu")?.checked()?;
    let probe = ssh("sudo qvm-run --pass-io sys-gpu airlock-vm-service gpu-probe")?.checked()?;
    fs::write(logs.join("probe.json"), &probe)?;
    let report: Value = serde_json::from_slice(&probe)?;
    assert_eq!(report["schema"], "airlock.gpu-probe.v1");
    assert_eq!(report["hostname"], "sys-gpu");
    assert_eq!(report["hardware_api_initialized"], false);
    assert_eq!(report["cross_vm_graphics_verified"], false);
    assert_eq!(
        ssh("sudo qvm-run --pass-io sys-gpu 'airlock-vm-service gpu-probe --require-hardware'")?
            .status
            .code(),
        Some(1)
    );
    for command in [
        "sudo qvm-shutdown --wait sys-gpu",
        "sudo qvm-start sys-gpu",
        "sudo qvm-run --pass-io sys-gpu 'test $(hostname) = sys-gpu'",
        "sudo qvm-shutdown --wait sys-gpu",
        "sudo qvm-check --running sys-gui",
    ] {
        ssh(command)?.checked()?;
    }
    Ok(())
}
