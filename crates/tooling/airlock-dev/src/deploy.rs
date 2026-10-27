//! Workstation submission and explicitly selected development repair transport.

mod transfer;

mod smoke;

use crate::{
    repository, source,
    support::{self, git, quote},
    transport::{self, Session},
};
use airlock_nix_core::{
    identity::{GitRevision, GuestName},
    store_path::StorePath,
};
use anyhow::{Context, Result, ensure};
use clap::{Args as ClapArgs, ValueEnum};
use serde_json::{Value, json};
use std::{
    fs,
    io::{self, Write},
    path::Path,
    process::Command,
    time::Duration,
};

#[derive(Clone, Copy, PartialEq, ValueEnum)]
pub(crate) enum Operation {
    Build,
    Plan,
    Apply,
    Status,
    Verify,
    Resume,
    Rollback,
    GuestPlan,
    GuestApply,
}

impl Operation {
    fn name(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Plan => "plan",
            Self::Apply => "apply",
            Self::Status => "status",
            Self::Verify => "verify",
            Self::Resume => "resume",
            Self::Rollback => "rollback",
            Self::GuestPlan => "guest-plan",
            Self::GuestApply => "guest-apply",
        }
    }

    fn guest(self) -> bool {
        matches!(self, Self::GuestPlan | Self::GuestApply)
    }
}

#[derive(Clone, Copy, PartialEq, ValueEnum)]
pub(crate) enum Profile {
    UsbLab,
    UsbGuiLab,
}

impl Profile {
    fn name(self) -> &'static str {
        match self {
            Self::UsbLab => "usb-lab",
            Self::UsbGuiLab => "usb-gui-lab",
        }
    }
}

#[derive(ClapArgs)]
pub(crate) struct Args {
    // Requested build, observation, submission or explicit repair operation.
    #[arg(value_enum)]
    action: Operation,
    // SSH host for the installed usr-assistant VM; never a dom0 SSH server.
    #[arg(long)]
    target: Option<String>,
    // Existing Qubes VM carrying the separate binary artifact stream.
    #[arg(long, default_value = "usr-assistant")]
    bridge_vm: GuestName,
    // Whole-machine development profile selected for local builds.
    #[arg(long, value_enum, default_value = "usb-lab")]
    profile: Profile,
    // Inactive admission receipt inside usr-assistant for guest operations.
    #[arg(long)]
    receipt: Option<String>,
    // Explicitly build and transfer the current coordinator for recovery.
    #[arg(long)]
    update_coordinator: bool,
    // Explicit administrative development transport, outside normal review submission.
    #[arg(long)]
    development_shell: bool,
    // Keep deployed VM artifacts while repairing the matching development host.
    #[arg(long)]
    host_repair: bool,
}

#[derive(ClapArgs)]
pub(crate) struct Style {
    // Planning is local; apply uses the existing development PTY and Qubes RPC.
    #[arg(value_enum)]
    action: StyleAction,
    // SSH target needed only when applying a style.
    #[arg(long)]
    target: Option<String>,
}

#[derive(Clone, Copy, ValueEnum)]
enum StyleAction {
    Plan,
    Apply,
}

fn clean(root: &Path) -> Result<(String, String)> {
    ensure!(
        git(root, &["status", "--porcelain"])?.is_empty(),
        "commit repository changes before deployment (including new files)"
    );
    let (_, machine) = repository::local(root)?;
    Ok((git(root, &["rev-parse", "HEAD"])?, machine))
}

fn nix(root: &Path, args: &[&str]) -> Result<Value> {
    let (mut command, _source) = repository::command(root, args)?;
    command.current_dir(root);
    Ok(serde_json::from_slice(&support::output(&mut command)?)?)
}

fn built_path(value: &Value) -> Result<String> {
    let result = value.as_array().context("Nix build result")?;
    ensure!(result.len() == 1, "expected exactly one build output");
    let path = result[0]["outputs"]["out"]
        .as_str()
        .context("missing build output")?;
    let _: StorePath = path.parse()?;
    Ok(path.to_owned())
}

fn build(root: &Path, profile: Profile) -> Result<(String, String, String)> {
    let (dev, machine) = clean(root)?;
    let release = built_path(&nix(
        root,
        &[
            "build",
            &format!(
                "{}/airlock-machine#airlock-machine-release-{}",
                root.display(),
                profile.name()
            ),
            "--json",
            "--no-link",
        ],
    )?)?;
    ensure!(
        clean(root)? == (dev.clone(), machine.clone()),
        "repository changed during build; retry from a clean commit"
    );
    let logs = root.join(".airlock-logs/machine-deploy").join(&dev);
    fs::create_dir_all(&logs)?;
    let (mut pin, _source) = repository::command(
        root,
        &[
            "build",
            &release,
            "--out-link",
            logs.join("release").to_str().context("release link")?,
        ],
    )?;
    support::output(&mut pin)?;
    support::record(
        &logs.join("build.json"),
        &json!({"devRevision":dev,"osRevision":machine,"profile":profile.name(),"release":release}),
    )?;
    Ok((release, machine, dev))
}

fn repair_snapshot(root: &Path, profile: Profile, session: &mut Session) -> Result<Value> {
    let mut snapshot: Value = serde_json::from_str(&session.command(&[
        "/run/current-system/sw/bin/airlock-dom0-service",
        "development-snapshot",
    ])?)?;
    ensure!(
        snapshot["devMode"] == true && snapshot["profile"] == profile.name(),
        "host repair requires the matching development boot profile"
    );
    let revision = if snapshot["manifest"].is_object() {
        snapshot["manifest"]["revision"]
            .as_str()
            .context("selected source revision")?
            .to_owned()
    } else {
        let boot: GitRevision = snapshot["boot"]["revision"]
            .as_str()
            .context("image has no verified boot source revision")?
            .parse()?;
        repository::pinned(root, boot.as_str())?
    };
    let revision: GitRevision = revision.parse()?;
    let lock = support::output(
        Command::new("git")
            .arg("-C")
            .arg(root.join("airlock-machine"))
            .args(["show", &format!("{revision}:flake.lock")]),
    )?;
    let hash = support::digest(&lock);
    ensure!(
        snapshot["manifest"].is_null() || snapshot["manifest"]["lockHash"] == hash,
        "selected machine lock differs from its committed source"
    );
    let _: airlock_nix_core::identity::LockHash = snapshot["topologyHash"]
        .as_str()
        .context("native topology fingerprint")?
        .parse()?;
    snapshot["revision"] = json!(revision);
    snapshot["lockHash"] = json!(hash);
    snapshot["baselineFlake"] = json!(format!(
        "git+{}?rev={revision}",
        repository::file_uri(&root.join("airlock-machine"))?
    ));
    snapshot["repairRevision"] = json!(git(&root.join("airlock-machine"), &["rev-parse", "HEAD"])?);
    snapshot
        .as_object_mut()
        .context("repair snapshot")?
        .remove("manifest");
    snapshot
        .as_object_mut()
        .context("repair snapshot")?
        .remove("devMode");
    Ok(snapshot)
}

fn repair(
    root: &Path,
    profile: Profile,
    session: &mut Session,
) -> Result<(String, String, String)> {
    let starting = clean(root)?;
    let snapshot = repair_snapshot(root, profile, session)?;
    let logs = root
        .join(".airlock-logs/machine-host-repair")
        .join(&starting.0);
    fs::create_dir_all(&logs)?;
    let path = logs.join("snapshot.json");
    support::record(&path, &snapshot)?;
    let (mut command, _source) = repository::command(
        root,
        &[
            "build",
            "--impure",
            &format!("{}#airlock-machine-host-repair", root.display()),
            "--json",
            "--out-link",
            logs.join("release").to_str().context("repair link")?,
        ],
    )?;
    command
        .current_dir(root)
        .env("AIRLOCK_HOST_REPAIR_SNAPSHOT", &path);
    let output: Value = serde_json::from_slice(&support::output(&mut command)?)?;
    ensure!(
        clean(root)? == starting,
        "repository changed during the host repair build"
    );
    let release = built_path(&output)?;
    support::record(
        &logs.join("build.json"),
        &json!({"release":release,"snapshot":snapshot}),
    )?;
    Ok((
        release,
        snapshot["revision"]
            .as_str()
            .context("repair source")?
            .into(),
        starting.0,
    ))
}

fn confirm(message: &str) -> Result<bool> {
    eprint!("{message} [y/N] ");
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(answer.trim().eq_ignore_ascii_case("y"))
}

fn engine(session: &mut Session) -> Result<String> {
    session.run("if [ -x /var/lib/airlock/machine/controller ]; then printf %s /var/lib/airlock/machine/controller; else printf %s /run/current-system/sw/bin/airlock-dom0-service; fi",Duration::from_secs(60))
}

pub(crate) fn execute(root: &Path, args: Args) -> Result<u8> {
    let action = args.action;
    ensure!(
        action == Operation::Build || args.target.is_some(),
        "--target is required"
    );
    ensure!(
        !args.host_repair
            || (args.development_shell
                && matches!(action, Operation::Plan | Operation::Apply)
                && args.profile == Profile::UsbLab),
        "--host-repair requires development-shell plan/apply for usb-lab"
    );
    ensure!(
        !action.guest() || args.receipt.is_some(),
        "--receipt is required for guest activation"
    );
    ensure!(
        !args.update_coordinator
            || action.guest()
            || (args.development_shell
                && matches!(action, Operation::Resume | Operation::Rollback)),
        "--update-coordinator requires guest activation or development-shell resume/rollback"
    );
    ensure!(
        args.profile == Profile::UsbLab || action == Operation::Build || args.development_shell,
        "usb-gui-lab operations require --development-shell"
    );
    if let Some(target) = &args.target {
        transport::target(target)?;
    }
    let target = args.target.as_deref().unwrap_or("");

    if !args.development_shell
        && args.profile == Profile::UsbLab
        && matches!(
            action,
            Operation::Plan
                | Operation::Apply
                | Operation::Status
                | Operation::Verify
                | Operation::Resume
                | Operation::Rollback
        )
    {
        if matches!(action, Operation::Plan | Operation::Apply) {
            source::push(root, target, None, None)?;
        }
        let remote =
            std::env::var("AIRLOCK_DEPLOY_REMOTE_CLIENT").unwrap_or_else(|_| "airlock".into());
        let script = support::join(&[&remote, "machine", action.name()]);
        let status = Command::new("ssh").args(["--", target, &script]).status()?;
        return Ok(status
            .code()
            .and_then(|c| u8::try_from(c).ok())
            .unwrap_or(1));
    }

    let mut session = None;
    let mut release = None;
    if matches!(
        action,
        Operation::Build | Operation::Plan | Operation::Apply
    ) {
        let built = if args.host_repair {
            let connection = session.insert(Session::connect(target)?);
            repair(root, args.profile, connection)?
        } else {
            build(root, args.profile)?
        };
        support::print(&json!({"release":built.0,"osRevision":built.1,"devRevision":built.2}))?;
        release = Some(built);
        if action == Operation::Build {
            return Ok(0);
        }
    }
    let session = match session.as_mut() {
        Some(session) => session,
        None => session.insert(Session::connect(target)?),
    };
    let updated = if args.update_coordinator {
        let starting = clean(root)?;
        fs::create_dir_all(root.join(".airlock-logs"))?;
        let package = built_path(&nix(
            root,
            &[
                "build",
                &format!("{}/airlock-machine#airlock-dom0-service", root.display()),
                "--json",
                "--out-link",
                root.join(".airlock-logs/machine-coordinator")
                    .to_str()
                    .context("coordinator link")?,
            ],
        )?)?;
        ensure!(
            clean(root)? == starting,
            "repository changed during coordinator build"
        );
        transfer::send(root, target, args.bridge_vm.as_str(), &package, session)?;
        Some(format!("{package}/bin/airlock-dom0-service"))
    } else {
        None
    };

    let mut command: Vec<String>;
    if action.guest() {
        let engine = match updated {
            Some(path) => path,
            None => engine(session)?,
        };
        let receipt =
            transfer::receipt(target, args.receipt.as_deref().context("missing receipt")?)?;
        let path = transfer::install_receipt(session, &receipt)?;
        let preview = session.command(&[&engine, "guest-plan", &path])?;
        println!("{preview}");
        if action == Operation::GuestPlan
            || !confirm("Activate this admitted VM generation (restarts affected VMs)?")?
        {
            return Ok(0);
        }
        command = if args.development_shell {
            let plan: Value = serde_json::from_str(&preview)?;
            let candidate = plan["candidate"].as_str().context("guest plan candidate")?;
            ensure!(
                Path::new(candidate).parent()
                    == Some(Path::new("/var/lib/airlock/machine/candidates")),
                "guest plan did not return a local machine candidate"
            );
            vec![
                engine,
                "apply".into(),
                candidate.into(),
                "--administrative".into(),
            ]
        } else {
            vec![engine, "guest-apply".into(), path]
        };
    } else if matches!(action, Operation::Plan | Operation::Apply) {
        let (release, machine, _) = release.context("missing built release")?;
        transfer::send(root, target, args.bridge_vm.as_str(), &release, session)?;
        let manifest: Value = serde_json::from_str(&session.command(&[
            "cat",
            "--",
            &format!("{release}/release.json"),
        ])?)?;
        ensure!(
            manifest["revision"] == machine && manifest["profile"] == args.profile.name(),
            "built release provenance does not match the requested commit/profile"
        );
        let engine = manifest["coordinator"]
            .as_str()
            .context("release coordinator")?;
        let _: airlock_nix_core::store_path::StoreFile = engine.parse()?;
        println!("{}", session.command(&[engine, "plan", &release])?);
        if action == Operation::Plan
            || !confirm("Apply this whole-machine release (may disconnect desktop and SSH)?")?
        {
            return Ok(0);
        }
        command = vec![engine.into(), "apply".into(), release];
        if args.development_shell {
            command.push("--administrative".into());
        }
    } else {
        command = vec![
            updated.unwrap_or_else(|| "/var/lib/airlock/machine/controller".into()),
            action.name().into(),
        ];
    }

    let refs: Vec<_> = command.iter().map(String::as_str).collect();
    if matches!(action, Operation::Status | Operation::Verify) {
        let script = if action == Operation::Status {
            format!(
                "if [ -e {0} ] || [ -L {0} ]; then {1}; else /run/current-system/sw/bin/airlock-dom0-service status; fi",
                quote(&command[0]),
                support::join(&refs)
            )
        } else {
            support::join(&refs)
        };
        println!("{}", session.run(&script, Duration::from_secs(900))?);
    } else {
        let unit = format!("airlock-machine-deploy-{}", &transport::nonce()?[..12]);
        let mut words = vec!["systemd-run", "--collect", "--property=Type=exec"];
        let flag = format!("--unit={unit}");
        words.push(&flag);
        words.extend(refs);
        println!("{}", session.command(&words)?);
        println!(
            "Started {unit} in dom0; it survives SSH loss. Reconnect with the status command."
        );
    }
    Ok(0)
}

pub(crate) fn style(root: &Path, args: Style) -> Result<()> {
    let (machine, revision) = repository::local(root)?;
    let mut style: Value = serde_json::from_slice(&support::output(
        Command::new("git")
            .arg("-C")
            .arg(machine)
            .args(["show", "HEAD:assets/sys-gui/gnome/gui-style.json"]),
    )?)?;
    let fields = style.as_object().context("GUI style")?;
    ensure!(
        fields.len() == 2
            && style["schema"] == "airlock.gui-style.v1"
            && style["color_width"]
                .as_u64()
                .is_some_and(|n| (1..=16).contains(&n)),
        "invalid committed GUI style"
    );
    style["revision"] = json!(revision);
    match args.action {
        StyleAction::Plan => {
            style["action"] = json!("reload-gui-style");
            style["vm_restarts"] = json!([]);
            style["host_reboot_required"] = json!(false);
            style["requires"] = json!("installed GUI border reload support");
            support::print(&style)
        }
        StyleAction::Apply => {
            let target = args.target.context("--target is required for apply")?;
            let mut session = Session::connect(&target)?;
            let request = serde_json::to_string(&style)?;
            println!(
                "{}",
                session.run(
                    &format!(
                        "printf '%s\\n' {} | qrexec-client -d sys-gui {}",
                        quote(&request),
                        quote("root:/run/current-system/sw/bin/airlock-sys-gui-service gui-style")
                    ),
                    Duration::from_secs(60)
                )?
            );
            Ok(())
        }
    }
}

pub(crate) fn pool_smoke(root: &Path) -> Result<()> {
    smoke::execute(root)
}
