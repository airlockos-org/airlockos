//! Local Qubes guest setup and probes; upstream agents retain device and protocol ownership.

use airlock_nix_core::runtime::process;
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use serde_json::Value;
use std::{
    fs,
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

/// Native guest operations installed through role-specific thin launchers.
#[derive(Args)]
pub(crate) struct Request {
    /// Selected local operation; existing qrexec policy remains the caller admission boundary.
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Check complementary object visibility inside this VM's filtered immutable store.
    StoreVisibility {
        /// Object exclusive to this VM's view.
        own: String,
        /// Object exclusive to its peer's view, which must be absent locally.
        other: String,
        /// Canonical object intentionally shared by both views.
        shared: String,
    },
    /// Preserve existing development checkouts and install absent guidance links.
    Workspace {
        /// Persistent tool state directory owned by the guest user.
        state: PathBuf,
        /// Installed tool guidance target.
        instructions: PathBuf,
        /// Guest user's home directory.
        home: PathBuf,
        /// Installed home guidance target.
        home_instructions: PathBuf,
        /// Current checkout destination, preserving an old checkout when appropriate.
        repo: PathBuf,
    },
    /// Set only missing effective Git identity defaults, refusing malformed configuration.
    GitIdentity {
        /// Existing local checkout; an absent checkout is left for source seeding.
        repo: PathBuf,
    },
    /// Observe the exact immutable system, store mount and read-only external device.
    StoreCheck,
    /// Mount imported configuration sources into their public read-only-source namespace.
    MountInputs {
        /// Directory containing the persisted input manifest.
        #[arg(long)]
        inputs: PathBuf,
        /// Private Nix root containing the imported source objects.
        #[arg(long)]
        store: PathBuf,
        /// Installed public source mountpoints.
        #[arg(long)]
        public: PathBuf,
    },
    /// Validate the configured Qubes role before running its unprivileged initializer.
    ConfigurationInit {
        /// Installed configuration role, independent of runtime observations.
        #[arg(long)]
        role: String,
        /// Unprivileged repository owner selected by the machine configuration.
        #[arg(long)]
        user: String,
        /// Explicit executable search path for the role's initializer.
        #[arg(long)]
        path: String,
        /// Installed initializer, not supplied by a remote caller.
        #[arg(long)]
        command: PathBuf,
    },
    /// Initialize private Qubes mounts using upstream setup and home helpers.
    PrivateStorage {
        /// Immutable upstream agent package containing its own initialization routines.
        #[arg(long)]
        agent: PathBuf,
        /// Absolute Bash executable selected by the package configuration, independent of PATH.
        #[arg(long)]
        bash: PathBuf,
        /// Configured unprivileged home owner.
        #[arg(long)]
        user: String,
    },
    /// Require the live private-device and home/local mount identities without changing them.
    PrivateStorageCheck,
    /// Move NetworkManager connections into persistent private storage.
    NetworkManagerState,
    /// Select upstream IPv4/IPv6 firewall rules from QubesDB observations.
    Firewall {
        /// Installed upstream rules package.
        #[arg(long)]
        agent: PathBuf,
    },
    /// Run upstream DNS forwarding and refresh the existing updates proxy when needed.
    NetworkHook {
        /// Fixed upstream forwarding helper selected at build time.
        #[arg(long)]
        dnat: PathBuf,
        /// Interface supplied by NetworkManager.
        interface: Option<String>,
        /// NetworkManager event spelling.
        event: Option<String>,
    },
    /// Publish the observed interface address through upstream QubesDB.
    ExternalIp {
        /// Interface supplied by NetworkManager.
        interface: Option<String>,
        /// NetworkManager event spelling.
        event: Option<String>,
    },
    /// Reconcile frontend uplinks discovered before root filesystem udev rules loaded.
    ExistingUplinks,
    /// Enroll the development assistant after bounded network checks.
    TailscaleUp,
    /// Enroll through the assistant user's exact sudo helper, without cross-VM caller authority.
    TailscaleUpLocal,
}

/// Capture one small upstream command without unbounded inherited pipes.
fn text(command: &mut Command) -> Result<String> {
    Ok(String::from_utf8(
        process::run(command, None, Some(Duration::from_secs(120)))?
            .checked("guest runtime helper")?,
    )?
    .trim_end_matches('\n')
    .into())
}

/// Preserve a failing command's status rather than masking it with later setup.
fn run(command: &mut Command) -> Result<()> {
    text(command)?;
    Ok(())
}

/// Check mount membership with the same upstream mountpoint semantics as the services.
fn mounted(path: &Path) -> bool {
    text(Command::new("mountpoint").arg("-q").arg(path)).is_ok()
}

/// Bind one persistent directory only when it is not already mounted.
fn bind(source: &Path, destination: &Path) -> Result<()> {
    if !mounted(destination) {
        run(Command::new("mount")
            .arg("--bind")
            .arg(source)
            .arg(destination))?;
    }
    Ok(())
}

/// Refuse missing/unknown manifest names and paths outside the explicitly selected private store.
fn mount_inputs(inputs: &Path, store: &Path, public: &Path) -> Result<()> {
    ensure!(
        store.is_absolute() && store != Path::new("/"),
        "private input store must be an absolute non-root path"
    );
    fs::create_dir_all(inputs)?;
    fs::create_dir_all(public)?;
    let manifest = inputs.join("manifest.json");
    if !manifest.is_file() {
        return Ok(());
    }
    let value: Value = airlock_nix_core::state::parse_json(&fs::read(&manifest)?, &manifest)?;
    let entries = value["inputs"]
        .as_object()
        .context("invalid input manifest")?;
    // Validate the complete set before making any public mount changes.
    let mut mounts = Vec::new();
    for (name, source) in entries {
        ensure!(
            [
                "nixpkgs",
                "nixpkgs-libvirt_10_5",
                "nixos-qubes",
                "airlock-support",
                "airlock-apps"
            ]
            .contains(&name.as_str()),
            "invalid config input name: {name}"
        );
        let source = Path::new(source.as_str().context("config input is not a path")?);
        ensure!(
            source.starts_with("/nix/store")
                && source
                    .components()
                    .all(|component| !matches!(component, std::path::Component::ParentDir))
                && source.components().count() > 3,
            "invalid config input path"
        );
        let physical = store.join(source.strip_prefix("/")?);
        ensure!(
            physical.is_dir(),
            "imported config input is missing: {physical}",
            physical = physical.display()
        );
        mounts.push((physical, public.join(name)));
    }
    for (source, target) in mounts {
        if mounted(&target) {
            continue;
        }
        if let Ok(metadata) = fs::symlink_metadata(&target)
            && !metadata.is_dir()
        {
            fs::remove_file(&target)?;
        }
        fs::create_dir_all(&target)?;
        bind(&source, &target)?;
    }
    Ok(())
}

/// Require the active generation and mount identity, and independently attempt a negative write probe.
fn store_check() -> Result<()> {
    let cmdline = fs::read_to_string("/proc/cmdline")?;
    let option = |name: &str| {
        cmdline.split_whitespace().find_map(|word| {
            word.split_once('=')
                .filter(|(key, _)| *key == name)
                .map(|(_, value)| value)
        })
    };
    let system = option("airlock.system")
        .filter(|value| !value.is_empty())
        .context("missing airlock.system kernel option")?;
    let device = option("airlock.storedev")
        .filter(|value| !value.is_empty())
        .context("missing airlock.storedev kernel option")?;
    let format = option("airlock.storefmt")
        .filter(|value| !value.is_empty())
        .unwrap_or("erofs");
    let blob = option("airlock.storeblobdev").unwrap_or("");
    ensure!(
        fs::metadata(Path::new(system).join("init"))?
            .permissions()
            .mode()
            & 0o111
            != 0,
        "system init is not executable"
    );
    ensure!(
        fs::canonicalize("/run/current-system")? == Path::new(system),
        "current system differs from selected immutable generation"
    );
    let source = text(Command::new("findmnt").args(["-rn", "-T", "/nix/store", "-o", "SOURCE"]))?;
    let options = text(Command::new("findmnt").args(["-rn", "-T", "/nix/store", "-o", "OPTIONS"]))?;
    ensure!(
        source == device,
        "store mount source differs from declared device"
    );
    if format == "erofs" && !blob.is_empty() {
        ensure!(
            fs::metadata(blob)?.file_type().is_block_device(),
            "external store device is missing"
        );
    }
    ensure!(
        options.split(',').any(|option| option == "ro"),
        "store is not mounted read-only"
    );
    let probe = PathBuf::from(format!(
        "/nix/store/.airlock-runtime-write-probe-{pid}",
        pid = std::process::id()
    ));
    if fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .is_ok()
    {
        let _ = fs::remove_file(probe);
        anyhow::bail!("/nix/store accepted a write probe");
    }
    println!(
        "system={system}\nstore_device={device}\nstore_format={format}\nstore_blob_device={blob}\nstore_options={options}"
    );
    Ok(())
}

/// Keep all object names in the store root and distinguish absence from an observation error.
fn visibility(root: &Path, own: &str, other: &str, shared: &str) -> Result<()> {
    for object in [own, other, shared] {
        ensure!(
            !object.is_empty()
                && ![".", ".."].contains(&object)
                && object
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"+._?=-".contains(&byte)),
            "invalid store object name"
        );
    }
    ensure!(
        root.join(own).try_exists()? && root.join(shared).try_exists()?,
        "required own/shared store object is missing"
    );
    ensure!(
        !root.join(other).try_exists()?,
        "unexpected peer-only object is visible"
    );
    Ok(())
}

/// Move only the old visible connection entries, retaining existing private entries on name conflicts.
fn network_state() -> Result<()> {
    let target = Path::new("/rw/config/NM-system-connections");
    let link = Path::new("/etc/NetworkManager/system-connections");
    fs::create_dir_all(target)?;
    fs::set_permissions(target, fs::Permissions::from_mode(0o700))?;
    fs::create_dir_all(link.parent().unwrap())?;
    if let Ok(metadata) = fs::symlink_metadata(link) {
        if metadata.is_dir() {
            for entry in fs::read_dir(link)? {
                let entry = entry?;
                if entry.file_name().as_encoded_bytes().starts_with(b".") {
                    continue;
                }
                let destination = target.join(entry.file_name());
                if fs::symlink_metadata(&destination).is_err() {
                    fs::rename(entry.path(), destination)?;
                }
            }
            fs::remove_dir_all(link)?;
        } else {
            fs::remove_file(link)?;
        }
    }
    std::os::unix::fs::symlink(target, link)?;
    Ok(())
}

/// Check direct caller admission before any network or enrollment operation.
fn tailscale() -> Result<()> {
    ensure!(
        std::env::var("QREXEC_REMOTE_DOMAIN").as_deref() == Ok("sys-gui")
            && std::env::var("QREXEC_SERVICE_ARGUMENT")
                .unwrap_or_default()
                .is_empty(),
        "unauthorized Tailscale enrollment caller or argument"
    );

    enroll_tailscale()
}

/// Perform the same bounded enrollment for the fixed local sudo helper.
fn tailscale_local() -> Result<()> {
    ensure!(
        rustix::process::geteuid().is_root(),
        "local Tailscale enrollment requires the installed privileged helper"
    );

    enroll_tailscale()
}

/// Check the assistant's network path before invoking the upstream interactive login once.
fn enroll_tailscale() -> Result<()> {
    println!("Checking the Internet connection from usr-assistant...");
    ensure!(
        !text(Command::new("ip").args(["-4", "route", "show", "default"]))?.is_empty(),
        "No network route in usr-assistant. Check sys-net and sys-firewall, then retry."
    );
    ensure!(
        process::run(
            Command::new("getent").args(["ahostsv4", "controlplane.tailscale.com"]),
            None,
            Some(Duration::from_secs(5))
        )?
        .status
        .success(),
        "DNS is not working from usr-assistant. Check sys-net and sys-firewall, then retry."
    );
    run(Command::new("curl").args([
        "--silent",
        "--show-error",
        "--output",
        "/dev/null",
        "--connect-timeout",
        "5",
        "--max-time",
        "15",
        "https://controlplane.tailscale.com/",
    ]))
    .context("Cannot reach Tailscale over HTTPS. Check sys-net and sys-firewall, then retry.")?;
    println!("Connection available. Starting Tailscale login (two-minute limit)...");
    // Keep interactive/browser login output live; upstream timeout owns its foreground cancellation behavior.
    let status = Command::new("timeout")
        .args([
            "--foreground",
            "--kill-after=5s",
            "120s",
            "tailscale",
            "up",
            "--ssh",
        ])
        .status()?;
    if !status.success() {
        if status.code() == Some(124) {
            eprintln!(
                "Tailscale login timed out. Check the connection and complete browser login, then retry."
            );
        }
        return Err(crate::HelperExit {
            code: status
                .code()
                .and_then(|code| u8::try_from(code).ok())
                .unwrap_or(1),
        }
        .into());
    }
    Ok(())
}

/// Dispatch local behavior; no command changes Qubes policy or grants VM control authority.
pub(crate) fn execute(request: Request) -> Result<()> {
    match request.action {
        Action::StoreVisibility { own, other, shared } => {
            visibility(Path::new("/nix/store"), &own, &other, &shared)?;
            store_check()?;
            println!("visibility_probe=passed");
        }
        Action::Workspace {
            state,
            instructions,
            home,
            home_instructions,
            repo,
        } => {
            let old = home.join("dev/airlock-machine");
            if old != repo && old.exists() && !old.is_symlink() {
                if repo.symlink_metadata().is_err() {
                    ensure!(
                        old.join(".git").is_dir(),
                        "old source path is not a Git checkout"
                    );
                    fs::rename(&old, &repo)?;
                } else {
                    eprintln!(
                        "Preserving both existing checkout paths: {old} and {repo}",
                        old = old.display(),
                        repo = repo.display()
                    );
                }
            }
            for (link, target) in [
                (home.join("AGENTS.md"), home_instructions),
                (state.join("AGENTS.md"), instructions),
            ] {
                if link.parent() == Some(state.as_path()) {
                    fs::create_dir_all(&state)?;
                    fs::set_permissions(&state, fs::Permissions::from_mode(0o700))?;
                }
                if link.symlink_metadata().is_err() {
                    std::os::unix::fs::symlink(target, link)?;
                }
            }
        }
        Action::GitIdentity { repo } => {
            if !repo.exists() {
                return Ok(());
            }
            run(Command::new("git")
                .arg("-C")
                .arg(&repo)
                .args(["rev-parse", "--git-dir"]))?;
            for (key, default) in [
                ("user.name", "Airlock User"),
                ("user.email", "user@airlock.invalid"),
            ] {
                let result = process::run(
                    Command::new("git")
                        .arg("-C")
                        .arg(&repo)
                        .args(["config", "--get", key]),
                    None,
                    Some(Duration::from_secs(30)),
                )?;
                match result.status.code() {
                    Some(0) => {
                        if !String::from_utf8(result.stdout)?.trim().is_empty() {
                            continue;
                        }
                    }
                    Some(1) => {}
                    _ => {
                        result.checked("read effective Git identity")?;
                        anyhow::bail!("unexpected Git identity status");
                    }
                }
                run(Command::new("git")
                    .arg("-C")
                    .arg(&repo)
                    .args(["config", "--local", key, default]))?;
            }
        }
        Action::StoreCheck => store_check()?,
        Action::MountInputs {
            inputs,
            store,
            public,
        } => mount_inputs(&inputs, &store, &public)?,
        Action::ConfigurationInit {
            role,
            user,
            path,
            command,
        } => {
            let name = text(Command::new("qubesdb-read").arg("/name")).unwrap_or_default();
            let observed = text(Command::new("qubesdb-read").arg("/features/airlock-role"))
                .unwrap_or_default();
            ensure!(
                observed.is_empty() || observed == role,
                "QubesDB role mismatch: expected={role} actual={observed} vm={name}"
            );
            ensure!(
                name.is_empty()
                    || name == role
                    || ![
                        "sys-config-vault",
                        "sys-config-staging",
                        "sys-config-validator"
                    ]
                    .contains(&name.as_str()),
                "configuration VM name mismatch: expected={role} actual={name}"
            );
            return Err(Command::new("runuser")
                .args([
                    "-u",
                    &user,
                    "--",
                    "env",
                    &format!("HOME=/home/{user}"),
                    &format!("USER={user}"),
                    &format!("LOGNAME={user}"),
                    &format!("XDG_CACHE_HOME=/home/{user}/.cache"),
                    &format!("PATH={path}"),
                ])
                .arg(command)
                .exec()
                .into());
        }
        Action::PrivateStorage { agent, bash, user } => {
            airlock_vm_service::private_storage::initialize(&agent, &bash, &user)?;
        }
        Action::PrivateStorageCheck => {
            airlock_vm_service::private_storage::observe()?;
        }
        Action::NetworkManagerState => network_state()?,
        Action::Firewall { agent } => {
            for family in ["ipv4", "ipv6"] {
                let file = if family == "ipv6"
                    && text(Command::new("qubesdb-read").arg("/qubes-ip6")).is_err()
                    && text(Command::new("qubesdb-read").arg("/qubes-netvm-gateway6")).is_err()
                {
                    "qubes-ipv6-disabled.nft".to_owned()
                } else {
                    format!("qubes-{family}.nft")
                };
                let rules = agent.join("etc/qubes").join(file);
                ensure!(rules.is_file(), "upstream firewall rules are missing");
                run(Command::new("nft").arg("-f").arg(rules))?;
            }
        }
        Action::NetworkHook {
            dnat,
            interface: _,
            event,
        } => {
            if event.is_some_and(|event| {
                ["up", "vpn-up", "vpn-down", "dhcp4-change"].contains(&event.as_str())
            }) {
                // NetworkManager hooks deliberately return success; upstream DNAT exit 100 means no proxy refresh.
                let status = Command::new(dnat).status();
                if !status.is_ok_and(|status| status.code() == Some(100)) {
                    let _ = Command::new("systemctl")
                        .args(["--no-block", "try-restart", "qubes-updates-proxy.service"])
                        .status();
                }
            }
        }
        Action::ExternalIp { interface, event } => match event.as_deref() {
            Some("up") => {
                let interface = interface.context("interface missing for up event")?;
                let addresses = text(Command::new("ip").args(["addr", "show", "dev", &interface]))
                    .unwrap_or_default()
                    .lines()
                    .filter(|line| line.contains("inet"))
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
                    .join("\n");
                run(Command::new("qubesdb-write").args(["/qubes-netvm-external-ip", &addresses]))?;
            }
            Some("down") => {
                run(Command::new("qubesdb-write").args(["/qubes-netvm-external-ip", ""]))?
            }
            _ => {}
        },
        Action::ExistingUplinks => {
            for entry in fs::read_dir("/sys/class/net")? {
                let entry = entry?;
                let interface = entry.file_name();
                let interface = interface.to_string_lossy();
                if interface.starts_with("vif") {
                    continue;
                }
                if fs::canonicalize(entry.path().join("device/driver"))
                    .ok()
                    .and_then(|path| path.file_name().map(|name| name == "vif"))
                    .unwrap_or(false)
                {
                    run(Command::new("systemctl").args([
                        "start",
                        &format!("qubes-network-uplink@{interface}.service"),
                    ]))?;
                }
            }
        }
        Action::TailscaleUp => tailscale()?,
        Action::TailscaleUpLocal => tailscale_local()?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Missing, extra and path-escaping objects cannot produce a passing guest isolation result.
    #[test]
    fn visibility_requires_complete_exact_view() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        fs::create_dir(root.join("own"))?;
        fs::create_dir(root.join("shared"))?;
        visibility(root, "own", "other", "shared")?;
        fs::create_dir(root.join("other"))?;
        assert!(visibility(root, "own", "other", "shared").is_err());
        fs::remove_dir(root.join("other"))?;
        fs::remove_dir(root.join("shared"))?;
        assert!(visibility(root, "own", "other", "shared").is_err());
        assert!(visibility(root, "../own", "other", "shared").is_err());
        Ok(())
    }
}
