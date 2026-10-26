//! Observe native boot artifacts, filtered store visibility and guest readiness through upstream tools.

use super::{Session, common, physical};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    process::Command,
    thread,
    time::{Duration, Instant},
};

/// One observed native boot identity; source paths remain distinct from runtime VM state.
pub(super) struct Boot {
    /// Declared immutable system generation expected inside the VM.
    pub(super) system: String,
    /// Immutable root image descriptor selected for the VM's writable root import.
    pub(super) root: String,
    /// Source closure descriptor used to materialize a filtered view.
    pub(super) store: String,
    /// Materialized EROFS metadata image.
    pub(super) view: String,
    /// Canonical object mapping for this exact generation's filtered view.
    pub(super) map: String,
    /// Published retained pool generation identifier.
    pub(super) generation: u64,
    /// Expected metadata block device in the guest.
    pub(super) device: String,
    /// Expected filtered external-data block device in the guest.
    pub(super) blob: String,
    /// Selected shared-view format, currently EROFS.
    pub(super) filesystem: String,
}

/// Read one required Qubes feature; empty metadata never becomes an accepted identity.
pub(super) fn feature(session: &mut Session, guest: &str, key: &str) -> Result<String> {
    let value = session.command(
        "qvm-features",
        &[guest, key],
        &format!("nix-closure-domain-{guest}-feature.log"),
    )?;
    ensure!(!value.is_empty(), "missing {key} feature for {guest}");
    Ok(value)
}

impl Boot {
    /// Check every physical source and supported layout before probing or switching a generation.
    pub(super) fn observe(session: &mut Session, guest: &str) -> Result<Self> {
        let boot = Self {
            system: feature(session, guest, "airlock-system-source")?,
            root: feature(session, guest, "airlock-root-source")?,
            store: feature(session, guest, "airlock-store-source")?,
            view: feature(session, guest, "airlock-store-view-image")?,
            map: feature(session, guest, "airlock-store-blob-map")?,
            generation: feature(session, guest, "airlock-store-generation")?.parse()?,
            device: feature(session, guest, "airlock-store-device")?,
            blob: feature(session, guest, "airlock-store-blob-device")?,
            filesystem: feature(session, guest, "airlock-store-filesystem")?,
        };
        ensure!(
            feature(session, guest, "airlock-store-mode")? == "shared-closure"
                && feature(session, guest, "airlock-store-view-backend")? == "erofs-objectmap"
                && boot.filesystem == "erofs",
            "unsupported shared-store layout for {guest}"
        );
        ensure!(
            physical(&boot.root).is_file()
                && physical(&boot.store).is_dir()
                && physical(&boot.store).join("store-paths").is_file()
                && physical(&boot.store).join("manifest.json").is_file()
                && physical(&boot.view).is_file()
                && physical(&boot.map).is_file(),
            "native boot artifacts are missing for {guest}"
        );
        Ok(boot)
    }

    /// Require the existing runtime service to report this exact immutable system and store layout.
    pub(super) fn runtime(&self, session: &mut Session, guest: &str, output: &str) -> Result<()> {
        let text = session.command(
            "qrexec-client",
            &[
                "-d",
                guest,
                "-T",
                "-w",
                "120",
                "DEFAULT:QUBESRPC airlock.NixStoreRuntimeCheck+ dom0",
            ],
            output,
        )?;
        let fields = common::fields(&text);
        for (key, expected) in [
            ("system", self.system.as_str()),
            ("store_device", self.device.as_str()),
            ("store_format", self.filesystem.as_str()),
            ("store_blob_device", self.blob.as_str()),
        ] {
            ensure!(
                fields.get(key).map(String::as_str) == Some(expected),
                "runtime service did not report expected {key} for {guest}"
            );
        }
        ensure!(
            fields
                .get("store_options")
                .is_some_and(|options| options.split(',').any(|option| option == "ro")),
            "runtime service did not report a read-only store for {guest}"
        );
        Ok(())
    }
}

/// Wait for a responding agent under the existing configurable finite deadline.
pub(super) fn ready(session: &mut Session, guest: &str, output: &str) -> Result<()> {
    let seconds: u64 = common::setting("AIRLOCK_NIX_CLOSURE_WAIT_SECONDS", "240").parse()?;
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(seconds))
        .context("qrexec wait too large")?;
    while Instant::now() < deadline {
        let timeout = Duration::from_secs(
            common::setting("AIRLOCK_NIX_CLOSURE_QREXEC_TIMEOUT_SECONDS", "45").parse()?,
        )
        .min(deadline.saturating_duration_since(Instant::now()));
        if session
            .remote_for(guest, ("uname", &["-a"]), None, output, timeout)
            .is_ok_and(|reply| reply.contains("Linux"))
        {
            return Ok(());
        }
        thread::sleep(
            Duration::from_secs(3).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
    anyhow::bail!("{guest} qrexec did not become ready within {seconds}s")
}

/// Verify Xen attaches only filtered external-data devices for both view components.
pub(super) fn libvirt(session: &mut Session, domain: &str, output: &str) -> Result<()> {
    let xml = match session.command("virsh", &["-c", "xen:///", "dumpxml", domain], output) {
        Ok(xml) => xml,
        Err(_) => session.command(
            "virsh",
            &["-c", "xen:///", "dumpxml", &format!("domain-{domain}")],
            output,
        )?,
    };
    let mut reader = quick_xml::Reader::from_str(&xml);
    let mut targets = std::collections::BTreeSet::new();
    loop {
        match reader.read_event()? {
            quick_xml::events::Event::Start(element) | quick_xml::events::Event::Empty(element)
                if element.name().as_ref() == b"target" =>
            {
                for attribute in element.attributes() {
                    let attribute = attribute?;
                    if attribute.key.as_ref() == b"dev" {
                        targets.insert(String::from_utf8(attribute.value.into_owned())?);
                    }
                }
            }
            quick_xml::events::Event::Eof => break,
            _ => {}
        }
    }
    ensure!(
        targets.contains("xvde")
            && targets.contains("xvdf")
            && xml.contains("/dev/mapper/airlock-")
            && !xml.contains("/var/lib/airlock/closure-store/objects/segments/"),
        "libvirt XML exposes incorrect or unfiltered store backing devices for {domain}"
    );
    Ok(())
}

/// Inspect the immutable root image and extract the filtered EROFS view, always detaching after inspection.
pub(super) fn images(session: &mut Session, domain: &str, boot: &Boot) -> Result<()> {
    let listing = session.command(
        "debugfs",
        &[
            "-R",
            "ls -p /nix/store",
            physical(&boot.root).to_str().context("root image path")?,
        ],
        "nix-closure-domain-root-image-check.log",
    )?;
    ensure!(
        !listing.lines().any(|line| {
            let parts = line.split('/').collect::<Vec<_>>();
            parts.len() >= 6 && ![".", ".."].contains(&parts[5])
        }),
        "root image contains unexpected /nix/store entries"
    );
    ensure!(
        fs::read_to_string(physical(&boot.store).join("store-paths"))?
            .lines()
            .any(|source| source == boot.system),
        "store closure omits the selected system"
    );
    let generation = boot.generation.to_string();
    let attach = session.command(
        "airlock-dom0-service",
        &[
            "storage",
            "pool",
            "attach-blob-view",
            "--domain",
            &format!("{domain}-runtime-store"),
            "--generation",
            &generation,
        ],
        "nix-closure-domain-store-attach.json",
    )?;
    let result: Result<()> = (|| {
        let attach: Value = serde_json::from_str(&attach)?;
        let device = attach["device"]
            .as_str()
            .filter(|device| device.starts_with("/dev/mapper/airlock-"))
            .context("unexpected filtered device")?;
        let resolved = fs::canonicalize(device)?;
        for backing in attach["backing_paths"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            ensure!(
                fs::canonicalize(backing)? != resolved,
                "filtered device resolves to canonical segment backing storage"
            );
        }
        let temporary = tempfile::Builder::new()
            .prefix("nix-closure-domain-store-extract-")
            .tempdir_in(&session.directory)?;
        session.command(
            "fsck.erofs",
            &[
                &format!("--device={device}"),
                &format!(
                    "--extract={directory}",
                    directory = temporary.path().display()
                ),
                physical(&boot.view)
                    .to_str()
                    .context("store view image path")?,
            ],
            "nix-closure-domain-store-view-check.log",
        )?;
        let relative = boot
            .system
            .strip_prefix("/nix/store/")
            .context("system source is not in /nix/store")?;
        ensure!(
            temporary
                .path()
                .join(relative)
                .join("init")
                .metadata()?
                .permissions()
                .mode()
                & 0o111
                != 0,
            "store view does not contain executable selected system init"
        );
        Ok(())
    })();
    let detach = session.command(
        "airlock-dom0-service",
        &[
            "storage",
            "pool",
            "detach-blob-view",
            "--domain",
            &format!("{domain}-runtime-store"),
            "--generation",
            &generation,
        ],
        "nix-closure-domain-store-detach.log",
    );
    result?;
    detach?;
    Ok(())
}

/// Run the guest boot/persistence/service probes using individual upstream programs, not a generated shell script.
pub(super) fn guest(
    session: &mut Session,
    domain: &str,
    boot: &Boot,
    role: &str,
    message: Option<&str>,
    output: &str,
) -> Result<()> {
    ready(session, domain, "nix-closure-domain-qrexec.log")?;
    let cmdline = session.remote(
        domain,
        "cat",
        &["/proc/cmdline"],
        None,
        "nix-closure-domain-cmdline.log",
    )?;
    let options = cmdline
        .split_whitespace()
        .filter_map(|word| word.split_once('='))
        .collect::<BTreeMap<_, _>>();
    let observed = session.remote(
        domain,
        "readlink",
        &["-f", "/run/current-system"],
        None,
        "nix-closure-domain-current-system.log",
    )?;
    ensure!(
        options.get("airlock.system") == Some(&boot.system.as_str())
            && observed == boot.system
            && options.get("airlock.storedev") == Some(&boot.device.as_str())
            && options.get("airlock.storefmt").copied().unwrap_or("erofs") == boot.filesystem
            && options.get("airlock.storeblobdev") == Some(&boot.blob.as_str()),
        "guest boot identity differs from the selected native generation"
    );
    session.remote(
        domain,
        "test",
        &["-x", &format!("{system}/init", system = boot.system)],
        None,
        "nix-closure-domain-guest-init.log",
    )?;
    session.remote(
        domain,
        "test",
        &["-b", &boot.blob],
        None,
        "nix-closure-domain-blob-device.log",
    )?;
    let block = boot
        .blob
        .strip_prefix("/dev/")
        .context("store blob device is not under /dev")?;
    ensure!(
        session.remote(
            domain,
            "cat",
            &[&format!("/sys/class/block/{block}/ro")],
            None,
            "nix-closure-domain-blob-readonly.log"
        )? == "1",
        "guest blob block device is writable"
    );
    session.runtime_store(domain, output)?;
    for service in [
        "qubes-db.service",
        "qubes-qrexec-agent.service",
        "airlock-qubes-rw-init.service",
    ] {
        session.remote(
            domain,
            "systemctl",
            &["is-active", service],
            None,
            "nix-closure-domain-guest-services.log",
        )?;
    }
    let user = common::setting("AIRLOCK_QUBE_USER", "user");
    let home = format!("/home/{user}");
    for directory in [
        "/rw",
        "/rw/home",
        "/usr/local",
        home.as_str(),
        "/run/qubes",
        "/var/log/qubes",
    ] {
        session.remote(
            domain,
            "test",
            &["-d", directory],
            None,
            "nix-closure-domain-guest-directories.log",
        )?;
    }
    session.remote(
        domain,
        "test",
        &["-w", &home],
        None,
        "nix-closure-domain-guest-home.log",
    )?;
    session.remote(
        domain,
        "touch",
        &[&format!("{home}/airlock-closure-smoke-home")],
        None,
        "nix-closure-domain-guest-home.log",
    )?;
    let observed_role = session
        .remote(
            domain,
            "cat",
            &["/etc/airlock/domain-role"],
            None,
            "nix-closure-domain-role.log",
        )
        .unwrap_or_default();
    ensure!(
        role.is_empty() || observed_role == role,
        "unexpected guest domain role: {observed_role}"
    );
    let applied = session
        .remote(
            domain,
            "cat",
            &["/etc/airlock/applied-message"],
            None,
            "nix-closure-domain-applied-message.log",
        )
        .unwrap_or_default();
    if let Some(message) = message {
        ensure!(
            applied == message,
            "guest did not boot the expected applied message"
        );
    }
    fs::write(
        session.file(output),
        format!(
            "cmdline={cmdline}\nsystem_path={system}\nstore_device={device}\nstore_format={filesystem}\nstore_blob_device={blob}\ncurrent_system={observed}\nguest_user={user}\nhome_dir={home}\ndomain_role={observed_role}\napplied_message={applied}\nruntime_probe=passed\n",
            system = boot.system,
            device = boot.device,
            filesystem = boot.filesystem,
            blob = boot.blob
        ),
    )?;
    Ok(())
}

/// Check complementary object visibility through each guest's already filtered store mount.
pub(super) fn visibility(
    session: &mut Session,
    domain: &str,
    own: &str,
    other: &str,
    shared: &str,
    output: &str,
) -> Result<()> {
    let reply = session.remote(
        domain,
        "airlock-vm-service",
        &["runtime", "store-visibility", own, other, shared],
        None,
        output,
    )?;
    ensure!(
        reply.lines().any(|line| line == "visibility_probe=passed"),
        "guest did not complete the visibility probe"
    );
    Ok(())
}

/// Invoke the existing canonical sharing report implementation used by offline tests too.
pub(super) fn sharing(
    session: &mut Session,
    domain: &str,
    peer: &str,
    boots: (&Boot, &Boot),
    second: bool,
) -> Result<Value> {
    let label = if second { "gen2" } else { "initial" };
    let output = session.file(if second {
        "nix-closure-domain-sharing-proof-gen2.json"
    } else {
        "nix-closure-domain-sharing-proof.json"
    });
    session.run(
        Command::new("airlock-test-report")
            .arg("sharing")
            .arg(label)
            .arg(domain)
            .arg(peer)
            .arg(physical(&boots.0.map))
            .arg(physical(&boots.1.map))
            .arg(&output),
        None,
        "nix-closure-domain-sharing.log",
    )?;
    Ok(serde_json::from_slice(&fs::read(output)?)?)
}
