//! Private machine state and inert Qubes peers for whole-machine transaction tests.

use super::*;
use std::{
    io::{Read, Write},
    os::unix::net::UnixListener,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
};

/// Overlay-capable bubblewrap can expose immutable dependencies without copying an entry for every host-store object.
fn store_overlay() -> bool {
    static AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        Path::new("/nix/store").is_dir()
            && common::tool("bwrap")
                .ok()
                .and_then(|tool| common::run(Command::new(tool).arg("--help"), None).ok())
                .is_some_and(|output| {
                    output.status.success()
                        && String::from_utf8_lossy(&output.stdout).contains("--ro-overlay")
                })
    })
}

/// Immutable host identity admitted by the fixture release.
pub const HOST: &str = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-fixture-host";

/// Setup helper belonging to the admitted host rather than an ambient executable.
pub const SETUP: &str =
    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-fixture-host/sw/bin/airlock-setup-config";

/// Source identity of the installed fixture generation.
pub fn revision() -> String {
    "a".repeat(40)
}

/// Lock identity shared by the prepared fixture generations.
pub fn lock_hash() -> String {
    "b".repeat(64)
}

/// Stable root artifact identity checked against each generation's pool metadata.
pub fn artifact() -> Value {
    json!({"schema": "airlock.root-artifact.v1", "sha256": "c".repeat(64),
        "logical_bytes": 65536, "payload_bytes": 64, "format": "ext4", "boot_abi": "airlock.nix-closure-root.v1"})
}

/// Distinguish immutable objects from the two fixture releases without manufacturing mutable store paths.
pub fn store(name: &str, version: u64) -> String {
    format!(
        "/nix/store/{hash}-{name}",
        hash = if version == 1 { "a" } else { "b" }.repeat(32)
    )
}

/// Describe a standalone closure-backed VM with its private disk and read-only shared store.
pub fn declaration(name: &str, version: u64) -> Value {
    json!({
        "class": "StandaloneVM", "template": null, "netvm": null, "devices": {},
        "prefs": {"autostart": true, "guivm": null}, "features": {}, "services": {},
        "backend": {
            "type": "nix-closure", "state": {"persistent": format!("{name}-private")},
            "system": {"source": store(&format!("{name}-system"), version)},
            "root": {"source": format!("{source}/root.img", source = store(&format!("{name}-root"), version))},
            "kernel": {"name": "qubes-kernel"},
            "store": {"source": store(&format!("{name}-closure"), version), "mode": "shared-closure",
                "device": "/dev/xvde", "blobDevice": "/dev/xvdf", "mountpoint": "/nix/store", "viewBackend": "erofs-objectmap"}
        }
    })
}

/// Write scenario data with the same durable layout expected by the native command under test.
pub fn save(path: impl AsRef<Path>, value: &Value) -> Result<()> {
    let path = path.as_ref();
    fs::create_dir_all(path.parent().context("fixture parent")?)?;
    fs::write(path, serde_json::to_vec(value)?)?;
    Ok(())
}

/// Decode a completed artifact rather than reaching into the coordinator's private Rust types.
pub fn read(path: impl AsRef<Path>) -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

/// One disposable root contains both releases, Qubes replies, host tools and namespace mount sources.
pub struct Machine {
    // Keeps every mutable mount source alive through child completion and socket teardown.
    pub temporary: tempfile::TempDir,
    // Mutable Qubes reply data; reload after a native invocation before editing observed state.
    pub data: Value,
    // Virtual path of the installed release in the namespace.
    pub baseline: String,
    // Virtual path of the proposed release, bound to a human review before activation.
    pub candidate: String,
    // Whether boot snapshot tests supply actual Qubes XML and qrexec policy files.
    boot: bool,
}

impl Machine {
    /// Prepare two generations with exact pool provenance and the real coordinator behind command peers.
    pub fn new() -> Result<Self> {
        let temporary = tempfile::tempdir()?;
        for name in [
            "machine",
            "etc",
            "host/sw/bin",
            "profiles",
            "bin",
            "tmp",
            "runtime",
            "view",
        ] {
            fs::create_dir_all(temporary.path().join(name))?;
        }
        for name in ["current-system", "booted-system"] {
            symlink(HOST, temporary.path().join("runtime").join(name))?;
        }
        fs::write(temporary.path().join("etc/machine-profile"), "usb-lab\n")?;
        save(
            temporary
                .path()
                .join("host/etc/airlock/machine-source.json"),
            &json!({"schema":"airlock.machine-source.v1","revision":revision(),"lockHash":lock_hash()}),
        )?;
        fs::write(temporary.path().join("etc/review-required"), "v1\n")?;
        save(
            temporary.path().join("etc/generation-retention.json"),
            &json!({"enabled": false}),
        )?;
        if Path::new("/nix/store").exists() && !store_overlay() {
            for entry in fs::read_dir("/nix/store")? {
                let name = entry?.file_name();
                symlink(
                    Path::new("/var/reference-store").join(&name),
                    temporary.path().join("view").join(name),
                )?;
            }
        }
        fs::create_dir(
            temporary
                .path()
                .join("view")
                .join(Path::new(HOST).file_name().unwrap()),
        )?;
        for name in [
            "qvm-ls",
            "qvm-check",
            "qvm-features",
            "qvm-start",
            "qvm-shutdown",
            "qrexec-client",
            "airlock-dom0-service",
            "nix-store",
            "nix-env",
            "airlock-setup-config",
            "systemctl",
            "airlock-start-qube-ready",
            "qvm-prefs",
            "qvm-volume",
            "qvm-tags",
            "qvm-remove",
            "machine-lock-race",
        ] {
            common::peer_link(&temporary.path().join("bin"), name)?;
        }
        for name in ["airlock-setup-config", "airlock-dom0-service"] {
            fs::copy(
                common::peer(),
                temporary.path().join("host/sw/bin").join(name),
            )?;
        }
        let mut data = json!({
            "running": ["usr-home"], "selected": {"usr-home": 1}, "generations": {},
            "host_pool": {"schema":"airlock.host-store.v1", "system":HOST, "generation":1,
                "manifest":"/var/lib/airlock/closure-store/domains/dom0/generations/1/manifest.json",
                "closure_hash":"d".repeat(64), "registration":"/var/lib/airlock/closure-store/host/registration",
                "registration_sha256":"a".repeat(64), "metadata_image":"/var/lib/airlock/closure-store/host/metadata.erofs",
                "metadata_image_sha256":"b".repeat(64), "blob_map":"/var/lib/airlock/closure-store/host/map.json",
                "blob_map_sha256":"c".repeat(64)}
        });
        for version in [1, 2] {
            let backend = &declaration("usr-home", version)["backend"];
            data["generations"][format!("usr-home:{version}")] = json!({
                "schema": "airlock.closure-store.generation-info.v1", "status": "passed", "domain": "usr-home-runtime-store", "generation": version,
                "manifest": format!("/var/lib/airlock/pool/usr-home/{version}/manifest.json"),
                "system": backend["system"]["source"], "root_source": backend["root"]["source"],
                "closure_source": backend["store"]["source"], "kernel_name": "qubes-kernel", "root_artifact": artifact(),
                "store": {"mode": "shared-closure", "device": "/dev/xvde", "blob_device": "/dev/xvdf",
                    "mountpoint": "/nix/store", "view_backend": "erofs-objectmap", "closure_hash": "d".repeat(64)},
                "approval": {"transport": "qrexec", "approved_by": "sys-ctrl", "source": backend["store"]["source"]},
                "provenance": {"source_revision": if version == 1 { revision() } else { "e".repeat(40) }, "lock_hash": lock_hash()},
                "verification": {"status": "passed"}, "retention": {"retain": true}
            });
        }
        let mut machine = Self {
            temporary,
            data,
            baseline: String::new(),
            candidate: String::new(),
            boot: false,
        };
        machine.persist()?;
        machine.baseline = machine.release("baseline", 1)?;
        machine.candidate = machine.release("candidates/new", 2)?;
        Ok(machine)
    }

    /// Locate a fixture file using a path relative to its private root.
    pub fn path(&self, name: &str) -> PathBuf {
        self.temporary.path().join(name)
    }

    /// Translate only the namespace-owned Airlock prefix into its host mount source.
    pub fn physical(&self, virtual_path: &str) -> PathBuf {
        self.path(
            virtual_path
                .strip_prefix("/var/lib/airlock/")
                .expect("fixture Airlock path"),
        )
    }

    /// Persist the supplied upstream state before a native invocation reads it.
    pub fn persist(&self) -> Result<()> {
        save(self.path("data.json"), &self.data)
    }

    /// Reload mutations made by Qubes command peers before changing another fixture field.
    pub fn reload(&mut self) -> Result<()> {
        self.data = read(self.path("data.json"))?;
        Ok(())
    }

    /// Create a complete immutable release directory with consistent staged generation and root identities.
    pub fn release(&self, relative: &str, version: u64) -> Result<String> {
        let manifest = json!({
            "schema": "airlock.machine-release.v1", "profile": "usb-lab", "host": HOST, "setup": SETUP,
            "revision": if version == 1 { revision() } else { "e".repeat(40) }, "lockHash": lock_hash(),
            "guestTransport": "direct-pool-v1", "stagedGenerations": {"usr-home": version},
            "guestRootArtifacts": {"usr-home": artifact()}, "sourceRelease": HOST, "hostPool": self.data["host_pool"],
            "retireDomains": [], "trashRetentionDays": 30
        });
        let topology = json!({"schema": "airlock.qubes-topology.v1", "kernels": {}, "prefs": {},
            "domains": {"usr-home": declaration("usr-home", version)}});
        let directory = self.path("machine").join(relative);
        for (name, value) in [
            ("release.json", &manifest),
            ("topology.json", &topology),
            ("staged.json", &manifest["stagedGenerations"]),
            ("root-artifacts.json", &manifest["guestRootArtifacts"]),
        ] {
            save(directory.join(name), value)?;
        }
        Ok(format!("/var/lib/airlock/machine/{relative}"))
    }

    /// Isolate every mutable system path; real host binaries retain their own immutable dependencies.
    pub fn command(&self, arguments: &[&str]) -> Result<Command> {
        self.program(
            &common::binary("AIRLOCK_DOM0_BIN", "airlock-dom0-service"),
            arguments,
        )
    }

    /// Select an explicit in-namespace driver when one scenario must coordinate concurrent native commands.
    pub fn program(&self, executable: &Path, arguments: &[&str]) -> Result<Command> {
        let mut command = Command::new(common::tool("bwrap")?);
        command.args([
            "--die-with-parent",
            "--unshare-user",
            "--uid",
            "0",
            "--gid",
            "0",
            "--ro-bind",
            "/",
            "/",
            "--tmpfs",
            "/nix",
        ]);
        if store_overlay() {
            command
                .args(["--overlay-src", "/nix/store", "--overlay-src"])
                .arg(self.path("view"))
                .args(["--ro-overlay", "/nix/store"]);
        } else {
            command
                .arg("--ro-bind")
                .arg(self.path("view"))
                .arg("/nix/store");
        }
        command
            .args(["--dir", "/nix/var/nix", "--bind"])
            .arg(self.path("profiles"))
            .arg("/nix/var/nix/profiles")
            .arg("--ro-bind")
            .arg(self.path("host"))
            .arg(HOST)
            .args(["--tmpfs", "/etc", "--ro-bind"])
            .arg(self.path("etc"))
            .arg("/etc/airlock")
            .args(["--tmpfs", "/var"]);
        if Path::new("/nix/store").exists() {
            command.args(["--ro-bind", "/nix/store", "/var/reference-store"]);
        }
        command
            .args(["--dir", "/var/lib", "--bind"])
            .arg(self.temporary.path())
            .arg("/var/lib/airlock")
            .arg("--bind")
            .arg(self.path("runtime"))
            .arg("/run")
            .args([
                "--symlink",
                "/run",
                "/var/run",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--setenv",
                "PATH",
                "/var/lib/airlock/bin",
                "--setenv",
                "TMPDIR",
                "/var/lib/airlock/tmp",
            ])
            .env(
                "AIRLOCK_DOM0_SERVICE",
                format!("{HOST}/sw/bin/airlock-dom0-service"),
            )
            .env(
                "AIRLOCK_FIXTURE_DOM0_BINARY",
                common::binary("AIRLOCK_DOM0_BIN", "airlock-dom0-service"),
            )
            .env("AIRLOCK_LOG_DIR", "/var/lib/airlock/log")
            .env("AIRLOCK_STARTUP_STATE_DIR", "/var/lib/airlock/startup")
            .env("AIRLOCK_TEST_MACHINE_ROOT", "/var/lib/airlock");
        for key in ["NIX_LD", "NIX_LD_LIBRARY_PATH"] {
            if let Some(value) = std::env::var_os(key) {
                let paths = std::env::split_paths(&value)
                    .map(fs::canonicalize)
                    .collect::<std::io::Result<Vec<_>>>()?;
                command.env(key, std::env::join_paths(paths)?);
            }
        }
        if self.boot {
            command
                .env("AIRLOCK_QUBES_XML", "/var/lib/airlock/qubes.xml")
                .env(
                    "AIRLOCK_QUBES_POLICY_DIR",
                    "/var/lib/airlock/qubes-policy.d",
                );
        }
        let pci = self.path("sys-pci");
        if pci.is_dir() {
            command
                .arg("--ro-bind")
                .arg(pci)
                .arg("/sys/bus/pci/devices");
        }
        command.arg(executable).args(arguments);
        Ok(command)
    }

    /// Decode exactly one final JSON reply, including expected failures with machine-readable errors.
    pub fn run(&self, arguments: &[&str], request: Option<Value>, success: bool) -> Result<Value> {
        let output = common::run(
            &mut self.command(arguments)?,
            request
                .map(|value| {
                    let mut frame = serde_json::to_vec(&value)?;
                    frame.push(b'\n');
                    Ok::<_, serde_json::Error>(frame)
                })
                .transpose()?,
        )?;
        assert_eq!(
            output.status.success(),
            success,
            "{stdout}; {stderr}",
            stdout = String::from_utf8_lossy(&output.stdout),
            stderr = String::from_utf8_lossy(&output.stderr)
        );
        Ok(serde_json::from_slice(&output.stdout)?)
    }

    /// Begin a source review against the installed baseline using the actual protected review store.
    pub fn context(&self, family: &str, target: Option<&str>) -> Result<Value> {
        self.run(
            &["review-control"],
            Some(json!({"op": "context", "revision": "e".repeat(40),
            "lock_hash": lock_hash(), "family": family, "target": target})),
            true,
        )
    }

    /// Apply a human approval to the context's source and explicit scope.
    pub fn decide(&self, context: &Value, scope: Option<Value>) -> Result<Value> {
        self.run(
            &["review-control"],
            Some(json!({"op": "decide", "request_id": context["request_id"],
            "decision": "approve", "scope": scope.unwrap_or_else(|| context["scope"].clone()),
            "review_fingerprint": "f".repeat(64)})),
            true,
        )
    }

    /// Approve and bind a candidate without granting any additional runtime authority to the fixture.
    pub fn approve(&self, scope: Option<Value>) -> Result<String> {
        let context = self.context("machine", None)?;
        assert_eq!(self.decide(&context, scope)?["status"], "approved");
        let identity = context["request_id"].as_str().unwrap();
        self.run(&["review-bind", identity, &self.candidate], None, true)?;
        Ok(identity.to_owned())
    }

    /// Read exact helper argument arrays to distinguish activation from read-only validation.
    pub fn calls(&self) -> Result<Vec<Value>> {
        let path = self.path("calls.jsonl");
        if !path.exists() {
            return Ok(Vec::new());
        }
        fs::read_to_string(path)?
            .lines()
            .map(|line| Ok(serde_json::from_str(line)?))
            .collect()
    }

    /// Construct a bound pool admission receipt from the upstream generation under inspection.
    pub fn receipt(&self) -> Value {
        let info = &self.data["generations"]["usr-home:2"];
        let mut receipt = json!({"schema": "airlock.closure-store.admission.v1", "status": "passed",
            "transport": "qrexec", "activated": false, "retained": true, "current_generation":1, "source_revision": "e".repeat(40),
            "lock_hash": lock_hash(), "closure_hash": info["store"]["closure_hash"]});
        for key in [
            "domain",
            "generation",
            "manifest",
            "system",
            "root_source",
            "root_artifact",
            "kernel_name",
        ] {
            receipt[key] = info[key].clone();
        }
        receipt["domain"] = json!("usr-home");
        receipt
    }

    /// Supply actual XML disk identities so boot-cache validation exercises the production parser.
    pub fn configure_boot(&mut self, foreign_alias: bool) -> Result<()> {
        let baseline = self.physical(&self.baseline);
        let mut topology = read(baseline.join("topology.json"))?;
        topology["domains"]["sys-gui"] = declaration("sys-gui", 1);
        save(self.path("etc/qubes-topology.json"), &topology)?;
        save(baseline.join("topology.json"), &topology)?;
        self.data["running"]
            .as_array_mut()
            .unwrap()
            .push(json!("sys-gui"));
        for name in topology["domains"].as_object().unwrap().keys() {
            self.data["selected"][name] = json!(1);
            if name == "usr-home" {
                continue;
            }
            let mut info = self.data["generations"]["usr-home:1"].clone();
            info["domain"] = json!(format!("{name}-runtime-store"));
            info["system"] = json!(store(&format!("{name}-system"), 1));
            info["root_source"] = json!(format!(
                "{source}/root.img",
                source = store(&format!("{name}-root"), 1)
            ));
            info["closure_source"] = json!(store(&format!("{name}-closure"), 1));
            info["approval"]["source"] = info["closure_source"].clone();
            self.data["generations"][format!("{name}:1")] = info;
        }
        self.persist()?;
        let mut xml = String::from(
            r#"<qubes><labels/><pools>
<pool name="file" driver="file" dir_path="/var/lib/airlock"/>
<pool name="closure" driver="airlock-closure" root_dir="/var/lib/airlock/pool"/>
</pools><properties/><domains>
<domain id="domain-0" class="AdminVM"><properties><property name="label">black</property></properties></domain>"#,
        );
        for name in topology["domains"].as_object().unwrap().keys() {
            xml.push_str(&format!(
                r#"<domain><properties><property name="name">{name}</property></properties>
<features/><tags/><volume-config>"#
            ));
            for kind in ["root", "private"] {
                let path = self.path(&format!("{name}-{kind}.img"));
                if !path.exists() {
                    fs::write(path, b"original data")?;
                }
                xml.push_str(&format!(
                    r#"<volume name="{kind}" pool="file" vid="{name}-{kind}" size="13"/>"#
                ));
            }
            for kind in ["store", "store-data"] {
                fs::write(self.path(&format!("{name}-{kind}")), b"immutable data")?;
                xml.push_str(&format!(r#"<volume name="{kind}" pool="closure" vid="{name}-{kind}" view_path="/var/lib/airlock/{name}-{kind}"/>"#));
            }
            if foreign_alias && name == "usr-home" {
                xml.push_str(r#"<volume name="alias" pool="file" vid="unrelated" source="sys-gui-private"/>"#);
            }
            xml.push_str("</volume-config></domain>");
        }
        xml.push_str("</domains></qubes>");
        fs::write(self.path("qubes.xml"), xml)?;
        fs::create_dir_all(self.path("qubes-policy.d"))?;
        fs::write(
            self.path("qubes-policy.d/90-airlock.policy"),
            "# applied policy\n",
        )?;
        self.boot = true;
        Ok(())
    }

    /// Replace one VM with another while retaining a private-volume copy and explicit retirement intent.
    pub fn replacement(&mut self) -> Result<Value> {
        let path = self.physical(&self.candidate);
        let mut topology = read(path.join("topology.json"))?;
        topology["domains"] = json!({"usr-new": declaration("usr-new", 2)});
        save(path.join("topology.json"), &topology)?;
        let mut manifest = read(path.join("release.json"))?;
        manifest["stagedGenerations"] = json!({"usr-new": 2});
        manifest["guestRootArtifacts"] = json!({"usr-new": artifact()});
        manifest["retireDomains"] = json!(["usr-home"]);
        manifest["privateVolumeCopies"] = json!({"usr-new": "usr-home"});
        save(path.join("release.json"), &manifest)?;
        save(path.join("staged.json"), &manifest["stagedGenerations"])?;
        let backend = &topology["domains"]["usr-new"]["backend"];
        let mut info = self.data["generations"]["usr-home:2"].clone();
        for (field, source) in [
            ("system", "system"),
            ("root_source", "root"),
            ("closure_source", "store"),
        ] {
            info[field] = backend[source]["source"].clone();
        }
        info["domain"] = json!("usr-new-runtime-store");
        info["manifest"] = json!("/var/lib/airlock/pool/usr-new/2/manifest.json");
        info["approval"]["source"] = info["closure_source"].clone();
        self.data["generations"]["usr-new:2"] = info;
        self.persist()?;
        fs::create_dir_all(self.path("qubes-policy.d"))?;
        fs::write(
            self.path("qubes-policy.d/05-airlock-retired.policy"),
            "* * @tag:airlock-retired @anyvm deny\n",
        )?;
        Ok(topology)
    }
}

/// A disposable qubesd volume interface; the production client still sends actual Qubes wire requests.
pub struct Volumes {
    // Signals the accept loop to finish after all native requests complete.
    stop: Arc<AtomicBool>,
    // Joins socket handling and propagates invalid requests to the owning Rust scenario.
    worker: Option<JoinHandle<Result<()>>>,
}

impl Volumes {
    /// Serve only the upstream volume methods used by copy and retirement scenarios.
    pub fn new(machine: &Machine) -> Result<Self> {
        let listener = UnixListener::bind(machine.path("runtime/qubesd.sock"))?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let root = machine.temporary.path().to_owned();
        let worker = std::thread::spawn(move || -> Result<()> {
            while !stopping.load(Ordering::Acquire) {
                let (mut peer, _) = match listener.accept() {
                    Ok(peer) => peer,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                peer.set_read_timeout(Some(Duration::from_secs(2)))?;
                let mut wire = Vec::new();
                peer.read_to_end(&mut wire)?;
                let boundary = wire
                    .iter()
                    .position(|byte| *byte == 0)
                    .context("Qubes request framing")?;
                let header = std::str::from_utf8(&wire[..boundary])?
                    .split_whitespace()
                    .collect::<Vec<_>>();
                ensure!(header.len() == 4, "invalid Qubes header");
                let (method, volume) = header[0].split_once('+').context("Qubes volume method")?;
                let domain = header[3];
                let mut data = read(root.join("data.json"))?;
                let reply = match method {
                    "admin.vm.List" => {
                        let names = data["selected"]
                            .as_object()
                            .unwrap()
                            .keys()
                            .cloned()
                            .chain(
                                data["pci_assigned"]
                                    .as_object()
                                    .into_iter()
                                    .flat_map(|m| m.keys().cloned()),
                            )
                            .chain(["dom0".to_owned()])
                            .collect::<std::collections::BTreeSet<_>>();
                        names
                            .into_iter()
                            .map(|name| format!("{name} class=AppVM\n"))
                            .collect()
                    }
                    "admin.vm.device.pci.Available" => data["pci_available"]
                        .as_str()
                        .context("missing fake PCI inventory")?
                        .into(),
                    "admin.vm.device.pci.Assigned" => {
                        data["pci_assigned"][domain].as_str().unwrap_or("").into()
                    }
                    "admin.vm.device.pci.Attached" => String::new(),
                    "admin.vm.device.pci.Assign" => {
                        let payload = std::str::from_utf8(&wire[boundary + 1..])?;
                        if data["pci_assigned"].is_null() {
                            data["pci_assigned"] = json!({});
                        }
                        data["pci_assigned"][domain] = json!(format!("{volume} {payload}"));
                        data["pci_assign_count"] =
                            json!(data["pci_assign_count"].as_u64().unwrap_or(0) + 1);
                        save(root.join("data.json"), &data)?;
                        String::new()
                    }
                    "admin.vm.device.pci.Unassign" => {
                        ensure!(
                            data["pci_assigned"][domain]
                                .as_str()
                                .is_some_and(|s| s.starts_with(&format!("{volume} "))),
                            "unexpected PCI unassignment"
                        );
                        data["pci_assigned"].as_object_mut().unwrap().remove(domain);
                        data["pci_unassign_count"] =
                            json!(data["pci_unassign_count"].as_u64().unwrap_or(0) + 1);
                        save(root.join("data.json"), &data)?;
                        String::new()
                    }
                    "admin.vm.volume.List" => "root\nprivate\nstore\nstore-data\n".to_owned(),
                    "admin.vm.volume.Info" => {
                        let source = if data["alias"] == json!([domain, volume]) {
                            "usr-home-private"
                        } else {
                            ""
                        };
                        format!(
                            "pool=file\nvid={domain}-{volume}\nsource={source}\nrw=True\nsave_on_stop=True\nsnap_on_start=False\nsize=4096"
                        )
                    }
                    "admin.vm.volume.CloneFrom" => {
                        data["clone_from_count"] =
                            json!(data["clone_from_count"].as_u64().unwrap_or(0) + 1);
                        save(root.join("data.json"), &data)?;
                        "private-clone-token".to_owned()
                    }
                    "admin.vm.volume.CloneTo" => {
                        ensure!(
                            &wire[boundary + 1..] == b"private-clone-token",
                            "clone token changed"
                        );
                        data["clone_count"] = json!(data["clone_count"].as_u64().unwrap_or(0) + 1);
                        fs::write(root.join("private-data"), "copied original")?;
                        save(root.join("data.json"), &data)?;
                        String::new()
                    }
                    _ => anyhow::bail!("unexpected Qubes volume method {method}"),
                };
                // The external clone can succeed before its reply is lost to the coordinator.
                if method == "admin.vm.volume.CloneTo" && data["clone_reply_lost"] == true {
                    continue;
                }
                if method == "admin.vm.device.pci.Assign" && data["pci_reply_lost"] == true {
                    continue;
                }
                peer.write_all(b"0\0")?;
                peer.write_all(reply.as_bytes())?;
            }
            Ok(())
        });
        Ok(Self {
            stop,
            worker: Some(worker),
        })
    }
}

impl Drop for Volumes {
    /// Release the socket loop even if a native command or assertion fails.
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let result = worker.join().expect("volume server panicked");
            if !std::thread::panicking() {
                result.expect("volume server failed");
            }
        }
    }
}
