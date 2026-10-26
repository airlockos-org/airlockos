//! Reuse applied Qubes configuration without treating a cache receipt as authority.
//! Boot still checks saved storage identities and each started guest's readiness.

use super::*;
use airlock_deployment_core::boot::{DomainState, Handoff, Reuse};
use airlock_machine_core::boot::BootInputs;
use airlock_nix_core::identity::LockHash;
use serde::{Deserialize, Serialize};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

/// Bound simultaneous guest boots to avoid exhausting memory during startup.
const BOOT_START_CONCURRENCY: usize = 2;

/// Start the ordinary assistant alongside home only when its headless providers are already ready.
fn parallel_assistant(topology: &Topology, foreground: &[GuestName]) -> Result<Option<GuestName>> {
    let home: GuestName = "usr-home".parse()?;
    let assistant: GuestName = "usr-assistant".parse()?;
    let Some(home_position) = foreground.iter().position(|name| *name == home) else {
        return Ok(None);
    };
    let Some(domain) = topology.domains.get(&assistant) else {
        return Ok(None);
    };
    if foreground.contains(&assistant)
        || domain.prefs.get("autostart") != Some(&Value::Bool(true))
        || domain.features.get("airlock-role") != Some(&json!("usr-assistant"))
    {
        return Ok(None);
    }

    let dependencies = planning::dependencies(topology, true)?;
    let available = foreground[..home_position]
        .iter()
        .filter(|name| name.as_str() != "sys-gui")
        .cloned()
        .collect::<BTreeSet<_>>();
    Ok(dependencies
        .get(&assistant)
        .is_none_or(|parents| parents.is_subset(&available))
        .then_some(assistant))
}

/// Name the systemd-owned readiness helper; the validated guest name needs no instance escaping.
fn guest_unit(name: &GuestName) -> String {
    format!("airlock-boot-guest@{name}.service")
}

/// Group independent starts while preserving every declared provider relationship.
fn start_batches(
    starts: &[GuestName],
    running: &BTreeSet<GuestName>,
    dependencies: &BTreeMap<GuestName, BTreeSet<GuestName>>,
) -> Result<Vec<Vec<GuestName>>> {
    let mut pending = starts
        .iter()
        .filter(|name| !running.contains(*name))
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut batches = Vec::new();
    while !pending.is_empty() {
        let batch = starts
            .iter()
            .filter(|name| {
                pending.contains(*name)
                    && dependencies
                        .get(*name)
                        .is_none_or(|parents| parents.is_disjoint(&pending))
            })
            .take(BOOT_START_CONCURRENCY)
            .cloned()
            .collect::<Vec<_>>();
        ensure!(!batch.is_empty(), "autostart VM dependency cycle");
        for name in &batch {
            pending.remove(name);
        }
        batches.push(batch);
    }
    Ok(batches)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ready network providers can precede two independent application boots in one batch.
    #[test]
    fn startup_batches_keep_dependencies_and_bound_concurrency() -> Result<()> {
        let net: GuestName = "sys-net".parse()?;
        let firewall: GuestName = "sys-firewall".parse()?;
        let assistant: GuestName = "usr-assistant".parse()?;
        let home: GuestName = "usr-home".parse()?;
        let controller: GuestName = "sys-ctrl".parse()?;
        let starts = vec![
            net.clone(),
            firewall.clone(),
            assistant.clone(),
            home.clone(),
            controller.clone(),
        ];
        let dependencies = BTreeMap::from([
            (firewall.clone(), BTreeSet::from([net.clone()])),
            (assistant.clone(), BTreeSet::from([firewall.clone()])),
            (home.clone(), BTreeSet::from([firewall.clone()])),
            (controller.clone(), BTreeSet::from([firewall.clone()])),
        ]);
        assert_eq!(
            start_batches(&starts, &BTreeSet::new(), &dependencies)?,
            vec![
                vec![net.clone()],
                vec![firewall.clone()],
                vec![assistant.clone(), home.clone()],
                vec![controller.clone()],
            ]
        );
        assert_eq!(
            start_batches(&starts, &BTreeSet::from([net, firewall]), &dependencies)?,
            vec![vec![assistant, home], vec![controller]]
        );
        Ok(())
    }

    /// A GUI link can wait for handoff; network and other service providers must precede home.
    #[test]
    fn assistant_overlap_preserves_declared_providers_and_autostart() -> Result<()> {
        let backend = json!({
            "type":"nix-closure",
            "system":{"source":"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-system"},
            "root":{"source":"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root/root.img"},
            "kernel":{"name":"qubes-kernel"},
            "store":{"source":"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-closure",
                "mode":"shared-closure", "device":"/dev/xvde", "blobDevice":"/dev/xvdf",
                "mountpoint":"/nix/store", "viewBackend":"erofs-objectmap"}
        });
        let mut raw = json!({"schema":"airlock.qubes-topology.v1", "domains":{}});
        for name in [
            "sys-net",
            "sys-firewall",
            "sys-gui",
            "usr-home",
            "usr-assistant",
            "sys-ctrl",
        ] {
            raw["domains"][name] = json!({"class":"StandaloneVM", "backend":backend,
                "netvm":null, "prefs":{"guivm":null}});
        }
        raw["domains"]["sys-firewall"]["netvm"] = json!("sys-net");
        raw["domains"]["usr-home"]["netvm"] = json!("sys-firewall");
        raw["domains"]["usr-home"]["features"] = json!({"airlock-boot-foreground":"1"});
        raw["domains"]["usr-assistant"]["netvm"] = json!("sys-firewall");
        raw["domains"]["usr-assistant"]["features"] = json!({"airlock-role":"usr-assistant"});
        raw["domains"]["usr-assistant"]["prefs"] = json!({"autostart":true,"guivm":"sys-gui"});

        let inputs = BootInputs::new(raw.clone())?;
        let foreground = airlock_machine_core::boot::foreground_guests(inputs.topology())?;
        assert_eq!(
            parallel_assistant(inputs.topology(), &foreground)?,
            Some("usr-assistant".parse()?)
        );

        let mut deferred_provider = raw.clone();
        deferred_provider["domains"]["usr-assistant"]["netvm"] = json!("sys-ctrl");
        let inputs = BootInputs::new(deferred_provider)?;
        assert_eq!(parallel_assistant(inputs.topology(), &foreground)?, None);

        raw["domains"]["usr-assistant"]["prefs"]["autostart"] = json!(false);
        let inputs = BootInputs::new(raw)?;
        assert_eq!(parallel_assistant(inputs.topology(), &foreground)?, None);
        Ok(())
    }
}

mod snapshot;

#[derive(Serialize, Deserialize)]
struct BootReceipt {
    // Version of the saved configuration optimization receipt.
    schema: String,
    // Hash of setup program, intended topology and selected storage generations.
    identity: LockHash,
    // Hash of shared Qubes configuration and policy.
    shared: LockHash,
    // Per-guest applied configuration and immutable artifact identities.
    domains: BTreeMap<GuestName, LockHash>,
}

struct BootSelection {
    // Setup program from the selected release or current image.
    setup: StoreFile,
    // Complete checked declaration, preserving omitted and explicitly reset settings.
    inputs: BootInputs,
    // Exact staged selections checked against committed generations; not deployment approval.
    handoff: Option<Handoff>,
    // Cache identity for this complete boot selection.
    identity: LockHash,
}

fn configured_path(key: &str, default: &str) -> Result<PathBuf> {
    let value = std::env::var(key).unwrap_or_else(|_| default.into());
    Ok(absolute(&value)?.to_owned())
}

fn runtime() -> Result<PathBuf> {
    configured_path("AIRLOCK_STARTUP_STATE_DIR", "/run/airlock/startup")
}

fn system() -> Result<PathBuf> {
    configured_path("AIRLOCK_SYSTEM_STATE_DIR", "/var/lib/airlock/system")
}

fn public_save(path: &Path, value: &Value) -> Result<()> {
    state::save(path, value)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

impl Coordinator {
    fn boot_selection(&self, setup: StoreFile, topology: &Path) -> Result<BootSelection> {
        if let Some(record) = state::optional::<Record>(&self.state.join("latest.json"))? {
            ensure!(
                record.phase.verified(),
                "interrupted deployment; resume or rollback in recovery"
            );
        }
        let selected = self.selection()?;
        let image_boot = selected.is_none();
        let (setup, raw, staged) = if let Some(selected) = selected {
            ensure!(
                selected.profile == state::profile()?,
                "selected deployment belongs to another boot profile"
            );
            let record = self.record(&selected.transaction)?;
            ensure!(
                record.phase.verified() && record.release == selected.release,
                "interrupted or inconsistent deployment selection"
            );
            let release = Release::load(selected.release.as_path())?;
            release.trust()?;
            self.check_recorded_release(&release, &record)?;
            ensure!(
                release.manifest.profile == selected.profile,
                "selected profile differs"
            );
            let staged = if release.manifest.staged_generations.is_empty() {
                None
            } else {
                let path = release.path.join("staged.json");
                ensure!(
                    state::read::<BTreeMap<GuestName, GenerationId>>(&path)?
                        == release.manifest.staged_generations,
                    "selected staged map missing or inconsistent"
                );
                Some(path)
            };
            (release.manifest.setup, release.raw_topology, staged)
        } else {
            (
                setup,
                state::configuration(topology)?,
                self.store().image_staged()?,
            )
        };
        let inputs = BootInputs::new(raw)?;
        let raw = inputs.raw().clone();
        let topology = inputs.topology().clone();
        let mut generations = staged
            .as_ref()
            .map(|path| state::read::<BTreeMap<GuestName, GenerationId>>(path))
            .transpose()?;
        if image_boot {
            let receipt_path = configured_path(
                "AIRLOCK_PREPARED_RUNTIME",
                "/var/lib/airlock/prepared-runtime.json",
            )?;
            let receipt = state::optional::<Value>(&receipt_path)?;
            ensure!(
                receipt.is_some() || !Path::new("/etc/airlock/usb-dev").exists(),
                "prepared USB runtime receipt is missing; use recovery"
            );
            if let Some(receipt) = receipt {
                ensure!(
                    matches!(
                        receipt["schema"].as_str(),
                        Some("airlock.prepared-runtime.v1" | "airlock.prepared-runtime.v2")
                    ),
                    "unsupported prepared runtime receipt"
                );
                // The image receipt is a selection hint, never a successful-validation token.
                // Initial images need not have a host-machine binding yet. All selected
                // generations are independently inspected and compared below.
                let prepared: BTreeMap<GuestName, GenerationId> =
                    if receipt["schema"] == "airlock.prepared-runtime.v2" {
                        ensure!(
                            receipt["boot_handoff"]["schema"] == "airlock.boot-handoff.v1"
                                && receipt["boot_handoff"]["status"] == "passed",
                            "invalid prepared boot handoff record"
                        );
                        serde_json::from_value(receipt["boot_handoff"]["generations"].clone())?
                    } else {
                        topology
                            .domains
                            .iter()
                            .filter(|(_, domain)| domain.backend.hermit().is_none())
                            .map(|(name, domain)| {
                                let descriptor: Value = state::read(
                                    &Path::new(domain.backend.nixos()?.store.source.as_str())
                                        .join("prepared.json"),
                                )?;
                                ensure!(
                                    descriptor["schema"] == "airlock.closure-store.prepared.v1"
                                        && descriptor["domain"]
                                            == crate::store::runtime_namespace(name.as_str()),
                                    "invalid legacy image descriptor: {name}"
                                );
                                let generation: GenerationId =
                                    serde_json::from_value(descriptor["generation"].clone())?;
                                Ok((name.clone(), generation))
                            })
                            .collect::<Result<_>>()?
                    };
                if let Some(mapping) = &generations {
                    ensure!(
                        prepared == *mapping,
                        "prepared runtime and boot generation map disagree"
                    );
                } else {
                    generations = Some(prepared);
                }
                let mapping = generations
                    .as_ref()
                    .context("prepared image boot generation map is missing")?;
                ensure!(
                    mapping.len() == topology.domains.len()
                        && topology
                            .domains
                            .keys()
                            .all(|name| mapping.contains_key(name)),
                    "prepared image boot generation map is incomplete or contains extra VMs"
                );
            }
        }
        let handoff = generations
            .as_ref()
            .map(|mapping| {
                crate::store::handoff::selected(&topology, mapping, |name, generation| {
                    self.store().describe(name, generation)
                })
            })
            .transpose()?;
        let identity =
            state::digest(&json!({"topology":raw,"setup":setup,"generations":generations}))?
                .parse()?;
        Ok(BootSelection {
            setup,
            inputs,
            handoff,
            identity,
        })
    }

    fn boot_receipt(&self) -> Result<Option<BootReceipt>> {
        let receipt: Option<BootReceipt> =
            state::optional(&self.state.join("boot-configuration.json"))?;
        if let Some(r) = &receipt {
            ensure!(
                r.schema == "airlock.applied-boot-configuration.v1",
                "unsupported applied boot configuration; use recovery"
            );
        }
        Ok(receipt)
    }

    fn boot_cached(&self, selection: &BootSelection, names: &[GuestName]) -> Result<bool> {
        let Some(receipt) = self.boot_receipt()? else {
            return Ok(false);
        };
        let known: Vec<_> = names
            .iter()
            .filter(|n| receipt.domains.contains_key(*n))
            .cloned()
            .collect();
        if known.len() != names.len() || receipt.identity != selection.identity {
            if !known.is_empty() {
                self.boot_snapshot(selection.inputs.topology(), &known)?;
            }
            return Ok(false);
        }
        let (shared, snapshots) = self.boot_snapshot(selection.inputs.topology(), names)?;
        let fresh = snapshots
            .iter()
            .map(|(name, fingerprint)| DomainState {
                domain: name.to_string(),
                fingerprint: fingerprint.to_string(),
            })
            .collect::<Vec<_>>();
        let saved = snapshots
            .keys()
            .map(|name| DomainState {
                domain: name.to_string(),
                fingerprint: receipt
                    .domains
                    .get(name)
                    .map(ToString::to_string)
                    .unwrap_or_default(),
            })
            .collect::<Vec<_>>();
        Ok(Reuse::check(
            selection.identity.to_string(),
            receipt.identity.as_str(),
            shared.as_str(),
            receipt.shared.as_str(),
            &fresh,
            &saved,
        )
        .is_some())
    }

    fn boot_record(&self, selection: &BootSelection, names: &[GuestName]) -> Result<()> {
        let (shared, mut domains) = self.boot_snapshot(selection.inputs.topology(), names)?;
        if let Some(previous) = self.boot_receipt()?
            && previous.identity == selection.identity
            && previous.shared == shared
        {
            for (n, v) in previous.domains {
                domains.entry(n).or_insert(v);
            }
        }
        state::save(
            &self.state.join("boot-configuration.json"),
            &BootReceipt {
                schema: "airlock.applied-boot-configuration.v1".into(),
                identity: selection.identity.clone(),
                shared,
                domains,
            },
        )
    }

    fn scoped_topology(&self, selection: &BootSelection, names: &[GuestName]) -> Result<Value> {
        let mut raw = selection.inputs.raw().clone();
        raw["domains"]
            .as_object_mut()
            .context("invalid topology domains")?
            .retain(|n, _| names.iter().any(|v| v.as_str() == n));
        if let Some(prefs) = raw.get_mut("prefs").and_then(Value::as_object_mut) {
            prefs.retain(|key, value| {
                ![
                    "clockvm",
                    "default_dispvm",
                    "default_netvm",
                    "default_guivm",
                    "default_audiovm",
                    "default_template",
                    "management_dispvm",
                    "updatevm",
                ]
                .contains(&key.as_str())
                    || value.as_str().is_none_or(|v| {
                        !selection
                            .inputs
                            .topology()
                            .domains
                            .keys()
                            .any(|n| n.as_str() == v)
                            || names.iter().any(|n| n.as_str() == v)
                    })
            });
        }
        let mut kernels = BTreeSet::new();
        let mut templates = BTreeSet::new();
        for name in names {
            let d = &selection.inputs.topology().domains[name];
            if let Ok(linux) = d.backend.nixos() {
                kernels.insert(linux.kernel.name.clone());
            }
            if let Some(k) = d.prefs.get("kernel").and_then(Value::as_str) {
                kernels.insert(k.into());
            }
            if let Some(t) = d.template.as_deref() {
                templates.insert(t.to_owned());
            }
        }
        if let Some(k) = selection
            .inputs
            .topology()
            .prefs
            .get("default_kernel")
            .and_then(Value::as_str)
        {
            kernels.insert(k.into());
        }
        if let Some(catalog) = raw.get_mut("kernels").and_then(Value::as_object_mut) {
            catalog.retain(|n, _| kernels.contains(n));
        }
        if let Some(catalog) = raw.get_mut("templates").and_then(Value::as_object_mut) {
            catalog.retain(|n, _| templates.contains(n));
        }
        Ok(raw)
    }

    /// Bind the process invocation to the published topology and checked selection together.
    /// A helper without the checked-setup protocol must refuse these arguments;
    /// silently retrying without the selection would change the admission policy.
    fn boot_setup_arguments(
        &self,
        selected: &BootSelection,
        raw: &Value,
        topology: &Path,
    ) -> Result<Vec<OsString>> {
        if let Some(handoff) = &selected.handoff {
            let record = topology.with_extension("selection.json");
            let digest = crate::setup_config::selection::BootSetup::save(handoff, raw, &record)?;
            return Ok(handoff
                .setup_arguments(
                    topology.to_str().context("topology path")?,
                    record.to_str().context("setup selection path")?,
                    digest.as_str(),
                )
                .into_iter()
                .map(OsString::from)
                .collect());
        }
        // Explicit legacy/manual boot with no staged selection retains its existing admission policy.
        Ok(vec!["--topology".into(), topology.as_os_str().to_owned()])
    }

    /// Configure the selected boot generation under one machine lock, optionally in GUI/background scopes.
    pub fn boot_setup(
        &self,
        setup: StoreFile,
        args: Vec<OsString>,
        gui: bool,
        background: bool,
    ) -> Result<Value> {
        let _guard = MachineLock::acquire(
            &self.state,
            "Machine startup",
            "Configure VMs from the selected boot generation",
            MachineOperation::Boot,
        )?;
        self.ensure_no_pruning()?;
        let selected = self.boot_selection(setup, Path::new("/etc/airlock/qubes-topology.json"))?;
        let mut env = Vec::new();
        if !gui && !background {
            let mut args = args;
            let path = runtime()?.join("topology.json");
            public_save(&path, selected.inputs.raw())?;
            args.extend(self.boot_setup_arguments(&selected, selected.inputs.raw(), &path)?);
            use crate::setup_config::report::{self, CompletedSetup, ExpectedSetup, Scope};
            let scope = if args.iter().any(|a| a == "--boot-critical") {
                Scope::BootCritical
            } else if args.iter().any(|a| a == "--deferred") {
                Scope::Deferred
            } else {
                Scope::All
            };
            let expected = ExpectedSetup::fresh(selected.inputs.raw())?.scoped(scope);
            env.push(("AIRLOCK_SETUP_RUN_ID".into(), expected.run().into()));
            let result_path =
                configured_path("AIRLOCK_LOG_DIR", "/var/log/airlock")?.join("setup-config.json");
            let protocol = self.runner.boot_setup_protocol(selected.setup.as_str())?;
            report::clear_result(&result_path)?;
            self.runner.run(
                selected.setup.as_str(),
                &args,
                Duration::from_secs(1800),
                &env,
            )?;
            // Prediction and explicit partial helpers do not publish a completion or cache entry.
            if args.iter().any(|a| a == "--apply")
                && !args.iter().any(|a| {
                    a == "--prepare-only" || a == "--backend-only" || a == "--devices-only"
                })
            {
                let complete = if protocol.covered() {
                    expected.complete(&result_path)?
                } else if protocol.bound() {
                    expected.complete_bound(&result_path)?
                } else {
                    CompletedSetup::legacy(&result_path)?
                };
                complete.require(&expected)?;
            }
            return state::read(&result_path);
        }
        ensure!(
            gui != background && args == [OsString::from("--apply")],
            "scoped boot setup accepts only --apply and one scope"
        );
        let started = Instant::now();
        let gui_names = airlock_machine_core::boot::foreground_guests(selected.inputs.topology())?;
        let assistant = parallel_assistant(selected.inputs.topology(), &gui_names)?;
        let mut configured = gui_names.clone();
        configured.extend(assistant.iter().cloned());
        let names = if gui {
            configured.clone()
        } else {
            planning::ordered(selected.inputs.topology())?
                .into_iter()
                .filter(|n| !configured.contains(n))
                .collect()
        };
        let runtime = runtime()?;
        let log = configured_path("AIRLOCK_LOG_DIR", "/var/log/airlock")?;
        let reused = self.boot_cached(&selected, &names)?;
        if gui {
            public_save(&runtime.join("topology.json"), selected.inputs.raw())?;
            for unit in [
                "qubes-db-dom0.service",
                "qubesd.service",
                "qubes-qrexec-policy-daemon.service",
            ] {
                self.runner
                    .text("systemctl", &["is-active", "--quiet", unit])?;
            }
            if reused && let Ok(device) = std::env::var("AIRLOCK_SETUP_CONFIG_STATUS_DEVICE") {
                let _ = fs::write(
                    device,
                    "\x1b[H\x1b[J\n  Airlock | Startup\n\n  Starting your desktop…\n",
                );
            }
        } else {
            ensure!(
                self.boot_cached(&selected, &configured)?,
                "GUI configuration changed after startup; repair in recovery"
            );
        }
        let mut result = json!({});
        if !reused {
            let path = runtime.join(if gui {
                "gui-topology.json"
            } else {
                "background-topology.json"
            });
            let scoped = self.scoped_topology(&selected, &names)?;
            public_save(&path, &scoped)?;
            let mut arguments = vec![OsString::from("--apply")];
            arguments.extend(self.boot_setup_arguments(&selected, &scoped, &path)?);
            env.push(("AIRLOCK_SETUP_CONFIG_PERSIST_STATE".into(), "0".into()));
            if !gui {
                env.push(("AIRLOCK_SETUP_CONFIG_STATUS_DEVICE".into(), "".into()));
                env.push((
                    "AIRLOCK_GUI_GPU_CHECK_TOPOLOGY".into(),
                    runtime.join("topology.json").into_os_string(),
                ));
            }
            let protocol = self.runner.boot_setup_protocol(selected.setup.as_str())?;
            let expected = crate::setup_config::report::ExpectedSetup::fresh(&scoped)?;
            env.push(("AIRLOCK_SETUP_RUN_ID".into(), expected.run().into()));
            let result_path = log.join("setup-config.json");
            crate::setup_config::report::clear_result(&result_path)?;
            self.runner.run(
                selected.setup.as_str(),
                &arguments,
                Duration::from_secs(1800),
                &env,
            )?;
            let complete = if protocol.covered() {
                expected.complete(&result_path)?
            } else if protocol.bound() {
                expected.complete_bound(&result_path)?
            } else {
                crate::setup_config::report::CompletedSetup::legacy(&result_path)?
            };
            complete.require(&expected)?;
            result = state::read(&result_path)?;
            self.boot_record(&selected, &names)?;
        }
        if gui {
            public_save(&runtime.join("gui-setup-result.json"), &result)?;
            // Qubes updates running clients when their GUI provider starts. Boot their
            // headless services now, keeping the physical startup screen visible until
            // the home VM and network path are ready for the guarded GPU handoff.
            for name in &gui_names {
                if name.as_str() != "sys-gui" {
                    if let Some(device) = std::env::var_os("AIRLOCK_SETUP_CONFIG_STATUS_DEVICE")
                        .filter(|path| !path.is_empty())
                    {
                        let _ = fs::write(
                            device,
                            format!(
                                "\x1b[H\x1b[J
  Airlock | Startup

  Starting and checking {name}…

  Your desktop will appear when home and network services are ready.
"
                            ),
                        );
                    }
                    if name.as_str() == "usr-home"
                        && let Some(assistant) = &assistant
                    {
                        // systemd owns both bounded helpers across the GPU handoff. Join only
                        // home here; background autostart joins the same assistant job later.
                        self.runner
                            .text("systemctl", &["start", "--no-block", &guest_unit(name)])?;
                        if let Err(error) = self.runner.text(
                            "systemctl",
                            &["start", "--no-block", &guest_unit(assistant)],
                        ) {
                            eprintln!("could not schedule early {assistant}: {error:#}");
                            crate::boot::guest_checkpoint(
                                assistant,
                                crate::boot::GuestState::Failed,
                                &format!("could not schedule startup: {error:#}"),
                            )?;
                        }
                        ensure!(
                            self.join_boot_guest(name)?,
                            "{name} startup was not scheduled"
                        );
                        continue;
                    }
                    self.runner.run(
                        "airlock-start-qube-ready",
                        &[
                            name.as_str().into(),
                            runtime.join("topology.json").into_os_string(),
                        ],
                        Duration::from_secs(airlock_machine_core::boot::GUEST_HELPER_SECONDS),
                        &[],
                    )?;
                }
            }
        } else {
            self.boot_record(
                &selected,
                &selected
                    .inputs
                    .topology()
                    .domains
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>(),
            )?;
            public_save(
                &system()?.join("current-topology.json"),
                selected.inputs.raw(),
            )?;
        }
        let report = json!({"schema":"airlock.boot-configuration-result.v1","status":"passed","scope":if gui { "gui" } else { "background" },"reused":reused,"domains":names,"elapsed_seconds":started.elapsed().as_secs_f64()});
        public_save(&log.join("boot-configuration.json"), &report)?;
        if background {
            let gui_result: Value = state::read(&runtime.join("gui-setup-result.json"))?;
            let mut combined = json!({"schema":"airlock.setup-config.v1","status":"passed","mode":"apply","scope":"all","reason":"GUI and background configuration are ready","boot_configuration":report,"unsupported_domains_count":0,"restart_required":false});
            for key in [
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
                combined[key] = json!(
                    gui_result[key]
                        .as_u64()
                        .unwrap_or(0)
                        .checked_add(result[key].as_u64().unwrap_or(0))
                        .context("setup count overflow")?
                );
            }
            public_save(&system()?.join("current-setup.json"), &combined)?;
        }
        Ok(report)
    }

    /// Join an existing readiness job without restarting failures or accepting an unstarted unit.
    fn join_boot_guest(&self, name: &GuestName) -> Result<bool> {
        let deadline =
            Instant::now() + Duration::from_secs(airlock_machine_core::boot::GUEST_HELPER_SECONDS);
        let unit = guest_unit(name);
        loop {
            let properties = self.runner.run(
                "systemctl",
                &[
                    "show".into(),
                    "--property=ActiveState".into(),
                    "--property=Job".into(),
                    unit.as_str().into(),
                ],
                Duration::from_secs(10),
                &[],
            )?;
            let state = properties
                .lines()
                .find_map(|line| line.strip_prefix("ActiveState="))
                .context("startup unit did not report ActiveState")?;
            let job = properties
                .lines()
                .find_map(|line| line.strip_prefix("Job="))
                .context("startup unit did not report Job")?;
            let queued = job.split_whitespace().next().is_some_and(|id| id != "0");
            match state {
                "active" => return Ok(true),
                "inactive" if !queued => return Ok(false),
                "activating" | "inactive" => {}
                state => bail!("{name} startup unit is {state}; inspect {unit}"),
            }
            ensure!(Instant::now() < deadline, "{name} startup unit timed out");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Observe the original selected boot inputs and keep machine mutation excluded until publication.
    /// The callback consumes opaque evidence while both machine and supervisor locks are held.
    pub(crate) fn accept_boot<T>(
        &self,
        boot: &str,
        scope: airlock_deployment_core::boot::acceptance::Scope,
        policy: &crate::boot::acceptance::Policy,
        publish: impl FnOnce(airlock_deployment_core::boot::acceptance::AcceptedBoot) -> Result<T>,
    ) -> Result<T> {
        let _guard = MachineLock::acquire(
            &self.state,
            "Boot acceptance",
            "Observe required guests before publishing startup success",
            MachineOperation::Boot,
        )?;
        let setup = if let Some(path) = std::env::var_os("AIRLOCK_BOOT_SETUP") {
            PathBuf::from(path)
        } else {
            fs::canonicalize("/run/current-system/sw/bin/airlock-setup-config")?
        };
        let setup = setup.to_str().context("setup path is not UTF-8")?.parse()?;
        let topology =
            configured_path("AIRLOCK_BOOT_TOPOLOGY", "/etc/airlock/qubes-topology.json")?;
        let selected = self.boot_selection(setup, &topology)?;
        let accepted =
            crate::boot::acceptance::observe(selected.inputs.topology(), policy, boot, scope)?;
        publish(accepted)
    }

    /// Start only declared autostart guests and dependencies, then verify their running generations.
    pub fn boot_start(&self, topology: &Path, required: &[GuestName]) -> Result<Value> {
        let mut guard = MachineLock::acquire(
            &self.state,
            "Machine startup",
            "Start the declared autostart VMs",
            MachineOperation::Boot,
        )?;
        let setup: StoreFile = fs::canonicalize("/run/current-system/sw/bin/airlock-setup-config")?
            .to_str()
            .context("invalid setup path")?
            .parse()?;
        let selected = self.boot_selection(setup, topology)?;
        self.enforce_trash(selected.inputs.topology())?;
        if selected
            .inputs
            .topology()
            .domains
            .keys()
            .any(|name| name.as_str() == "sys-gui")
        {
            let foreground =
                airlock_machine_core::boot::foreground_guests(selected.inputs.topology())?;
            if let Some(assistant) = parallel_assistant(selected.inputs.topology(), &foreground)? {
                self.join_boot_guest(&assistant)?;
            }
        }
        let running = self.running()?;
        ensure!(
            required
                .iter()
                .all(|n| selected.inputs.topology().domains.contains_key(n) && running.contains(n)),
            "guarded VMs are not declared and running"
        );
        let starts = planning::plan(
            selected.inputs.topology(),
            selected.inputs.topology(),
            &BTreeSet::new(),
            &[],
            false,
        )?
        .start;
        let batches = start_batches(
            &starts,
            &running,
            &planning::dependencies(selected.inputs.topology(), false)?,
        )?;
        let topology_path = runtime()?.join("autostart-topology.json");
        public_save(&topology_path, selected.inputs.raw())?;
        let executable = std::env::current_exe()?;
        let mut started = Vec::new();
        for batch in batches {
            let arguments = batch
                .iter()
                .map(|name| {
                    vec![
                        "start-qube-ready".into(),
                        name.as_str().into(),
                        topology_path.as_os_str().to_owned(),
                    ]
                })
                .collect::<Vec<_>>();
            let outputs = self.runner.boot_workers(
                &executable,
                &arguments,
                Duration::from_secs(airlock_machine_core::boot::GUEST_HELPER_SECONDS),
                &[],
            )?;
            for (name, output) in batch.into_iter().zip(outputs) {
                ensure!(
                    output.status.success() && !output.limited,
                    "{name} failed to become ready: {status}; {error}",
                    status = output.status,
                    error = String::from_utf8_lossy(&output.stderr),
                );
                started.push(name);
            }
        }
        let baseline = self.baseline()?;
        let observed =
            self.verify_topology(&baseline, &starts.iter().chain(required).cloned().collect())?;
        if self.selection()?.is_some() {
            self.verify_locked(&mut guard)?;
        }
        Ok(
            json!({"autostart":starts,"started":started,"observed":observed,"trash_active":self.trash()?.into_iter().filter(|r| r.status.is_active()).map(|r| r.id).collect::<Vec<_>>()}),
        )
    }
}
