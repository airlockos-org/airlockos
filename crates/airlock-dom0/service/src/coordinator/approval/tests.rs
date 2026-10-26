//! Exercise the production handoff with real durable files in an isolated dom0 namespace.
//! Child exits model crashes; injected post-write errors model uncertain publication.

use super::*;
use std::process::Command;

struct Fixture {
    // The creating process owns cleanup; reopened workers borrow its records.
    _directory: Option<tempfile::TempDir>,
    // Real coordinator using production journal and review persistence.
    coordinator: Coordinator,
    // Candidate whose exact contents are bound into the operation.
    release: Release,
    // Prior machine generation supplying the reviewed baseline.
    baseline: Release,
    // Protected approval request filename identity.
    request: airlock_nix_core::identity::ReviewId,
}

impl Fixture {
    /// Build a minimal reviewed candidate without invoking any VM or storage helper.
    fn new() -> Result<Self> {
        let directory = tempfile::tempdir_in("/var/lib/airlock")?;
        let coordinator = Coordinator::new(directory.path().to_owned());
        let host = state::host()?;
        let manifest = json!({
            "schema": "airlock.machine-release.v1", "profile": "test",
            "host": host, "setup": format!("{host}/bin/setup"),
            "revision": "a".repeat(40), "lockHash": "b".repeat(64),
            "retireDomains": [], "trashRetentionDays": 30,
        });
        let topology = json!({"schema": "airlock.qubes-topology.v1", "kernels": {}, "prefs": {}, "domains": {}});
        for name in ["candidates/new", "baseline"] {
            state::save(&directory.path().join(name).join("release.json"), &manifest)?;
            state::save(
                &directory.path().join(name).join("topology.json"),
                &topology,
            )?;
        }
        let release = Release::load(&directory.path().join("candidates/new"))?;
        let baseline = Release::load(&directory.path().join("baseline"))?;
        let fingerprint = state::digest(&json!({
            "selection": null, "boot_id": state::boot_id()?, "host": host,
            "revision": baseline.manifest.revision, "lock_hash": baseline.manifest.lock_hash,
        }))?;
        let approval: ApprovalRecord = serde_json::from_value(json!({
            "request_id": "c".repeat(64),
            "binding": {"revision": "a".repeat(40), "lock_hash": "b".repeat(64), "family": "machine", "target": null},
            "review_fingerprint": "d".repeat(64), "baseline_state": fingerprint,
            "scope": {"allowed_vms": ["usr-home"], "allow_reboot": true}, "status": "approved",
        }))?;
        let binding = ReleaseBinding {
            request_id: approval.request_id.clone(),
            release: ReleasePath::from_path(&release.path)?,
            revision: release.manifest.revision.clone(),
            lock_hash: release.manifest.lock_hash.clone(),
        };
        let key = format!(
            "{:x}",
            Sha256::digest(release.path.as_os_str().as_encoded_bytes())
        );
        state::save(
            &directory
                .path()
                .join("reviews/bindings")
                .join(format!("{key}.json")),
            &binding,
        )?;
        state::save(&coordinator.review_path(&approval.request_id), &approval)?;
        Ok(Self {
            _directory: Some(directory),
            coordinator,
            release,
            baseline,
            request: approval.request_id,
        })
    }

    /// Reopen files after a worker exits; no in-memory authorization survives.
    fn reopen(path: &Path) -> Result<Self> {
        Ok(Self {
            _directory: None,
            coordinator: Coordinator::new(path.to_owned()),
            release: Release::load(&path.join("candidates/new"))?,
            baseline: Release::load(&path.join("baseline"))?,
            request: "c".repeat(64).parse()?,
        })
    }

    /// Run the real authorization checks and construct the same preflight intent as activation.
    fn intent(
        &self,
        previous: Option<&Record>,
        id: &str,
    ) -> Result<(Record, AuthorizedDeployment)> {
        self.intent_plan(
            previous,
            id,
            Plan {
                configure: self.release.topology.domains.keys().cloned().collect(),
                ..Plan::default()
            },
        )
    }

    /// Bind a supplied planner result through the real checked operation constructor.
    fn intent_plan(
        &self,
        previous: Option<&Record>,
        id: &str,
        plan: Plan,
    ) -> Result<(Record, AuthorizedDeployment)> {
        let authorization =
            self.coordinator
                .authorize(&self.release, &self.baseline, &plan, previous, false)?;
        let id = TransactionId::try_from(id.to_owned())?;
        let authorization = if let Some(previous) = previous {
            authorization.recover(
                &id,
                self.coordinator
                    .recovery_decision(previous, ApplyMode::Resume)?,
            )?
        } else {
            authorization.operation(&id)?
        };
        let operation = authorization.record()?;
        let record = Record {
            id,
            boot_id: state::boot_id()?,
            release: ReleasePath::from_path(&self.release.path)?,
            previous: ReleasePath::from_path(&self.baseline.path)?,
            revision: self.release.manifest.revision.clone(),
            plan,
            phase: Phase::Preflight,
            observed: BTreeMap::new(),
            host_running: None,
            host_selected: None,
            verified_at: None,
            generation_verified_at: None,
            metadata: JournalMetadata {
                origin: JournalOrigin::Native(NativeJournal {
                    native_coordinator: NativeVersion::V2,
                    release_fingerprint: self.release.fingerprint().clone(),
                    previous_fingerprint: self.baseline.fingerprint().clone(),
                }),
                details: JournalDetails {
                    operation: Some(operation),
                    recovery_of: previous.map(|r| r.id.clone()),
                    ..JournalDetails::default()
                },
            },
        };
        Ok((record, authorization))
    }

    /// Read protected status independently of the current transaction journal.
    fn approval(&self) -> Result<ApprovalRecord> {
        state::read(&self.coordinator.review_path(&self.request))
    }
}

/// Run durable I/O in a private root namespace; production ownership checks stay enabled.
#[test]
#[ignore = "requires bubblewrap and make native-test-fixtures-build; CI prepares both"]
fn durable_handoff() -> Result<()> {
    if let Ok(path) = std::env::var("AIRLOCK_DURABLE_TEST_WORKER") {
        return crash_worker(Path::new(&path));
    }
    if std::env::var_os("AIRLOCK_DURABLE_TEST_NAMESPACE").is_some() {
        fs::create_dir_all("/etc/airlock")?;
        fs::write("/etc/airlock/review-required", b"v1")?;
        return scenarios();
    }
    let temporary = tempfile::tempdir()?;
    let peer = std::env::var_os("AIRLOCK_TEST_PEER_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::current_exe()
                .expect("test executable")
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("airlock-test-peer")
        });
    ensure!(
        peer.is_file(),
        "run make native-test-fixtures-build NATIVE_BUILD_PROFILE=dev before durable_handoff"
    );
    let store_view = tempfile::tempdir()?;
    let host = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-durable-test-host";
    fs::create_dir(
        store_view
            .path()
            .join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-durable-test-host"),
    )?;
    if Path::new("/nix/store").is_dir() {
        for entry in fs::read_dir("/nix/store")? {
            let name = entry?.file_name();
            std::os::unix::fs::symlink(
                Path::new("/var/reference-store").join(&name),
                store_view.path().join(name),
            )?;
        }
    }
    let mut command = Command::new("bwrap");
    command
        .args([
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
            "/var",
            "--dir",
            "/var/lib",
            "--bind",
        ])
        .arg(temporary.path())
        .arg("/var/lib/airlock")
        .args([
            "--tmpfs",
            "/etc",
            "--tmpfs",
            "/tmp",
            "--tmpfs",
            "/run",
            "--symlink",
            host,
            "/run/current-system",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
        ]);
    if Path::new("/nix/store").is_dir() {
        command.args(["--ro-bind", "/nix/store", "/var/reference-store"]);
    }
    let output = command
        .args(["--tmpfs", "/nix", "--ro-bind"])
        .arg(store_view.path())
        .arg("/nix/store")
        .arg(std::env::current_exe()?)
        .args([
            "--exact",
            "coordinator::approval::tests::durable_handoff",
            "--ignored",
            "--nocapture",
        ])
        .env("AIRLOCK_DURABLE_TEST_NAMESPACE", "1")
        .env("TMPDIR", "/tmp")
        .env("AIRLOCK_TEST_PEER_BIN", peer)
        .env(
            "AIRLOCK_TEST_REPLIES",
            "/var/lib/airlock/helpers/replies.json",
        )
        .env(
            "PATH",
            format!(
                "/var/lib/airlock/helpers:{path}",
                path = std::env::var("PATH")?
            ),
        )
        .output()?;
    ensure!(
        output.status.success(),
        "namespace tests failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

/// Include complete checked selections in the same journal writes exercised by crash injection.
fn pin_intent(
    fixture: &Fixture,
    record: &mut Record,
    previous: Option<&Record>,
    authorization: &AuthorizedDeployment,
) -> Result<airlock_deployment_core::storage::staging::persistence::PinnedGenerations> {
    if let JournalOrigin::Native(native) = &mut record.metadata.origin {
        native.native_coordinator = NativeVersion::V3;
    }
    fixture.coordinator.pin_images(
        &fixture.release,
        record,
        previous,
        authorization.storage_plan(),
    )
}

/// Exit at a requested real persistence boundary or return an uncertain write error.
fn crash_worker(path: &Path) -> Result<()> {
    let fixture = Fixture::reopen(path)?;
    let (mut record, authorization) = fixture.intent(None, "100")?;
    let pinned = pin_intent(&fixture, &mut record, None, &authorization)?;
    let boundary: usize = std::env::var("AIRLOCK_DURABLE_TEST_BOUNDARY")?.parse()?;
    let uncertain = std::env::var_os("AIRLOCK_DURABLE_TEST_UNCERTAIN").is_some();
    let mut writes = 0;
    let result =
        fixture
            .coordinator
            .publish_intent_with(&record, authorization, &mut |path, value| {
                if writes == boundary && !uncertain {
                    std::process::exit(86);
                }
                state::save(path, value)?;
                if writes == boundary && uncertain {
                    bail!("injected post-publication I/O error");
                }
                writes += 1;
                Ok(())
            });
    if uncertain {
        ensure!(
            result.is_err(),
            "uncertain publication must not yield execution authority"
        );
        return Ok(());
    }
    let mut durable = result?;
    durable.begin(&record)?;
    durable.activate_pinned(&record, pinned)?;
    if boundary == 3 {
        std::process::exit(86);
    }
    // An idempotent simulated external service records the requested target.
    // Its outcome exists independently of the coordinator's completion journal.
    state::save(
        &path.join("external.json"),
        &json!({"selected": record.release}),
    )?;
    std::process::exit(86);
}

/// Cover each distinct handoff boundary, ambiguity, repeated recovery and invalid authority.
fn scenarios() -> Result<()> {
    let publication = tempfile::tempdir_in("/var/lib/airlock")?;
    state::test_interrupted_publication(publication.path())?;
    legacy_gap()?;
    verified_adapter()?;
    effect_requests()?;
    configuration_requests()?;
    shutdown_requests()?;
    rollback_before_selection()?;
    for (boundary, uncertain) in [
        (0, false),
        (1, false),
        (2, false),
        (3, false),
        (4, false),
        (0, true),
        (1, true),
        (2, true),
    ] {
        let fixture = Fixture::new()?;
        let mut child = Command::new(std::env::current_exe()?);
        child
            .args([
                "--exact",
                "coordinator::approval::tests::durable_handoff",
                "--ignored",
                "--nocapture",
            ])
            .env("AIRLOCK_DURABLE_TEST_WORKER", &fixture.coordinator.state)
            .env("AIRLOCK_DURABLE_TEST_BOUNDARY", boundary.to_string());
        if uncertain {
            child.env("AIRLOCK_DURABLE_TEST_UNCERTAIN", "1");
        }
        let output = child.output()?;
        ensure!(
            output.status.code() == Some(if uncertain { 0 } else { 86 }),
            "worker failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let mut current = fixture.coordinator.current()?;
        assert_eq!(current.is_some(), boundary > 0 || uncertain);
        if current.is_none() {
            assert_eq!(fixture.approval()?.status, ApprovalStatus::Approved);
        }
        let mut operation = current
            .as_ref()
            .map(|r| r.metadata.details.operation.clone());
        for attempt in ["101", "102", "103"] {
            let (mut record, checked) = fixture.intent(current.as_ref(), attempt)?;
            let pinned = pin_intent(&fixture, &mut record, current.as_ref(), &checked)?;
            let mut durable = fixture.coordinator.publish_intent(&record, checked)?;
            durable.begin(&record)?;
            durable.activate_pinned(&record, pinned)?;
            let saved = fixture
                .coordinator
                .current()?
                .context("published intent missing")?;
            assert_eq!(saved.id, record.id);
            assert!(saved.metadata.details.guest_generations.is_some());
            if let Some(previous) = &current {
                assert_eq!(
                    serde_json::to_value(&saved.metadata.details.guest_generations)?,
                    serde_json::to_value(&previous.metadata.details.guest_generations)?
                );
            }
            if let Some(expected) = &operation {
                assert_eq!(&saved.metadata.details.operation, expected);
            }
            operation = Some(saved.metadata.details.operation.clone());
            assert_eq!(
                fixture.approval()?.deployment_operation.as_ref(),
                saved.metadata.details.operation.as_ref().map(|o| &o.id)
            );
            // Reconcile an uncertain external result before requesting it again.
            let external = fixture.coordinator.state.join("external.json");
            if let Some(observed) = state::optional::<Value>(&external)? {
                assert_eq!(observed["selected"], json!(record.release));
            } else {
                state::save(&external, &json!({"selected": record.release}))?;
            }
            record.phase = Phase::Failed;
            record.metadata.details.error = Some("external outcome requires reconciliation".into());
            durable.finish(false);
            assert!(durable.check(&record).is_err());
            fixture.coordinator.persist(&record)?;
            current = Some(record);
        }
        let mut complete = current.context("recovered record missing")?;
        complete.phase = Phase::Complete;
        fixture.coordinator.persist(&complete)?;
        assert_eq!(
            fixture.coordinator.current()?.unwrap().phase,
            Phase::Complete
        );
    }
    invalid_authority()?;
    damaged_records()?;
    recovery_compatibility()?;
    recovery_publication()?;
    Ok(())
}

/// Rollback before selection must still account for the attempted candidate's VMs.
fn rollback_before_selection() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let mut topology = lifecycle_topology(&fixture)?;
    topology
        .domains
        .retain(|name, _| name.as_str() == "usr-home");
    state::save(&fixture.release.path.join("topology.json"), &topology)?;
    fixture.release = Release::load(&fixture.release.path)?;
    let (record, checked) = fixture.intent(None, "100")?;
    fixture.coordinator.publish_intent(&record, checked)?;
    let decision = fixture
        .coordinator
        .recovery_decision(&record, ApplyMode::Rollback)?;
    let baseline = Release::load(Path::new(decision.releases().1.path()))?;
    let running = BTreeSet::from(["usr-home".parse()?]);
    let plan = fixture
        .coordinator
        .make_plan(&baseline, &fixture.baseline, &running, true)?;
    assert!(plan.stop.contains(&"usr-home".parse()?));
    Ok(())
}

/// Declare a small protected topology for lifecycle dependency and observation scenarios.
fn lifecycle_topology(fixture: &Fixture) -> Result<Topology> {
    let mut topology = fixture.release.raw_topology.clone();
    let host = fixture.release.manifest.host.as_str();
    let domain = json!({
        "class": "StandaloneVM", "netvm": null, "template": null,
        "backend": {
            "type": "nix-closure", "system": {"source": host},
            "root": {"source": format!("{host}/root.img")}, "kernel": {"name": "test"},
            "store": {"source": host, "mode": "shared-closure", "mountpoint": "/nix/store",
                "device": "/dev/xvde", "blobDevice": "/dev/xvdf", "viewBackend": "erofs-objectmap"},
        },
    });
    topology["domains"]["usr-home"] = domain.clone();
    topology["domains"]["sys-net"] = domain.clone();
    topology["domains"]["sys-gui"] = domain;
    Ok(serde_json::from_value(topology)?)
}

/// Exercise the complete production adapter with a bounded fake Qubes executable.
/// The fake records no VM effects; the real command journal records exact dispatch arguments.
fn effect_requests() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let mut topology = lifecycle_topology(&fixture)?;
    let home = topology.domains.get_mut(&"usr-home".parse()?).unwrap();
    home.netvm = VmReference::Named("sys-net".parse()?);
    home.prefs.insert("autostart".into(), json!(true));
    let dependency_plan = planning::plan(&topology, &topology, &BTreeSet::new(), &[], false)?;
    assert_eq!(
        dependency_plan
            .start
            .iter()
            .map(|n| n.as_str())
            .collect::<Vec<_>>(),
        ["sys-net", "usr-home"]
    );
    let mut changed = topology.clone();
    changed
        .domains
        .get_mut(&"sys-net".parse()?)
        .unwrap()
        .features
        .insert("test-change".into(), json!("1"));
    let dependent_stops = planning::plan(
        &topology,
        &changed,
        &BTreeSet::from(["usr-home".parse()?, "sys-net".parse()?]),
        &[],
        false,
    )?;
    assert_eq!(
        dependent_stops
            .stop
            .iter()
            .map(|n| n.as_str())
            .collect::<Vec<_>>(),
        ["usr-home", "sys-net"]
    );
    let provider_review = Fixture::new()?;
    let mut approval = serde_json::to_value(provider_review.approval()?)?;
    approval["scope"]["allowed_vms"] = json!(["sys-net"]);
    state::save(
        &provider_review
            .coordinator
            .review_path(&provider_review.request),
        &approval,
    )?;
    assert!(provider_review.coordinator.authorize(&provider_review.release, &provider_review.baseline,
        &dependent_stops, None, false).is_err_and(|error| matches!(
            error.downcast_ref::<airlock_nix_core::Error>(), Some(airlock_nix_core::Error::ScopeExceeded { names })
                if names.iter().any(|name| name.as_str() == "usr-home")
        )));
    assert!(
        fixture
            .coordinator
            .authorize(
                &fixture.release,
                &fixture.baseline,
                &dependency_plan,
                None,
                false,
            )
            .is_err()
    );
    // A preserved GUI client is an interruption effect, even when it never stops.
    let gui_review = Fixture::new()?;
    let mut gui_baseline = lifecycle_topology(&gui_review)?;
    let home = gui_baseline.domains.get_mut(&"usr-home".parse()?).unwrap();
    home.prefs.insert("guivm".into(), json!("sys-gui"));
    home.features
        .insert("airlock-gui-reconnect".into(), json!("1"));
    let mut gui_candidate = gui_baseline.clone();
    gui_candidate
        .domains
        .get_mut(&"sys-gui".parse()?)
        .unwrap()
        .features
        .insert("update".into(), json!("1"));
    let gui_plan = planning::plan(
        &gui_baseline,
        &gui_candidate,
        &BTreeSet::from(["sys-gui".parse()?, "usr-home".parse()?]),
        &[],
        false,
    )?;
    assert_eq!(
        gui_plan.gui_reconnect[&"sys-gui".parse()?],
        vec!["usr-home".parse::<GuestName>()?]
    );
    assert!(!gui_plan.stop.contains(&"usr-home".parse()?));
    let mut approval = serde_json::to_value(gui_review.approval()?)?;
    approval["scope"]["allowed_vms"] = json!(["sys-gui"]);
    state::save(
        &gui_review.coordinator.review_path(&gui_review.request),
        &approval,
    )?;
    assert!(gui_review.coordinator.authorize(&gui_review.release, &gui_review.baseline,
        &gui_plan, None, false).is_err_and(|error| matches!(
            error.downcast_ref::<airlock_nix_core::Error>(), Some(airlock_nix_core::Error::ScopeExceeded { names })
                if names.iter().any(|name| name.as_str() == "usr-home")
        )));

    // Carry a real planner result through publication, dispatch and recovery below.
    topology
        .domains
        .retain(|name, _| name.as_str() == "usr-home");
    topology
        .domains
        .get_mut(&"usr-home".parse()?)
        .unwrap()
        .netvm = VmReference::Disabled;
    let mut changed = topology.clone();
    changed
        .domains
        .get_mut(&"usr-home".parse()?)
        .unwrap()
        .features
        .insert("test-change".into(), json!("1"));
    let plan = planning::plan(
        &topology,
        &changed,
        &BTreeSet::from(["usr-home".parse()?]),
        &[],
        false,
    )?;
    state::save(&fixture.release.path.join("topology.json"), &changed)?;
    fixture.release = Release::load(&fixture.release.path)?;
    let (record, checked) = fixture.intent_plan(None, "200", plan)?;

    // The opaque operation cannot be published under a different ID or expanded plan.
    let mut substituted = record.clone();
    substituted.metadata.details.operation.as_mut().unwrap().id = "999".to_owned().try_into()?;
    let mut writes = 0;
    assert!(
        fixture
            .coordinator
            .publish_intent_with(&substituted, checked, &mut |_, _| {
                writes += 1;
                Ok(())
            })
            .is_err()
    );
    assert_eq!(writes, 0);
    let (_, checked) = fixture.intent_plan(None, "200", record.plan.clone())?;
    substituted = record.clone();
    substituted.plan.start.push("sys-net".parse()?);
    assert!(
        fixture
            .coordinator
            .publish_intent(&substituted, checked)
            .is_err()
    );
    assert!(fixture.coordinator.current()?.is_none());

    let (_, checked) = fixture.intent_plan(None, "200", record.plan.clone())?;
    let mut durable = fixture.coordinator.publish_intent(&record, checked)?;
    let target = "usr-home".parse()?;
    let no_dependents = ShutdownObservation::new("usr-home".into(), vec![]);
    assert!(durable.start(&record, &target).is_err());
    assert!(durable.shutdown(&record, &target, &no_dependents).is_err());
    durable.begin(&record)?;
    assert!(durable.start(&record, &"sys-net".parse()?).is_err());
    for field in [
        "id",
        "release",
        "previous",
        "revision",
        "release_fingerprint",
        "previous_fingerprint",
    ] {
        let mut raw = serde_json::to_value(&record)?;
        raw[field] = match field {
            "id" => json!("999"),
            "release" | "previous" => json!("/different/release"),
            "revision" => json!("e".repeat(40)),
            _ => json!("e".repeat(64)),
        };
        let changed: Record = serde_json::from_value(raw)?;
        assert!(
            durable.start(&changed, &target).is_err(),
            "accepted changed {field}"
        );
        assert!(
            durable.shutdown(&changed, &target, &no_dependents).is_err(),
            "shutdown accepted changed {field}"
        );
    }
    let mut changed = record.clone();
    changed.metadata.details.operation.as_mut().unwrap().id = "999".to_owned().try_into()?;
    assert!(durable.start(&changed, &target).is_err());
    assert!(durable.shutdown(&changed, &target, &no_dependents).is_err());
    changed.metadata.details.operation = None;
    assert!(durable.start(&changed, &target).is_err());
    assert!(durable.shutdown(&changed, &target, &no_dependents).is_err());
    changed = record.clone();
    changed
        .metadata
        .details
        .operation
        .as_mut()
        .unwrap()
        .authority = OperationAuthority::Administrative;
    assert!(durable.start(&changed, &target).is_err());
    assert!(durable.shutdown(&changed, &target, &no_dependents).is_err());

    let commands = fixture.coordinator.state.join("commands");
    fixture.coordinator.runner.record_to(commands.clone())?;
    for program in [
        "qvm-start",
        "/usr/bin/qvm-start",
        "qvm-shutdown",
        "/usr/bin/qvm-shutdown",
        "qvm-kill",
        "/usr/bin/qvm-kill",
        "qvm-create",
        "/usr/bin/qvm-create",
    ] {
        assert!(
            fixture
                .coordinator
                .runner
                .run(program, &["usr-home".into()], Duration::from_secs(1), &[])
                .is_err()
        );
        assert!(
            fixture
                .coordinator
                .runner
                .capture(program, &["usr-home".into()], Duration::from_secs(1), &[])
                .is_err()
        );
        assert!(
            fixture
                .coordinator
                .runner
                .stream(program, &["usr-home".into()], Duration::from_secs(1))
                .is_err()
        );
    }
    assert_eq!(fs::read_dir(&commands)?.count(), 0);

    // Reuse the repository's inert Rust command peer with literal argument matching.
    let helpers = Path::new("/var/lib/airlock/helpers");
    fs::create_dir_all(helpers)?;
    let helper = helpers.join("qvm-start");
    std::os::unix::fs::symlink(
        std::env::var_os("AIRLOCK_TEST_PEER_BIN").context("missing Rust command peer")?,
        &helper,
    )?;
    for exit in [0, 1] {
        state::save(
            &helpers.join("replies.json"),
            &json!({
                "commands": {"qvm-start": [{"args": ["usr-home"], "exit": exit}]},
            }),
        )?;
        let result = fixture
            .coordinator
            .runner
            .start_deployment(durable.start(&record, &target)?);
        assert_eq!(result.is_ok(), exit == 0, "command peer: {result:?}");
    }
    for entry in fs::read_dir(&commands)? {
        let command: Value = state::read(&entry?.path())?;
        assert_eq!(command["program"], "qvm-start");
        assert_eq!(command["args"], json!(["usr-home"]));
    }
    durable.finish(false);
    assert!(durable.start(&record, &target).is_err());
    fs::remove_file(helper)?;

    // A fresh recovery gate keeps the operation, requires new publication, and rejects old attempts.
    let (retry, checked) = fixture.intent_plan(Some(&record), "201", record.plan.clone())?;
    let mut recovered = fixture.coordinator.publish_intent(&retry, checked)?;
    assert!(recovered.start(&retry, &target).is_err());
    recovered.begin(&retry)?;
    assert!(recovered.start(&record, &target).is_err());
    assert_eq!(recovered.start(&retry, &target)?.target(), "usr-home");
    recovered.finish(true);
    assert!(recovered.start(&retry, &target).is_err());
    Ok(())
}

/// Exercise real shutdown argument dispatch and GUI observation without touching live Qubes.
fn shutdown_requests() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut topology = lifecycle_topology(&fixture)?;
    let helpers = Path::new("/var/lib/airlock/helpers");
    let peer = std::env::var_os("AIRLOCK_TEST_PEER_BIN").context("missing Rust command peer")?;
    for program in ["qvm-shutdown", "qvm-ls", "qvm-prefs"] {
        match fs::symlink_metadata(helpers.join(program)) {
            Ok(_) => fs::remove_file(helpers.join(program))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        std::os::unix::fs::symlink(&peer, helpers.join(program))?;
    }
    let mut replies = json!({"commands": {
        "qvm-ls": [{"args": ["--raw-data", "--fields", "NAME,STATE"],
            "stdout": "usr-home|Running\n"}],
        "qvm-shutdown": [{"args": ["--wait", "--timeout", "120", "usr-home"]}],
        "qvm-prefs": [{"args": ["usr-home", "guivm"], "stdout": "sys-gui\n"}],
    }});
    state::save(&helpers.join("replies.json"), &replies)?;
    let normal = Plan {
        stop: vec!["usr-home".parse()?],
        ..Plan::default()
    };
    let (mut record, checked) = fixture.intent_plan(None, "300", normal)?;
    let mut durable = fixture.coordinator.publish_intent(&record, checked)?;
    durable.begin(&record)?;
    record.phase = Phase::Stopping;
    fixture
        .coordinator
        .runner
        .record_to(fixture.coordinator.state.join("commands"))?;
    let target = "usr-home".parse()?;
    let observation = fixture
        .coordinator
        .shutdown_observation(&topology, &target)?;
    let request = durable.shutdown(&record, &target, &observation)?;
    assert!(!request.forced());
    fixture.coordinator.runner.shutdown_deployment(request)?;
    durable.finish(true);
    assert!(durable.shutdown(&record, &target, &observation).is_err());

    // Review scope must include GUI clients even when start/affected lists omit them.
    let fixture = Fixture::new()?;
    let mut approval = serde_json::to_value(fixture.approval()?)?;
    approval["scope"]["allowed_vms"] = json!(["sys-gui"]);
    state::save(
        &fixture.coordinator.review_path(&fixture.request),
        &approval,
    )?;
    let gui_plan = Plan {
        stop: vec!["sys-gui".parse()?],
        gui_reconnect: BTreeMap::from([("sys-gui".parse()?, vec!["usr-home".parse()?])]),
        ..Plan::default()
    };
    assert!(fixture.intent_plan(None, "310", gui_plan.clone()).is_err_and(|error| matches!(
        error.downcast_ref::<airlock_nix_core::Error>(), Some(airlock_nix_core::Error::ScopeExceeded { names })
            if names.iter().any(|name| name.as_str() == "usr-home")
    )));
    // Simulate a human decision covering both effects; authorization never widens it itself.
    approval["scope"]["allowed_vms"] = json!(["sys-gui", "usr-home"]);
    state::save(
        &fixture.coordinator.review_path(&fixture.request),
        &approval,
    )?;
    let (record, checked) = fixture.intent_plan(None, "310", gui_plan)?;
    let mut durable = fixture.coordinator.publish_intent(&record, checked)?;
    durable.begin(&record)?;
    let commands = fixture.coordinator.state.join("commands");
    fixture.coordinator.runner.record_to(commands.clone())?;
    replies["commands"]["qvm-ls"][0]["stdout"] = json!("sys-gui|Running\nusr-home|Running\n");
    replies["commands"]["qvm-shutdown"][0]["args"] =
        json!(["--force", "--wait", "--timeout", "120", "sys-gui"]);
    state::save(&helpers.join("replies.json"), &replies)?;
    let target = "sys-gui".parse()?;
    let observed = fixture
        .coordinator
        .shutdown_observation(&topology, &target)?;
    assert!(
        observed
            .domains()
            .iter()
            .any(|row| row.name == "usr-home" && row.gui_provider.as_deref() == Some("sys-gui"))
    );
    assert!(observed.domains().iter().all(|row| !row.hard_dependent));
    fixture
        .coordinator
        .runner
        .shutdown_deployment(durable.shutdown(&record, &target, &observed)?)?;
    assert!(
        durable
            .shutdown(&record, &"usr-home".parse()?, &observed)
            .is_err()
    );

    replies["commands"]["qvm-ls"][0]["stdout"] =
        json!("sys-gui|Running\nusr-home|Running\nusr-other|Running\n");
    replies["commands"]["qvm-prefs"]
        .as_array_mut()
        .unwrap()
        .push(json!({"args": ["usr-other", "guivm"], "stdout": "sys-gui\n"}));
    state::save(&helpers.join("replies.json"), &replies)?;
    let unexpected = fixture
        .coordinator
        .shutdown_observation(&topology, &target)?;
    assert!(
        unexpected
            .domains()
            .iter()
            .any(|row| row.name == "usr-other" && row.gui_provider.as_deref() == Some("sys-gui"))
    );
    assert!(durable.shutdown(&record, &target, &unexpected).is_err());

    // A declared paused peer is still a GUI client, independently of unknown-domain blocking.
    replies["commands"]["qvm-ls"][0]["stdout"] =
        json!("sys-gui|Running\nusr-home|Running\nsys-net|Paused\n");
    replies["commands"]["qvm-prefs"][1]["args"] = json!(["sys-net", "guivm"]);
    state::save(&helpers.join("replies.json"), &replies)?;
    let paused = fixture
        .coordinator
        .shutdown_observation(&topology, &target)?;
    assert!(paused.domains().iter().any(|row| row.name == "sys-net"
        && row.needs_probe("sys-gui")
        && row.declared
        && row.gui_provider.as_deref() == Some("sys-gui")));
    assert!(durable.shutdown(&record, &target, &paused).is_err());

    // Pausing an already approved client does not remove its observation or expand authority.
    replies["commands"]["qvm-ls"][0]["stdout"] = json!("sys-gui|Running\nusr-home|Paused\n");
    state::save(&helpers.join("replies.json"), &replies)?;
    let paused = fixture
        .coordinator
        .shutdown_observation(&topology, &target)?;
    assert!(durable.shutdown(&record, &target, &paused)?.forced());

    // Unsupported states and failed probes never become permission to dispatch.
    replies["commands"]["qvm-ls"][0]["stdout"] =
        json!("sys-gui|Running\nusr-home|Running\nusr-other|Unknown\n");
    state::save(&helpers.join("replies.json"), &replies)?;
    let uncertain = fixture
        .coordinator
        .shutdown_observation(&topology, &target)?;
    assert!(durable.shutdown(&record, &target, &uncertain).is_err());
    replies["commands"]["qvm-ls"][0]["stdout"] = json!("sys-gui|Running\nusr-home|Paused\n");
    replies["commands"]["qvm-prefs"][0]["exit"] = json!(1);
    state::save(&helpers.join("replies.json"), &replies)?;
    assert!(
        fixture
            .coordinator
            .shutdown_observation(&topology, &target)
            .is_err()
    );
    replies["commands"]["qvm-prefs"][0]["exit"] = json!(0);

    replies["commands"]["qvm-ls"][0]["stdout"] =
        json!("sys-gui|Running\nusr-home|Running\nusr-other|Paused\n");
    replies["commands"]["qvm-prefs"][1]["args"] = json!(["usr-other", "guivm"]);
    // An unknown running VM also blocks force when it is not observed as a GUI client.
    replies["commands"]["qvm-prefs"][1]["stdout"] = json!("none\n");
    state::save(&helpers.join("replies.json"), &replies)?;
    let unclassified = fixture
        .coordinator
        .shutdown_observation(&topology, &target)?;
    assert!(
        unclassified
            .domains()
            .iter()
            .any(|row| row.name == "usr-other" && !row.declared)
    );
    assert!(durable.shutdown(&record, &target, &unclassified).is_err());

    replies["commands"]["qvm-ls"][0]["stdout"] = json!("sys-gui|Running\nusr-home|Running\n");
    state::save(&helpers.join("replies.json"), &replies)?;
    topology
        .domains
        .get_mut(&"usr-home".parse()?)
        .unwrap()
        .netvm = VmReference::Named("sys-gui".parse()?);
    let hard = fixture
        .coordinator
        .shutdown_observation(&topology, &target)?;
    assert!(
        hard.domains()
            .iter()
            .any(|row| row.name == "usr-home" && row.hard_dependent)
    );
    assert!(durable.shutdown(&record, &target, &hard).is_err());
    topology
        .domains
        .get_mut(&"usr-home".parse()?)
        .unwrap()
        .netvm = VmReference::Disabled;
    let mut altered = record.clone();
    altered
        .plan
        .gui_reconnect
        .get_mut(&target)
        .unwrap()
        .push("sys-net".parse()?);
    assert!(durable.shutdown(&altered, &target, &observed).is_err());

    // Only the admitted GUI target has reached the process adapter so far.
    let dispatched: Vec<Value> = fs::read_dir(&commands)?
        .map(|entry| state::read(&entry?.path()))
        .collect::<Result<_>>()?;
    let shutdowns: Vec<_> = dispatched
        .iter()
        .filter(|v| v["program"] == "qvm-shutdown")
        .collect();
    assert_eq!(shutdowns.len(), 1);
    assert_eq!(
        shutdowns[0]["args"],
        replies["commands"]["qvm-shutdown"][0]["args"]
    );

    replies["commands"]["qvm-shutdown"][0]["exit"] = json!(1);
    state::save(&helpers.join("replies.json"), &replies)?;
    assert!(
        fixture
            .coordinator
            .runner
            .shutdown_deployment(durable.shutdown(&record, &target, &observed)?)
            .is_err()
    );
    durable.finish(false);
    assert!(durable.shutdown(&record, &target, &observed).is_err());

    let (retry, checked) = fixture.intent_plan(Some(&record), "311", record.plan.clone())?;
    assert_eq!(
        retry.metadata.details.operation,
        record.metadata.details.operation
    );
    let mut recovered = fixture.coordinator.publish_intent(&retry, checked)?;
    assert!(recovered.shutdown(&retry, &target, &observed).is_err());
    recovered.begin(&retry)?;
    assert!(recovered.shutdown(&record, &target, &observed).is_err());
    assert!(recovered.shutdown(&retry, &target, &observed)?.forced());
    recovered.finish(true);
    assert!(recovered.shutdown(&retry, &target, &observed).is_err());
    for program in ["qvm-shutdown", "qvm-ls", "qvm-prefs"] {
        fs::remove_file(helpers.join(program))?;
    }
    Ok(())
}

/// Exercise conversions outside the proof boundary, including every VM effect source.
fn verified_adapter() -> Result<()> {
    let fixture = Fixture::new()?;
    let (record, checked) = fixture.intent(None, "100")?;
    let mut durable = fixture.coordinator.publish_intent(&record, checked)?;
    let attempt = TransactionId::try_from("101".to_owned())?;
    assert!(
        fixture
            .coordinator
            .authorize(
                &fixture.release,
                &fixture.baseline,
                &record.plan,
                Some(&record),
                false
            )?
            .operation(&attempt)
            .is_err()
    );
    let checked = fixture.coordinator.authorize(
        &fixture.release,
        &fixture.baseline,
        &record.plan,
        Some(&record),
        false,
    )?;
    let mut substituted = record.clone();
    substituted.plan.start.push("usr-home".parse()?);
    let decision = fixture
        .coordinator
        .recovery_decision(&substituted, ApplyMode::Resume)?;
    assert!(checked.recover(&attempt, decision).is_err());
    for field in [
        "configure",
        "changed",
        "stage",
        "stop",
        "start",
        "affected",
        "retire",
        "restore",
    ] {
        let mut raw = serde_json::to_value(Plan::default())?;
        raw[field] = json!(["sys-net"]);
        let plan = serde_json::from_value(raw)?;
        assert!(
            fixture
                .coordinator
                .authorize(
                    &fixture.release,
                    &fixture.baseline,
                    &plan,
                    Some(&record),
                    false,
                )
                .is_err_and(|error| matches!(
                    error.downcast_ref::<airlock_nix_core::Error>(),
                    Some(airlock_nix_core::Error::ScopeExceeded { .. })
                )),
            "omitted scope field {field}"
        );
    }
    for (source, target) in [("sys-net", "usr-home"), ("usr-home", "sys-net")] {
        let mut plan = Plan::default();
        plan.extra.insert(
            "private_copies".into(),
            json!([
                {"source": {"domain": source}, "target_name": target}
            ]),
        );
        assert!(
            fixture
                .coordinator
                .authorize(
                    &fixture.release,
                    &fixture.baseline,
                    &plan,
                    Some(&record),
                    false,
                )
                .is_err(),
            "omitted private-copy endpoint"
        );
    }

    // Device ownership is independent of the lifecycle lists and needs both endpoints.
    for (source, target) in [("sys-net", "usr-home"), ("usr-home", "sys-net")] {
        let plan = Plan {
            pci_handoff: Some(json!({"from": source, "to": target})),
            ..Plan::default()
        };
        assert!(
            fixture
                .coordinator
                .authorize(
                    &fixture.release,
                    &fixture.baseline,
                    &plan,
                    Some(&record),
                    false
                )
                .is_err()
        );
    }
    for (field, value) in [
        ("future_effect", json!({"vm": "sys-net"})),
        ("changed", json!([])),
        ("host_reboot_required", json!(false)),
    ] {
        let mut plan = Plan::default();
        plan.extra.insert(field.into(), value);
        for administrative in [false, true] {
            assert!(
                fixture
                    .coordinator
                    .authorize(
                        &fixture.release,
                        &fixture.baseline,
                        &plan,
                        None,
                        administrative
                    )
                    .is_err(),
                "unclassified or shadowed field {field}"
            );
        }
    }
    // Explicit policy exemptions retain their meaning for a completely classified plan.
    let exempt = Plan {
        changed: vec!["sys-net".parse()?],
        ..Plan::default()
    };
    fixture
        .coordinator
        .authorize(&fixture.release, &fixture.baseline, &exempt, None, true)?;
    fs::remove_file("/etc/airlock/review-required")?;
    fixture
        .coordinator
        .authorize(&fixture.release, &fixture.baseline, &exempt, None, false)?;
    let mut unknown = exempt;
    unknown.extra.insert("future_effect".into(), json!(true));
    assert!(
        fixture
            .coordinator
            .authorize(&fixture.release, &fixture.baseline, &unknown, None, false)
            .is_err()
    );
    fs::write("/etc/airlock/review-required", "")?;

    // The approved record cannot be exchanged under an already published token.
    let mut changed = record.clone();
    changed.plan.start.push("sys-net".parse()?);
    assert!(durable.check(&changed).is_err());
    changed = record.clone();
    changed
        .metadata
        .details
        .operation
        .as_mut()
        .unwrap()
        .authority = OperationAuthority::Administrative;
    assert!(durable.check(&changed).is_err());
    durable.begin(&record)?;
    assert!(durable.begin(&record).is_err());
    durable.finish(true);
    assert!(durable.check(&record).is_err());

    // Fresh review mapping still requires explicit reboot approval and the same baseline.
    let fixture = Fixture::new()?;
    let mut approval = serde_json::to_value(fixture.approval()?)?;
    approval["scope"]["allow_reboot"] = json!(false);
    state::save(
        &fixture.coordinator.review_path(&fixture.request),
        &approval,
    )?;
    let mut plan = Plan {
        host_reboot_required: true,
        ..Plan::default()
    };
    assert!(
        fixture
            .coordinator
            .authorize(&fixture.release, &fixture.baseline, &plan, None, false,)
            .is_err_and(|error| matches!(
                error.downcast_ref::<airlock_nix_core::Error>(),
                Some(airlock_nix_core::Error::RebootNotApproved)
            ))
    );
    plan.host_reboot_required = false;
    fixture
        .coordinator
        .authorize(&fixture.release, &fixture.baseline, &plan, None, false)?;
    approval["baseline_state"] = json!("0".repeat(64));
    state::save(
        &fixture.coordinator.review_path(&fixture.request),
        &approval,
    )?;
    assert!(
        fixture
            .coordinator
            .authorize(&fixture.release, &fixture.baseline, &plan, None, false,)
            .is_err()
    );
    Ok(())
}

/// An interrupted recovery publication preserves the operation even if its attempt changes.
fn recovery_publication() -> Result<()> {
    for boundary in 0..4 {
        let fixture = Fixture::new()?;
        let (old, checked) = fixture.intent(None, "100")?;
        fixture.coordinator.publish_intent(&old, checked)?;
        let (next, checked) = fixture.intent(Some(&old), "101")?;
        let mut writes = 0;
        let result = fixture
            .coordinator
            .publish_intent_with(&next, checked, &mut |path, value| {
                ensure!(writes != boundary, "interrupted recovery publication");
                state::save(path, value)?;
                writes += 1;
                Ok(())
            });
        assert!(result.is_err());
        let current = fixture
            .coordinator
            .current()?
            .context("lost recovery intent")?;
        assert_eq!(
            current.metadata.details.operation,
            old.metadata.details.operation
        );
        let (next, checked) = fixture.intent(Some(&current), "102")?;
        fixture.coordinator.publish_intent(&next, checked)?;
        let (collision, checked) = fixture.intent(Some(&next), "100")?;
        assert!(
            fixture
                .coordinator
                .publish_intent(&collision, checked)
                .is_err()
        );
    }
    Ok(())
}

/// Legacy native recovery binds an identity, and interrupted rollback keeps the original review.
fn recovery_compatibility() -> Result<()> {
    let fixture = Fixture::new()?;
    let (mut legacy, _) = fixture.intent(None, "100")?;
    legacy.metadata.details.operation = None;
    if let JournalOrigin::Native(native) = &mut legacy.metadata.origin {
        native.native_coordinator = NativeVersion::V1;
    }
    fixture.coordinator.persist(&legacy)?;
    let mut approval = fixture.approval()?;
    approval.status = ApprovalStatus::DeploymentStarted;
    approval.release = Some(legacy.release.clone());
    state::save(
        &fixture.coordinator.review_path(&fixture.request),
        &approval,
    )?;

    let (mut rollback, _) = fixture.intent(Some(&legacy), "101")?;
    assert_eq!(
        rollback.metadata.details.operation.as_ref().unwrap().id,
        legacy.id
    );
    rollback.release = legacy.previous.clone();
    rollback.previous = legacy.release.clone();
    rollback.metadata.origin = JournalOrigin::Native(NativeJournal {
        native_coordinator: NativeVersion::V2,
        release_fingerprint: fixture.baseline.fingerprint().clone(),
        previous_fingerprint: fixture.release.fingerprint().clone(),
    });
    let checked = fixture
        .coordinator
        .authorize(
            &fixture.baseline,
            &fixture.release,
            &rollback.plan,
            Some(&legacy),
            false,
        )?
        .recover(
            &rollback.id,
            fixture
                .coordinator
                .recovery_decision(&legacy, ApplyMode::Rollback)?,
        )?;
    fixture.coordinator.publish_intent(&rollback, checked)?;

    // A restarted rollback has the baseline as its target, but must still read
    // the original candidate's binding, not look for approval of the baseline.
    let checked = fixture.coordinator.authorize(
        &fixture.baseline,
        &fixture.release,
        &Plan::default(),
        Some(&rollback),
        false,
    )?;
    let next = TransactionId::try_from("102".to_owned())?;
    assert_eq!(
        checked
            .recover(
                &next,
                fixture
                    .coordinator
                    .recovery_decision(&rollback, ApplyMode::Resume)?,
            )?
            .record()?,
        rollback.metadata.details.operation.clone().unwrap()
    );

    // Changing the current boot does not invalidate published recovery intent.
    rollback.boot_id = "11111111-1111-1111-1111-111111111111".parse()?;
    assert!(
        fixture
            .coordinator
            .authorize(
                &fixture.baseline,
                &fixture.baseline,
                &Plan::default(),
                Some(&rollback),
                false,
            )
            .is_ok()
    );
    Ok(())
}

/// Reproduce the old handoff state: direct same-boot retry works, normal checks and a new boot do not.
fn legacy_gap() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut approval = fixture.approval()?;
    approval.status = ApprovalStatus::DeploymentStarted;
    approval.release = Some(ReleasePath::from_path(&fixture.release.path)?);
    state::save(
        &fixture.coordinator.review_path(&fixture.request),
        &approval,
    )?;
    assert!(fixture.coordinator.current()?.is_none());
    assert!(
        fixture
            .coordinator
            .approved_review(
                &fixture.request,
                &fixture.release.manifest.revision,
                &fixture.release.manifest.lock_hash
            )
            .is_err()
    );
    assert!(fixture.intent(None, "100").is_ok());
    // The old implementation included boot ID in this digest. Change the digest
    // to model the same orphaned approval surviving a host restart.
    approval.baseline_state = "e".repeat(64).parse()?;
    state::save(
        &fixture.coordinator.review_path(&fixture.request),
        &approval,
    )?;
    assert!(
        fixture
            .intent(None, "100")
            .err()
            .context("accepted stale legacy approval")?
            .to_string()
            .contains("stale_review")
    );
    Ok(())
}

/// Recovery never creates approval or widens the original decision's identity and scope.
fn invalid_authority() -> Result<()> {
    let fixture = Fixture::new()?;
    let (record, checked) = fixture.intent(None, "100")?;
    fixture.coordinator.publish_intent(&record, checked)?;
    let original = serde_json::to_value(fixture.approval()?)?;
    let path = fixture.coordinator.review_path(&fixture.request);
    for (key, value) in [
        ("status", json!("rejected")),
        ("review_fingerprint", json!("e".repeat(64))),
        ("deployment_operation", json!("999")),
        ("deployment_operation", Value::Null),
        ("release", json!("/different/candidate")),
        (
            "scope",
            json!({"allowed_vms": ["sys-net"], "allow_reboot": true}),
        ),
    ] {
        let mut damaged = original.clone();
        damaged[key] = value;
        state::save(&path, &damaged)?;
        assert!(
            fixture.intent(Some(&record), "101").is_err(),
            "accepted changed {key}"
        );
    }
    state::save(&path, &original)?;
    let mut plan = Plan::default();
    plan.stop.push("sys-net".parse()?);
    assert!(
        fixture
            .coordinator
            .authorize(
                &fixture.release,
                &fixture.baseline,
                &plan,
                Some(&record),
                false
            )
            .is_err()
    );
    assert!(fixture.intent(None, "101").is_err());
    let mut wrong = record.clone();
    wrong.metadata.details.operation.as_mut().unwrap().authority =
        OperationAuthority::Administrative;
    assert!(fixture.intent(Some(&wrong), "101").is_err());
    let mut manifest: Value = state::read(&fixture.release.path.join("release.json"))?;
    manifest["trashRetentionDays"] = json!(31);
    state::save(&fixture.release.path.join("release.json"), &manifest)?;
    assert!(fixture.intent(Some(&record), "101").is_err());
    Ok(())
}

/// Missing projections are repairable; missing or conflicting authority fails closed.
fn damaged_records() -> Result<()> {
    let fixture = Fixture::new()?;
    let (record, checked) = fixture.intent(None, "100")?;
    fixture.coordinator.publish_intent(&record, checked)?;
    let history = fixture
        .coordinator
        .state
        .join("transactions/100/status.json");
    state::unlink(&history)?;
    assert_eq!(fixture.coordinator.record(&record.id)?.id, record.id);
    assert!(
        fixture
            .coordinator
            .release_inventory()?
            .contains_key(record.release.as_str())
    );
    fixture.coordinator.persist(&record)?;
    let mut old = record.clone();
    old.phase = Phase::Failed;
    state::save(&history, &old)?;
    assert_eq!(
        fixture.coordinator.record(&record.id)?.phase,
        Phase::Preflight
    );
    old.release = "/different/candidate".parse()?;
    state::save(&history, &old)?;
    assert!(fixture.coordinator.current().is_err());
    fs::write(&history, b"{")?;
    assert!(fixture.coordinator.current().is_err());
    state::save(&history, &record)?;
    let latest = fixture.coordinator.state.join("latest.json");
    state::unlink(&latest)?;
    assert!(fixture.coordinator.current().is_err());
    fs::write(&latest, b"{")?;
    assert!(fixture.coordinator.current().is_err());
    state::save(&latest, &record)?;
    fs::write(fixture.coordinator.review_path(&fixture.request), b"{")?;
    assert!(fixture.intent(Some(&record), "101").is_err());
    state::unlink(&fixture.coordinator.review_path(&fixture.request))?;
    assert!(fixture.intent(Some(&record), "101").is_err());
    let mut raw = serde_json::to_value(record)?;
    let mut missing = raw.clone();
    missing.as_object_mut().unwrap().remove("operation");
    assert!(serde_json::from_value::<Record>(missing).is_err());
    let mut downgraded = raw.clone();
    downgraded["native_coordinator"] = json!("airlock-dom0-service-v1");
    assert!(serde_json::from_value::<Record>(downgraded).is_err());
    raw["operation"] = Value::Null;
    assert!(serde_json::from_value::<Record>(raw).is_err());
    Ok(())
}

/// Declared configuration passes through protected approval, intent and typed dispatch.
fn configuration_requests() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let mut topology = serde_json::to_value(lifecycle_topology(&fixture)?)?;
    topology["domains"]
        .as_object_mut()
        .unwrap()
        .retain(|name, _| name == "usr-home");
    topology["domains"]["usr-home"]["label"] = json!("green");
    topology["domains"]["usr-home"]["prefs"] = json!({"memory":1024});
    topology["domains"]["usr-home"]["features"] = json!({"role":"home"});
    topology["domains"]["usr-home"]["services"] = json!({"qrexec":true});
    state::save(&fixture.release.path.join("topology.json"), &topology)?;
    fixture.release = Release::load(&fixture.release.path)?;
    let plan = Plan {
        configure: vec!["usr-home".parse()?],
        ..Plan::default()
    };

    // Exemptions bypass review, but still need the complete configuration namespace.
    for administrative in [true, false] {
        if !administrative {
            fs::remove_file("/etc/airlock/review-required")?;
        }
        assert!(
            fixture
                .coordinator
                .authorize(
                    &fixture.release,
                    &fixture.baseline,
                    &Plan::default(),
                    None,
                    administrative,
                )
                .is_err_and(|error| error.to_string()
                    == "device definitions differ from checked configuration scope")
        );

        let checked = fixture.coordinator.authorize(
            &fixture.release,
            &fixture.baseline,
            &plan,
            None,
            administrative,
        )?;
        assert!(checked.approval.is_none());
        assert_eq!(
            checked.authority,
            if administrative {
                OperationAuthority::Administrative
            } else {
                OperationAuthority::ReviewNotRequired
            }
        );
    }
    fs::write("/etc/airlock/review-required", "")?;

    let (record, checked) = fixture.intent_plan(None, "310", plan)?;
    let mut durable = fixture.coordinator.publish_intent(&record, checked)?;
    assert!(durable.configuration_create(&record, 0, false).is_err());
    durable.begin(&record)?;
    let helpers = Path::new("/var/lib/airlock/helpers");
    fs::create_dir_all(helpers)?;
    let peer = std::env::var_os("AIRLOCK_TEST_PEER_BIN").context("missing native command peer")?;
    for program in ["qvm-create", "qvm-prefs", "qvm-features", "qvm-service"] {
        match fs::symlink_metadata(helpers.join(program)) {
            Ok(_) => fs::remove_file(helpers.join(program))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        std::os::unix::fs::symlink(&peer, helpers.join(program))?;
    }
    state::save(
        &helpers.join("replies.json"),
        &json!({"commands":{
            "qvm-create":[{"args":["--class","StandaloneVM","--label","green","usr-home"]}],
            "qvm-prefs":[{"args":["usr-home","memory","1024"]}],
            "qvm-features":[{"args":["usr-home","role","home"]}],
            "qvm-service":[{"args":["usr-home","qrexec","on"]}]
        }}),
    )?;
    let commands = fixture.coordinator.state.join("commands");
    fixture.coordinator.runner.record_to(commands.clone())?;
    fixture
        .coordinator
        .runner
        .create_deployment(durable.configuration_create(&record, 0, false)?.unwrap())?;
    for (kind, setting) in [
        (airlock_deployment_core::configuration::Kind::Property, 1),
        (airlock_deployment_core::configuration::Kind::Feature, 0),
        (airlock_deployment_core::configuration::Kind::Service, 0),
    ] {
        let selection = airlock_deployment_core::configuration::Selection {
            domain: 0,
            kind,
            setting,
        };
        let observation = airlock_deployment_core::configuration::SettingObservation {
            name: "usr-home",
            current: None,
            explicit: true,
            power: airlock_deployment_core::inventory::PowerState::classify("Halted"),
        };
        let request = durable
            .configuration_setting(&record, selection, &observation)?
            .unwrap();
        fixture.coordinator.runner.setting_deployment(request)?;
    }
    assert_eq!(fs::read_dir(commands)?.count(), 4);
    durable.finish(false);
    assert!(durable.configuration_create(&record, 0, false).is_err());
    Ok(())
}
