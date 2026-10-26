//! Exercise the real boot decoder, evidence loader and publication loop in a disposable root.

use super::*;
use serde_json::json;

/// Immutable host identity used without invoking live pool or bootloader operations.
const SYSTEM: &str = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-host";

/// One private stage-one filesystem with a valid release and independent transaction.
struct Fixture {
    /// Owns all boot state and is removed without touching deployed data.
    root: tempfile::TempDir,
    /// Authenticated host-loader output supplied to restoration.
    receipt: HostReceipt,
    /// Saved boot binding, before any corruption or interruption.
    binding: Value,
}

impl Fixture {
    /// Create a complete binding for one guest with a positive generation.
    fn new() -> Result<Self> {
        let root = tempfile::tempdir()?;
        let machine = root.path().join(host::MACHINE.trim_start_matches('/'));
        let candidate = machine.join("candidates/one");
        let logical = format!("{}/candidates/one", host::MACHINE);
        let baseline = format!("{}/candidates/zero", host::MACHINE);
        let topology = json!({"schema":"airlock.qubes-topology.v1","domains":{"usr-home":{
            "class":"StandaloneVM","backend":{"type":"nix-closure",
                "system":{"source":SYSTEM},"root":{"source":format!("{SYSTEM}/root.img")},
                "kernel":{"name":"linux"},"store":{"source":SYSTEM,"mode":"shared-closure",
                    "mountpoint":"/nix/store","device":"/dev/xvde","blobDevice":"/dev/xvdf","viewBackend":"erofs-objectmap"}}
        }}});
        write(&candidate.join("topology.json"), &topology, 0o600)?;
        write(
            &candidate.join("release.json"),
            &json!({"schema":"airlock.machine-release.v1",
            "profile":"test","host":SYSTEM,"setup":format!("{SYSTEM}/bin/setup"),
            "revision":"a".repeat(40),"lockHash":"b".repeat(64),"stagedGenerations":{"usr-home":7}}),
            0o600,
        )?;
        write(
            &candidate.join("staged.json"),
            &json!({"usr-home":7}),
            0o600,
        )?;
        let selection: Selection =
            serde_json::from_value(json!({"release":logical,"previous":baseline,
            "transaction":"1","profile":"test","selection_extension":"retained"}))?;
        write(
            &machine.join("transactions/1/status.json"),
            &json!({"id":"1","release":logical,
            "previous":baseline,"phase":"complete","diagnostic":{"retained":true}}),
            0o600,
        )?;
        let receipt = json!({"schema":"airlock.host-store.v1","system":SYSTEM,"generation":2,
            "manifest":"/pool/manifest.json","closure_hash":"a".repeat(64),
            "registration":"/pool/registration","registration_sha256":"b".repeat(64),
            "metadata_image":"/pool/metadata.erofs","metadata_image_sha256":"c".repeat(64),
            "blob_map":"/pool/map.json","blob_map_sha256":"d".repeat(64)});
        let loaded = evidence(&machine, Path::new(host::MACHINE), &selection)?;
        let binding = json!({"schema":"airlock.host-machine.v2","system":SYSTEM,"generation":2,
            "host_record":serde_json::from_value::<HostReceipt>(receipt.clone())?.binding()?,
            "selection":selection,"release_fingerprint":loaded.fingerprint,"staged":{"usr-home":7}});
        let fixture = Self {
            root,
            receipt: serde_json::from_value(receipt)?,
            binding,
        };
        fixture.save_binding(&fixture.binding)?;
        Ok(fixture)
    }

    /// Virtual machine state lives below the disposable stage-one root.
    fn machine(&self) -> PathBuf {
        self.root.path().join(host::MACHINE.trim_start_matches('/'))
    }

    /// Host-store state is independent of the machine selection files.
    fn storage(&self) -> PathBuf {
        self.root.path().join(host::HOST.trim_start_matches('/'))
    }

    /// Publish a chosen binding to the location selected by the booted receipt.
    fn save_binding(&self, binding: &Value) -> Result<()> {
        write(
            &self.storage().join("generations/2/machine.json"),
            binding,
            0o600,
        )
    }

    /// Refusal must precede any mutation of an existing, inconsistent live selection.
    fn refuses(&self) -> Result<()> {
        write(
            &self.machine().join("selection.json"),
            &json!({"stale":true}),
            0o644,
        )?;
        assert!(restore(self.root.path(), &self.receipt).is_err());
        assert_eq!(
            state::read::<Value>(&self.machine().join("selection.json"))?,
            json!({"stale":true})
        );
        assert!(!self.storage().join("boot-staged.json").exists());
        assert!(!self.machine().join("controller").is_symlink());
        Ok(())
    }
}

/// Every persistence boundary can be replayed, including success before an interrupted return.
#[test]
fn interrupted_boot_publication_replays_the_complete_bound_snapshot() -> Result<()> {
    for interrupted in 0..=4 {
        let fixture = Fixture::new()?;
        let result = restore_with(fixture.root.path(), &fixture.receipt, |step| {
            ensure!(step != interrupted, "simulated crash after {step} writes");
            Ok(())
        });
        assert!(result.is_err());
        for _ in 0..2 {
            restore(fixture.root.path(), &fixture.receipt)?;
            assert_eq!(
                state::read::<Value>(&fixture.machine().join("selection.json"))?,
                fixture.binding["selection"]
            );
            assert_eq!(
                state::read::<Value>(&fixture.machine().join("latest.json"))?,
                state::read::<Value>(&fixture.machine().join("transactions/1/status.json"))?
            );
            assert_eq!(
                state::read::<Value>(&fixture.storage().join("boot-staged.json"))?,
                fixture.binding["staged"]
            );
            assert_eq!(
                fs::read_link(fixture.machine().join("controller"))?,
                PathBuf::from(format!("{SYSTEM}/sw/bin/airlock-dom0-service"))
            );
        }
    }
    Ok(())
}

/// Host receipt, full release, journal coordinates and complete guest maps all constrain restore.
#[test]
fn conflicting_boot_evidence_refuses_before_any_publication() -> Result<()> {
    for (file, field, value) in [
        (
            "binding",
            "system",
            json!("/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-host"),
        ),
        ("binding", "generation", json!(3)),
        ("binding", "host_record", json!("e".repeat(64))),
        ("binding", "release_fingerprint", json!("e".repeat(64))),
        ("binding", "staged", json!({"usr-home":8})),
        ("status", "id", json!("2")),
        ("status", "previous", json!("/different")),
        ("status", "release", json!("/different")),
        ("status", "phase", json!("host-boot-selection")),
        ("status", "phase", json!("failed")),
        (
            "release",
            "host",
            json!("/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-host"),
        ),
        ("release", "profile", json!("different")),
    ] {
        let fixture = Fixture::new()?;
        let path = match file {
            "binding" => fixture.storage().join("generations/2/machine.json"),
            "status" => fixture.machine().join("transactions/1/status.json"),
            _ => fixture.machine().join("candidates/one/release.json"),
        };
        let mut value_before: Value = state::read(&path)?;
        value_before[field] = value;
        write(&path, &value_before, 0o600)?;
        fixture
            .refuses()
            .with_context(|| format!("accepted {file}.{field}"))?;
    }
    Ok(())
}

/// An empty manifest map is an exact constraint, even for pre-existing v1 snapshots.
#[test]
fn legacy_bindings_cannot_skip_empty_guest_declarations_or_changed_staging() -> Result<()> {
    for empty_manifest in [false, true] {
        let fixture = Fixture::new()?;
        let legacy = json!({"schema":"airlock.host-machine.v1","system":SYSTEM,
            "selection":fixture.binding["selection"],"staged":{"usr-home":7}});
        fixture.save_binding(&legacy)?;
        if empty_manifest {
            let path = fixture.machine().join("candidates/one/release.json");
            let mut manifest: Value = state::read(&path)?;
            manifest["stagedGenerations"] = json!({});
            write(&path, &manifest, 0o600)?;
        } else {
            write(
                &fixture.machine().join("candidates/one/staged.json"),
                &json!({"usr-home":8}),
                0o600,
            )?;
        }
        fixture.refuses()?;
    }
    let fixture = Fixture::new()?;
    fixture.save_binding(&json!({"schema":"airlock.host-machine.v1","system":SYSTEM,
        "selection":fixture.binding["selection"],"staged":{"usr-home":7}}))?;
    restore(fixture.root.path(), &fixture.receipt)?;
    Ok(())
}

/// Decoding rejects missing nullable fields, unsupported formats and malformed guest identities.
#[test]
fn boot_binding_protocol_is_typed_and_fail_closed() -> Result<()> {
    let fixture = Fixture::new()?;
    for field in [
        "selection",
        "release_fingerprint",
        "staged",
        "generation",
        "host_record",
    ] {
        let mut invalid = fixture.binding.clone();
        invalid.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<BootBinding>(invalid).is_err(),
            "accepted missing {field}"
        );
    }
    for (field, value) in [
        ("schema", json!("unknown")),
        ("generation", json!(0)),
        ("staged", json!({"usr-home":0})),
        ("staged", json!({"dom0":7})),
        ("staged", json!({"../escape":7})),
        ("staged", json!({"usr-home":"7"})),
        ("extension", json!(true)),
    ] {
        let mut invalid = fixture.binding.clone();
        invalid[field] = value;
        assert!(
            serde_json::from_value::<BootBinding>(invalid).is_err(),
            "accepted {field}"
        );
    }
    // The verified core checks mathematical entries as well as document equality.
    let decoded: BootBinding = serde_json::from_value(fixture.binding.clone())?;
    let boot = fixture.receipt.observation()?;
    let observed = evidence(
        &fixture.machine(),
        Path::new(host::MACHINE),
        decoded.selection().unwrap(),
    )?;
    let mut missing_fingerprint = decoded.verified()?;
    missing_fingerprint.selection.as_mut().unwrap().fingerprint = None;
    assert!(!boot::snapshot(
        &missing_fingerprint,
        &boot,
        Some(&observed)
    ));
    assert!(Restoration::reconcile(&missing_fingerprint, &boot, Some(&observed)).is_none());
    for generation in [0, 7, 8] {
        let mut checked = decoded.verified()?;
        checked.guests.entries.push(boot::Guest {
            domain: "usr-home".into(),
            generation,
        });
        assert!(!boot::snapshot(&checked, &boot, Some(&observed)));
        assert!(Restoration::reconcile(&checked, &boot, Some(&observed)).is_none());
    }
    let path = fixture.storage().join("generations/2/machine.json");
    fs::write(
        &path,
        b"{\"schema\":\"airlock.host-machine.v1\",\"schema\":\"airlock.host-machine.v2\"}",
    )?;
    fixture.refuses()?;
    Ok(())
}

/// A no-selection image snapshot explicitly clears stale transaction metadata on every replay.
#[test]
fn image_binding_and_bootstrap_exception_do_not_invent_a_transaction() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut image = fixture.binding.clone();
    image["selection"] = Value::Null;
    image["release_fingerprint"] = Value::Null;
    fixture.save_binding(&image)?;
    write(
        &fixture.machine().join("selection.json"),
        &json!({"stale":true}),
        0o644,
    )?;
    write(
        &fixture.machine().join("latest.json"),
        &json!({"stale":true}),
        0o644,
    )?;
    for _ in 0..2 {
        restore(fixture.root.path(), &fixture.receipt)?;
        assert!(!fixture.machine().join("selection.json").exists());
        assert!(!fixture.machine().join("latest.json").exists());
    }
    fs::remove_file(fixture.storage().join("generations/2/machine.json"))?;
    assert!(restore(fixture.root.path(), &fixture.receipt).is_err());
    let mut initial = fixture.receipt.clone();
    initial.generation = 1.try_into()?;
    assert!(restore(fixture.root.path(), &initial).is_err());
    fs::remove_file(fixture.storage().join("boot-staged.json"))?;
    restore(fixture.root.path(), &initial)?;
    write(
        &fixture.machine().join("latest.json"),
        &json!({"stale":true}),
        0o644,
    )?;
    assert!(restore(fixture.root.path(), &initial).is_err());
    Ok(())
}

/// Native publication captures a full receipt and content digest, including the precommit phase.
#[test]
fn save_captures_checked_identity_and_refuses_inconsistent_snapshot() -> Result<()> {
    let fixture = Fixture::new()?;
    let machine = fixture.machine();
    let release = machine.join("candidates/one");
    let previous = machine.join("candidates/zero");
    let selection =
        json!({"release":release,"previous":previous,"transaction":"1","profile":"test"});
    write(&machine.join("selection.json"), &selection, 0o644)?;
    write(
        &machine.join("transactions/1/status.json"),
        &json!({"id":"1","release":release,
        "previous":previous,"phase":"host-boot-selection"}),
        0o600,
    )?;
    save(
        &fixture.root.path().join("pool"),
        &fixture.storage(),
        &machine,
        &fixture.receipt,
    )?;
    let bound: Value = state::read(&fixture.storage().join("generations/2/machine.json"))?;
    assert_eq!(bound["schema"], "airlock.host-machine.v2");
    assert_eq!(bound["host_record"], fixture.binding["host_record"]);
    assert_eq!(
        bound["release_fingerprint"],
        fixture.binding["release_fingerprint"]
    );
    assert_eq!(bound["selection"], selection);
    // Checkpoint must preserve this binding rather than replace it with an unfinished selection.
    assert!(!checkpoint(
        &fixture.root.path().join("pool"),
        &fixture.storage(),
        &machine,
        &fixture.receipt
    )?);
    let status_path = machine.join("transactions/1/status.json");
    let mut status: Value = state::read(&status_path)?;
    status["phase"] = json!("failed");
    write(&status_path, &status, 0o600)?;
    assert!(!checkpoint(
        &fixture.root.path().join("pool"),
        &fixture.storage(),
        &machine,
        &fixture.receipt
    )?);
    status["phase"] = json!("reboot-required");
    write(&status_path, &status, 0o600)?;
    assert!(checkpoint(
        &fixture.root.path().join("pool"),
        &fixture.storage(),
        &machine,
        &fixture.receipt
    )?);
    write(&release.join("staged.json"), &json!({}), 0o600)?;
    assert!(
        save(
            &fixture.root.path().join("pool"),
            &fixture.storage(),
            &machine,
            &fixture.receipt
        )
        .is_err()
    );
    assert_eq!(
        state::read::<Value>(&fixture.storage().join("generations/2/machine.json"))?,
        bound
    );
    Ok(())
}

/// An interruption never permits later recovery to skip fresh journal validation.
#[test]
fn changed_evidence_after_interruption_cannot_finish_the_snapshot() -> Result<()> {
    let fixture = Fixture::new()?;
    assert!(
        restore_with(fixture.root.path(), &fixture.receipt, |step| {
            ensure!(step != 1, "crash after selection publication");
            Ok(())
        })
        .is_err()
    );
    let status_path = fixture.machine().join("transactions/1/status.json");
    let mut status: Value = state::read(&status_path)?;
    status["phase"] = json!("failed");
    write(&status_path, &status, 0o600)?;
    assert!(restore(fixture.root.path(), &fixture.receipt).is_err());
    assert!(!fixture.storage().join("boot-staged.json").exists());
    assert!(!fixture.machine().join("controller").is_symlink());
    Ok(())
}
