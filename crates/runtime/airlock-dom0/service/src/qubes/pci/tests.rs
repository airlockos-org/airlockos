//! Validate structured upstream device records, malformed replies and the sysfs/API join.

use super::*;

/// Upstream virtual-device properties encode identity independently of the row's qarg head.
fn fields(port: &str, identity: &str) -> String {
    format!("device_id='{identity}' port_id='{port}' devclass='pci' backend_domain='dom0'")
}

#[test]
fn exact_wildcard_and_concrete_rows_round_trip() -> Result<()> {
    let owner: VmName = "usr-assistant".parse()?;
    for (port, identity) in [
        ("01_00.0", "*"),
        ("00_1c.0-00_00.0", "8086:153a::p020000"),
        ("0001_40_01.0-00_00.0", "0000:0000::?******"),
    ] {
        let head = argument("dom0", port, identity);
        let reply = format!(
            "{head} {fields} mode='required' frontend_domain='usr-assistant' _no-strict-reset='True'",
            fields = fields(port, identity)
        );
        let rows = usages(&reply, &owner, Kind::Assigned)?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].identity, identity);
        assert_eq!(rows[0].port, port);
    }
    Ok(())
}

#[test]
fn malformed_incomplete_conflicting_and_duplicate_records_fail_closed() -> Result<()> {
    let owner: VmName = "usr-assistant".parse()?;
    let valid = format!(
        "dom0+01_00.0+_ {fields} mode='required'",
        fields = fields("01_00.0", "*")
    );
    for reply in [
        valid.replace("dom0+01_00.0+_", "dom0+02_00.0+_"),
        valid.replace(" mode='required'", ""),
        valid.replace("device_id='*'", ""),
        valid.replace("mode='required'", "mode='future-mode'"),
        format!("{valid} frontend_domain='foreign'"),
        format!("{valid} port_id='02_00.0'"),
        format!("{valid}\n{valid}"),
    ] {
        assert!(
            usages(&reply, &owner, Kind::Assigned).is_err(),
            "accepted {reply}"
        );
    }
    assert!(domains("usr-assistant class=AppVM state=Running\n").is_err());
    assert!(domains("dom0 class=AdminVM\ndom0 class=AdminVM\n").is_err());
    Ok(())
}

#[test]
fn unavailable_network_hardware_is_not_silently_omitted() -> Result<()> {
    let root = tempfile::tempdir()?;
    let path = root.path().join("0000:01:00.0");
    fs::create_dir(&path)?;
    fs::write(path.join("class"), "0x020000\n")?;
    assert!(devices(root.path(), &BTreeMap::new()).is_err());
    let reply = format!(
        "01_00.0:8086:153a::p020000 {fields} interfaces='p020000' _sbdf='0000:01:00.0'",
        fields = fields("01_00.0", "8086:153a::p020000")
    );
    let available = available(&reply)?;
    let observed = devices(root.path(), &available)?;
    assert_eq!(observed[0].class, 0x020000);
    assert_eq!(observed[0].identity, "8086:153a::p020000");
    for invalid in [
        reply.replace(" _sbdf='0000:01:00.0'", ""),
        reply.replace("0000:01:00.0", "../../elsewhere"),
        format!(
            "{reply}\n{duplicate}",
            duplicate = reply
                .replace("01_00.0:", "02_00.0:")
                .replace("port_id='01_00.0'", "port_id='02_00.0'")
        ),
    ] {
        assert!(super::available(&invalid).is_err(), "accepted {invalid}");
    }
    fs::remove_dir_all(path)?;
    assert!(devices(root.path(), &available).is_err());
    assert!(
        super::available(&reply.replace("backend_domain='dom0'", "backend_domain='foreign'"))
            .is_err()
    );
    Ok(())
}

/// Exercise the actual structured observer and transport adapter without live Qubes or hardware.
#[test]
fn complete_snapshot_and_uncertain_unassignment_reconcile_without_duplicate_effect() -> Result<()> {
    use airlock_deployment_core::{operation::*, plan::AuthorizedPlan, publication::Event};
    use airlock_machine_planning::effects::PlanEffects;
    let root = tempfile::tempdir()?;
    fs::create_dir(root.path().join("0000:01:00.0"))?;
    fs::write(root.path().join("0000:01:00.0/class"), "0x020000")?;
    let available = format!(
        "00_1c.0-00_00.0:8086:153a::p020000 {fields} _sbdf='0000:01:00.0'",
        fields = fields("00_1c.0-00_00.0", "8086:153a::p020000")
    );
    let assigned = format!(
        "dom0+00_1c.0-00_00.0+_ {fields} mode='required'",
        fields = fields("00_1c.0-00_00.0", "*")
    );
    let mut complete = Vec::new();
    let mut observe = |removed: bool, foreign: bool, fail: bool| {
        snapshot(root.path(), |domain, method| {
            complete.push((domain.to_string(), method));
            Ok(match method {
                "admin.vm.List" => "dom0 class=AdminVM\nusr-assistant class=AppVM\nsys-net class=AppVM\nforeign class=AppVM".as_bytes().to_vec(),
                "admin.vm.device.pci.Available" => available.as_bytes().to_vec(),
                "admin.vm.device.pci.Assigned" if domain.as_str() == "usr-assistant" && !removed => assigned.as_bytes().to_vec(),
                "admin.vm.device.pci.Attached" if domain.as_str() == "foreign" && foreign => assigned.replace("mode='required'", "mode='manual'").into_bytes(),
                "admin.vm.device.pci.Attached" if domain.as_str() == "foreign" && fail => anyhow::bail!("lost observation"),
                "admin.vm.device.pci.Assigned" | "admin.vm.device.pci.Attached" => Vec::new(),
                _ => anyhow::bail!("unexpected API"),
            })
        })
    };
    assert!(observe(false, false, true).is_err());
    assert!(
        observe(false, true, false)?
            .check("usr-assistant".into(), "sys-net".into(), false)
            .is_none()
    );
    let before = observe(false, false, false)?
        .check("usr-assistant".into(), "sys-net".into(), false)
        .context("valid handoff")?;
    let effects = PlanEffects {
        configure: vec![],
        changed: vec![],
        stage: vec![],
        stop: vec![],
        start: vec![],
        affected: vec![],
        retire: vec![],
        restore: vec![],
        copy_sources: vec![],
        copy_targets: vec![],
        gui_providers: vec![],
        gui_clients: vec![],
        pci_sources: vec!["usr-assistant"],
        pci_targets: vec!["sys-net"],
        unknown: vec![],
        reboot: Some(false),
    };
    // This adapter test uses the explicit administrative policy; reviewed scope has separate core tests.
    let plan =
        AuthorizedPlan::policy_exempt(&effects, vec![], PlanBinding::new("plan".into())).unwrap();
    let pci = plan.pci_handoff();
    let operation = plan
        .operation(
            AttemptId::new("attempt".into()),
            AuthorityBinding::new("authority".into()),
        )
        .unwrap();
    let context = ExecutionContext {
        attempt: AttemptId::new("attempt".into()),
        operation: OperationId::new("attempt".into()),
        authority: AuthorityBinding::new("authority".into()),
        plan: PlanBinding::new("plan".into()),
    };
    let mut durable = operation
        .publication(
            &context.attempt,
            &context.operation,
            &context.authority,
            &context.plan,
            IntentBinding::new("intent".into()),
        )
        .unwrap();
    durable.advance(Event::IntentSaved);
    durable.advance(Event::ApprovalSaved);
    assert!(durable.begin(&context.attempt, &IntentBinding::new("intent".into())));
    let execution = pci.execution(&durable, &context, &before).unwrap();
    let request = execution.request(0).unwrap();
    let mut changes = 0;
    assert!(
        unassign_with(request, |owner, arg| {
            assert_eq!(owner.as_str(), "usr-assistant");
            assert_eq!(arg, "dom0+00_1c.0-00_00.0+_");
            changes += 1;
            anyhow::bail!("effect succeeded, reply lost")
        })
        .is_err()
    );
    for _ in 0..3 {
        let after = observe(true, false, false)?
            .check("usr-assistant".into(), "sys-net".into(), true)
            .context("already unassigned recovery")?;
        let execution = pci.execution(&durable, &context, &after).unwrap();
        assert!((0..execution.len()).all(|i| execution.request(i).is_none()));
    }
    assert_eq!(changes, 1);
    assert!(
        complete.iter().any(
            |(domain, method)| domain == "foreign" && *method == "admin.vm.device.pci.Attached"
        )
    );
    Ok(())
}

/// Physical route addresses must resolve to topology ports before the recovery NIC is excluded.
#[test]
fn recovery_routes_use_upstream_physical_addresses() -> Result<()> {
    let reply = format!(
        "00_1c.0-00_00.0:8086:153a::p020000 {first} _sbdf='0000:04:00.0'\n0001_40_01.0-00_00.0:8086:153b::p020000 {second} _sbdf='0001:41:00.0'",
        first = fields("00_1c.0-00_00.0", "8086:153a::p020000"),
        second = fields("0001_40_01.0-00_00.0", "8086:153b::p020000")
    );
    let inventory = available(&reply)?;
    assert_eq!(
        ports_for_addresses(&[address("0000:04:00.0")?], &inventory)?,
        ["00_1c.0-00_00.0"]
    );
    assert!(ports_for_addresses(&[address("0000:05:00.0")?], &inventory).is_err());
    let root = tempfile::tempdir()?;
    for physical in ["0000:04:00.0", "0001:41:00.0"] {
        fs::create_dir(root.path().join(physical))?;
        fs::write(root.path().join(physical).join("class"), "0x020000")?;
    }
    let observed = devices(root.path(), &inventory)?;
    assert_eq!(observed.len(), 2);
    assert!(
        observed
            .iter()
            .any(|device| device.port == "0001_40_01.0-00_00.0")
    );

    for invalid in [
        "",
        "00_20.0",
        "00_00.8",
        "00_1c.0-",
        "-00_00.0",
        "00_1c.0--00_00.0",
        "00_1c.0/00_00.0",
        "00_1c.0+00_00.0",
        "00_1c.0-*",
        "*",
    ] {
        assert!(validate_port(invalid).is_err(), "accepted {invalid}");
    }
    Ok(())
}

/// Real publication and checked-plan ownership for an inert direct device API test.
fn device_gate() -> Result<(
    airlock_deployment_core::devices::DevicePlan,
    airlock_deployment_core::operation::DurableOperation,
)> {
    use airlock_deployment_core::{operation::*, plan::AuthorizedPlan, publication::Event};
    use airlock_machine_planning::effects::PlanEffects;
    let effects = PlanEffects {
        configure: vec!["sys-net"],
        changed: vec![],
        stage: vec![],
        stop: vec![],
        start: vec![],
        affected: vec![],
        retire: vec![],
        restore: vec![],
        copy_sources: vec![],
        copy_targets: vec![],
        gui_providers: vec![],
        gui_clients: vec![],
        pci_sources: vec![],
        pci_targets: vec![],
        unknown: vec![],
        reboot: Some(false),
    };
    let plan =
        AuthorizedPlan::policy_exempt(&effects, vec![], PlanBinding::new("plan".into())).unwrap();
    let topology = serde_json::json!({"domains":{"sys-net":{"devices":{"pci":[{"backend":"dom0","id":"01_00.0","match":"port","mode":"required","options":{"no-strict-reset":"True"}}]}}}});
    let definitions = crate::setup_config::devices::definitions(&topology)?;
    let devices = plan.devices(definitions).unwrap();
    let operation = plan
        .operation(
            AttemptId::new("attempt".into()),
            AuthorityBinding::new("authority".into()),
        )
        .unwrap();
    let c = device_context();
    let mut durable = operation
        .publication(
            &c.attempt,
            &c.operation,
            &c.authority,
            &c.plan,
            IntentBinding::new("intent".into()),
        )
        .unwrap();
    durable.advance(Event::IntentSaved);
    durable.advance(Event::ApprovalSaved);
    assert!(durable.begin(&c.attempt, &IntentBinding::new("intent".into())));
    Ok((devices, durable))
}

/// Exact current operation identifiers are compared at every selection.
fn device_context() -> airlock_deployment_core::operation::ExecutionContext {
    use airlock_deployment_core::operation::*;
    ExecutionContext {
        attempt: AttemptId::new("attempt".into()),
        operation: OperationId::new("attempt".into()),
        authority: AuthorityBinding::new("authority".into()),
        plan: PlanBinding::new("plan".into()),
    }
}

/// Build complete evidence for one exact physical function and the supplied observed assignments.
fn device_observation(
    uses: Vec<Usage>,
    state: &str,
) -> airlock_deployment_core::devices::Observation {
    airlock_deployment_core::devices::Observation {
        name: "sys-net".into(),
        power: airlock_deployment_core::inventory::PowerState::classify(state),
        hardware: vec![Device {
            port: "01_00.0".into(),
            identity: "8086:1234::p020000".into(),
            class: 0x020000,
        }],
        uses,
        recovery_routes: vec![],
    }
}

#[test]
fn replacement_and_lost_reply_reconcile_exact_assignment_without_repeating_completed_effect()
-> Result<()> {
    let (devices, durable) = device_gate()?;
    let old = format!(
        "dom0+01_00.0+_ {fields} mode='required' _no-strict-reset='False'",
        fields = fields("01_00.0", "*")
    );
    let o = device_observation(usages(&old, &"sys-net".parse()?, Kind::Assigned)?, "Halted");
    let selection = devices
        .explicit(&durable, &device_context(), 0, 0, &o.hardware[0], &o)
        .unwrap();
    assert!(!assignment_current(&selection, &o.uses));
    let mut calls = Vec::new();
    assert!(
        assign_with(
            selection.permit(&o).unwrap(),
            &o.uses,
            |domain, method, arg, payload| {
                calls.push(method);
                assert_eq!(domain.as_str(), "sys-net");
                assert_eq!(method, "admin.vm.device.pci.Unassign");
                assert_eq!(arg, "dom0+01_00.0+_");
                assert!(payload.is_empty());
                anyhow::bail!("unassigned successfully, then reply lost")
            }
        )
        .is_err()
    );
    assert_eq!(calls, ["admin.vm.device.pci.Unassign"]);

    let o = device_observation(vec![], "Halted");
    let selection = devices
        .explicit(&durable, &device_context(), 0, 0, &o.hardware[0], &o)
        .unwrap();
    let mut recorded = String::new();
    let mut assignments = 0;
    assert!(
        assign_with(
            selection.permit(&o).unwrap(),
            &o.uses,
            |domain, method, arg, payload| {
                assert_eq!(domain.as_str(), "sys-net");
                assert_eq!(method, "admin.vm.device.pci.Assign");
                assert_eq!(arg, "dom0+01_00.0+_");
                let text = std::str::from_utf8(payload)?;
                let props = properties(text)?;
                assert_eq!(props["_no-strict-reset"], "True");
                assert_eq!(props["frontend_domain"], "sys-net");
                recorded = format!("{arg} {text}");
                assignments += 1;
                anyhow::bail!("assigned successfully, then reply lost")
            }
        )
        .is_err()
    );
    for _ in 0..3 {
        let o = device_observation(
            usages(&recorded, &"sys-net".parse()?, Kind::Assigned)?,
            "Running",
        );
        let selection = devices
            .explicit(&durable, &device_context(), 0, 0, &o.hardware[0], &o)
            .unwrap();
        assert!(assignment_current(&selection, &o.uses));
        assert!(selection.permit(&o).is_none());
    }
    assert_eq!(assignments, 1);
    Ok(())
}

#[test]
fn property_serialization_cannot_create_additional_fields_or_hide_termination() -> Result<()> {
    let value = "literal' frontend_domain='foreign";
    let encoded = property("_option", value)?;
    assert_eq!(
        properties(&encoded)?,
        BTreeMap::from([("_option".into(), value.into())])
    );
    assert!(property("_option", "trailing\\").is_err());
    assert!(property("frontend domain", "foreign").is_err());
    Ok(())
}

#[test]
fn declaration_decoder_preserves_cli_option_normalization_and_refuses_unsupported_rules()
-> Result<()> {
    let mut topology = serde_json::json!({"domains":{"sys-net":{"devices":{"pci":[{"backend":"dom0","id":"01_00.0","match":"port","mode":"required","options":{"ro":true,"read-only":"no"}}]}}}});
    let definitions = crate::setup_config::devices::definitions(&topology)?;
    let options = &definitions[0].assignments[0].options;
    assert_eq!(options.len(), 1);
    assert_eq!(options[0].name, "read-only");
    assert_eq!(options[0].value, "yes");
    for (field, value) in [
        ("backend", "other-vm"),
        ("match", "future-rule"),
        ("mode", "future-mode"),
        ("id", "../elsewhere"),
    ] {
        let original = topology["domains"]["sys-net"]["devices"]["pci"][0][field].clone();
        topology["domains"]["sys-net"]["devices"]["pci"][0][field] = serde_json::json!(value);
        assert!(crate::setup_config::devices::definitions(&topology).is_err());
        topology["domains"]["sys-net"]["devices"]["pci"][0][field] = original;
    }
    Ok(())
}
