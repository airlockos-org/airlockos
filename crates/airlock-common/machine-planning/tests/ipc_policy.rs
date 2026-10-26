//! Exercise exact policy projection and publication-bound refresh capabilities without external effects.

use airlock_machine_planning::ipc_policy::{
    Argument, CheckedPolicy, Declaration, Endpoint, Installation, RefreshKind, RefreshOutcome,
    Service,
};

/// One literal allow followed by a service-specific wildcard denial.
fn declarations() -> Vec<Declaration> {
    vec![
        Declaration {
            service: "airlock.Test".into(),
            argument: "+one".into(),
            source: "sys-ctrl".into(),
            target: "usr-home".into(),
            action: "allow".into(),
        },
        Declaration {
            service: "airlock.Test".into(),
            argument: "*".into(),
            source: "@anyvm".into(),
            target: "@anyvm".into(),
            action: "deny".into(),
        },
    ]
}

/// Exact fields, order and duplicate rows survive the production decoder and encoder.
#[test]
fn ordered_projection_is_exact_and_does_not_invent_permissions() {
    let policy = CheckedPolicy::decode(declarations()).unwrap();
    assert_eq!(
        policy
            .text()
            .lines()
            .filter(|line| !line.starts_with('#'))
            .collect::<Vec<_>>(),
        [
            "airlock.Test +one sys-ctrl usr-home allow",
            "airlock.Test * @anyvm @anyvm deny"
        ]
    );
    let mut rows = declarations();
    rows.reverse();
    rows.extend(declarations());
    let policy = CheckedPolicy::decode(rows).unwrap();
    assert_eq!(
        policy
            .text()
            .lines()
            .filter(|line| !line.starts_with('#'))
            .collect::<Vec<_>>(),
        [
            "airlock.Test * @anyvm @anyvm deny",
            "airlock.Test +one sys-ctrl usr-home allow",
            "airlock.Test +one sys-ctrl usr-home allow",
            "airlock.Test * @anyvm @anyvm deny"
        ]
    );
}

/// Malformed tokens, wildcard allows, protected services and unknown actions reject the whole policy.
#[test]
fn unsupported_or_broader_rules_fail_closed() {
    for (field, invalid) in [
        ("service", "airlock.Config.Apply"),
        ("service", "airlock.Config.Rollback"),
        ("service", "qubes.Execute"),
        ("service", "airlock.Test\nairlock.Evil"),
        ("service", "airlock.Test * @anyvm @anyvm allow"),
        ("argument", "word"),
        ("argument", "+x target=dom0"),
        ("source", "@anyvm"),
        ("source", "@tag:trusted"),
        ("target", "dom0"),
        ("target", "@anyvm"),
        ("action", "ask"),
        ("target", "usr-home\n!include evil"),
    ] {
        let mut rows = declarations();
        let value = invalid.into();
        match field {
            "service" => rows[0].service = value,
            "argument" => rows[0].argument = value,
            "source" => rows[0].source = value,
            "target" => rows[0].target = value,
            _ => rows[0].action = value,
        }
        assert!(
            CheckedPolicy::decode(rows).is_none(),
            "accepted {field}: {invalid}"
        );
    }
    assert!(Argument::new("+".into()).is_some());
    assert!(Endpoint::new("dom0".into()).is_some());
    assert!(Service::new("airlock.".into()).is_none());
}

/// The original target and bytes must survive publication, refresh dispatch and completion readback.
#[test]
fn refresh_preserves_the_complete_original_policy_binding() {
    let make = || {
        Installation::new(
            "/policy/90-airlock.policy".into(),
            CheckedPolicy::decode(declarations()).unwrap(),
        )
        .unwrap()
    };
    let install = make();
    assert!(
        install
            .published("/other/90-airlock.policy", "wrong")
            .is_none()
    );
    let install = make();
    assert!(
        install
            .published("/policy/90-airlock.policy", "changed bytes")
            .is_none()
    );
    for outcome in [
        RefreshOutcome::Failed,
        RefreshOutcome::Uncertain,
        RefreshOutcome::Running,
    ] {
        let install = make();
        let text = install.text().to_owned();
        let request = install
            .published("/policy/90-airlock.policy", &text)
            .unwrap()
            .request();
        assert_eq!(
            request.arguments(RefreshKind::Reload),
            ["reload", "qubes-qrexec-policy-daemon.service"]
        );
        assert_eq!(
            request.arguments(RefreshKind::Restart),
            ["try-restart", "qubes-qrexec-policy-daemon.service"]
        );
        assert_eq!(
            request.active_arguments(),
            ["is-active", "--quiet", "qubes-qrexec-policy-daemon.service"]
        );
        assert_eq!(
            request
                .complete("/policy/90-airlock.policy", &text, outcome)
                .is_some(),
            matches!(outcome, RefreshOutcome::Running)
        );
    }
    let install = make();
    let text = install.text().to_owned();
    let request = install
        .published("/policy/90-airlock.policy", &text)
        .unwrap()
        .request();
    assert!(
        request
            .complete(
                "/policy/90-airlock.policy",
                "substituted",
                RefreshOutcome::Running
            )
            .is_none()
    );
}
