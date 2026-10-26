//! Review identity matching preserves source, target family and deployed baseline independently of encoding.

use airlock_machine_planning::review_identity::{Identity, Target, equal, same_context};

/// A fixed source restriction used independently by matching and adversarial comparisons.
fn guest() -> Identity<'static> {
    Identity {
        revision: "revision",
        lock: "lock",
        target: Target::Guest("usr-home"),
    }
}

/// Matching includes every source coordinate and never equates a guest restriction with whole-machine work.
#[test]
fn source_and_target_identity_are_exact() {
    let original = guest();
    assert!(equal(&original, &guest()));
    for other in [
        Identity {
            revision: "changed",
            ..guest()
        },
        Identity {
            lock: "changed",
            ..guest()
        },
        Identity {
            target: Target::Guest("usr-other"),
            ..guest()
        },
        Identity {
            target: Target::Machine,
            ..guest()
        },
    ] {
        assert!(!equal(&original, &other));
        assert!(!equal(&other, &original));
        assert!(!same_context(&original, "baseline", &other, "baseline"));
    }
    let machine = Identity {
        target: Target::Machine,
        ..guest()
    };
    let empty_guest = Identity {
        target: Target::Guest(""),
        ..guest()
    };
    assert!(!equal(&machine, &empty_guest));
}

/// Identical sources cannot reuse a protected review against another deployed baseline.
#[test]
fn changed_baseline_refuses_context_reuse() {
    assert!(same_context(&guest(), "baseline", &guest(), "baseline"));
    assert!(!same_context(
        &guest(),
        "baseline",
        &guest(),
        "new-baseline"
    ));
}
