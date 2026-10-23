//! Exercise the executable checked planner with independent package, feature and source obligations.

use airlock_build_plan::{CheckedPackageSource, Fact, Input, Package, Profile, Requirements, Rule};

/// Two packages, an optional dependency, an implicit target and a separately optional build script.
fn fixture() -> (Vec<Package>, Vec<Input>, Vec<Fact>, Vec<Rule>) {
    let inputs = [
        ("Cargo.toml", None, false),
        ("Cargo.lock", None, false),
        ("app/Cargo.toml", None, false),
        ("dep/Cargo.toml", None, false),
        ("app/src", Some(0), false),
        ("dep/src", Some(1), false),
        ("dep/implicit.rs", None, false),
        ("dep/build.rs", Some(1), true),
    ]
    .into_iter()
    .map(|(path, package, optional)| Input {
        path: path.into(),
        package,
        optional,
    })
    .collect();
    let packages = vec![
        Package {
            name: "app".into(),
            manifest: 2,
            discovery: vec![],
        },
        Package {
            name: "dep".into(),
            manifest: 3,
            discovery: vec![6],
        },
    ];
    let facts = vec![
        Fact::Feature {
            package: 0,
            name: "default".into(),
        },
        Fact::Feature {
            package: 0,
            name: "extra".into(),
        },
        Fact::Dependency,
    ];
    let rules = vec![
        Rule {
            first: 0,
            second: Some(3),
            result: 4,
        },
        Rule {
            first: 4,
            second: None,
            result: 1,
        },
    ];
    (packages, inputs, facts, rules)
}

/// Keep manifest/discovery metadata even when its implementation is not selected.
#[test]
fn source_projection_is_complete_and_excludes_unrequired_implementations() {
    for (features, expected) in [
        (
            vec![],
            vec![
                "Cargo.toml",
                "Cargo.lock",
                "app/Cargo.toml",
                "dep/Cargo.toml",
                "app/src",
                "dep/implicit.rs",
            ],
        ),
        (
            vec!["extra".into()],
            vec![
                "Cargo.toml",
                "Cargo.lock",
                "app/Cargo.toml",
                "dep/Cargo.toml",
                "app/src",
                "dep/src",
                "dep/implicit.rs",
                "dep/build.rs",
            ],
        ),
    ] {
        let (packages, inputs, facts, rules) = fixture();
        let plan = CheckedPackageSource::check(
            packages,
            inputs,
            facts,
            rules,
            Profile {
                package: 0,
                defaults: false,
                features,
            },
        )
        .unwrap();
        let paths: Vec<_> = (0..plan.file_count())
            .map(|i| plan.file(i).unwrap().path.as_str())
            .collect();
        assert_eq!(paths, expected);
        assert!(plan.file(plan.file_count()).is_none());
        if plan.includes(1) {
            assert!(plan.file(plan.file_count() - 1).unwrap().optional);
        }
    }
}

/// Compilation receives exactly the original package/default/feature selection.
#[test]
fn arguments_preserve_the_request_and_unknown_features_cannot_create_a_plan() {
    let (packages, inputs, facts, rules) = fixture();
    let plan = CheckedPackageSource::check(
        packages,
        inputs,
        facts,
        rules,
        Profile {
            package: 0,
            defaults: false,
            features: vec!["extra".into()],
        },
    )
    .unwrap();
    assert_eq!(
        plan.arguments(),
        ["-p", "app", "--no-default-features", "--features", "extra"]
    );
    let (packages, inputs, facts, rules) = fixture();
    assert!(
        CheckedPackageSource::check(
            packages,
            inputs,
            facts,
            rules,
            Profile {
                package: 0,
                defaults: true,
                features: vec!["unknown".into()],
            }
        )
        .is_none()
    );
}

/// Missing, conditional or optional workspace metadata must fail before projection.
#[test]
fn malformed_source_obligations_and_references_fail_closed() {
    for defect in [
        "manifest-owner",
        "manifest-optional",
        "discovery",
        "owner",
        "rule",
        "profile",
    ] {
        let (mut packages, mut inputs, facts, mut rules) = fixture();
        let mut profile = Profile {
            package: 0,
            defaults: true,
            features: vec![],
        };
        match defect {
            "manifest-owner" => inputs[2].package = Some(0),
            "manifest-optional" => inputs[2].optional = true,
            "discovery" => packages[1].discovery = vec![100],
            "owner" => inputs[5].package = Some(100),
            "rule" => rules[0].result = 100,
            "profile" => profile.package = 100,
            _ => unreachable!(),
        }
        assert!(
            CheckedPackageSource::check(packages, inputs, facts, rules, profile).is_none(),
            "accepted {defect}"
        );
    }
}

/// Feature cycles converge without granting disconnected facts; order and duplication do not matter.
#[test]
fn least_closure_handles_conjunction_cycles_and_rule_order() {
    let rules = vec![
        Rule {
            first: 1,
            second: Some(2),
            result: 3,
        },
        Rule {
            first: 0,
            second: None,
            result: 1,
        },
        Rule {
            first: 3,
            second: None,
            result: 0,
        },
    ];
    let mut reordered = rules.clone();
    reordered.reverse();
    reordered.push(rules[0]);
    for (second, expected) in [
        (false, vec![true, true, false, false, false]),
        (true, vec![true, true, true, true, false]),
    ] {
        let seeds = vec![true, false, second, false, false];
        for order in [rules.clone(), reordered.clone()] {
            assert_eq!(
                Requirements::new(5, order)
                    .unwrap()
                    .solve(seeds.clone())
                    .unwrap(),
                expected
            );
        }
    }
}
