//! Interpret Cargo declarations as positive local build requirements.
//! This TOML adapter is checked against Cargo; the resulting solver and source projection are verified.

use super::*;
use airlock_build_plan::{
    CheckedPackageSource, Fact, Input, Package as DeclaredPackage, Profile, Rule,
};

/// Canonical fact identities; package coordinates are shared with input ownership.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Atom {
    /// Selected local package.
    Package(
        // Canonical package coordinate.
        usize,
    ),
    /// Named feature or feature-expansion token.
    Feature(
        // Canonical package coordinate.
        usize,
        // Original Cargo token.
        String,
    ),
    /// Activation of a named local dependency.
    Dependency(
        // Package declaring this dependency.
        usize,
        // Dependency alias, which can differ from its package name.
        String,
    ),
}

/// Normalized implication graph; this layer grants no source selection itself.
struct Graph {
    // Stable fact-to-coordinate correspondence.
    indices: BTreeMap<Atom, usize>,
    // Reverse correspondence used when forwarding feature tokens.
    atoms: Vec<Atom>,
    // Positive requirements consumed by the verified solver.
    rules: Vec<Rule>,
}

impl Graph {
    /// Reuse an existing coordinate or append one new identity.
    fn fact(&mut self, atom: Atom) -> usize {
        if let Some(index) = self.indices.get(&atom) {
            return *index;
        }
        let index = self.atoms.len();
        self.indices.insert(atom.clone(), index);
        self.atoms.push(atom);
        index
    }

    /// Preserve all premise and conclusion identities while lowering an implication.
    fn rule(&mut self, first: Atom, second: Option<Atom>, result: Atom) {
        let first = self.fact(first);
        let second = second.map(|atom| self.fact(atom));
        let result = self.fact(result);
        self.rules.push(Rule {
            first,
            second,
            result,
        });
    }
}

/// Optional dependency aliases are implicit features unless Cargo explicitly suppresses them.
fn implicit(manifest: &Value, alias: &str) -> bool {
    let definitions = manifest.get("features").and_then(Value::as_table);
    !definitions.is_some_and(|definitions| {
        definitions.contains_key(alias)
            || definitions
                .values()
                .filter_map(Value::as_array)
                .flatten()
                .any(|value| value.as_str() == Some(&format!("dep:{alias}")))
    })
}

/// Unknown compiler features cannot silently produce an incomplete source plan.
fn requested_feature(manifest: &Value, token: &str) -> bool {
    if manifest
        .get("features")
        .and_then(Value::as_table)
        .is_some_and(|features| features.contains_key(token))
    {
        return true;
    }
    if let Some((alias, feature)) = token.split_once('/') {
        let alias = alias.strip_suffix('?').unwrap_or(alias);
        return !feature.is_empty()
            && !feature.contains('/')
            && dependencies(manifest)
                .iter()
                .any(|(name, _)| *name == alias);
    }
    dependencies(manifest).iter().any(|(alias, declaration)| {
        *alias == token
            && declaration.get("optional").and_then(Value::as_bool) == Some(true)
            && implicit(manifest, alias)
    })
}

/// Lower only local dependencies; registry dependencies do not contribute first-party source paths.
fn local(package: &Package, packages: &BTreeMap<String, Package>) -> Vec<(String, usize, Value)> {
    let mut result = Vec::new();
    for (alias, dependency) in dependencies(&package.manifest) {
        if dependency.get("workspace").and_then(Value::as_bool) == Some(true) {
            let contents = if package.directory.starts_with("vendor/rusix/") {
                include_str!("../../../../../vendor/rusix/Cargo.toml")
            } else {
                include_str!("../../../../../Cargo.toml")
            };
            let workspace: Value = toml::from_str(contents).unwrap();
            assert!(
                workspace["workspace"]
                    .get("dependencies")
                    .and_then(|table| table.get(alias))
                    .and_then(|entry| entry.get("path"))
                    .is_none(),
                "inherited local dependencies require source inventory support"
            );
        }
        let Some(path) = dependency.get("path").and_then(Value::as_str) else {
            continue;
        };
        let directory = relative(package.directory, path);
        let target = packages
            .values()
            .position(|package| package.directory == directory)
            .expect("local dependency belongs to the source inventory");
        result.push((alias.to_owned(), target, dependency.clone()));
    }
    result
}

/// Compile defaults, aliases, dependency activation and weak forwarding into bounded fact references.
fn requirements(
    packages: &BTreeMap<String, Package>,
    root: usize,
    features: &[&str],
) -> (Vec<Fact>, Vec<Rule>) {
    let mut graph = Graph {
        indices: BTreeMap::new(),
        atoms: Vec::new(),
        rules: Vec::new(),
    };
    for p in 0..packages.len() {
        assert_eq!(graph.fact(Atom::Package(p)), p);
    }
    let locals: Vec<_> = packages
        .values()
        .map(|package| local(package, packages))
        .collect();
    for (p, package) in packages.values().enumerate() {
        graph.fact(Atom::Feature(p, "default".into()));
        if let Some(definitions) = package.manifest.get("features").and_then(Value::as_table) {
            for (name, values) in definitions {
                graph.fact(Atom::Feature(p, name.clone()));
                for value in values.as_array().expect("feature definition is an array") {
                    graph.rule(
                        Atom::Package(p),
                        Some(Atom::Feature(p, name.clone())),
                        Atom::Feature(p, value.as_str().expect("feature token is text").to_owned()),
                    );
                }
            }
        }
        for (alias, target, declaration) in &locals[p] {
            let active = Atom::Dependency(p, alias.clone());
            if declaration.get("optional").and_then(Value::as_bool) != Some(true) {
                graph.rule(Atom::Package(p), None, active.clone());
            } else if implicit(&package.manifest, alias) {
                graph.rule(
                    Atom::Package(p),
                    Some(Atom::Feature(p, alias.clone())),
                    active.clone(),
                );
            }
            graph.rule(
                Atom::Package(p),
                Some(Atom::Feature(p, format!("dep:{alias}"))),
                active.clone(),
            );
            graph.rule(active.clone(), None, Atom::Package(*target));
            if declaration.get("default-features").and_then(Value::as_bool) != Some(false) {
                graph.rule(
                    active.clone(),
                    None,
                    Atom::Feature(*target, "default".into()),
                );
            }
            if let Some(values) = declaration.get("features").and_then(Value::as_array) {
                for feature in values {
                    graph.rule(
                        active.clone(),
                        None,
                        Atom::Feature(*target, feature.as_str().unwrap().to_owned()),
                    );
                }
            }
        }
    }
    for feature in features {
        graph.fact(Atom::Feature(root, (*feature).to_owned()));
    }

    // Forwarding can introduce another local feature token, so process the finite suffix closure.
    let mut next = packages.len();
    while next < graph.atoms.len() {
        if let Atom::Feature(p, token) = graph.atoms[next].clone()
            && let Some((alias, feature)) = token.split_once('/')
        {
            assert!(
                !feature.is_empty() && !feature.contains('/'),
                "unsupported nested feature forwarding"
            );
            let weak = alias.ends_with('?');
            let alias = alias.strip_suffix('?').unwrap_or(alias);
            for (name, target, _) in &locals[p] {
                if name == alias {
                    let active = Atom::Dependency(p, name.clone());
                    if !weak {
                        graph.rule(
                            Atom::Package(p),
                            Some(Atom::Feature(p, token.clone())),
                            active.clone(),
                        );
                    }
                    graph.rule(
                        active,
                        Some(Atom::Feature(p, token.clone())),
                        Atom::Feature(*target, feature.to_owned()),
                    );
                }
            }
        }
        next += 1;
    }
    let facts = graph
        .atoms
        .into_iter()
        .skip(packages.len())
        .map(|atom| match atom {
            Atom::Feature(package, name) => Fact::Feature { package, name },
            Atom::Dependency(..) => Fact::Dependency,
            Atom::Package(_) => unreachable!("package facts precede feature facts"),
        })
        .collect();
    (facts, graph.rules)
}

/// Insert a source obligation without silently merging conflicting owners or missing-file policies.
fn input(
    files: &mut BTreeMap<(String, Option<usize>), bool>,
    path: String,
    owner: Option<usize>,
    optional: bool,
) {
    if let Some(previous) = files.insert((path, owner), optional) {
        assert_eq!(previous, optional, "conflicting source requirements");
    }
}

/// Decode source obligations once, then let verified Rust select every output coordinate.
pub(super) fn checked(
    packages: &BTreeMap<String, Package>,
    package: &str,
    defaults: bool,
    features: &[&str],
) -> CheckedPackageSource {
    let root = packages
        .keys()
        .position(|name| name == package)
        .expect("package belongs to the source inventory");
    let declaration = &packages[package].manifest;
    for feature in features {
        assert!(
            requested_feature(declaration, feature),
            "unknown or unsupported feature {feature} for {package}"
        );
    }
    let (facts, rules) = requirements(packages, root, features);
    let mut files = BTreeMap::new();
    for path in ["Cargo.toml", "Cargo.lock", "vendor/rusix/Cargo.toml"] {
        input(&mut files, path.into(), None, false);
    }
    let mut discoveries = Vec::new();
    for (p, (name, package)) in packages.iter().enumerate() {
        let directory = package.directory;
        input(&mut files, format!("{directory}/Cargo.toml"), None, false);
        let bins = package.manifest.get("bin").and_then(Value::as_array);
        if let Some(bins) = bins {
            assert!(
                bins.iter()
                    .all(|bin| bin.get("path").and_then(Value::as_str).is_some()),
                "binary targets require explicit source paths"
            );
        }
        let discovery = if directory.starts_with("vendor/rusix/crates/")
            || (package.manifest.get("lib").is_none() && bins.is_none_or(Vec::is_empty))
        {
            let path = format!("{directory}/src/lib.rs");
            input(&mut files, path.clone(), None, false);
            vec![path]
        } else {
            Vec::new()
        };
        discoveries.push(discovery);
        input(&mut files, format!("{directory}/src"), Some(p), false);
        for target in package
            .manifest
            .get("lib")
            .into_iter()
            .chain(bins.into_iter().flatten())
        {
            if let Some(path) = target.get("path").and_then(Value::as_str)
                && !path.starts_with("src/")
            {
                input(&mut files, relative(directory, path), Some(p), false);
            }
        }
        if package.manifest["package"]
            .get("build")
            .and_then(Value::as_bool)
            != Some(false)
        {
            let declaration = package.manifest["package"].get("build");
            assert!(
                declaration.is_none_or(|value| value.is_str()),
                "unsupported build-script declaration"
            );
            let explicit = declaration.and_then(Value::as_str);
            let build = explicit.unwrap_or("build.rs");
            input(
                &mut files,
                relative(directory, build),
                Some(p),
                explicit.is_none(),
            );
        }
        let assets: Vec<String> = match name.as_str() {
            "airlock-build" => vec!["airlock-tests/fixtures/memory_accounting.c".into()],
            "airlock-config" => vec!["verus.json".into()],
            "airlock-desktop" => vec![format!("{directory}/assets")],
            "airlock-sys-ctrl-gui" => vec![
                format!("{directory}/assets/fonts"),
                format!("{directory}/examples"),
            ],
            "airlock-tests" => vec![
                format!("{directory}/fixtures/memory_accounting.c"),
                format!("{directory}/fixtures/gui"),
            ],
            _ => Vec::new(),
        };
        for asset in assets {
            input(&mut files, asset, Some(p), false);
        }
    }
    let coordinates: BTreeMap<_, _> = files
        .keys()
        .enumerate()
        .map(|(i, key)| (key.clone(), i))
        .collect();
    let declarations = packages
        .iter()
        .enumerate()
        .map(|(p, (name, package))| DeclaredPackage {
            name: name.clone(),
            manifest: coordinates[&(
                format!("{directory}/Cargo.toml", directory = package.directory),
                None,
            )],
            discovery: discoveries[p]
                .iter()
                .map(|path| coordinates[&(path.clone(), None)])
                .collect(),
        })
        .collect();
    let inputs = files
        .into_iter()
        .map(|((path, package), optional)| Input {
            path,
            package,
            optional,
        })
        .collect();
    CheckedPackageSource::check(
        declarations,
        inputs,
        facts,
        rules,
        Profile {
            package: root,
            defaults,
            features: features
                .iter()
                .map(|feature| (*feature).to_owned())
                .collect(),
        },
    )
    .expect("invalid or incomplete package-source requirements")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A branch can select the same package without activating another owner's optional dependency.
    fn declarations() -> [(&'static str, &'static str); 4] {
        [
            (
                "a",
                r#"
                [package]
                name = "a"
                version = "0.1.0"
                edition = "2024"
                [dependencies]
                b = { path = "../b", optional = true, default-features = false }
                c = { path = "../c", default-features = false }
                [features]
                default = ["activate"]
                activate = ["cycle", "dep:b", "b/extra"]
                cycle = ["activate"]
                weak = ["b?/extra"]
                branch = ["c/hook"]
            "#,
            ),
            (
                "b",
                r#"
                [package]
                name = "b"
                version = "0.1.0"
                edition = "2024"
                [dependencies]
                d = { path = "../d", optional = true }
                [features]
                extra = ["dep:d"]
            "#,
            ),
            (
                "c",
                r#"
                [package]
                name = "c"
                version = "0.1.0"
                edition = "2024"
                [dependencies]
                b = { path = "../b", optional = true, default-features = false }
                [features]
                hook = ["dep:b"]
            "#,
            ),
            (
                "d",
                r#"
                [package]
                name = "d"
                version = "0.1.0"
                edition = "2024"
            "#,
            ),
        ]
    }

    /// Decode the exact fixture manifests also supplied independently to Cargo.
    fn fixture() -> BTreeMap<String, Package> {
        declarations()
            .into_iter()
            .map(|(directory, text)| {
                (
                    directory.to_owned(),
                    Package {
                        directory,
                        manifest: toml::from_str(text).unwrap(),
                    },
                )
            })
            .collect()
    }

    /// Check weak forwarding, optional activation, aliases and feature cycles against Cargo itself.
    #[test]
    fn optional_and_weak_feature_rules_match_cargo() {
        let model = fixture();
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        std::fs::write(
            root.join("Cargo.toml"),
            r#"
            [workspace]
            members = ["a", "b", "c", "d"]
            resolver = "3"
        "#,
        )
        .unwrap();
        for (name, text) in declarations() {
            let path = root.join(name);
            std::fs::create_dir_all(path.join("src")).unwrap();
            // Cargo only resolves these empty library targets; no fixture program is compiled.
            std::fs::write(path.join("src/lib.rs"), "").unwrap();
            std::fs::write(path.join("Cargo.toml"), text).unwrap();
        }
        let lock = std::process::Command::new(env!("CARGO"))
            .args(["generate-lockfile", "--offline", "--manifest-path"])
            .arg(root.join("Cargo.toml"))
            .output()
            .unwrap();
        assert!(
            lock.status.success(),
            "{error}",
            error = String::from_utf8_lossy(&lock.stderr)
        );

        for (defaults, features, expected) in [
            (false, vec![], vec!["a", "c"]),
            (false, vec!["weak"], vec!["a", "c"]),
            (false, vec!["weak", "branch"], vec!["a", "b", "c"]),
            (true, vec![], vec!["a", "b", "c", "d"]),
        ] {
            let plan = checked(&model, "a", defaults, &features);
            let output = std::process::Command::new(env!("CARGO"))
                .args([
                    "tree",
                    "--offline",
                    "--locked",
                    "--prefix",
                    "none",
                    "--format",
                    "{p}",
                    "--edges",
                    "normal,build",
                    "--target",
                    "all",
                    "--manifest-path",
                ])
                .arg(root.join("Cargo.toml"))
                .args(plan.arguments())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{error}",
                error = String::from_utf8_lossy(&output.stderr)
            );
            let actual: BTreeSet<_> = String::from_utf8(output.stdout)
                .unwrap()
                .lines()
                .filter_map(|line| line.split_whitespace().next())
                .map(str::to_owned)
                .collect();
            let selected: BTreeSet<_> = model
                .keys()
                .enumerate()
                .filter(|(i, _)| plan.includes(*i))
                .map(|(_, name)| name.clone())
                .collect();
            assert_eq!(selected, expected.into_iter().map(str::to_owned).collect());
            assert_eq!(
                selected, actual,
                "defaults={defaults}, features={features:?}"
            );
        }
    }

    /// Unsupported requests or unresolved local paths cannot produce an opaque source plan.
    #[test]
    fn invalid_features_and_missing_local_references_are_rejected() {
        let mut model = fixture();
        assert!(std::panic::catch_unwind(|| checked(&model, "a", false, &["unknown"])).is_err());
        model.get_mut("a").unwrap().manifest["dependencies"]["b"]["path"] =
            Value::String("../missing".into());
        assert!(std::panic::catch_unwind(|| checked(&model, "a", false, &[])).is_err());
    }

    /// A declared target or build script is mandatory even when its filename resembles an implicit one.
    #[test]
    fn explicit_targets_and_build_scripts_retain_required_paths() {
        let mut model = fixture();
        let original = checked(&model, "a", false, &[]);
        assert!((0..original.file_count()).any(|i| {
            let file = original.file(i).unwrap();
            file.path == "a/build.rs" && file.optional
        }));

        let manifest = &mut model.get_mut("a").unwrap().manifest;
        manifest["package"]
            .as_table_mut()
            .unwrap()
            .insert("build".into(), Value::String("build.rs".into()));
        manifest.as_table_mut().unwrap().insert(
            "lib".into(),
            toml::from_str::<Value>(r#"path = "entry.rs""#).unwrap(),
        );
        let plan = checked(&model, "a", false, &[]);
        for path in ["a/build.rs", "a/entry.rs"] {
            assert!(
                (0..plan.file_count()).any(|i| {
                    let file = plan.file(i).unwrap();
                    file.path == path && !file.optional
                }),
                "missing mandatory {path}"
            );
        }
    }
}
