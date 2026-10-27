//! Construct full build releases and payload-free transports for dom0 admission.
//! The controller retains VM payloads; dom0 receives their identities and root metadata.

use airlock_build::{Workspace, tools::Tool};
use rusix::{
    interop::{
        NixExpression, NixPath, PackageFunction,
        raw::{NixRepresentation, NixValue},
    },
    nix_record, nix_text,
    nixos::{ContextualModule, ModuleBody, ModuleContext},
};

/// Dependencies captured before NixOS evaluates a release module.
pub(crate) struct Build {
    /// Machine source containing implementation assets and its dependency lock.
    pub source: NixPath,
    /// Native application sources used by setup and coordination executables.
    pub workspace: Workspace,
    /// VM build entries whose system identities must match the final deployment topology.
    pub entries: NixValue,
    /// Source commit, timestamp and lock hash bound into the release manifest.
    pub metadata: NixValue,
}

/// Describe a release from explicit build dependencies, with no release-specific module arguments.
pub(crate) fn module(build: &Build) -> NixValue {
    ContextualModule::new(|context| {
        let topology = context.config.clone().select("airlock.qubes.topology");
        let domains = context
            .lib
            .clone()
            .select("mapAttrs")
            .call(NixValue::function(|_| {
                NixValue::function(|domain| {
                    let entry = matching_entry(build, &domain);
                    let backend = domain.clone().select("backend");
                    let updated = domain.clone().merge_attrs(nix_record! {
                        "backend": backend.clone().merge_attrs(nix_record! {
                            "store": backend.select("store").merge_attrs(nix_record! {
                                "source": entry.select("storeArtifact").to_text(),
                            }),
                        }),
                    });

                    NixValue::if_else(is_closure(&domain), updated, domain)
                })
            }))
            .call(topology.clone().select("domains"));

        let configuration = topology
            .merge_attrs(nix_record! {
                "domains": domains,
            })
            .bind(|topology| artifacts(&context, build, topology));

        ModuleBody::new(configuration).key("airlock.machine.release")
    })
    .into_expression()
}

/// Identify a closure-backed VM without forcing payload fields of other Qubes backends.
fn is_closure(domain: &NixValue) -> NixValue {
    domain.clone().select("backend.type").equals("nix-closure")
}

/// Require a VM artifact with the exact system identity selected by the deployment topology.
fn matching_entry(build: &Build, domain: &NixValue) -> NixValue {
    let matches = NixValue::builtin("filter")
        .call(NixValue::function(|entry| {
            NixValue::if_else(
                entry
                    .clone()
                    .attr_or("backendType", "nix-closure")
                    .equals("hermit"),
                NixValue::null(),
                entry.select("configuration.config.system.build.toplevel"),
            )
            .to_text()
            .equals(domain.clone().select("backend.system.source"))
        }))
        .call(NixValue::builtin("attrValues").call(build.entries.clone()));

    matches.bind(|matches| {
        NixValue::if_else(
            matches.clone().equals(NixValue::list([])),
            NixValue::builtin("throw").call("No closure artifact for machine deployment domain"),
            NixValue::builtin("head").call(matches),
        )
    })
}

/// Construct the runtime manifest using the final host configuration and captured source identity.
fn manifest(context: &ModuleContext, build: &Build) -> NixValue {
    let deployment = context.config.clone().select("airlock.machineDeployment");
    let setup = Tool::Setup.build(&context.pkgs, &build.workspace, &build.source);
    let engine = Tool::Dom0.build(&context.pkgs, &build.workspace, &build.source);

    nix_record! {
        "schema": airlock_machine_core::model::MANIFEST_SCHEMA,
        "profile": deployment.clone().select("profile"),
        "host": context
            .config
            .clone()
            .select("system.build.toplevel")
            .to_text(),
        "setup": nix_text!("{setup}/bin/airlock-setup-config", setup = setup),
        "coordinator": nix_text!("{engine}/bin/airlock-dom0-service", engine = engine),
        "revision": build.metadata.clone().select("revision"),
        "timestamp": build.metadata.clone().select("timestamp"),
        "lockHash": build.metadata.clone().select("lockHash"),
        "retireDomains": deployment.clone().select("retireDomains"),
        "privateVolumeCopies": deployment.clone().select("privateVolumeCopies"),
        "trashRetentionDays": deployment.select("trashRetentionDays"),
    }
}

/// Retain only root descriptors in the transport, while the full release retains VM closures.
fn artifacts(context: &ModuleContext, build: &Build, topology: NixValue) -> NixValue {
    let pkgs = &context.pkgs;
    let run = |name, attrs, script: NixValue| {
        pkgs.clone()
            .select("runCommand")
            .call(name)
            .call(attrs)
            .call(script)
    };
    let json = |name, value| {
        pkgs.clone()
            .select("writeText")
            .call(name)
            .call(NixValue::builtin("toJSON").call(value))
    };
    let roots = context
        .lib
        .clone()
        .select("mapAttrsToList")
        .call(NixValue::function(|name| {
            NixValue::function(|domain| {
                let entry = matching_entry(build, &domain);
                let script = nix_text!(
                    r#"
                {jq}/bin/jq --arg name {name} \
                  --slurpfile artifact {metadata}/root.json \
                  '. + {{($name): $artifact[0]}}' "$out" > next.json
                mv next.json "$out"
            "#,
                    jq = pkgs.clone().select("jq"),
                    name = context.lib.clone().select("escapeShellArg").call(name),
                    metadata = entry.select("rootImage.metadata"),
                );

                NixValue::if_else(is_closure(&domain), script, "")
            })
        }))
        .call(topology.clone().select("domains"));
    let root_artifacts = run(
        "airlock-machine-root-artifacts.json",
        nix_record! {},
        nix_text!(
            r#"
        echo '{{}}' > "$out"
        {roots}
    "#,
            roots = context
                .lib
                .clone()
                .select("concatStringsSep")
                .call("\n")
                .call(roots),
        )
        .into(),
    );

    let hermit_links = context
        .lib
        .clone()
        .select("mapAttrsToList")
        .call(NixValue::function(|name| {
            NixValue::function(|domain| {
                NixValue::if_else(
                    domain.clone().select("backend.type").equals("hermit"),
                    nix_text!(
                        "ln -s {image} \"$out/hermit/\"{name}",
                        image = domain.select("backend.system.source"),
                        name = context.lib.clone().select("escapeShellArg").call(name)
                    ),
                    "",
                )
            })
        }))
        .call(topology.clone().select("domains"));
    let hermit_links = context
        .lib
        .clone()
        .select("concatStringsSep")
        .call("\n")
        .call(hermit_links);

    let hermit_images = context
        .lib
        .clone()
        .select("mapAttrsToList")
        .call(NixValue::function(|_| {
            NixValue::function(|domain| domain.select("backend.system.source"))
        }))
        .call(
            context
                .lib
                .clone()
                .select("filterAttrs")
                .call(NixValue::function(|_| {
                    NixValue::function(|domain| domain.select("backend.type").equals("hermit"))
                }))
                .call(
                    context
                        .config
                        .clone()
                        .select("airlock.qubes.topology.domains"),
                ),
        );

    manifest(context, build).bind(|manifest| {
        let release_manifest = json("airlock-machine-release.json", manifest.clone());
        let transport_manifest = json(
            "airlock-machine-pool-release.json",
            manifest.clone().merge_attrs(nix_record! {
                "guestTransport": "direct-pool-v1",
            }),
        );
        let deployment_topology = topology.clone();
        let topology = json("airlock-machine-topology.json", topology);
        let detached = run(
            "airlock-machine-pool-topology.json",
            nix_record! {
                "__structuredAttrs": true,
                "unsafeDiscardReferences": nix_record! {
                    "out": true,
                },
            },
            nix_text!(
                r#"
        cp {topology} "$out"
    "#,
                topology = topology.clone(),
            )
            .into(),
        );

        detached.bind(|detached| {
            root_artifacts.bind(|root_artifacts| {
                let release = run(
                    "airlock-machine-release",
                    nix_record! {
                        "passthru": nix_record! {
                            "manifest": manifest,
                            "topology": deployment_topology,
                        },
                    },
                    nix_text!(
                        r#"
            mkdir -p "$out/hermit"
            {hermit_links}
            cp {manifest} "$out/release.json"
            cp {topology} "$out/topology.json"
            cp {roots} "$out/root-artifacts.json"
            ln -s {transport} "$out/transport"
        "#,
                        hermit_links = hermit_links.clone(),
                        manifest = release_manifest,
                        topology = topology,
                        roots = root_artifacts.clone(),
                        transport = context
                            .config
                            .clone()
                            .select("system.build.airlockMachineTransport"),
                    )
                    .into(),
                );
                let transport = run(
                    "airlock-machine-transport",
                    nix_record! {},
                    nix_text!(
                        r#"
            mkdir -p "$out/hermit"
            {hermit_links}
            cp {manifest} "$out/release.json"
            cp {topology} "$out/topology.json"
            cp {roots} "$out/root-artifacts.json"
        "#,
                        hermit_links = hermit_links.clone(),
                        manifest = transport_manifest,
                        topology = detached.clone(),
                        roots = root_artifacts,
                    )
                    .into(),
                );

                nix_record! {
                    "system": nix_record! {
                        "build": nix_record! {
                            "airlockMachineRelease": release,
                            "airlockMachineTransport": transport,
                        },
                        // Diskless guests have no pool seed to retain their boot executable.
                        "extraDependencies": NixValue::concat_lists([
                            NixValue::builtin("map")
                                .call(NixValue::function(|kernel| kernel.select("source")))
                                .call(NixValue::builtin("attrValues")
                                    .call(context.config.clone().select("airlock.qubes.kernels"))),
                            hermit_images,
                        ]),
                    },
                    "environment": nix_record! {
                        "etc": nix_record! {
                            "airlock/qubes-topology.json": nix_record! {
                                "text": context.lib.clone().select("mkForce").call(NixValue::null()),
                                "source": context.lib.clone().select("mkDefault").call(detached),
                            },
                        },
                    },
                }
            })
        })
    })
}

/// Expose explicit release dependencies to bootstrap and image integration callers.
pub(crate) fn constructor() -> PackageFunction {
    PackageFunction::from_function_attrs(["source", "apps", "entries", "metadata"], |args| {
        let build = Build {
            source: NixPath::from_expression(args.clone().select("source")),
            workspace: Workspace::new(NixPath::from_expression(args.clone().select("apps"))),
            entries: args.clone().select("entries"),
            metadata: args.select("metadata"),
        };

        (Vec::<(&str, NixValue)>::new(), module(&build))
    })
}
