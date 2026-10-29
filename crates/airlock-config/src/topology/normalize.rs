//! Lower validated topology declarations into the existing runtime wire format.

use rusix::{
    interop::{NixExpression, raw::NixValue},
    nix_record, nix_text,
};

/// Normalize merged declarations without losing store-path dependency contexts.
pub(super) fn topology(config: NixValue) -> NixValue {
    nix_record! {
        "schema": super::SCHEMA,
        "templates": map_attrs(config.clone().select("templates"), |_, template| {
            source(&template).bind(|source| {
                require(
                    template
                        .clone()
                        .select("import")
                        .equals(false)
                        .or(is_set(&source)),
                    "An imported template requires source or sourceRef.",
                    source.merge_attrs(nix_record! {
                        "import": template.clone().select("import"),
                        "skip_start": template.select("skipStart"),
                    }),
                )
            })
        }),
        "kernels": map_attrs(config.clone().select("kernels"), |_, kernel| {
            let value = kernel.select("source");
            require(
                value
                    .clone()
                    .equals(NixValue::null())
                    .equals(false)
                    .and(value.clone().equals("").equals(false)),
                "A Qubes kernel requires a nonempty source directory.",
                nix_record! {
                    "source": value.to_text(),
                },
            )
        }),
        "domains": map_attrs(config.clone().select("domains"), domain),
        "prefs": config.clone().select("prefs"),
        "qrexec_policy": policy(config.select("qrexecPolicy.rules")),
    }
}

/// Select exactly one concrete or candidate-output source for an artifact.
pub(crate) fn source(value: &NixValue) -> NixValue {
    non_null(value.clone(), nix_record! {}).bind(|value| {
        let direct = value.clone().attr_or("source", NixValue::null());
        let reference = value.attr_or("sourceRef", NixValue::null());
        let empty = direct.clone().equals(NixValue::null());
        let raw = NixValue::if_else(empty.clone(), reference.clone(), direct);

        raw.bind(|raw| {
            let result = NixValue::if_else(
                raw.clone().equals(NixValue::null()),
                nix_record! {
                    "source": NixValue::null(),
                    "source_ref": NixValue::null(),
                },
                NixValue::if_else(
                    NixValue::builtin("isAttrs").call(raw.clone()),
                    nix_record! {
                        "source": NixValue::null(),
                        "source_ref": nix_record! {
                            "type": "flake-output",
                            "attr": raw.clone().select("build"),
                            "subpath": raw.clone().select("subpath"),
                        },
                    },
                    nix_record! {
                        "source": raw.to_text(),
                        "source_ref": NixValue::null(),
                    },
                ),
            );

            require(
                empty.or(reference.equals(NixValue::null())),
                "An artifact cannot set both source and sourceRef.",
                result,
            )
        })
    })
}

/// Determine whether either representation of an artifact has been supplied.
pub(crate) fn is_set(source: &NixValue) -> NixValue {
    source
        .clone()
        .select("source")
        .equals(NixValue::null())
        .equals(false)
        .or(source
            .clone()
            .select("source_ref")
            .equals(NixValue::null())
            .equals(false))
}

/// Infer class defaults from the chosen Qubes backend and keep its template relationship consistent.
fn domain(name: NixValue, value: NixValue) -> NixValue {
    let raw_backend = value.clone().select("backend");
    let backend = non_null(raw_backend.clone(), nix_record! {});
    backend.bind(|backend| {
        let kind = backend.clone().attr_or("type", NixValue::null());
        let default_class = NixValue::if_else(
            kind.clone()
                .equals("nix-closure")
                .or(kind.clone().equals("qubes-standalone")),
            "StandaloneVM",
            NixValue::if_else(
                kind.clone().equals("qubes-template-root"),
                "TemplateVM",
                "AppVM",
            ),
        );
        let default_class = NixValue::if_else(kind.clone().equals("hermit"), "HermitVM", default_class);
        let class = non_null(value.clone().select("class"), default_class);
        class.bind(|class| {
            let template = value.clone().select("template");
            let backend_kind = NixValue::if_else(
                raw_backend.equals(NixValue::null()),
                NixValue::if_else(
                    class.clone().equals("AppVM"),
                    "qubes-template",
                    NixValue::if_else(
                        class.clone().equals("TemplateVM"),
                        "qubes-template-root",
                        "qubes-standalone",
                    ),
                ),
                kind,
            );
            let backend_template = non_null(
                backend.clone().attr_or("template", NixValue::null()),
                template.clone(),
            );
            backend_kind.bind(|backend_kind| {
                let resolved_template = NixValue::if_else(
                    backend_kind.clone().equals("qubes-template"),
                    backend_template.clone(),
                    template.clone(),
                );
                let default_prefs = NixValue::if_else(
                    class
                        .clone()
                        .equals("AppVM")
                        .or(class.clone().equals("StandaloneVM")),
                    nix_record! {
                        "autostart": false,
                        "include_in_backups": false,
                    },
                    nix_record! {},
                );
                let ordinary = nix_record! {
                    "type": backend_kind.clone(),
                    "template": NixValue::if_else(
                        backend_kind.clone().equals("qubes-template"),
                        backend_template.clone(),
                        NixValue::null(),
                    ),
                };
                let closure = closure_backend(&name, &backend);
                let normalized = nix_record! {
                    "class": class.clone(),
                    "label": value.clone().select("label"),
                    "netvm": value.clone().select("netvm"),
                    "template": resolved_template,
                    "prefs": default_prefs.merge_attrs(value.clone().select("prefs")),
                    "features": value.clone().select("features"),
                    "services": value.clone().select("services"),
                    "devices": devices(value.select("devices.pci")),
                    "backend": NixValue::if_else(
                        backend_kind.clone().equals("nix-closure"),
                        closure,
                        NixValue::if_else(backend_kind.clone().equals("hermit"), hermit_backend(&backend), ordinary),
                    ),
                };
                let valid = NixValue::if_else(
                    backend_kind.clone().equals("qubes-template"),
                    class
                        .clone()
                        .equals("AppVM")
                        .and(
                            backend_template
                                .clone()
                                .equals(NixValue::null())
                                .equals(false),
                        )
                        .and(
                            template
                                .clone()
                                .equals(NixValue::null())
                                .or(template.clone().equals(backend_template)),
                        ),
                    NixValue::if_else(
                        backend_kind.clone().equals("qubes-template-root"),
                        class
                            .clone()
                            .equals("TemplateVM")
                            .and(template.clone().equals(NixValue::null())),
                        NixValue::if_else(
                            backend_kind
                                .clone()
                                .equals("nix-closure")
                                .or(backend_kind.clone().equals("qubes-standalone")),
                            class.clone()
                                .equals("StandaloneVM")
                                .and(template.clone().equals(NixValue::null())),
                            backend_kind.equals("hermit")
                                .and(class.equals("HermitVM"))
                                .and(template.equals(NixValue::null())),
                        ),
                    ),
                );

                require(
                    valid,
                    "VM class, backend and template must agree.",
                    normalized,
                )
            })
        })
    })
}

/// Preserve closure artifact bindings and the runtime's persistent-volume representation.
fn closure_backend(name: &NixValue, backend: &NixValue) -> NixValue {
    let root = non_null(
        backend.clone().attr_or("root", NixValue::null()),
        nix_record! {},
    );
    let store = non_null(
        backend.clone().attr_or("store", NixValue::null()),
        nix_record! {},
    );
    let state = non_null(
        backend.clone().attr_or("state", NixValue::null()),
        nix_record! {},
    );
    let persistent = non_null(
        state.clone().attr_or("persistent", NixValue::null()),
        nix_text!("{name}-private", name = name.clone()).into(),
    );

    // Read protocol options from the validated configuration. Replacing them with
    // constants would leave invalid definitions lazy and silently accept overrides.
    let root = required_source(&root, "A closure-backed VM requires a root image.").merge_attrs(
        nix_record! {
            "mode": root.clone().attr_or("mode", "qubes-root-image"),
            "read_only": root.clone().attr_or("readOnly", false),
        },
    );

    let store = required_source(
        &store,
        "A closure-backed VM requires an immutable store view.",
    )
    .merge_attrs(nix_record! {
        "mode": store.clone().attr_or("mode", "shared-closure"),
        "mountpoint": store.clone().attr_or("mountpoint", "/nix/store"),
        "device": store.clone().attr_or("device", "/dev/xvde"),
        "blobDevice": store.clone().attr_or("blobDevice", "/dev/xvdf"),
        "viewBackend": store.clone().attr_or("viewBackend", "erofs-objectmap"),
        "blob_device": store.clone().attr_or("blobDevice", "/dev/xvdf"),
        "view_backend": store.clone().attr_or("viewBackend", "erofs-objectmap"),
        "read_only": store.clone().attr_or("readOnly", true),
    });

    nix_record! {
        "type": "nix-closure",
        "template": NixValue::null(),
        "system": required_source(
            &backend.clone().attr_or("system", NixValue::null()),
            "A closure-backed VM requires a NixOS system source.",
        ),
        "kernel": boot_component(backend.clone().attr_or("kernel", NixValue::null()), true),
        "initrd": boot_component(backend.clone().attr_or("initrd", NixValue::null()), false),
        "modules": boot_component(backend.clone().attr_or("modules", NixValue::null()), false),
        "root": root,
        "store": store,
        "state": nix_record! {
            "persistent": persistent,
            "persistent_size": state.clone().attr_or("persistentSize", NixValue::null()),
            "volatile": state.attr_or("volatile", NixValue::null()),
        },
    }
}

/// Project the diskless boot contract and reject unsupported Linux configuration before it disappears.
fn hermit_backend(backend: &NixValue) -> NixValue {
    let no_linux = [
        "template", "kernel", "initrd", "modules", "root", "store", "state",
    ]
    .into_iter()
    .fold(true.into(), |valid: NixValue, field| {
        valid.and(
            backend
                .clone()
                .attr_or(field, NixValue::null())
                .equals(NixValue::null()),
        )
    });
    let artifact = backend.clone().select("artifact");
    require(
        no_linux.and(artifact.clone().equals(NixValue::null()).equals(false)),
        "Hermit requires an executable descriptor and cannot use Linux boot or storage fields.",
        nix_record! {
            "type": "hermit",
            "system": required_source(&backend.clone().select("system"), "Hermit requires an immutable system source."),
            "artifact": artifact,
            "scratch": backend.clone().attr_or("scratch", NixValue::null()),
        },
    )
}

/// Require a concrete or candidate artifact while retaining its original store dependency context.
fn required_source(value: &NixValue, message: &str) -> NixValue {
    source(value).bind(|source| require(is_set(&source), message, source))
}

/// A kernel needs a name or artifact; optional initrd and module bindings may remain empty.
fn boot_component(value: NixValue, required: bool) -> NixValue {
    let value = non_null(value, nix_record! {});
    let name = value.clone().attr_or("name", NixValue::null());

    source(&value).bind(|source| {
        let output = source.clone().merge_attrs(nix_record! {
            "name": name.clone(),
        });
        if !required {
            return output;
        }

        require(
            name.equals(NixValue::null())
                .equals(false)
                .or(is_set(&source)),
            "A closure-backed VM requires a kernel name or artifact.",
            output,
        )
    })
}

/// Convert scalar device options to the string representation expected by Qubes.
fn devices(pci: NixValue) -> NixValue {
    let devices = NixValue::builtin("map")
        .call(NixValue::function(|device| {
            let options = map_attrs(device.clone().select("options"), |_, value| {
                NixValue::if_else(
                    NixValue::builtin("isBool").call(value.clone()),
                    NixValue::if_else(value.clone(), "True", "False"),
                    value.to_text(),
                )
            });

            device.merge_attrs(nix_record! {
                "options": options,
            })
        }))
        .call(pci);

    nix_record! {
        "pci": devices,
    }
}

/// Restrict topology-owned permissions and append one catch-all denial per service when needed.
fn policy(rules: NixValue) -> NixValue {
    let rules = NixValue::builtin("map")
        .call(NixValue::function(|rule| {
            let allow = rule.clone().select("action").equals("allow");
            let concrete = rule
                .clone()
                .select("source")
                .equals("@anyvm")
                .equals(false)
                .and(rule.clone().select("target").equals("@anyvm").equals(false));
            let permitted = rule
                .clone()
                .select("target")
                .equals("dom0")
                .equals(false)
                .and(allow.equals(false).or(concrete));

            require(
                permitted,
                "Topology policy cannot target dom0 or grant wildcard permissions.",
                rule,
            )
        }))
        .call(rules);

    rules.bind(|rules| {
        let services = NixValue::builtin("attrNames").call(
            NixValue::builtin("listToAttrs").call(
                NixValue::builtin("map")
                    .call(NixValue::function(|rule| {
                        nix_record! {
                            "name": rule.select("service"),
                            "value": true,
                        }
                    }))
                    .call(rules.clone()),
            ),
        );
        let missing = NixValue::builtin("filter")
            .call(NixValue::function(|service| {
                NixValue::builtin("any")
                    .call(NixValue::function(|rule| {
                        rule.clone()
                            .select("service")
                            .equals(service)
                            .and(rule.clone().select("argument").equals("*"))
                            .and(rule.clone().select("source").equals("@anyvm"))
                            .and(rule.clone().select("target").equals("@anyvm"))
                            .and(rule.select("action").equals("deny"))
                    }))
                    .call(rules.clone())
                    .equals(false)
            }))
            .call(services);
        let denied = NixValue::builtin("map")
            .call(NixValue::function(|service| {
                nix_record! {
                    "service": service,
                    "argument": "*",
                    "source": "@anyvm",
                    "target": "@anyvm",
                    "action": "deny",
                }
            }))
            .call(missing);

        nix_record! {
            "rules": NixValue::concat_lists([rules, denied]),
        }
    })
}

/// Map named values lazily with a Rust-authored transformation.
pub(crate) fn map_attrs(
    value: NixValue,
    transform: impl FnOnce(NixValue, NixValue) -> NixValue,
) -> NixValue {
    NixValue::builtin("mapAttrs")
        .call(NixValue::function(|name| {
            NixValue::function(|value| transform(name, value))
        }))
        .call(value)
}

/// Apply a fallback only to explicit null, preserving false and empty values.
pub(crate) fn non_null(value: NixValue, fallback: NixValue) -> NixValue {
    value.bind(|value| NixValue::if_else(value.clone().equals(NixValue::null()), fallback, value))
}

/// Reject an inconsistent relationship at the point its normalized value is demanded.
pub(crate) fn require(condition: NixValue, message: &str, value: NixValue) -> NixValue {
    NixValue::if_else(condition, value, NixValue::builtin("throw").call(message))
}
