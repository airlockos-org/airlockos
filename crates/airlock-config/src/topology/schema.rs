//! Describe the accepted machine topology once for module merging and exported configuration validation.

use rusix::{interop::raw::NixValue, nix_record};

/// Qubes VM classes supported by the existing materialization workflow.
pub(super) const CLASSES: &[&str] = &["AppVM", "StandaloneVM", "TemplateVM", "HermitVM"];

/// Backend protocols understood by Airlock's Qubes setup and runtime tools.
pub(super) const BACKENDS: &[&str] = &[
    "qubes-template",
    "qubes-template-root",
    "qubes-standalone",
    "nix-closure",
    "hermit",
];

/// Qubes labels accepted by the runtime topology contract.
pub(super) const LABELS: &[&str] = &[
    "red",
    "orange",
    "yellow",
    "green",
    "gray",
    "blue",
    "purple",
    "black",
    "khaki",
    "light-gray",
];

/// Persistent assignment modes delegated to Qubes device management.
pub(super) const ASSIGNMENTS: &[&str] = &["auto-attach", "ask-to-attach", "required"];

/// Qubes device identity matching strategies.
pub(super) const MATCHES: &[&str] = &["port-and-device", "port", "device"];

/// Transport operations whose policy is owned by bootstrap, never by a candidate topology.
pub(super) const RESERVED_SERVICES: &[&str] = &[
    "airlock.Config.CandidateExport",
    "airlock.Config.ValidateCandidate",
    "airlock.Config.InputsImport",
    "airlock.Config.ArchiveCandidate",
    "airlock.Config.ArchiveDeployment",
];

/// Construct option declarations with the caller's authoritative NixOS library.
pub(crate) struct Schema<'a> {
    /// Library supplying the actual option merge and validation semantics.
    pub lib: &'a NixValue,
}

impl Schema<'_> {
    /// Resolve an upstream NixOS type by its documented name.
    pub fn kind(&self, name: &str) -> NixValue {
        self.lib.clone().select("types").select(name)
    }

    /// Permit null in addition to a concrete option type.
    pub fn nullable(&self, kind: NixValue) -> NixValue {
        self.kind("nullOr").call(kind)
    }

    /// Validate every list element while retaining normal NixOS list merging.
    pub fn list(&self, kind: NixValue) -> NixValue {
        self.kind("listOf").call(kind)
    }

    /// Validate every attribute value without closing the set of keys.
    pub fn attrs(&self, kind: NixValue) -> NixValue {
        self.kind("attrsOf").call(kind)
    }

    /// Close a string type over a finite set of supported protocol values.
    pub fn enumeration(&self, values: &[&str]) -> NixValue {
        self.kind("enum").call(strings(values))
    }

    /// Reject strings outside the protocol's exact spelling constraints.
    pub fn matching(&self, pattern: &str) -> NixValue {
        self.kind("strMatching").call(pattern)
    }

    /// Declare a required or defaulted value with its domain purpose attached.
    pub fn option(&self, kind: NixValue, default: Option<NixValue>, description: &str) -> NixValue {
        let mut fields = vec![("type", kind), ("description", description.into())];
        if let Some(default) = default {
            fields.push(("default", default));
        }

        self.lib
            .clone()
            .select("mkOption")
            .call(NixValue::record(fields))
    }

    /// Treat a nested record as a NixOS submodule with unknown fields rejected.
    pub fn record(&self, options: NixValue) -> NixValue {
        self.kind("submodule").call(nix_record! {
            "options": options,
        })
    }

    /// Supply a null default for an optional field.
    pub fn optional(&self, kind: NixValue, description: &str) -> NixValue {
        self.option(self.nullable(kind), Some(NixValue::null()), description)
    }

    /// Restrict scalar settings to values represented directly by JSON and Qubes properties.
    fn scalar(&self, nullable: bool) -> NixValue {
        let kind = self.kind("oneOf").call(NixValue::list([
            self.kind("bool"),
            self.kind("int"),
            self.kind("str"),
        ]));

        if nullable { self.nullable(kind) } else { kind }
    }

    /// Validate a Qubes VM or template identity rather than a free-form shell token.
    fn vm_name(&self) -> NixValue {
        self.matching("[A-Za-z][A-Za-z0-9_.-]*")
    }

    /// Validate protocol setting keys and volume identifiers.
    fn loose_name(&self) -> NixValue {
        self.matching("[A-Za-z0-9_.:+-]+")
    }

    /// Validate attribute names as well as their values without changing NixOS merging.
    pub fn named_attrs(&self, value: NixValue, pattern: &str) -> NixValue {
        let names = NixValue::function(|attrs| {
            NixValue::builtin("all")
                .call(NixValue::function(|name| {
                    NixValue::builtin("match")
                        .call(pattern)
                        .call(name)
                        .equals(NixValue::null())
                        .equals(false)
                }))
                .call(NixValue::builtin("attrNames").call(attrs))
        });

        self.kind("addCheck").call(self.attrs(value)).call(names)
    }

    /// Constrain a candidate flake output and any path inside its resulting artifact.
    pub fn source_reference(&self) -> NixValue {
        let relative = self
            .kind("addCheck")
            .call(self.kind("str"))
            .call(NixValue::function(|path| {
                let segments = NixValue::builtin("split").call("/").call(path.clone());
                let safe = NixValue::builtin("all")
                    .call(NixValue::function(|part| {
                        NixValue::builtin("isString")
                            .call(part.clone())
                            .equals(false)
                            .or(part
                                .clone()
                                .equals(".")
                                .equals(false)
                                .and(part.equals("..").equals(false)))
                    }))
                    .call(segments);

                path.clone().equals("").or(NixValue::builtin("match")
                    .call("[A-Za-z0-9_.+-]+(/[A-Za-z0-9_.+-]+)*")
                    .call(path)
                    .equals(NixValue::null())
                    .equals(false)
                    .and(safe))
            }));

        self.record(nix_record! {
            "type": self.option(
                self.enumeration(&["flake-output"]),
                Some("flake-output".into()),
                "Artifact reference protocol.",
            ),
            "build": self.option(
                self.matching(r"[A-Za-z0-9_+-]+(\.[A-Za-z0-9_+-]+)*"),
                None,
                "Candidate flake output attribute building the artifact.",
            ),
            "subpath": self.option(
                relative,
                Some("".into()),
                "Safe relative path within the output.",
            ),
        })
    }

    /// Accept an existing source path or a deferred candidate output reference.
    fn source_type(&self) -> NixValue {
        self.kind("oneOf").call(NixValue::list([
            self.kind("path"),
            self.kind("str"),
            self.source_reference(),
        ]))
    }

    /// Declare mutually exclusive concrete and deferred artifact bindings.
    pub fn source_fields(&self) -> NixValue {
        nix_record! {
            "source": self.optional(
                self.source_type(),
                "Concrete artifact or candidate output reference.",
            ),
            "sourceRef": self.optional(
                self.source_reference(),
                "Candidate output used when no concrete source is given.",
            ),
        }
    }

    /// Describe importable Qubes templates with explicit startup policy.
    pub fn templates(&self) -> NixValue {
        self.named_attrs(
            self.record(self.source_fields().merge_attrs(nix_record! {
                "import": self.option(
                    self.kind("bool"),
                    Some(false.into()),
                    "Import the template if it is absent.",
                ),
                "skipStart": self.option(
                    self.kind("bool"),
                    Some(true.into()),
                    "Skip initial template startup during import.",
                ),
            })),
            "[A-Za-z][A-Za-z0-9_.-]*",
        )
    }

    /// Describe kernel directories keyed by their Qubes kernel identity.
    pub fn kernels(&self) -> NixValue {
        self.named_attrs(
            self.record(nix_record! {
                "source": self.optional(
                    self.kind("oneOf")
                        .call(NixValue::list([self.kind("path"), self.kind("str")])),
                    "Directory containing the Qubes VM kernel files.",
                ),
            }),
            "[^/]+",
        )
    }

    /// Declare kernel, initrd or module-directory bindings with optional named identity.
    fn boot_component(&self) -> NixValue {
        self.record(self.source_fields().merge_attrs(nix_record! {
            "name": self.optional(
                self.loose_name(),
                "Boot component identity, such as a Qubes kernel name.",
            ),
        }))
    }

    /// Describe the immutable store view expected by the existing Qubes storage adapter.
    fn store(&self) -> NixValue {
        self.record(self.source_fields().merge_attrs(nix_record! {
            "mode": self.option(
                self.enumeration(&["shared-closure"]),
                Some("shared-closure".into()),
                "Shared closure protocol.",
            ),
            "mountpoint": self.option(
                self.enumeration(&["/nix/store"]),
                Some("/nix/store".into()),
                "VM mountpoint for the immutable closure.",
            ),
            "device": self.option(
                self.enumeration(&["/dev/xvde"]),
                Some("/dev/xvde".into()),
                "Block device exposing the closure view.",
            ),
            "blobDevice": self.option(
                self.enumeration(&["/dev/xvdf"]),
                Some("/dev/xvdf".into()),
                "Block device exposing immutable data blobs.",
            ),
            "viewBackend": self.option(
                self.enumeration(&["erofs-objectmap"]),
                Some("erofs-objectmap".into()),
                "Runtime store representation.",
            ),
            "readOnly": self.option(
                self.enumeration_bool(true),
                Some(true.into()),
                "Closure views must be read-only.",
            ),
        }))
    }

    /// Restrict a boolean when a storage protocol requires a single supported value.
    fn enumeration_bool(&self, expected: bool) -> NixValue {
        self.kind("addCheck")
            .call(self.kind("bool"))
            .call(NixValue::function(|value| value.equals(expected)))
    }

    /// Require a complete immutable Hermit image identity before lowering to deployment.
    fn hermit_artifact(&self) -> NixValue {
        let mut fields = vec![
            (
                "schema",
                self.option(
                    self.enumeration(&["airlock.hermit-pvh.v1"]),
                    None,
                    "Hermit image descriptor version.",
                ),
            ),
            (
                "authority",
                self.option(
                    self.enumeration(&["disconnected", "normal"]),
                    None,
                    "Production machine images cannot provision laboratory authority.",
                ),
            ),
            (
                "bytes",
                self.option(
                    self.kind("ints.positive"),
                    None,
                    "Exact bounded executable length, checked again during admission.",
                ),
            ),
        ];
        for (name, description) in [
            ("executable", "Immutable store file loaded by Xen."),
            ("sha256", "SHA-256 of the complete executable."),
            ("source_revision", "Reviewed application Git revision."),
            (
                "integration_revision",
                "Pinned external Hermit/Xen Git revision.",
            ),
            ("build_lock", "SHA-256 of the integration dependency lock."),
        ] {
            fields.push((name, self.option(self.kind("str"), None, description)));
        }
        self.record(NixValue::record(fields))
    }

    /// Define the full set of backend fields before normalization chooses the selected protocol.
    fn backend(&self) -> NixValue {
        let root = self.record(self.source_fields().merge_attrs(nix_record! {
            "mode": self.option(
                self.enumeration(&["qubes-root-image"]),
                Some("qubes-root-image".into()),
                "Qubes writable root-image materialization.",
            ),
            "readOnly": self.option(
                self.enumeration_bool(false),
                Some(false.into()),
                "Qubes root images are imported as writable volumes.",
            ),
        }));
        let state = self.record(nix_record! {
            "persistent": self.optional(self.loose_name(), "Persistent private-volume identity."),
            "persistentSize": self.optional(
                self.kind("ints.positive"),
                "Desired private-volume size in bytes.",
            ),
            "volatile": self.optional(self.loose_name(), "Optional volatile-volume identity."),
        });

        self.record(nix_record! {
            "type": self.optional(self.enumeration(BACKENDS), "Domain construction protocol."),
            "template": self.optional(
                self.vm_name(),
                "Template identity for a template-backed VM.",
            ),
            "system": self.optional(self.record(self.source_fields()), "Immutable guest system object."),
            "artifact": self.optional(self.hermit_artifact(), "Authenticated Hermit PVH executable."),
            "kernel": self.optional(
                self.boot_component(),
                "Required kernel name or artifact for closure-backed VMs.",
            ),
            "initrd": self.optional(self.boot_component(), "Optional separate initrd artifact."),
            "modules": self.optional(self.boot_component(), "Optional kernel-module artifact."),
            "root": self.optional(root, "Qubes-compatible root image."),
            "store": self.optional(self.store(), "Read-only closure view."),
            "state": self.optional(state, "Persistent and volatile state bindings."),
        })
    }

    /// Define persistent PCI assignments using upstream Qubes matching and attachment modes.
    fn devices(&self) -> NixValue {
        let device = self.record(nix_record! {
            "backend": self.option(
                self.vm_name(),
                Some("dom0".into()),
                "VM exposing the PCI device.",
            ),
            "id": self.option(
                self.loose_name(),
                None,
                "Qubes PCI device identity from machine inventory.",
            ),
            "match": self.option(
                self.enumeration(MATCHES),
                Some("port".into()),
                "Parts of the device identity that must match.",
            ),
            "mode": self.option(
                self.enumeration(ASSIGNMENTS),
                Some("required".into()),
                "Persistent Qubes attachment mode.",
            ),
            "options": self.option(
                self.named_attrs(self.scalar(false), "[A-Za-z0-9_.:+-]+"),
                Some(nix_record! {}),
                "Device-assignment options passed through Qubes.",
            ),
        });

        self.record(nix_record! {
            "pci": self.option(
                self.list(device),
                Some(NixValue::list([])),
                "Persistent PCI assignments.",
            ),
        })
    }

    /// Describe one VM's Qubes identity, resources, capabilities and boot artifacts.
    pub fn domains(&self) -> NixValue {
        let scalars = self.named_attrs(self.scalar(true), "[A-Za-z0-9_.:+-]+");
        let domain = self.record(nix_record! {
            "backend": self.optional(self.backend(), "Explicit VM construction backend."),
            "class": self.optional(
                self.enumeration(CLASSES),
                "Qubes class inferred from the backend when omitted.",
            ),
            "template": self.optional(self.vm_name(), "TemplateVM used by an AppVM."),
            "label": self.option(
                self.enumeration(LABELS),
                Some("red".into()),
                "Qubes trust-domain label.",
            ),
            "netvm": self.optional(
                self.vm_name(),
                "Network provider; null explicitly disables networking.",
            ),
            "prefs": self.option(scalars.clone(), Some(nix_record! {}), "Qubes property overrides."),
            "features": self.option(scalars, Some(nix_record! {}), "Features advertised to Qubes."),
            "services": self.option(
                self.named_attrs(self.kind("bool"), "[A-Za-z0-9_.:+-]+"),
                Some(nix_record! {}),
                "Qubes service enablement.",
            ),
            "devices": self.option(
                self.devices(),
                Some(nix_record! {}),
                "Persistent Qubes device assignments.",
            ),
        });

        self.named_attrs(domain, "[A-Za-z][A-Za-z0-9_.-]*")
    }

    /// Describe topology-owned policy; privileged bootstrap services remain outside this interface.
    pub fn policy(&self) -> NixValue {
        let service = self
            .kind("addCheck")
            .call(self.matching(r"airlock\.[A-Za-z0-9_.-]+"))
            .call(NixValue::function(|service| {
                NixValue::builtin("elem")
                    .call(service)
                    .call(strings(RESERVED_SERVICES))
                    .equals(false)
            }));
        let rule = self.record(nix_record! {
            "service": self.option(service, None, "Topology-owned Airlock RPC service."),
            "argument": self.option(
                self.matching(r"\*|[A-Za-z0-9_.:+-]+"),
                Some("*".into()),
                "Qubes service argument matcher.",
            ),
            "source": self.option(
                self.matching("@anyvm|[A-Za-z][A-Za-z0-9_.-]*"),
                None,
                "Source VM or wildcard for a deny rule.",
            ),
            "target": self.option(
                self.matching("@anyvm|[A-Za-z][A-Za-z0-9_.-]*"),
                None,
                "Target VM; topology policy cannot target dom0.",
            ),
            "action": self.option(
                self.enumeration(&["allow", "deny"]),
                None,
                "Qubes authorization decision.",
            ),
        });

        self.record(nix_record! {
            "rules": self.option(
                self.list(rule),
                Some(NixValue::list([])),
                "Ordered topology-owned policy rules.",
            ),
        })
    }

    /// Export the closed topology configuration schema used by both module and standalone callers.
    pub fn fields(&self) -> NixValue {
        nix_record! {
            "schema": self.option(
                self.enumeration(&[super::SCHEMA]),
                Some(super::SCHEMA.into()),
                "Topology wire format.",
            ),
            "templates": self.option(
                self.templates(),
                Some(nix_record! {}),
                "Templates imported before VM setup.",
            ),
            "kernels": self.option(self.kernels(), Some(nix_record! {}), "Qubes kernel directories."),
            "domains": self.option(self.domains(), Some(nix_record! {}), "Declared Qubes VMs."),
            "prefs": self.option(
                self.named_attrs(self.scalar(true), "[A-Za-z0-9_.:+-]+"),
                Some(nix_record! {}),
                "Global Qubes preferences.",
            ),
            "qrexecPolicy": self.option(self.policy(), Some(nix_record! {}), "Topology-owned Qubes policy."),
        }
    }
}

/// Convert fixed protocol choices without losing declaration order.
fn strings(values: &[&str]) -> NixValue {
    NixValue::list(values.iter().map(|value| (*value).into()))
}
