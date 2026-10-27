//! Dependency semantics shared before and after Nix evaluation.
//! This projection needs VM references and defaults, without invented artifact paths.

use crate::model::{Domain, Topology, VmReference};
use airlock_machine_planning::topology::{
    Declaration, Defaults, InvalidTopology, NamedGraph, Reference,
};
use airlock_nix_core::identity::GuestName;
use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// References contributing to a VM's startup and lifecycle dependencies.
#[derive(Clone, Default)]
pub struct VmRelationships {
    /// Network provider, retaining omitted, null, empty and named settings.
    pub netvm: VmReference,
    /// Template provider with the same Qubes reference semantics.
    pub template: VmReference,
    /// Display, audio and disposable-VM references, including explicit reset values.
    pub prefs: BTreeMap<String, Value>,
    /// Qubes device assignments whose backend VMs supply startup dependencies.
    pub devices: Value,
    /// Explicit component service providers interpreted with the same checked reference rules.
    pub service_providers: Vec<Value>,
}

impl From<&Domain> for VmRelationships {
    /// Project evaluated references without changing the runtime wire records.
    fn from(domain: &Domain) -> Self {
        Self {
            netvm: domain.netvm.clone(),
            template: domain.template.clone(),
            prefs: domain.prefs.clone(),
            devices: domain.devices.clone(),
            service_providers: ["airlock-clipboard-authority", "airlock-clipboard-service"]
                .iter()
                .filter_map(|key| domain.features.get(*key).cloned())
                .collect(),
        }
    }
}

/// Machine references sufficient to validate ordering before artifacts are evaluated.
#[derive(Default)]
pub struct Relationships {
    /// VM declarations whose references are interpreted together.
    pub domains: BTreeMap<GuestName, VmRelationships>,
    /// Host defaults inherited only when the VM omits the corresponding setting.
    pub prefs: BTreeMap<String, Value>,
}

impl From<&Topology> for Relationships {
    /// Select the dependency-bearing part of an evaluated topology.
    fn from(topology: &Topology) -> Self {
        Self {
            domains: topology
                .domains
                .iter()
                .map(|(name, domain)| (name.clone(), VmRelationships::from(domain)))
                .collect(),
            prefs: topology.prefs.clone(),
        }
    }
}

impl Relationships {
    /// Resolve all declared dependency kinds; optionally omit display-provider edges.
    /// References outside the declared set remain visible for lifecycle checks.
    pub fn dependencies(
        &self,
        omit_display: bool,
    ) -> Result<BTreeMap<GuestName, BTreeSet<GuestName>>> {
        dependencies(self, omit_display)
    }

    /// Order declared VMs after their dependencies, rejecting cycles.
    /// External references retain the runtime's existing treatment and are not ordered.
    pub fn ordered(&self) -> Result<Vec<GuestName>> {
        ordered(self)
    }
}

/// VM identities referenced by one domain.
type Names = BTreeSet<GuestName>;

/// Decode JSON shape without interpreting inheritance, names or relationships.
fn raw_reference(value: Option<&Value>) -> Reference {
    match value {
        None => Reference::Omitted,
        Some(Value::Null) => Reference::Disabled,
        Some(Value::String(name)) => Reference::Named(name.clone()),
        Some(_) => Reference::Invalid,
    }
}

/// Preserve all four typed wire-reference cases for verified interpretation.
fn typed_reference(value: &VmReference) -> Reference {
    match value {
        VmReference::Inherit => Reference::Omitted,
        VmReference::Disabled => Reference::Disabled,
        VmReference::Empty => Reference::Named(String::new()),
        VmReference::Named(name) => Reference::Named(name.to_string()),
    }
}

impl Relationships {
    /// Decode the five host defaults; both disposable settings share default_dispvm.
    pub(crate) fn defaults(&self) -> Defaults {
        Defaults {
            netvm: raw_reference(self.prefs.get("default_netvm")),
            template: raw_reference(self.prefs.get("default_template")),
            guivm: raw_reference(self.prefs.get("default_guivm")),
            audiovm: raw_reference(self.prefs.get("default_audiovm")),
            dispvm: raw_reference(self.prefs.get("default_dispvm")),
        }
    }

    /// Decode fields without selecting effective providers or assigning graph indices.
    pub(crate) fn declarations(&self, omit_display: &Names) -> Vec<Declaration> {
        self.domains
            .iter()
            .map(|(name, d)| {
                let mut devices = Vec::new();
                // Preserve the existing wire semantics: non-object containers and absent
                // backend fields contribute nothing; a non-array assignment list is invalid.
                if let Some(classes) = d.devices.as_object() {
                    for assignments in classes.values() {
                        match assignments.as_array() {
                            Some(assignments) => devices.extend(
                                assignments
                                    .iter()
                                    .map(|device| raw_reference(device.get("backend"))),
                            ),
                            None => devices.push(Reference::InvalidAssignments),
                        }
                    }
                }

                // The verified reference interpreter handles explicit providers without
                // inheritance. These service edges are not Qubes device assignments.
                devices.extend(
                    d.service_providers
                        .iter()
                        .map(|value| raw_reference(Some(value))),
                );
                Declaration {
                    name: name.to_string(),
                    netvm: typed_reference(&d.netvm),
                    template: typed_reference(&d.template),
                    guivm: raw_reference(d.prefs.get("guivm")),
                    audiovm: raw_reference(d.prefs.get("audiovm")),
                    dispvm: raw_reference(d.prefs.get("dispvm")),
                    default_dispvm: raw_reference(d.prefs.get("default_dispvm")),
                    devices,
                    omit_display: omit_display.contains(name),
                }
            })
            .collect()
    }

    /// Check the proposed lexical universe and compile original decoded relationships.
    fn indexed(&self, extra: &Names, omit_display: &Names) -> Result<NamedGraph> {
        let names = self.domains.keys().chain(extra).cloned().collect::<Names>();
        let graph = NamedGraph::new(
            strings(&names),
            &self.declarations(omit_display),
            &self.defaults(),
            &strings(extra),
        )
        .map_err(|error| relationship_error("machine", error))?;
        Ok(graph)
    }
}

/// Resolve dependencies through the same verified interpreter used by graph construction.
fn dependencies(t: &Relationships, omit_display: bool) -> Result<BTreeMap<GuestName, Names>> {
    let omitted = if omit_display {
        t.domains.keys().cloned().collect()
    } else {
        Names::new()
    };
    let defaults = t.defaults();
    t.declarations(&omitted)
        .iter()
        .map(|d| {
            let providers = airlock_machine_planning::topology::interpret(d, &defaults)
                .map_err(|error| relationship_error(&d.name, error))?;
            Ok((d.name.parse()?, guests(providers)?.into_iter().collect()))
        })
        .collect()
}

/// Retain actionable wire diagnostics without interpreting authority or altering rejection.
fn relationship_error(name: &str, error: InvalidTopology) -> anyhow::Error {
    match error {
        InvalidTopology::DeviceAssignments => anyhow::anyhow!("{name}: invalid device assignments"),
        InvalidTopology::Reference => anyhow::anyhow!("{name}: invalid VM reference"),
        InvalidTopology::Identity => {
            anyhow::anyhow!("{name}: invalid machine relationship identities")
        }
    }
}

/// Return dependency-first startup order for declared guests, rejecting dependency cycles.
fn ordered(t: &Relationships) -> Result<Vec<GuestName>> {
    guests(
        t.indexed(&Names::new(), &Names::new())?
            .ordered(&strings(&t.domains.keys().cloned().collect()), false)
            .context("VM dependency cycle")?,
    )
}

/// Cross the typed/string boundary without resolving names or assigning any graph positions.
pub(crate) fn strings(names: &Names) -> Vec<String> {
    names.iter().map(ToString::to_string).collect()
}

/// Restore ordinary validated wire types after verified named planning.
pub(crate) fn guests(names: Vec<String>) -> Result<Vec<GuestName>> {
    names.into_iter().map(|name| Ok(name.parse()?)).collect()
}
