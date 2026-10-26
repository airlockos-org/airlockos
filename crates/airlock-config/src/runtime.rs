//! Author an editable controller candidate and emit the artifacts admitted by the runtime protocol.

mod outputs;

use crate::model::{HostPlatform, MachineSnapshot, VmHandle};
use rusix::{nix_record, nixos::NixosModule};
use std::{collections::BTreeMap, path::Path};

/// Requested activation class for a controller-authored host change.
#[derive(Clone, Copy, Default)]
pub enum Activation {
    /// Switch ordinary package/file changes live; stage arbitrary modules for the next boot.
    #[default]
    Automatic,
    /// Explicitly request a live NixOS switch.
    Switch,
    /// Stage the generation for the next boot.
    Boot,
}

/// Explicit operation on an existing host service after candidate activation.
#[derive(Clone, Copy)]
pub enum ServiceAction {
    /// Restart the service so it consumes the new configuration.
    Restart,
    /// Ask the service to reload its configuration without restarting.
    Reload,
}

/// One service operation and the explanation retained in the deployment plan.
struct ServiceRequest {
    /// Systemd operation selected by the candidate author.
    action: ServiceAction,
    /// Human-readable reason for the operation.
    reason: String,
}

/// Admitted local source trees made available by the configuration-input transport.
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Sources {
    /// Pinned nixpkgs source used for target package and module evaluation.
    pub nixpkgs: String,
    /// Pinned compatibility package source used for Qubes libvirt.
    pub libvirt: String,
    /// Upstream Qubes modules and overlays.
    pub qubes: String,
    /// Machine integration patches, assets and generated seed artifacts.
    pub machine: String,
    /// Native application and authoring workspace.
    pub applications: String,
}

impl Default for Sources {
    /// Use the read-only input mount supplied to configuration VMs.
    fn default() -> Self {
        let root = "/etc/airlock/config-inputs";

        Self {
            nixpkgs: format!("{root}/nixpkgs"),
            libvirt: format!("{root}/nixpkgs-libvirt_10_5"),
            qubes: format!("{root}/nixos-qubes"),
            machine: format!("{root}/airlock-support"),
            applications: format!("{root}/airlock-apps"),
        }
    }
}

/// One validated VM snapshot plus the host changes and metadata submitted with it.
/// Commit the Rust source; prepare its Nix interface separately before validation.
pub struct Candidate {
    /// Final VM identities, resources and connections; no mutable authoring handles remain.
    machine: MachineSnapshot,
    /// Human-readable message recorded by the applied host profile.
    message: String,
    /// Host package attributes resolved against the selected target package set.
    packages: Vec<String>,
    /// Host configuration files keyed by their path beneath /etc.
    files: BTreeMap<String, String>,
    /// Additional host modules whose live-switch safety is not inferred from arbitrary code.
    modules: Vec<NixosModule>,
    /// Requested host activation classification.
    activation: Activation,
    /// Explicit live service operations, indexed by validated systemd unit names.
    services: BTreeMap<String, ServiceRequest>,
    /// Explicit dom0-to-VM RPC grants, restricted to declarations in the captured machine.
    host_calls: BTreeMap<String, Vec<String>>,
}

impl Candidate {
    /// Start a candidate from a complete nested-machine snapshot.
    /// Physical-machine deployment uses the machine release workflow instead.
    pub fn new(machine: MachineSnapshot) -> Result<Self, String> {
        if !matches!(
            machine.host().map(|host| host.platform),
            Some(HostPlatform::Bootstrap)
        ) {
            return Err("a runtime candidate requires a bootstrap host snapshot".into());
        }

        Ok(Self {
            machine,
            message: "initial".into(),
            packages: Vec::new(),
            files: BTreeMap::new(),
            modules: Vec::new(),
            activation: Activation::Automatic,
            services: BTreeMap::new(),
            host_calls: BTreeMap::new(),
        })
    }

    /// Record a message shown in the admitted profile and deployment metadata.
    pub fn set_message(&mut self, message: impl Into<String>) {
        self.message = message.into();
    }

    /// Install one package from the target package set; package changes can switch live by default.
    pub fn add_host_package(&mut self, attribute: impl Into<String>) {
        self.packages.push(attribute.into());
    }

    /// Install a host text file beneath /etc; reject absolute paths and directory traversal.
    pub fn add_host_file(&mut self, path: &str, text: impl Into<String>) -> Result<(), String> {
        if path.is_empty()
            || Path::new(path)
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err("host file paths must be relative paths beneath /etc".into());
        }

        self.files.insert(path.to_owned(), text.into());
        Ok(())
    }

    /// Append a normal Rusix NixOS contribution; automatic activation stages these changes for boot.
    pub fn add_host_module(&mut self, module: NixosModule) {
        self.modules.push(module);
    }

    /// Request a live operation on a host service after activation.
    /// Reject names that could introduce additional arguments into a systemd operation.
    pub fn add_service_action(
        &mut self,
        name: &str,
        action: ServiceAction,
        reason: impl Into<String>,
    ) -> Result<(), String> {
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.:+@-".contains(&byte))
        {
            return Err("service names must be systemd unit identities".into());
        }

        self.services.insert(
            name.to_owned(),
            ServiceRequest {
                action,
                reason: reason.into(),
            },
        );
        Ok(())
    }

    /// Permit dom0 to call one named RPC on a VM in this candidate.
    /// Wildcard services and foreign or subsequently registered handles are rejected.
    /// The topology schema applies the remaining reserved-service restrictions.
    pub fn allow_host_call<R>(
        &mut self,
        service: &str,
        target: &VmHandle<R>,
    ) -> Result<(), String> {
        if service.is_empty()
            || !service
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        {
            return Err("RPC grants require a concrete service name".into());
        }
        if !self.machine.contains(target) {
            return Err(format!(
                "RPC target {name} is absent from this candidate",
                name = target.name()
            ));
        }

        self.host_calls
            .entry(service.into())
            .or_default()
            .push(target.name().to_string());
        Ok(())
    }

    /// Override the conservative automatic activation decision when the author knows the change class.
    pub fn set_activation(&mut self, activation: Activation) {
        self.activation = activation;
    }

    /// Emit the candidate flake and VM modules into a prepared source tree.
    /// Generated files are build artifacts and must stay in ignored build directories.
    pub fn export(&self, directory: &Path) -> Result<(), Box<dyn std::error::Error>> {
        std::fs::create_dir_all(directory.join("generated"))?;
        crate::export_installation(&self.machine, &directory.join("generated"))?;
        for (index, module) in self.modules.iter().enumerate() {
            let artifact = crate::compile_module(module)
                .map_err(|diagnostic| diagnostic.render(Path::new(".")))?;
            std::fs::write(
                directory.join(format!("generated/host-{index}.nix")),
                artifact.module.source,
            )?;
        }

        let sources: Sources =
            serde_json::from_slice(&std::fs::read(directory.join("config-inputs.json"))?)?;
        let generated = crate::compile(self.configuration(&sources))
            .map_err(|diagnostic| diagnostic.render(Path::new(".")))?;
        std::fs::write(directory.join("flake.nix"), generated.source)?;

        Ok(())
    }

    /// Describe the static flake input boundary and Rust-authored candidate outputs.
    fn configuration(&self, sources: &Sources) -> rusix::Config {
        rusix::Config::new()
            .set_dynamic("description", "Airlock runtime configuration candidate")
            .set_dynamic(
                "inputs",
                nix_record! {
                    "hermit-xen": crate::hermit_build::input(),
                    "nixpkgs": nix_record! {
                        "url": format!("path:{path}", path = sources.nixpkgs),
                    },
                },
            )
            .set_dynamic("outputs", outputs::configuration(self, sources))
    }

    /// Resolve activation mode without pretending arbitrary modules are safe to switch live.
    fn switch_action(&self) -> &'static str {
        match self.activation {
            Activation::Automatic if self.modules.is_empty() => "switch",
            Activation::Switch => "switch",
            Activation::Automatic | Activation::Boot => "boot",
        }
    }

    /// Explain the chosen mode in the deployment plan.
    fn reason(&self) -> &'static str {
        match self.activation {
            Activation::Automatic if self.modules.is_empty() => {
                "dom0 host userland config can be applied live"
            }
            Activation::Automatic => "dom0 host config includes arbitrary NixOS modules",
            Activation::Switch => "author explicitly requested a live host switch",
            Activation::Boot => "author explicitly requested the next host boot generation",
        }
    }
}
