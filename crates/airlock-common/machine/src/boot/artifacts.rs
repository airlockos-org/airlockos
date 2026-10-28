//! Project every validated guest into the shared verified boot contract.
//! JSON and kernel-source lookup stay here; backend requirements are derived by the verified core.

use super::BootInputs;
use crate::model::GuestBackend;
use airlock_deployment_core::boot::artifacts::{self as verified, Guest, Requirements};
use airlock_nix_core::{identity::GuestName, store_path::StorePath};
use anyhow::{Context, Result};
use serde_json::Value;

/// Complete requirements borrowed from one immutable, validated topology.
///
/// ```compile_fail
/// use airlock_machine_core::boot::artifacts::BootRequirements;
/// /// Wire data must pass topology validation and exhaustive derivation first.
/// fn bypass<'a>() {
///     fn deserialize<T: serde::de::DeserializeOwned>() {}
///     deserialize::<BootRequirements<'a>>();
/// }
/// ```
pub struct BootRequirements<'a> {
    // Complete immutable input, retained so scope and source cannot be substituted.
    inputs: &'a BootInputs,
    // One declaration per guest, in the topology map's canonical order.
    requirements: Requirements,
}

impl BootInputs {
    /// Derive every guest's requirements through an exhaustive backend match.
    pub fn requirements(&self) -> Result<BootRequirements<'_>> {
        let guests = self
            .topology()
            .domains
            .iter()
            .map(|(name, domain)| {
                let system = domain.backend.system.source.to_string();
                Ok(match &domain.backend.guest {
                    GuestBackend::Nixos(backend) => Guest::Nixos {
                        name: name.to_string(),
                        system,
                        root: backend.root.source.to_string(),
                        store: backend.store.source.to_string(),
                        kernel: backend.kernel.name.clone(),
                        kernel_source: self
                            .topology()
                            .kernels
                            .get(&backend.kernel.name)
                            .map(|kernel| {
                                kernel["source"]
                                    .as_str()
                                    .map(str::to_owned)
                                    .context("declared kernel requires a source")
                            })
                            .transpose()?,
                    },
                    GuestBackend::Hermit(backend) => Guest::Hermit {
                        name: name.to_string(),
                        system,
                        executable: backend.artifact.executable.to_string(),
                    },
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(BootRequirements {
            inputs: self,
            requirements: Requirements::derive(guests),
        })
    }
}

impl<'a> BootRequirements<'a> {
    /// Borrow the original full input rather than reconstructing a reduced topology.
    pub fn inputs(&self) -> &'a BootInputs {
        self.inputs
    }

    /// Borrow the complete canonical guest set retained by the verified derivation.
    pub fn guests(&self) -> &[Guest] {
        self.requirements.guests()
    }

    /// Select a declared guest's contract without manufacturing backend-specific requirements.
    pub fn guest(&self, name: &GuestName) -> Result<&Guest> {
        self.guests()
            .iter()
            .find(|guest| guest.name() == name.as_str())
            .context("guest missing from complete boot requirements")
    }

    /// Describe only host objects; Linux guest payloads remain in the prepared guest pool.
    pub fn host_roots(&self) -> Vec<&str> {
        self.guests().iter().filter_map(Guest::host_root).collect()
    }

    /// Consume the complete set when binding an image to its actual packaged inventory.
    pub fn check_image(
        self,
        identity: verified::Identity,
        paths: &[String],
    ) -> Result<verified::CheckedImage> {
        self.requirements
            .check(identity, paths)
            .context("packaged host inventory does not cover the complete selected boot topology")
    }
}

/// Explicit boot selection; a validated topology alone does not identify the profile or host.
pub struct SelectedBoot {
    // Requested normal or independent recovery policy.
    profile: verified::Profile,
    // Exact host generation expected in the retained image records.
    system: StorePath,
    // Complete immutable declaration whose requirements will be checked.
    inputs: BootInputs,
}

impl SelectedBoot {
    /// Validate the complete declaration and bind it to an explicit host and profile.
    pub fn new(profile: verified::Profile, system: StorePath, topology: Value) -> Result<Self> {
        Ok(Self {
            profile,
            system,
            inputs: BootInputs::new(topology)?,
        })
    }

    /// Borrow the validated topology and its original wire representation.
    pub fn inputs(&self) -> &BootInputs {
        &self.inputs
    }

    /// Return the explicitly selected policy; no default can silently select recovery.
    pub fn profile(&self) -> verified::Profile {
        self.profile
    }

    /// Borrow the exact immutable host generation bound to this selection.
    pub fn system(&self) -> &StorePath {
        &self.system
    }
}
