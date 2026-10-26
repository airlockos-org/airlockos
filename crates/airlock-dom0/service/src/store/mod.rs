//! A storage generation is a read-only view of a host or guest's Nix store files.
//! Running and retained generations keep shared data alive until it can be reclaimed.
//! The coordinator supplies deployment decisions; this boundary owns storage
//! operations, image preparation and early boot through one native implementation.
//! Loaded generations, guest installation receipts and resolved roots cross internal
//! boundaries as distinct records. JSON is decoded at ingress and encoded at CLI
//! egress; diagnostic extensions do not supply identity or daemon-restoration decisions.

mod cli;

mod response;

mod host_receipt;

pub(crate) use host_receipt::HostReceipt;

pub(crate) use response::{
    AdmissionReceipt, GenerationMatch, GenerationMatchOutcome, GenerationMatchSchema, ResolvedRoot,
};

mod domain;

pub(crate) mod qubes_inspect;

pub(crate) mod qubes_volume;

mod domain_cli;

mod artifacts;

mod artifact_cli;

mod pool_cli;

mod builder;

mod builder_cli;

mod database;

mod host;

mod host_cli;

mod host_boot;

mod boot_artifacts;

pub(crate) mod boot_cache;

mod presentation;

mod host_machine;

mod host_install;

mod prepared;

mod progress;

mod image_cli;

mod image_cache;

pub(crate) mod handoff;

mod fs;

mod generations;

mod maintenance;

mod protection;

mod tracing;

mod physical;

mod relocation;

mod segment_retirement;

mod logical_retirement;

mod runtime;

mod mounts;

mod root;

mod segments;

mod records;

mod views;

pub(crate) use airlock_deployment_core::attachment::runtime_namespace;

pub(crate) use cli::{Command, execute};

use crate::{
    model::{Backend, GenerationId, StorePath},
    process::Runner,
};
use airlock_nix_core::identity::{GuestName, LockHash};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    ffi::OsString,
    path::{Path, PathBuf},
    time::Duration,
};

/// Encode every immutable reference for the private, locked storage receiver.
fn protection_arguments(
    references: &[airlock_deployment_core::retention::Protection],
) -> Vec<String> {
    use airlock_deployment_core::retention::Protection;
    let mut args = Vec::new();
    for reference in references {
        match reference {
            Protection::Exact(g) => {
                args.push("--protect-generation".into());
                args.push(format!(
                    "{domain}:{number}",
                    domain = g.domain,
                    number = g.number
                ));
            }
            Protection::System { domain, system } => {
                args.push("--protect-system".into());
                args.push(format!("{domain}:{system}"));
            }
        }
    }
    args
}

/// Reject root-image descriptors with unknown fields, formats or invalid sizes.
pub(crate) fn validate_root_descriptor(value: &Value) -> Result<()> {
    let object = value.as_object().context("invalid root descriptor")?;
    ensure!(
        object.keys().map(String::as_str).collect::<BTreeSet<_>>()
            == BTreeSet::from([
                "schema",
                "sha256",
                "logical_bytes",
                "payload_bytes",
                "format",
                "boot_abi"
            ]),
        "invalid root descriptor fields"
    );
    let _: LockHash = serde_json::from_value(value["sha256"].clone())?;
    let logical = value["logical_bytes"]
        .as_u64()
        .context("invalid root logical size")?;
    let payload = value["payload_bytes"]
        .as_u64()
        .context("invalid root payload size")?;
    let header = b"AIRLOCK-ROOT-SPARSE-1\n".len() as u64 + 8;
    ensure!(
        value["schema"] == "airlock.root-artifact.v1"
            && value["format"] == "ext4"
            && value["boot_abi"] == "airlock.nix-closure-root.v1"
            && logical > 0
            && logical <= 64 * 1024u64.pow(3)
            && payload >= header
            && payload <= logical + 12 * logical.div_ceil(65536) + header,
        "invalid root artifact identity or size"
    );
    Ok(())
}

/// Storage operations using the coordinator's existing bounded process runner.
/// This shares transaction logging and process cleanup without another service.
pub(crate) struct Store<'a> {
    // The current transaction's runner retains command evidence and owns children.
    runner: &'a Runner,
}

impl<'a> Store<'a> {
    /// Borrow a runner without opening the storage pool or changing state.
    pub(crate) fn new(runner: &'a Runner) -> Self {
        Self { runner }
    }

    fn pool(&self, args: &[&str]) -> Result<Value> {
        self.json("pool", args, Duration::from_secs(60))
    }

    fn host(&self, args: &[&str]) -> Result<Value> {
        self.json("host", args, Duration::from_secs(60))
    }

    fn service(&self) -> Result<String> {
        match std::env::var("AIRLOCK_DOM0_SERVICE") {
            Ok(service) => Ok(service),
            Err(_) => Ok(std::env::current_exe()?
                .to_str()
                .context("invalid service path")?
                .to_owned()),
        }
    }

    fn call(&self, subsystem: &str, args: &[&str], timeout: Duration) -> Result<String> {
        if subsystem == "host" && args.first() != Some(&"validate") {
            self.runner.require_separate_host_policy()?;
        }
        let args = ["storage", subsystem]
            .into_iter()
            .chain(args.iter().copied())
            .map(OsString::from)
            .collect::<Vec<_>>();
        self.runner.run(&self.service()?, &args, timeout, &[])
    }

    fn json(&self, subsystem: &str, args: &[&str], timeout: Duration) -> Result<Value> {
        let output = self.call(subsystem, args, timeout)?;
        Ok(airlock_nix_core::state::parse_json(
            output.as_bytes(),
            Path::new("<storage-response>"),
        )?)
    }

    /// Read optional retained metadata for deciding whether to release a generation.
    /// A missing record means storage has already reclaimed that generation.
    pub(crate) fn generation_record(
        &self,
        domain: &GuestName,
        generation: GenerationId,
    ) -> Result<Option<Value>> {
        let path = Path::new("/var/lib/airlock/closure-store/domains")
            .join(runtime_namespace(domain.as_str()))
            .join("generations")
            .join(generation.to_string())
            .join("manifest.json");

        crate::state::optional(&path)
    }

    /// Locate the image's boot generation map when no deployment has selected one.
    pub(crate) fn image_staged(&self) -> Result<Option<PathBuf>> {
        let path = PathBuf::from("/var/lib/airlock/host-store/boot-staged.json");
        Ok(if path.try_exists()? { Some(path) } else { None })
    }

    /// Locate retained root bytes and their descriptor for a generation's boot-cache check.
    /// Builder-only generations have no root artifact and return an empty list.
    pub(crate) fn retained_root_files(
        &self,
        manifest: &Path,
        pool_root: Option<&str>,
    ) -> Result<Vec<PathBuf>> {
        let manifest: Value = crate::state::read(manifest)?;
        let Some(artifact) = manifest["root"].get("artifact").filter(|a| !a.is_null()) else {
            return Ok(Vec::new());
        };
        validate_root_descriptor(artifact)?;

        let directory = Path::new(pool_root.context("missing closure pool root")?)
            .join("root-artifacts")
            .join(artifact["sha256"].as_str().context("invalid root digest")?);
        Ok(["root.img", "artifact.json"]
            .iter()
            .map(|name| directory.join(name))
            .collect())
    }

    /// Describe an exact committed guest generation without selecting it.
    pub(crate) fn describe(
        &self,
        domain: &GuestName,
        generation: GenerationId,
    ) -> Result<crate::model::GenerationInfo> {
        Ok(serde_json::from_value(self.pool(&[
            "describe-generation",
            "--domain",
            &runtime_namespace(domain.as_str()),
            "--generation",
            &generation.to_string(),
        ])?)?)
    }

    /// Find a retained generation matching every supplied guest artifact identity.
    pub(crate) fn find(
        &self,
        domain: &GuestName,
        backend: &Backend,
        approved_by: &str,
    ) -> Result<GenerationMatch> {
        Ok(serde_json::from_value(self.pool(&[
            "find-generation",
            "--domain",
            &runtime_namespace(domain.as_str()),
            "--system",
            backend.system.source.as_str(),
            "--closure-source",
            backend.store.source.as_str(),
            "--root-source",
            backend.root.source.as_str(),
            "--kernel-name",
            &backend.kernel.name,
            "--view-backend",
            &backend.store.view_backend,
            "--approved-by",
            approved_by,
        ])?)?)
    }

    /// Retire a guest generation after storage checks its running references.
    pub(crate) fn retire_generation(
        &self,
        domain: &GuestName,
        generation: GenerationId,
    ) -> Result<()> {
        self.call(
            "pool",
            &[
                "retire-generation",
                "--domain",
                &runtime_namespace(domain.as_str()),
                "--generation",
                &generation.to_string(),
            ],
            Duration::from_secs(60),
        )?;
        Ok(())
    }

    /// Release only the exact automatic pin accepted by the complete protection decision.
    pub(crate) fn release_retention(
        &self,
        request: &airlock_deployment_core::retention::ReleaseRequest<'_>,
    ) -> Result<()> {
        let mut args = vec![
            "release-automatic".to_owned(),
            "--pool-root".into(),
            "/var/lib/airlock/closure-store".into(),
            "--domain".into(),
            request.domain().into(),
            "--generation".into(),
            request.generation().to_string(),
        ];
        args.extend(protection_arguments(request.references()));
        self.call(
            "pool",
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
            Duration::from_secs(60),
        )?;
        Ok(())
    }

    /// Transport every protection to the receiver, which rechecks its own live references under lock.
    pub(crate) fn collect_protected(
        &self,
        protected: &airlock_deployment_core::retention::inventory::ProtectionInventory,
    ) -> Result<Value> {
        let mut args = vec![
            "gc".to_owned(),
            "--pool-root".into(),
            "/var/lib/airlock/closure-store".into(),
            "--keep-generations".into(),
            "2".into(),
        ];
        args.extend(protection_arguments(protected.references()));
        self.json(
            "pool",
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
            Duration::from_secs(3600),
        )
    }

    /// Publish and validate the host software view without selecting its boot entry.
    pub(crate) fn publish_host(&self, system: &StorePath) -> Result<HostReceipt> {
        Ok(serde_json::from_value(
            self.host(&["publish", system.as_str()])?,
        )?)
    }

    /// Verify the already published host view and return its recorded identity.
    pub(crate) fn validate_host(&self, system: &StorePath) -> Result<HostReceipt> {
        Ok(serde_json::from_value(
            self.host(&["validate", system.as_str()])?,
        )?)
    }

    /// Install boot artifacts in the existing isolated host installation path.
    pub(crate) fn install_host_boot(&self, system: &StorePath) -> Result<()> {
        self.call(
            "host",
            &["install-boot", system.as_str()],
            Duration::from_secs(600),
        )?;
        Ok(())
    }

    /// Authenticate retained boot artifacts, optionally preserving the default entry.
    pub(crate) fn seal_host_boot(&self, keep_default: bool) -> Result<()> {
        let args: &[&str] = if keep_default {
            &["seal-boot", "--keep-default"]
        } else {
            &["seal-boot"]
        };
        self.call("host", args, Duration::from_secs(60))?;
        Ok(())
    }

    /// Retire a host view after storage verifies its remaining references.
    pub(crate) fn retire_host(&self, system: &StorePath) -> Result<()> {
        self.call(
            "host",
            &["retire", system.as_str()],
            Duration::from_secs(60),
        )?;
        Ok(())
    }

    /// Receive an inactive artifact constrained by an already authorized identity.
    /// The duplex protocol owns stdin/stdout, including its failure responses.
    pub(crate) fn receive(
        &self,
        domain: &GuestName,
        approved_by: &str,
        identity: &Path,
    ) -> Result<()> {
        self.runner.stream(
            &self.service()?,
            &[
                "storage".into(),
                "artifact".into(),
                "receive-incremental".into(),
                "--expected-domain".into(),
                domain.as_str().into(),
                "--approved-by".into(),
                approved_by.into(),
                "--expected-identity".into(),
                identity.as_os_str().into(),
            ],
            Duration::from_secs(3600),
        )
    }
}

/// Dispatch storage requests shared with the native Qubes extension module.
pub(crate) fn qubes_request(request: serde_json::Value) -> anyhow::Result<serde_json::Value> {
    qubes_inspect::execute(request)
}

/// Decode declarations at the isolated Qubes worker's input boundary.
#[cfg(feature = "qubes")]
pub(crate) use domain::objects_request;

/// Installed typed attachment policy, separate from the plugin callback protocol.
#[cfg(feature = "qubes")]
pub(crate) use domain::ObjectsPolicy;
