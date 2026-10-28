//! Native image-store preparation and verification, independent of Qubes object creation.
//! Runtime adoption checks prebuilt identities without rebuilding or admitting source packages.

use super::{fs::*, generations, prepared, root};
use anyhow::{Result, ensure};
use clap::{Args, Subcommand, ValueEnum};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
};

/// Explicit boot policy decoded only at the image command boundary.
#[derive(Clone, Copy, ValueEnum)]
enum Profile {
    /// Normal VM and graphical startup.
    Normal,
    /// Independent text recovery.
    Recovery,
}

#[derive(Args)]
struct Selection {
    // Profile whose complete topology is being packaged, with no implicit default.
    #[arg(long, value_enum)]
    profile: Profile,
    // Exact host generation selected by this profile.
    #[arg(long)]
    host: crate::model::StorePath,
}

impl Selection {
    /// Bind the command's explicit profile and host to the complete validated topology.
    fn decode(
        self,
        topology: &Path,
    ) -> Result<airlock_machine_core::boot::artifacts::SelectedBoot> {
        use airlock_deployment_core::boot::artifacts::Profile as Checked;
        let profile = match self.profile {
            Profile::Normal => Checked::Normal,
            Profile::Recovery => Checked::Recovery,
        };
        airlock_machine_core::boot::artifacts::SelectedBoot::new(
            profile,
            self.host,
            crate::state::configuration(topology)?,
        )
    }
}

/// Parsed store request, validated by the application's single command parser.
#[derive(Args)]
pub(crate) struct Request {
    // Build-time preparation or read-only validation operation.
    #[command(subcommand)]
    operation: Operation,
}

#[derive(Subcommand)]
enum Operation {
    BootRequirements {
        // Exact generated topology whose complete native requirements are emitted.
        topology: PathBuf,
    },
    PreparePool {
        // Fresh directory receiving immutable guest and builder data.
        root: PathBuf,
        // Fresh closure-descriptor output directory.
        descriptors: PathBuf,
        // JSON array naming the selected guest and builder closures.
        specs: PathBuf,
        // Installed location embedded in the prepared pool metadata.
        runtime_root: PathBuf,
        // Nix-built package fragments and common indexes for this image only.
        #[arg(long)]
        cache: Option<PathBuf>,
    },
    VerifyOutputs {
        // Physical prepared pool to validate without mutation.
        root: PathBuf,
        // Descriptors binding the selected seed files.
        descriptors: PathBuf,
    },
    VerifyHandoff {
        // Exact generated topology consumed by first boot.
        topology: PathBuf,
        // Physical prepared pool; committed records retain runtime paths.
        pool: PathBuf,
        // Runtime pool identity embedded in descriptors and manifests.
        #[arg(long, default_value = "/var/lib/airlock/closure-store")]
        runtime_root: PathBuf,
    },
    VerifyTopology {
        // Generated boot configuration decoded with the runtime's typed model.
        topology: PathBuf,
    },
    PrepareHost {
        // Prepared guest seed copied into the unified host image.
        seed: PathBuf,
        // Fresh unified seed output directory.
        output: PathBuf,
        // Complete host closure registration in Nix dump/load format.
        registration: PathBuf,
        // Primary host system included in this image.
        system: String,
        // JSON mapping specialised boot paths to their actual host systems.
        choices: PathBuf,
        // Nix-built fragments for the host and refreshed builder closures.
        #[arg(long)]
        cache: Option<PathBuf>,
    },
    InstallHost {
        // Mounted image whose conventional bootstrap store is being discarded.
        root: PathBuf,
        // Complete closure reserved for independent recovery.
        recovery_paths: PathBuf,
        // Recovery system whose boot entry must already be installed.
        recovery_system: String,
    },
    VerifyHost {
        // Unified prepared image store, checked without assembling mounts.
        seed: PathBuf,
        // Exact guest topology whose Hermit executables must be retained by dom0.
        topology: PathBuf,
        // Explicit profile and host bound to the integrity check.
        #[command(flatten)]
        selection: Selection,
    },
    AssembleHost {
        // Immutable seed whose integrity and completeness authorize this invocation.
        seed: PathBuf,
        // Complete selected topology, rather than a list of prefiltered requirements.
        topology: PathBuf,
        // Profile and host that the upstream builder will assemble.
        #[command(flatten)]
        selection: Selection,
        // Original upstream Nix builder and its unchanged arguments.
        #[arg(last = true, required = true)]
        command: Vec<OsString>,
    },
    VerifyPrepared {
        // JSON request binding the selected descriptor to the configured VM.
        #[arg(long)]
        request: PathBuf,
    },
    InspectPrepared {
        // JSON request naming one selected image VM and its physical seed pool.
        #[arg(long)]
        request: PathBuf,
    },
    RootDescriptor {
        // Regular ext4 image to hash in canonical sparse form.
        source: PathBuf,
        // Optional output file for build scripts; stdout always carries the descriptor.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    FormatBootEntry {
        // Loader entry whose hardware directives are preserved.
        entry: PathBuf,
        // Explicit normal or recovery boot role.
        #[arg(long)]
        role: String,
        // Logical host system recorded in this entry.
        #[arg(long)]
        system: String,
        // NixOS boot-menu generation used for descending sort order.
        #[arg(long)]
        generation: u64,
    },
}

fn request(path: &Path) -> Result<Value> {
    if path == Path::new("-") {
        Ok(serde_json::from_reader(std::io::stdin().lock())?)
    } else {
        read(path)
    }
}

pub(super) fn run(command: Request) -> Result<Value> {
    let label = match &command.operation {
        Operation::PreparePool { .. } => "Guest store",
        Operation::PrepareHost { .. } => "Unified store",
        Operation::VerifyOutputs { .. } => "Verify guest store",
        Operation::VerifyHost { .. } => "Verify unified store",
        Operation::AssembleHost { .. } => "Verify and assemble image",
        Operation::InstallHost { .. } => "Install host store",
        _ => return execute(command),
    };
    super::progress::run(label, || execute(command))
}

fn execute(command: Request) -> Result<Value> {
    match command.operation {
        Operation::BootRequirements { topology } => {
            let inputs = airlock_machine_core::boot::BootInputs::new(crate::state::configuration(
                &topology,
            )?)?;
            let requirements = inputs.requirements()?;
            let guests = requirements
                .guests()
                .iter()
                .map(|guest| {
                    json!({"domain":guest.name(),
                "volumes":guest.volumes().iter().map(|volume| volume.name()).collect::<Vec<_>>()})
                })
                .collect::<Vec<_>>();
            Ok(
                json!({"schema":"airlock.boot-requirements.v1","host_roots":requirements.host_roots(),"guests":guests}),
            )
        }
        Operation::PreparePool {
            root,
            descriptors,
            specs,
            runtime_root,
            cache,
        } => super::image_cache::with(cache.as_deref(), || {
            with_image_build(|| {
                prepared::prepare_pool(&root, &descriptors, &read(&specs)?, &runtime_root)
            })
        }),
        Operation::VerifyOutputs { root, descriptors } => {
            prepared::verify_outputs(&root, &descriptors)
        }
        Operation::VerifyHandoff {
            topology,
            pool,
            runtime_root,
        } => super::handoff::image(
            crate::state::configuration(&topology)?,
            &pool,
            &runtime_root,
        ),
        Operation::VerifyTopology { topology } => {
            let inputs = airlock_machine_core::boot::BootInputs::new(crate::state::configuration(
                &topology,
            )?)?;
            Ok(json!({"status":"passed","domains":inputs.topology().domains.len()}))
        }
        Operation::PrepareHost {
            seed,
            output,
            registration,
            system,
            choices,
            cache,
        } => super::image_cache::with(cache.as_deref(), || {
            with_image_build(|| {
                prepared::prepare_host(&seed, &output, &registration, &system, &read(&choices)?)
            })
        }),
        Operation::InstallHost {
            root,
            recovery_paths,
            recovery_system,
        } => super::progress::phase("Installing recovery and sealing host boot", || {
            prepared::install_host(&root, &recovery_paths, &recovery_system)
        }),
        Operation::VerifyHost {
            seed,
            topology,
            selection,
        } => Ok(super::VerifiedImageSeed::verify(&seed, selection.decode(&topology)?)?.report()),
        Operation::AssembleHost {
            seed,
            topology,
            selection,
            command,
        } => {
            let evidence = super::VerifiedImageSeed::verify(&seed, selection.decode(&topology)?)?;
            evidence.assemble(&command[0], &command[1..])
        }
        Operation::VerifyPrepared { request: path } => {
            let value = request(&path)?;
            if !Path::new(&text(&value, "artifact")?)
                .join("prepared.json")
                .try_exists()?
            {
                return Ok(Value::Null);
            }
            let input: prepared::Verification = serde_json::from_value(value)?;
            Ok(serde_json::to_value(
                prepared::verify_prepared(&input)?.map(|g| g.number()),
            )?)
        }
        Operation::InspectPrepared { request: path } => {
            let request = request(&path)?;
            let descriptor: Value = read(Path::new(&text(&request, "descriptor")?))?;
            ensure!(
                descriptor["schema"] == "airlock.closure-store.prepared.v1",
                "unsupported prepared descriptor"
            );
            let namespace = super::runtime_namespace(&text(&request, "domain")?);
            ensure!(
                descriptor["domain"] == namespace,
                "prepared domain mismatch"
            );
            for key in ["pool_root", "system", "root_source", "kernel_name"] {
                ensure!(descriptor[key] == request[key], "prepared {key} mismatch");
            }
            let physical = PathBuf::from(text(&request, "physical_pool")?);
            let logical = PathBuf::from(text(&request, "pool_root")?);
            let result = generations::load(
                &physical,
                &logical,
                &namespace,
                number(&descriptor, "generation")?,
            )?;
            ensure!(
                descriptor["system"] == result.identity.system
                    && descriptor["root_source"] == result.identity.root_source
                    && descriptor["kernel_name"] == result.identity.kernel_name
                    && descriptor["closure_hash"] == result.closure_hash,
                "prepared identity differs from committed generation"
            );
            Ok(serde_json::to_value(result)?)
        }
        Operation::RootDescriptor { source, output } => {
            let descriptor = root::encode(&source, None)?;
            if let Some(output) = output {
                write(&output, &descriptor, 0o644)?;
            }
            Ok(serde_json::to_value(descriptor)?)
        }
        Operation::FormatBootEntry {
            entry,
            role,
            system,
            generation,
        } => {
            let formatted = super::presentation::format(
                &fs::read_to_string(&entry)?,
                generation,
                &role,
                &system,
                super::presentation::source(Path::new(&system))?.as_ref(),
            )?;
            atomic(&entry, formatted.as_bytes(), 0o644)?;
            Ok(json!({"formatted":entry}))
        }
    }
}
