//! Explicit USB inspection, image writing and offline personalization.

pub(crate) mod copy;

pub(crate) mod device;

pub(crate) mod growth;

pub(crate) mod personalize;

pub(crate) mod progress;

use crate::support::{regular, root_only, run};
use airlock_nix_core::identity::GitRevision;
use airlock_nix_core::state::{OperationKind, OperationOwner, StateStore};
use airlock_provisioning_core as verified;
use anyhow::{Context, Result, ensure};
use clap::{Args, Parser, Subcommand};
use serde_json::json;
use std::{
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom},
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
};

const MARKER: &str = "airlock-usb-dev-v2\n";

#[derive(Parser)]
#[command(
    about = "Explicit, guarded USB provisioning. No command runs implicitly at boot.",
    version
)]
struct Cli {
    // User-selected operation; inspection alone never grants write authority.
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Inspect by default; explicitly opt into erasing a USB.
    Write(Write),
    /// Use a build result link and an exact hardware serial.
    WriteLatest(Latest),
    /// Write the image, expand root and personalize before first boot.
    ProvisionLatest(Provision),
    /// Collect credentials now and provision only after the build owner signals success on stdin.
    ProvisionAfterBuild {
        // Existing USB and personalization settings for this run.
        #[command(flatten)]
        provision: Provision,
        // Application source captured by the build owner before preparation.
        #[arg(long)]
        application_revision: GitRevision,
        // Machine source captured by the build owner before preparation.
        #[arg(long)]
        machine_revision: GitRevision,
    },
    /// Personalize an already mounted Airlock USB root.
    Personalize {
        // Offline ext4 root of the previously written Airlock image.
        #[arg(long)]
        root: PathBuf,
        // Committed source snapshot and authorized SSH key to install offline.
        #[command(flatten)]
        settings: personalize::Settings,
    },
}

#[derive(Args)]
struct Provision {
    // Build result and selected disk; this operation always writes after validation.
    #[command(flatten)]
    source: LatestSource,
    // Committed source snapshot and authorized SSH key to install offline.
    #[command(flatten)]
    settings: personalize::Settings,
    // Off-USB location for partition-table backups and receipts.
    #[arg(long, default_value = "/var/log/airlock/usb-root-expansion")]
    resize_backup_dir: PathBuf,
}

#[derive(Args)]
struct Write {
    // Uncompressed GPT image whose bytes will be written.
    #[arg(long)]
    image: PathBuf,
    // Whole-disk USB identity; direct /dev/sdX spellings are refused.
    #[arg(long)]
    device: PathBuf,
    // Explicit acknowledgement that this operation destroys USB data.
    #[arg(long)]
    write: bool,
    // Hardware serial repeated independently for a direct write.
    #[arg(long)]
    confirm_serial: Option<String>,
    // SHA-256 expected for the source before destructive access.
    #[arg(long)]
    sha256: Option<String>,
    // Write zero-filled holes as well as allocated source extents.
    #[arg(long)]
    full_write: bool,
    // Read the complete image prefix back; implies a full write.
    #[arg(long)]
    verify: bool,
}

#[derive(Args)]
struct LatestSource {
    // Result symlink produced by the most recent explicit image build.
    #[arg(long)]
    result_link: PathBuf,
    // Physical root of the isolated Nix store if not mounted at /nix.
    #[arg(long)]
    nix_root: Option<PathBuf>,
    // Exact hardware serial, never a model or a kernel disk letter.
    #[arg(long)]
    serial: String,
}

#[derive(Args)]
struct Latest {
    // Image and USB selection shared with full provisioning.
    #[command(flatten)]
    source: LatestSource,
    // Inspection remains the default for the write-latest command.
    #[arg(long)]
    write: bool,
    // Materialize all sparse image holes on the USB.
    #[arg(long)]
    full_write: bool,
    // Verify the entire image prefix after flushing.
    #[arg(long)]
    verify: bool,
}

pub(crate) fn result_image(link: &Path, nix_root: Option<&Path>) -> Result<PathBuf> {
    let result = match fs::canonicalize(link) {
        Ok(result) => result,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let root = fs::canonicalize(nix_root.context(
                "Result link points outside the mounted /nix/store; supply --nix-root.",
            )?)?;
            let target = fs::read_link(link)?;
            let relative = target
                .strip_prefix("/nix/store")
                .context("Dangling result link is not a Nix store output.")?;
            ensure!(
                relative
                    .components()
                    .all(|c| matches!(c, std::path::Component::Normal(_))),
                "Invalid result link path"
            );
            let result = fs::canonicalize(root.join("nix/store").join(relative))?;
            ensure!(
                result.starts_with(&root),
                "Resolved image escaped the configured Nix root."
            );
            result
        }
        Err(error) => return Err(error.into()),
    };

    let candidates = if result.is_file() {
        vec![result.clone()]
    } else {
        fs::read_dir(&result)?
            .map(|entry| entry.map(|e| e.path()))
            .collect::<std::io::Result<Vec<_>>>()?
    };
    let images: Vec<_> = candidates
        .into_iter()
        .filter(|p| p.is_file() && p.extension().is_some_and(|e| e == "img"))
        .map(|path| -> Result<PathBuf> {
            let canonical = fs::canonicalize(path)?;
            ensure!(
                !result.is_dir() || canonical.starts_with(&result),
                "Image escaped the selected build output"
            );
            Ok(canonical)
        })
        .collect::<Result<_>>()?;
    ensure!(
        images.len() == 1,
        "Expected exactly one raw .img under {}; found {}.",
        result.display(),
        images.len()
    );

    Ok(images[0].clone())
}

// A direct image needs an independent digest; a selected build result computes
// its own digest once, immediately before writing the pinned source file.
enum SourcePolicy {
    /// Standalone command requires an independently supplied digest.
    Direct,
    /// Standalone command explicitly selects a published output.
    Published(
        // Exact supplying output selected by the standalone command.
        String,
    ),
    /// A waiting run must retain its original confirmed disk and exact successful output.
    Built {
        // Original confirmed target and same-run publication.
        authority: verified::Authority,
        // Freshly observed output supplying the actual opened image.
        publication: String,
    },
}

/// Manual provisioning and waiting-build completion retain different authority sources.
enum ProvisionAuthority {
    /// Explicit standalone provisioning without a waiting build.
    Published,
    /// Original waiting-build authority, never a fresh post-build confirmation.
    Built(
        // Original confirmed physical target and opaque successful build publication.
        verified::Authority,
    ),
}

/// Snapshot the selected output coordinate independently of its physical private-store mapping.
fn publication(source: &LatestSource) -> Result<String> {
    let path = match fs::read_link(&source.result_link) {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
            fs::canonicalize(&source.result_link)?
        }
        Err(error) => return Err(error.into()),
    };
    Ok(path
        .to_str()
        .context("non-UTF-8 image publication")?
        .to_owned())
}

fn latest(
    source: &LatestSource,
    write: bool,
    full_write: bool,
    verify: bool,
) -> Result<(Write, device::Disk, String)> {
    let output = publication(source)?;
    let image = result_image(&source.result_link, source.nix_root.as_deref())?;
    ensure!(
        output == publication(source)?,
        "image publication changed during selection"
    );
    let device = device::select(&source.serial)?;
    let selected = device::inspect(&device, false)?;
    ensure!(
        selected.serial.as_deref() == Some(&source.serial),
        "USB serial changed during selection"
    );
    Ok((
        Write {
            image,
            device,
            write,
            confirm_serial: Some(source.serial.clone()),
            sha256: None,
            full_write,
            verify,
        },
        selected,
        output,
    ))
}

fn write_image(args: &Write, policy: SourcePolicy, selected: Option<&device::Disk>) -> Result<()> {
    let image = fs::canonicalize(&args.image)?;
    ensure!(
        image.extension().is_some_and(|e| e == "img"),
        "Use the uncompressed raw .img file."
    );
    let mut source = regular(&image)?;
    let source_info = source.metadata()?;
    let size = source_info.len();
    let info = if selected.is_some() {
        device::inspect(&args.device, false)?
    } else {
        device::checked(&args.device)?
    };
    if let Some(selected) = selected {
        selected.same_disk(&info)?;
    }
    ensure!(size <= info.size, "USB is smaller than the image.");
    ensure!(size > 1024 * 1024, "Image is implausibly small.");
    source.seek(SeekFrom::Start(512))?;
    let mut header = [0; 8];
    source.read_exact(&mut header)?;
    ensure!(&header == b"EFI PART", "Image does not have a GPT header.");

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "device": info.name,
            "identity": args.device,
            "model": info.model,
            "serial": info.serial,
            "bytes": info.size,
            "image": image,
            "image_bytes": size,
            "write": args.write,
            "write_mode": if args.full_write || args.verify { "full" } else { "sparse" },
            "full_verify": args.verify,
        }))?
    );
    if !args.write {
        println!(
            "Inspection only. Writing requires --write --confirm-serial SERIAL --sha256 HASH."
        );
        return Ok(());
    }

    root_only()?;
    ensure!(
        args.confirm_serial == info.serial,
        "Serial confirmation does not match."
    );
    let intent = if args.write {
        verified::Intent::Write
    } else {
        verified::Intent::Inspect
    };
    let serial = args
        .confirm_serial
        .as_deref()
        .context("Serial confirmation is required")?;
    let (authority, publication) = match policy {
        SourcePolicy::Direct => {
            let expected = args
                .sha256
                .as_ref()
                .context("Image SHA-256 is required.")?
                .to_ascii_lowercase();
            ensure!(
                expected.len() == 64 && expected.bytes().all(|b| b.is_ascii_hexdigit()),
                "Invalid image SHA-256."
            );
            (
                info.confirm(intent, serial)?
                    .direct(expected)
                    .context("invalid direct image authority")?,
                None,
            )
        }
        SourcePolicy::Published(output) => (
            info.confirm(intent, serial)?
                .published(output.clone())
                .context("invalid published image authority")?,
            Some(output),
        ),
        SourcePolicy::Built {
            authority,
            publication,
        } => (authority, Some(publication)),
    };
    ensure!(
        authority.matches_disk(&info.evidence()?),
        "USB identity differs from the original confirmed target"
    );
    let source = copy::CheckedSource::check(source, &source_info, publication, &authority)?;

    if selected.is_some() {
        device::unmount(&args.device, &info)?;
    }
    let again = device::checked(&args.device)?;
    info.same_disk(&again)?;
    let before = fs::metadata(&info.name)?;
    ensure!(
        before.file_type().is_block_device(),
        "USB disappeared before opening"
    );
    let destination = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags((rustix::fs::OFlags::EXCL | rustix::fs::OFlags::NOFOLLOW).bits() as i32)
        .open(&info.name)?;
    ensure!(
        destination.metadata()?.file_type().is_block_device()
            && destination.metadata()?.rdev() == before.rdev(),
        "USB device changed while opening."
    );

    let mode = if args.verify {
        verified::CopyMode::Verified
    } else if args.full_write {
        verified::CopyMode::Full
    } else {
        verified::CopyMode::Sparse
    };
    copy::execute(copy::WriteRequest::new(
        source,
        destination,
        authority,
        &args.device,
        mode,
    )?)
}

pub(crate) fn main() -> Result<()> {
    let action = Cli::parse().action;
    let reason = match &action {
        Action::Write(args) if args.write => {
            Some(format!("write image to {}", args.device.display()))
        }
        Action::WriteLatest(args) if args.write => {
            Some(format!("write image to USB serial {}", args.source.serial))
        }
        Action::ProvisionLatest(Provision { source, .. })
        | Action::ProvisionAfterBuild {
            provision: Provision { source, .. },
            ..
        } => Some(format!(
            "write, expand and personalize USB serial {}",
            source.serial
        )),
        Action::Personalize { root, .. } => {
            Some(format!("personalize offline USB root {}", root.display()))
        }
        _ => None,
    };
    let _lock = if let Some(reason) = reason {
        root_only()?;
        let directory = Path::new("/run/airlock/usb");
        fs::create_dir_all(directory)?;
        let state = StateStore::initialize(directory)?;
        Some(state.try_operation(
            &"provision".parse()?,
            OperationOwner::new("airlock-usb".into(), reason, OperationKind::Maintenance)?,
        )?)
    } else {
        None
    };

    match action {
        Action::Write(args) => write_image(&args, SourcePolicy::Direct, None),
        Action::WriteLatest(args) => {
            let (write, selected, output) =
                latest(&args.source, args.write, args.full_write, args.verify)?;
            write_image(&write, SourcePolicy::Published(output), Some(&selected))
        }
        Action::Personalize { root, settings } => {
            let selected = device::check_mount(&root, None)?;
            settings.prepare()?.install(&root, &selected)
        }
        Action::ProvisionLatest(provision) => {
            let prepared = provision.settings.prepare()?;
            provision.install(prepared, ProvisionAuthority::Published)
        }
        Action::ProvisionAfterBuild {
            provision,
            application_revision,
            machine_revision,
        } => {
            let mut reply = crate::provisioning::reply_pipe()?;
            ensure!(
                fs::symlink_metadata(&provision.source.result_link)
                    .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
                "The build result must be a new path unique to this run."
            );
            let device = device::select(&provision.source.serial)?;
            let selected = device::inspect(&device, false)?;
            ensure!(
                selected.serial.as_deref() == Some(&provision.source.serial),
                "USB serial changed during selection"
            );
            growth::backup_location(&provision.resize_backup_dir, &selected)?;
            growth::backup_location(
                provision
                    .source
                    .result_link
                    .parent()
                    .context("image result parent")?,
                &selected,
            )?;
            println!(
                "USB selected for provisioning after the build: {serial}, {model}, {bytes} bytes.",
                serial = provision.source.serial,
                model = selected.model.as_deref().unwrap_or("unknown model"),
                bytes = selected.size,
            );
            let prepared = provision.settings.prepare()?;
            ensure!(
                prepared.revision() == &application_revision,
                "personalization source differs from the original build source"
            );
            let run = crate::provisioning::BuildRun::new(
                provision.source.result_link.clone(),
                application_revision,
                machine_revision,
            )?;
            let waiting = selected
                .confirm(verified::Intent::Write, &provision.source.serial)?
                .wait(run.evidence());
            let completed =
                crate::provisioning::wait_for_build(&run, std::io::stdin().lock(), &mut reply)?;
            let authority = waiting
                .complete(completed.into_evidence())
                .context("build completion belongs to another waiting USB run")?;
            drop(reply);
            provision.install(prepared, ProvisionAuthority::Built(authority))
        }
    }
}

impl Provision {
    /// Revalidate the selected image and disk, then reuse the ordinary provisioning sequence.
    fn install(self, prepared: personalize::Prepared, authority: ProvisionAuthority) -> Result<()> {
        let (args, selected, publication) = latest(&self.source, true, false, false)?;
        let policy = match authority {
            ProvisionAuthority::Published => SourcePolicy::Published(publication),
            ProvisionAuthority::Built(authority) => SourcePolicy::Built {
                authority,
                publication,
            },
        };
        growth::backup_location(&self.resize_backup_dir, &selected)?;
        write_image(&args, policy, Some(&selected))?;
        run(Command::new("udevadm").arg("settle"))?;
        growth::expand(&args.device, &selected, &self.resize_backup_dir)?;

        let root = tempfile::Builder::new()
            .prefix("airlock-usb-")
            .tempdir_in("/run")?
            .keep();
        let current = device::checked(&args.device)?;
        selected.same_disk(&current)?;
        let partition = current.partition(&args.device)?;
        let mount = growth::Mounted::new(&partition, &root, "nosuid,nodev")?;
        prepared.install(&root, &selected)?;
        progress::waiting(
            "Flushing personalized USB filesystem",
            Some(&args.device),
            || run(&mut Command::new("sync")),
        )?;
        progress::waiting("Unmounting personalized USB", Some(&args.device), || {
            mount.unmount()
        })
    }
}
