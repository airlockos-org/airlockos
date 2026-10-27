//! A passed-through GPU belongs to a VM while dom0 validates its assignment and firmware.
//! These operations preserve Qubes lifecycle control and never reset or reassign PCI devices.

mod assignment;

mod firmware;

mod framebuffer;

mod xml;

mod preflight;

use airlock_nix_core::identity::GuestName;
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fmt, fs,
    io::Read,
    path::{Path, PathBuf},
    str::FromStr,
};

/// Segment-zero PCI address; parsing excludes traversal and unsupported device numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
struct Bdf {
    // PCI bus within segment zero.
    bus: u8,
    // Device number within a bus, at most 31.
    device: u8,
    // Function number within a device, at most seven.
    function: u8,
}

impl FromStr for Bdf {
    type Err = anyhow::Error;

    fn from_str(text: &str) -> Result<Self> {
        let b = text.as_bytes();
        ensure!(
            b.len() == 12 && &b[..5] == b"0000:" && b[7] == b':' && b[10] == b'.',
            "BDF must be a segment-zero address such as 0000:04:00.0"
        );
        ensure!(
            [5, 6, 8, 9, 11].iter().all(|i| b[*i].is_ascii_hexdigit()),
            "invalid PCI address"
        );
        let value = Self {
            bus: u8::from_str_radix(&text[5..7], 16)?,
            device: u8::from_str_radix(&text[8..10], 16)?,
            function: u8::from_str_radix(&text[11..12], 16)?,
        };
        ensure!(
            value.device <= 31 && value.function <= 7,
            "PCI device/function outside supported bounds"
        );
        Ok(value)
    }
}

impl TryFrom<String> for Bdf {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        value.parse()
    }
}

impl From<Bdf> for String {
    fn from(value: Bdf) -> Self {
        value.to_string()
    }
}

impl fmt::Display for Bdf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "0000:{:02x}:{:02x}.{:x}",
            self.bus, self.device, self.function
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Phase {
    Bootstrap,
    Start,
}

#[derive(Args)]
pub(crate) struct Request {
    // Host-side GPU operation selected by Nix units or the Qubes extension.
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Inspect the lab AMD GPU without changing driver ownership or reset state.
    Preflight,
    /// Validate and optionally extract one GPU's firmware without PCI writes.
    Firmware(firmware::Args),
    /// Check physical ownership against declarative topology without changing it.
    #[cfg(feature = "qubes")]
    Check {
        // Reviewed GPU selection installed by Nix.
        #[arg(long, default_value = "/etc/airlock/gui-gpu.json")]
        config: PathBuf,
        // Whole-machine topology whose sys-gui assignment must match.
        #[arg(long, default_value = "/etc/airlock/qubes-topology.json")]
        topology: PathBuf,
        // Startup requires the persistent assignment created during bootstrap.
        #[arg(long, value_enum, default_value = "bootstrap")]
        phase: Phase,
    },
    /// Release only the selected sole GPU's firmware framebuffer before VM startup.
    Framebuffer {
        // Exact segment-zero display device selected by Nix.
        #[arg(long)]
        gpu: Bdf,
        // Durable handoff evidence, also printed on stdout.
        #[arg(long)]
        report: PathBuf,
    },
    #[command(hide = true)]
    Qubes,
}

fn path(key: &str, default: &str) -> PathBuf {
    std::env::var_os(key)
        .map(PathBuf::from)
        .unwrap_or_else(|| default.into())
}

fn pci_root() -> PathBuf {
    path("AIRLOCK_GPU_PCI", "/sys/bus/pci/devices")
}

fn hex(text: &str) -> Result<u32> {
    let text = text.trim();
    let text = text.strip_prefix("0x").unwrap_or(text);
    ensure!(
        !text.is_empty() && text.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid hexadecimal hardware identifier"
    );
    Ok(u32::from_str_radix(text, 16)?)
}

fn attribute(path: &Path) -> Result<u32> {
    hex(&fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?)
}

fn driver(path: &Path) -> Result<String> {
    // sysfs driver links may disappear concurrently; canonicalization must not
    // accept an unavailable or invented target as evidence of driver ownership.
    Ok(fs::canonicalize(path)?
        .file_name()
        .context("driver has no name")?
        .to_str()
        .context("non-UTF-8 driver")?
        .into())
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
enum Hook {
    Settings {
        // VM whose reviewed firmware configuration is being resolved by Rust.
        name: GuestName,
    },
    Hotplug {
        // Qubes VM receiving an upstream PCI pre-attach or pre-detach event.
        name: GuestName,
        // Runtime state observed through Qubes at the lifecycle boundary.
        running: bool,
    },
    Validate {
        // Live Qubes properties collected without side effects by the extension.
        vm: assignment::Vm,
        // Explicit bus-zero PCI slot from the Nix configuration.
        slot: u8,
    },
    Prepare {
        // Current assignment, revalidated before creating machine-local firmware.
        vm: assignment::Vm,
        // Destination slot shared by VFCT and libvirt XML.
        slot: u8,
    },
    Render {
        // Fresh Qubes snapshot to reject assignment changes after preparation.
        vm: assignment::Vm,
        // Current configured destination slot.
        slot: u8,
        // Exact artifact produced for this startup attempt.
        report: Option<firmware::Prepared>,
        // Existing upstream XML whose security flags and devices are preserved.
        xml: String,
    },
    Verify {
        // Fresh Qubes properties at the last gate before native VM creation.
        vm: assignment::Vm,
        // Current configured destination slot, checked again after XML conversion.
        slot: u8,
        // Exact prepared artifact whose address/path must survive conversion.
        report: firmware::Prepared,
        // libvirt's xen-xl output, checked before VM creation proceeds.
        native: String,
    },
    Check {
        // Declarative hardware identity; it does not authorize changing ownership.
        selection: assignment::Selection,
        // Topology containing the sole required sys-gui GPU assignment.
        topology: Value,
        // Read-only Qubes inventory from the adapter.
        inventory: assignment::Inventory,
        // Required persistence differs before and after initial setup.
        phase: Phase,
    },
}

pub(crate) fn qubes_request(request: Value) -> Result<Value> {
    let request: Hook = serde_json::from_value(request)?;
    match request {
        Hook::Settings { name } => Ok(serde_json::to_value(settings(&name)?)?),
        Hook::Hotplug { name, running } => {
            ensure!(
                !running || settings(&name)?.is_none(),
                "AMD VFCT GPU hotplug is unsupported; firmware is prepared at VM startup"
            );
            Ok(Value::Null)
        }
        Hook::Validate { vm, slot } => Ok(serde_json::to_value(assignment::selected(&vm, slot)?)?),
        Hook::Prepare { vm, slot } => {
            Ok(serde_json::to_value(firmware::prepare_start(&vm, slot)?)?)
        }
        Hook::Render {
            vm,
            slot,
            report,
            xml,
        } => {
            let report = report.context("AMD VFCT is not prepared; start the VM through Qubes")?;
            report.current(&vm, slot)?;
            Ok(json!(xml::inject(&xml, &report)?))
        }
        Hook::Verify {
            vm,
            slot,
            report,
            native,
        } => {
            report.current(&vm, slot)?;
            xml::verify(&native, &report)?;
            Ok(Value::Null)
        }
        Hook::Check {
            selection,
            topology,
            inventory,
            phase,
        } => assignment::check(&selection, &topology, &inventory, phase),
    }
}

/// Reviewed firmware slot for one Qubes VM; no extension reads configuration files.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    // Bus-zero slot shared by the filtered firmware and libvirt XML.
    #[serde(rename = "guestSlot")]
    slot: u8,
}

/// Resolve optional firmware configuration and reject malformed configured slots.
fn settings(name: &GuestName) -> Result<Option<Settings>> {
    let path = path("AIRLOCK_AMD_VBIOS_CONFIG", "/etc/airlock/amd-vbios.json");
    if !path.try_exists()? {
        return Ok(None);
    }

    let bytes = bounded(&path, 1024 * 1024)?;
    let config: Value = airlock_nix_core::state::parse_json(&bytes, &path)?;
    let domains = config["domains"]
        .as_object()
        .context("missing AMD VFCT domains")?;
    domains
        .get(name.as_str())
        .map(|value| {
            let settings: Settings = serde_json::from_value(value.clone())?;
            ensure!(
                (8..=31).contains(&settings.slot),
                "AMD VFCT VM slot must be between 8 and 31"
            );
            Ok(settings)
        })
        .transpose()
}

pub(crate) fn execute(request: Request) -> Result<()> {
    let value = match request.action {
        Action::Preflight => {
            let report = preflight::inspect()?;
            println!("{}", serde_json::to_string(&report)?);
            ensure!(
                report["assignment_gate_passed"] == true,
                "GPU preflight refused assignment"
            );
            return Ok(());
        }
        Action::Firmware(args) => firmware::execute(args)?,
        Action::Qubes => qubes_request(crate::input_value("-")?)?,
        #[cfg(feature = "qubes")]
        Action::Check {
            config,
            topology,
            phase,
        } => {
            let result = (|| -> Result<Value> {
                let selection: assignment::Selection = crate::state::configuration(&config)?;
                let topology: Value = crate::state::configuration(&topology)?;
                let port = selection
                    .port
                    .as_deref()
                    .filter(|_| selection.enable)
                    .unwrap_or("");
                let inventory = airlock_qubes::gpu::inventory(port)?;
                let inventory = serde_json::from_value(inventory)?;
                assignment::check(&selection, &topology, &inventory, phase)
            })();
            if let Err(error) = &result {
                println!(
                    "{}",
                    json!({"schema":"airlock.gui-gpu-check.v1","phase":phase,"status":"failed","error":format!("{error:#}")})
                );
            }
            result?
        }
        Action::Framebuffer { gpu, report } => {
            let lock_root = path("AIRLOCK_GPU_RUNTIME", "/run/airlock/gpu");
            crate::state::directory(&lock_root)?;
            let locks = airlock_nix_core::state::StateStore::initialize(&lock_root)?;
            let _lock = locks.try_operation(
                &"framebuffer".parse()?,
                airlock_nix_core::state::OperationOwner::new(
                    "airlock-dom0-service GPU handoff".into(),
                    format!("release the firmware framebuffer for {gpu} before VM startup"),
                    airlock_nix_core::state::OperationKind::Maintenance,
                )?,
            )?;

            crate::model::absolute(
                report
                    .to_str()
                    .context("non-UTF-8 framebuffer report path")?,
            )?;
            crate::state::directory(report.parent().context("report needs a parent directory")?)?;
            crate::state::save(
                &report,
                &json!({"schema":"airlock.boot-framebuffer.v1","status":"preparing","gpu":gpu}),
            )?;

            let result = framebuffer::release(&path("AIRLOCK_GPU_SYSFS", "/sys"), &gpu.to_string());
            let value = match &result {
                Ok(value) => value.clone(),
                Err(error) => {
                    json!({"schema":"airlock.boot-framebuffer.v1","status":"failed","error":format!("{error:#}")})
                }
            };
            crate::state::save(&report, &value)?;
            println!("{}", serde_json::to_string(&value)?);
            result?;
            return Ok(());
        }
    };
    println!("{}", serde_json::to_string(&value)?);
    Ok(())
}

fn bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let file = fs::File::from(rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?);
    ensure!(
        file.metadata()?.is_file(),
        "GPU firmware input must be a regular file"
    );
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "GPU input exceeds size limit");
    Ok(bytes)
}
