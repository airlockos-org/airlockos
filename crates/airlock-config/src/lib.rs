//! Author, validate and compile connected Airlock machines through Rusix.
//! Rust assembles the machine; NixOS evaluates its modules and deferred build recipes.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

mod assembly;

mod commands;

pub mod components;

mod firewall;

mod host;

mod inputs;

mod input;

mod dev_terminal;

mod topology;

mod system_plan;

pub mod inspection;

mod lowering;

mod packages;

mod image;

mod flakes;

pub mod runtime;

pub mod preparation;

pub mod profiles;

pub mod model;

mod displays;

mod release;

pub mod review;

mod vm_modules;

mod vm_build;

mod hermit_build;

mod vm;

use rusix::{IntoConfig, interop::PackageFunction};
use std::path::Path;

/// Keep build artifacts small while retaining Rusix diagnostics and exact source spans.
#[track_caller]
pub(crate) fn compile(config: impl IntoConfig) -> Result<rusix::Generated, Box<rusix::Diagnostic>> {
    rusix::compile_with_options(config, build_rendering())
}

/// Compile NixOS contributions with the same artifact layout as standalone expressions.
#[track_caller]
pub(crate) fn compile_module(
    module: &rusix::nixos::NixosModule,
) -> Result<rusix::nixos::NixosArtifact, Box<rusix::Diagnostic>> {
    rusix::nixos::compile_module_with_options(module, build_rendering())
}

/// Select compiler layout before rendering so diagnostic offsets match the emitted source.
fn build_rendering() -> rusix::RenderOptions {
    rusix::RenderOptions {
        layout: rusix::RenderLayout::Compact,
        ..Default::default()
    }
}

/// The generated Nix entry point, exposing VM factories and dom0 module composition.
#[derive(IntoConfig)]
struct CompiledMachine {
    /// Nix function accepting the caller's library, machine source and Qubes builder factory.
    builders: PackageFunction,
    /// Host composition for the selected platform, applied after VM descriptors are evaluated.
    host_modules: Option<PackageFunction>,
    /// Machine artifact and system constructors sharing one deferred build scope.
    assembly: Option<PackageFunction>,
}

/// Compiles a finalized snapshot into VM factories and dom0 composition.
/// The caller can reuse that exact snapshot for module export and review.
/// Compilation failures are returned as rendered Rusix diagnostics.
pub fn generate(machine: &model::MachineSnapshot) -> Result<rusix::Generated, String> {
    let host = machine.host().ok_or("snapshot has no host configuration")?;

    crate::compile(CompiledMachine {
        builders: lowering::builders(machine),
        host_modules: matches!(host.platform, model::HostPlatform::Bootstrap)
            .then(|| host::modules(host, machine)),
        assembly: if matches!(host.platform, model::HostPlatform::UsbLab) {
            Some(assembly::entry_points(machine)?)
        } else {
            None
        },
    })
    .map_err(|diagnostic| diagnostic.render(Path::new(".")))
}

/// Compiles GNOME configuration for Nix machine compositions that supply their own VM builders.
/// The emitted module requires the machine source as its `airlockSupport` special argument.
/// Configuration and behavior are authored in `components::desktop`.
pub fn desktop_module() -> Result<rusix::nixos::NixosArtifact, String> {
    crate::compile_module(&components::desktop::module())
        .map_err(|diagnostic| diagnostic.render(Path::new(".")))
}

/// Writes the USB lab VM profile, its diagnostics variant and the regression fixture
/// with source metadata.
/// Extra VM contributions are composed in order and emitted as separate NixOS
/// modules before their enclosing machine factories. Existing artifact files
/// are overwritten; filesystem and compilation errors are returned to the caller.
pub fn export(directory: &Path) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(directory)?;

    for (name, machine) in [
        ("bootstrap", profiles::bootstrap::machine()?),
        ("complete", profiles::usb_lab::machine(false)?),
        ("firewall-diagnostics", profiles::usb_lab::machine(true)?),
    ] {
        export_snapshot(&machine, &directory.join(name))?;
    }

    Ok(())
}

/// Writes one validated machine's modules, source metadata and resolved connections.
/// Export into a dedicated directory; matching files are overwritten. No build or
/// deployment occurs. The snapshot must have host bindings for its machine entry point.
pub fn export_snapshot(
    machine: &model::MachineSnapshot,
    output: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    write_snapshot(machine, output, true)
}

/// Writes the Nix entry points consumed by the machine flake.
/// Diagnostic metadata remains available through `export_snapshot`; it is not needed
/// in the application source shipped to the controller's builder.
pub fn export_installation(
    machine: &model::MachineSnapshot,
    output: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    write_snapshot(machine, output, false)
}

/// Emits one snapshot, optionally retaining diagnostic maps and connection inspection data.
fn write_snapshot(
    machine: &model::MachineSnapshot,
    output: &Path,
    metadata: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(output)?;

    if let Some(host) = machine.host()
        && matches!(host.platform, model::HostPlatform::UsbLab)
    {
        let artifact = crate::compile_module(&host::physical::hardware())
            .map_err(|diagnostic| diagnostic.render(Path::new(".")))?;
        std::fs::write(output.join("hardware.nix"), &artifact.module.source)?;
        if metadata {
            std::fs::write(
                output.join("hardware.json"),
                serde_json::to_vec_pretty(&artifact)?,
            )?;
        }
    }

    for vm in machine.vms() {
        if vm.modules.is_empty() {
            continue;
        }

        let mut combined = rusix::nixos::NixosModule::empty();
        for module in &vm.modules {
            combined = combined.module(module.clone());
        }

        let artifact = crate::compile_module(&combined)
            .map_err(|diagnostic| diagnostic.render(Path::new(".")))?;

        std::fs::write(
            output.join(format!("{name}.nix", name = vm.name)),
            &artifact.module.source,
        )?;
        if metadata {
            std::fs::write(
                output.join(format!("{name}.json", name = vm.name)),
                serde_json::to_vec_pretty(&artifact)?,
            )?;
        }
    }

    let generated = generate(machine)?;
    std::fs::write(output.join("default.nix"), &generated.source)?;
    if metadata {
        std::fs::write(
            output.join("connections.json"),
            serde_json::to_vec_pretty(
                &serde_json::json!({ "screenCapture": machine.capture_connections() }),
            )?,
        )?;
        std::fs::write(
            output.join("default.json"),
            serde_json::to_vec_pretty(&generated)?,
        )?;
    }

    Ok(())
}

/// Compile the nested bootstrap machine with factories indexed by VM identity.
pub fn bootstrap_configuration() -> Result<rusix::Generated, Box<dyn std::error::Error>> {
    Ok(generate(&profiles::bootstrap::machine()?)?)
}

/// Compiles service-owned package constructors for standalone and machine Nix consumers.
pub fn gui_service_packages() -> Result<rusix::Generated, String> {
    crate::compile(airlock_sys_gui_service::authoring::packages())
        .map_err(|diagnostic| diagnostic.render(Path::new(".")))
}

/// Compiles native application recipes for standalone builds and machine components.
pub fn application_packages() -> Result<rusix::Generated, String> {
    crate::compile(packages::configuration())
        .map_err(|diagnostic| diagnostic.render(Path::new(".")))
}

/// Compile VM system, boot-filesystem and store-manifest constructors for Nix entry points.
pub fn vm_builders() -> Result<rusix::Generated, String> {
    crate::compile(rusix::Config::new().set_dynamic("builders", vm_build::constructors()))
        .map_err(|diagnostic| diagnostic.render(Path::new(".")))
}

/// Compile VM module entry points for machine integrations outside the typed authoring API.
pub fn machine_modules() -> Result<rusix::Generated, String> {
    crate::compile(vm::modules()).map_err(|diagnostic| diagnostic.render(Path::new(".")))
}

/// Compile graphical validation environments and descriptor materialization at the flake boundary.
pub fn display_builders() -> Result<rusix::Generated, String> {
    let configuration = rusix::Config::new()
        .set_dynamic("displays", displays::builders())
        .set_dynamic("release", release::constructor())
        .set_dynamic(
            "materialize",
            rusix::interop::raw::NixValue::function(|entry| {
                assembly::materialize(entry, &rusix::nix_record! {}, "")
            }),
        );

    crate::compile(configuration).map_err(|diagnostic| diagnostic.render(Path::new(".")))
}

/// Compile an application or development flake entry point.
/// Unknown kinds and Rusix compilation diagnostics are returned without writing files.
pub fn flake(kind: &str) -> Result<rusix::Generated, String> {
    crate::compile(flakes::configuration(kind)?)
        .map_err(|diagnostic| diagnostic.render(Path::new(".")))
}

/// Rusix authoring primitives used for additional machine and VM contributions.
pub use rusix;

/// Emit a prepared machine build tree from its physical and nested source declarations.
/// This writes generated Nix artifacts and performs no evaluation, build or deployment.
pub fn export_machine(
    physical: &model::MachineSnapshot,
    bootstrap: &model::MachineSnapshot,
    application_revision: &str,
    directory: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    export_installation(physical, &directory.join("generated/machine"))?;
    export_installation(bootstrap, &directory.join("generated/bootstrap"))?;
    export_installation(
        &profiles::local_lab::machine()?,
        &directory.join("generated/local-lab"),
    )?;
    let flake = crate::compile(flakes::machine_configuration(application_revision))
        .map_err(|diagnostic| diagnostic.render(directory))?;
    std::fs::write(directory.join("flake.nix"), flake.source)?;
    std::fs::write(directory.join("generated/schemas.nix"), schemas()?.source)?;

    Ok(())
}

/// Compile the topology and deployment-plan schema entry points for protocol integration checks.
pub fn schemas() -> Result<rusix::Generated, String> {
    crate::compile(
        rusix::Config::new()
            .set_dynamic("topology", topology::library())
            .set_dynamic("system", system_plan::library()),
    )
    .map_err(|diagnostic| diagnostic.render(Path::new(".")))
}
