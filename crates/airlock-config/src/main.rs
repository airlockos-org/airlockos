//! Command-line entry point for configuration compilation and inspection.

use std::path::Path;

/// Dispatches generation, export, configuration review, offline planning or error mapping.
/// With no arguments, prints the six-VM USB lab definition. `bootstrap` emits the
/// the nested QEMU machine used for lifecycle validation.
/// Other commands consume explicit file paths and propagate failures to the entry point.
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();

    match arguments.as_slice() {
        [] => println!(
            "{}",
            airlock_config::generate(&airlock_config::profiles::usb_lab::machine(false)?)?.source
        ),
        [command, source, cache] if command == "prepare" => {
            let tree =
                airlock_config::preparation::development(Path::new(source), Path::new(cache))?;
            println!("path:{path}", path = tree.display());
        }
        [command, source, state, profile, nix, consumer, args @ ..]
            if command == "component-inputs" =>
        {
            let roots = airlock_config::preparation::components::prepare(
                Path::new(source),
                Path::new(state),
                profile,
                &|| {
                    let mut command = std::process::Command::new(nix);
                    command.args(["--extra-experimental-features", "nix-command flakes"]);
                    command
                },
            )?;
            let status = std::process::Command::new(consumer)
                .arg(roots.manifest())
                .args(args)
                .status()?;
            if !status.success() {
                return Err("component input consumer failed".into());
            }
        }
        [command, source, state, profile, nix, store] if command == "build-components" => {
            use airlock_config::preparation::component_build::{Request, build};
            let release = build(Request {
                source: Path::new(source),
                state: Path::new(state),
                profile,
                nix: Path::new(nix),
                store: Path::new(store),
                expected: None,
            })?;
            println!("{release}");
        }
        [command, directory] if command == "inspection" => {
            airlock_config::preparation::inspection(Path::new(directory))?;
        }
        [command, directory] if command == "runtime-seed" => {
            airlock_config::runtime::Candidate::new(airlock_config::profiles::runtime::machine()?)?
                .export(Path::new(directory))?;
        }
        [command, kind] if command == "flake" => {
            print!("{}", airlock_config::flake(kind)?.source);
        }
        [command] if command == "schemas" => {
            print!("{}", airlock_config::schemas()?.source);
        }
        [command] if command == "bootstrap" => {
            println!("{}", airlock_config::bootstrap_configuration()?.source);
        }
        [command] if command == "gui-service-packages" => {
            print!("{}", airlock_config::gui_service_packages()?.source);
        }
        [command] if command == "application-packages" => {
            print!("{}", airlock_config::application_packages()?.source);
        }
        [command] if command == "vm-builders" => {
            print!("{}", airlock_config::vm_builders()?.source);
        }

        [command] if command == "display-builders" => {
            print!("{}", airlock_config::display_builders()?.source);
        }
        [command] if command == "machine-modules" => {
            print!("{}", airlock_config::machine_modules()?.source);
        }
        [command] if command == "desktop-module" => {
            print!("{}", airlock_config::desktop_module()?.module.source);
        }
        [command, directory] if command == "export" => {
            airlock_config::export(Path::new(directory))?
        }
        [command, directory] if command == "machine" => airlock_config::export_installation(
            &airlock_config::profiles::usb_lab::machine(false)?,
            Path::new(directory),
        )?,
        [command, before, after] if command == "diff" => {
            let diff = airlock_config::review::compare_files(Path::new(before), Path::new(after))?;
            println!("{}", serde_json::to_string_pretty(&diff)?);
        }
        [command, before, after, running @ ..] if command == "inspect" => {
            let result = airlock_config::inspection::inspect_files(
                Path::new(before),
                Path::new(after),
                running,
            )?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        [command, planner, before, after, output, running @ ..] if command == "plan" => {
            let plan = airlock_config::inspection::plan(
                Path::new(planner),
                Path::new(before),
                Path::new(after),
                Path::new(output),
                running,
            )?;
            println!("{}", serde_json::to_string_pretty(&plan)?);
        }
        [command, artifact, source, nixpkgs, stderr] if command == "diagnose" => {
            let artifact: rusix::nixos::NixosArtifact =
                serde_json::from_slice(&std::fs::read(artifact)?)?;
            let diagnostic = artifact.diagnose(
                rusix::DiagnosticKind::NixEval,
                &std::fs::read_to_string(stderr)?,
                Path::new(source),
                Path::new(nixpkgs),
            );

            // Cargo source locations are relative to this example crate.
            println!(
                "{}",
                diagnostic.render(Path::new(env!("CARGO_MANIFEST_DIR")))
            );
        }
        _ => {
            return Err(
                "usage: airlock-config [prepare SOURCE CACHE | component-inputs SOURCE STATE PROFILE NIX CONSUMER [ARGS ...] | build-components SOURCE STATE PROFILE NIX STORE | inspection DIR | runtime-seed DIR | flake KIND | bootstrap | desktop-module | \
                 gui-service-packages | \
                 application-packages | vm-builders | display-builders | machine-modules | export DIR | \
                 machine DIR | diff BEFORE AFTER | inspect BEFORE AFTER [RUNNING_VM ...] | \
                 plan PLANNER BEFORE AFTER OUTPUT [RUNNING_VM ...] | \
                 diagnose ARTIFACT SOURCE NIXPKGS STDERR]"
                    .into(),
            );
        }
    }

    Ok(())
}

/// Reports command failures on stderr and exits unsuccessfully for shell callers.
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
