//! Thin command entry point. Backend authority stays behind existing qrexec policy.
mod artifact;

mod builder_store;

mod inspect;

mod machine;

mod submit;

use std::{env, process::ExitCode};

fn main() -> ExitCode {
    let mut args = env::args_os();
    let _program = args.next();

    match args.next() {
        Some(command) if command == "builder-store" => {
            builder_store::main_from(std::iter::once("airlock builder-store".into()).chain(args))
        }
        Some(command) if command == "artifact" => {
            artifact::main_from(std::iter::once("airlock artifact".into()).chain(args))
        }
        Some(command) if command == "inspect" => {
            inspect::main_from(std::iter::once("airlock inspect".into()).chain(args))
        }
        Some(command) if command == "diagnostics" => airlock_diagnostics::cli::main_from(
            std::iter::once("airlock diagnostics".into()).chain(args),
        ),
        Some(command) if command == "machine" => {
            machine::main_from(std::iter::once("airlock machine".into()).chain(args))
        }
        Some(command) if command == "--version" || command == "-V" => {
            println!("airlock {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some(command) if command == "--help" || command == "-h" => {
            help();
            ExitCode::SUCCESS
        }
        None => {
            help();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("airlock: unknown command {other:?}; use --help");
            ExitCode::from(2)
        }
    }
}

fn help() {
    println!(
        r#"{description}

Usage: airlock <COMMAND>

Commands:
  builder-store Mount or stop the guest builder store
  artifact      Transfer a frozen Nix configuration through dom0 admission
  inspect       Read-only local record and lock inspection (see inspect --help)
  machine       Configuration, deployment and maintenance (see machine --help)
  diagnostics   Discover and request scoped read-only VM evidence

Options:
  -h, --help     Show help
  -V, --version  Show version"#,
        description = env!("CARGO_PKG_DESCRIPTION")
    );
}
