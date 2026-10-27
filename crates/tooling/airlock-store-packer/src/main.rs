//! Pack one immutable store package; this tool has no deployment or Qubes control interface.

use anyhow::{Result, bail};
use std::{env, path::Path};

/// Accept the fixed fragment operation used by the Nix cache derivation.
fn run() -> Result<()> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    match args.as_slice() {
        [operation, logical, source, output] if operation == "fragment" => {
            airlock_store_packer::pack(
                logical
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("non-UTF8 store path"))?,
                Path::new(source),
                Path::new(output),
            )?;
        }
        _ => bail!("usage: airlock-store-packer fragment STORE_PATH SOURCE OUTPUT"),
    }
    Ok(())
}

/// Preserve failure diagnostics for the Nix builder and exit unsuccessfully on any packing error.
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("airlock-store-packer: {error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
