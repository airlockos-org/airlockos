//! Native Hermit entry point. The boot challenge correlates a startup; it never
//! chooses a network provider, client interface or control peer.

#[cfg(target_os = "hermit")]
use hermit as _;

/// Parse the existing shared startup contract and run the native service.
#[cfg(target_os = "hermit")]
fn main() {
    let mut parser = airlock_qubes_network::boot::Parser::empty();
    for argument in std::env::args() {
        if !parser.push(argument.as_bytes()) {
            eprintln!("AIRLOCK_FIREWALL_STOP error=BootArgument");
            std::process::exit(1);
        }
    }
    let Some(challenge) = parser.finish() else {
        eprintln!("AIRLOCK_FIREWALL_STOP error=MissingBootChallenge");
        std::process::exit(1);
    };
    let mut seed = [0; 32];
    if getrandom::fill(&mut seed).is_err() {
        eprintln!("AIRLOCK_FIREWALL_STOP error=EntropyUnavailable");
        std::process::exit(1);
    }
    println!(
        "AIRLOCK_FIREWALL_BUILD source={source} scope=ipv4-experiment",
        source = option_env!("AIRLOCK_SOURCE_REVISION").unwrap_or("unrecorded")
    );
    if let Err(error) = airlock_sys_firewall::service::run(challenge, seed) {
        eprintln!("AIRLOCK_FIREWALL_STOP error={error:?}");
        std::process::exit(1);
    }
}

/// Reject accidental host execution instead of supplying a mock network path.
#[cfg(not(target_os = "hermit"))]
fn main() {
    panic!("sys-firewall requires the Hermit PVH application builder");
}
