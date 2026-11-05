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
    // Upstream filtering/formatting owns the logging boundary. The boot identity
    // and monotonic clock correlate application and transport events without UTC.
    use std::io::Write;
    let boot = String::from_utf8_lossy(challenge.as_bytes()).into_owned();
    let logger_boot = boot.clone();
    let mut logger =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"));
    logger.format(move |buffer, record| {
        writeln!(
            buffer,
            "level={level} target={target} boot={logger_boot} monotonic_ns={now} {message}",
            level = record.level(),
            target = record.target(),
            now = xen_transport::hermit::endpoint::now_ns(),
            message = record.args()
        )
    });
    if let Err(error) = logger.try_init() {
        eprintln!("AIRLOCK_FIREWALL_LOG_INIT error={error}");
    }
    log::info!("operation=startup state=starting");
    let mut seed = [0; 32];
    if getrandom::fill(&mut seed).is_err() {
        eprintln!("AIRLOCK_FIREWALL_STOP error=EntropyUnavailable");
        std::process::exit(1);
    }
    println!(
        "AIRLOCK_FIREWALL_BUILD source={source} scope=dual-stack-experiment",
        source = option_env!("AIRLOCK_SOURCE_REVISION").unwrap_or("unrecorded")
    );
    if let Err(error) = airlock_sys_firewall::service::run(challenge, seed) {
        eprintln!(
            "AIRLOCK_FIREWALL_STOP boot={boot} monotonic_ns={now} error={error:?}",
            now = xen_transport::hermit::endpoint::now_ns()
        );
        std::process::exit(1);
    }
}

/// Reject accidental host execution instead of supplying a mock network path.
#[cfg(not(target_os = "hermit"))]
fn main() {
    panic!("sys-firewall requires the Hermit PVH application builder");
}
