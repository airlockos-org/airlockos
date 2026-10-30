//! Hermit PVH entry point; the admitted boot contract selects GUI-bound or isolated operation.

#[cfg(target_os = "hermit")]
use hermit as _;

/// Start the admitted GUI connection, or park an explicitly disconnected service.
#[cfg(target_os = "hermit")]
fn main() {
    // The immutable builder supplies this identity; it is diagnostic evidence,
    // never an authorization token or a replacement for the executable digest.
    let source = option_env!("AIRLOCK_SOURCE_REVISION").unwrap_or("unrecorded");
    println!("AIRLOCK_CLIPBOARD_BUILD source={source}");
    let (live, peak) = airlock_sys_clipboard::heap::APPLICATION_HEAP.usage();
    println!(
        "AIRLOCK_CLIPBOARD_HEAP cap={cap} live={live} peak={peak}",
        cap = airlock_sys_clipboard::heap::APP_HEAP_BYTES
    );
    let mut parser = airlock_clipboard_core::boot::BootParser::new();
    for argument in std::env::args() {
        parser = match parser.push(argument.as_bytes()) {
            Ok(next) => next,
            Err(error) => {
                println!("AIRLOCK_CLIPBOARD_BOOT_REJECT error={error:?}");
                std::process::exit(1);
            }
        };
    }
    let config = match parser.finish() {
        Ok(config) => config,
        Err(error) => {
            println!("AIRLOCK_CLIPBOARD_BOOT_REJECT error={error:?}");
            std::process::exit(1);
        }
    };
    let (challenge, mode) = config.into_parts();
    let nonce = match core::str::from_utf8(challenge.as_bytes()) {
        Ok(nonce) => nonce,
        Err(_) => {
            println!("AIRLOCK_CLIPBOARD_BOOT_REJECT error=ChallengeInvariant");
            std::process::exit(1);
        }
    };
    if let airlock_clipboard_core::boot::Mode::Connected {
        authority,
        scratch_bytes,
    } = mode
    {
        if let Err(error) =
            airlock_sys_clipboard::service::run(authority, &challenge, scratch_bytes)
        {
            println!("AIRLOCK_CLIPBOARD_STOP error={error:?} boot={nonce}");
            std::process::exit(1);
        }
        return;
    }
    println!("AIRLOCK_CLIPBOARD_EXECUTING authority=disconnected readiness=isolated boot={nonce}");
    loop {
        std::thread::park();
    }
}

/// Reject accidental native execution; native tests exercise policy and framing.
#[cfg(not(target_os = "hermit"))]
fn main() {
    panic!("sys-clipboard requires the Hermit PVH application builder");
}
