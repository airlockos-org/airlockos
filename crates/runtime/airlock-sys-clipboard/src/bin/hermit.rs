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
    let nonce = std::env::args()
        .find_map(|argument| argument.strip_prefix("airlock.boot=").map(str::to_owned))
        .filter(|value| {
            value.len() == 36
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
        })
        .expect("deployment must provide a boot challenge");
    if let Some(authority) = std::env::args().find_map(|argument| {
        argument
            .strip_prefix("airlock.authority=")
            .map(str::to_owned)
    }) {
        let authority = authority
            .parse::<u16>()
            .expect("invalid clipboard authority");
        let scratch_bytes = std::env::args()
            .find_map(|argument| {
                argument
                    .strip_prefix("airlock.scratch=")
                    .and_then(|value| value.parse::<u64>().ok())
            })
            .expect("normal clipboard requires admitted ephemeral storage");
        airlock_sys_clipboard::service::run(authority, &nonce, scratch_bytes)
            .expect("clipboard service failed");
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
