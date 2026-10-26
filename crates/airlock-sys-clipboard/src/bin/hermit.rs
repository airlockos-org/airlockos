//! Hermit PVH entry point. Deployment stays disconnected from clipboard traffic
//! until a production GUI authorization path is provisioned.

#[cfg(target_os = "hermit")]
use hermit as _;

/// Report execution without granting a peer access or accepting clipboard requests.
/// Parking uses Hermit's scheduler; no polling loop or dom0 runtime broker is needed.
#[cfg(all(target_os = "hermit", not(feature = "lab-authority")))]
fn main() {
    let nonce = std::env::args()
        .find_map(|argument| argument.strip_prefix("airlock.boot=").map(str::to_owned))
        .filter(|value| {
            value.len() == 36
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
        })
        .expect("deployment must provide a boot challenge");
    println!("AIRLOCK_CLIPBOARD_EXECUTING authority=disconnected readiness=isolated boot={nonce}");
    loop {
        std::thread::park();
    }
}

/// Establish the laboratory's dom0-only grant channel and run the real service.
#[cfg(all(target_os = "hermit", feature = "lab-authority"))]
fn main() {
    use xen_transport::{Peer, hermit::Hermit};

    println!("AIRLOCK_CLIPBOARD_START");
    let mut epoch = 0;
    let mut channel = Hermit::connect(Peer { domain: 0 }, 10_000_000_000, |offer| {
        epoch = offer.session;
        println!(
            "XEN_IPC_OFFER port={port} grant={grant} session={session}",
            port = offer.port,
            grant = offer.grant,
            session = offer.session
        );
    })
    .expect("connect controlled dom0 authority");
    airlock_sys_clipboard::laboratory::serve(&mut channel, epoch)
        .expect("clipboard service and transport cleanup");
    println!("AIRLOCK_CLIPBOARD_PASS");
}

/// Reject accidental native execution; native testing uses the policy and peer.
#[cfg(not(target_os = "hermit"))]
fn main() {
    panic!("sys-clipboard requires the Hermit PVH application builder");
}
