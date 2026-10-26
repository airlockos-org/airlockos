//! Hermit PVH entry point for the controlled clipboard laboratory service.

#[cfg(target_os = "hermit")]
use hermit as _;

/// Establish the laboratory's dom0-only grant channel and run the real service.
#[cfg(target_os = "hermit")]
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
