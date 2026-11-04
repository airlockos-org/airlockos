//! Exercise bounded service pressure through real independently owned Xen channels.
//! Only a disposable boot may designate this Linux peer as its trusted authority.
//! Several principals share that peer domain; this is endpoint stress, not a test
//! of GUI membership or isolation between 32 separate Linux VMs.

use super::{Client, DATA_CHUNK, Error, Format, Reply, Request, formats, pattern};
use airlock_clipboard_core::{
    resources::{LIVE_LIMIT, SLOT_LIMIT},
    shared::{DEFAULT_CAPACITY, MAX_FORMAT_NAME, MAX_FORMATS, storage::RAM_LIMIT},
};
use airlock_machine_core::services::ClipboardEndpoint;
use airlock_sys_clipboard::shared::{self, Incoming, MAX_PACKET};
use anyhow::{Context, Result, bail, ensure};
use std::{
    fs::File,
    io::Read,
    path::Path,
    thread,
    time::{Duration, Instant},
};
use xen_transport::{Error as TransportError, Kind, Message};

/// Provision one principal through the guest's boot-bound authority channel.
/// Capacity remains an ordinary reply; transport failures cannot masquerade as rejection.
fn provision(
    authority: &mut Client,
    principal: u64,
    domain: u16,
    guest: u16,
) -> Result<Option<Client>> {
    match authority.request(Request::Connect { principal, domain })? {
        Reply::Connected { epoch, port, grant } => Ok(Some(Client::attach(ClipboardEndpoint {
            domain: guest,
            principal,
            epoch,
            port,
            grant,
        })?)),
        Reply::Error(Error::Capacity) => Ok(None),
        _ => bail!("unexpected provisioning reply category"),
    }
}

/// Require an available slot without hiding a rejected admission in a retry.
fn admit(authority: &mut Client, principal: u64, domain: u16, guest: u16) -> Result<Client> {
    provision(authority, principal, domain, guest)?
        .context("unexpected endpoint capacity rejection")
}

/// Reclaim asynchronously closed endpoints within a fixed laboratory deadline.
fn readmit(authority: &mut Client, principal: u64, domain: u16, guest: u16) -> Result<Client> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(client) = provision(authority, principal, domain, guest)? {
            return Ok(client);
        }
        ensure!(
            Instant::now() < deadline,
            "endpoint capacity did not recover"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

/// Encode test requests through the production codec, retaining its error category.
fn encode(request: &Request) -> Result<Vec<u8>> {
    request
        .try_encode()
        .map_err(|error| anyhow::anyhow!("request encode: {error:?}"))
}

/// Publish a request without consuming its response, preserving exact response IDs.
fn send(client: &mut Client, request: Request) -> Result<u64> {
    client.sequence = client
        .sequence
        .checked_add(1)
        .context("sequence exhausted")?;
    let deadline = client.channel.deadline_after(5_000_000_000);
    for frame in shared::frames(Kind::Request, client.sequence, &encode(&request)?)
        .map_err(|error| anyhow::anyhow!("request framing: {error:?}"))?
    {
        client
            .channel
            .send(&frame, deadline)
            .map_err(|error| anyhow::anyhow!("request send: {error:?}"))?;
    }
    Ok(client.sequence)
}

/// Drain exactly one queued response; a partial response or transport close fails the test.
fn receive(client: &mut Client, expected: u64) -> Result<Reply> {
    let deadline = client.channel.deadline_after(5_000_000_000);
    let mut incoming = Incoming::responses();
    loop {
        let frame = client
            .channel
            .recv(deadline)
            .map_err(|error| anyhow::anyhow!("response receive: {error:?}"))?;
        ensure!(frame.id == expected, "response sequence mismatch");
        if let Some(packet) = incoming
            .push(&frame)
            .map_err(|error| anyhow::anyhow!("response assembly: {error:?}"))?
        {
            return Reply::decode(&packet)
                .map_err(|error| anyhow::anyhow!("reply decode: {error:?}"));
        }
    }
}

/// Maximal metadata makes each Offer response exceed the eight-frame transport queue.
fn rich_formats(size: usize) -> Vec<Format> {
    (0..MAX_FORMATS)
        .map(|index| Format {
            name: format!(
                "{index:03}{suffix}",
                suffix = "x".repeat(MAX_FORMAT_NAME - 3)
            ),
            size: size / MAX_FORMATS + usize::from(index < size % MAX_FORMATS),
        })
        .collect()
}

/// Assert byte identity for an already queued read without printing its payload.
fn check_data(reply: Reply, format: usize, offset: usize, count: usize) -> Result<()> {
    let Reply::Data(bytes) = reply else {
        bail!("queued read failed");
    };
    let mut expected = vec![0; count];
    pattern(format, offset, &mut expected);
    ensure!(bytes == expected, "queued read payload mismatch");
    Ok(())
}

/// Keep response queues full on every other peer while one peer continues useful work.
fn backpressure(peers: &mut [Client], metadata: &[Format]) -> Result<()> {
    let generation = peers[0].verify(metadata)?;
    let mut requests = Vec::new();
    for peer in &mut peers[1..] {
        requests.push(send(
            peer,
            Request::Read {
                generation,
                format: 0,
                offset: 0,
            },
        )?);
    }
    // Read replies contain 4096 bytes and cannot fit into eight 224-byte frames.
    // Fill each request ring while its response is deliberately left unread.
    let mut queued = Vec::new();
    for peer in &mut peers[1..] {
        let mut ids = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let next = peer.sequence + 1;
            let frame = shared::frames(Kind::Request, next, &encode(&Request::Offer)?)
                .map_err(|error| anyhow::anyhow!("queue frame: {error:?}"))?
                .remove(0);
            match peer.channel.try_send(&frame) {
                Ok(()) => {
                    peer.sequence = next;
                    ids.push(next);
                }
                Err(TransportError::Full) => break,
                Err(error) => bail!("request queue failure: {error:?}"),
            }
            ensure!(
                ids.len() <= 16 && Instant::now() < deadline,
                "request queue never applied backpressure"
            );
        }
        ensure!(!ids.is_empty(), "no requests queued behind unread reply");
        queued.push(ids);
    }
    // A blocked connection must not monopolize the service loop.
    peers[0].verify(metadata)?;
    for ((peer, read), ids) in peers[1..].iter_mut().zip(requests).zip(queued) {
        check_data(receive(peer, read)?, 0, 0, DATA_CHUNK)?;
        for id in ids {
            ensure!(
                matches!(receive(peer, id)?, Reply::Offer(current, Some(offer))
                if current == generation && offer.formats == metadata),
                "queued metadata corrupted"
            );
        }
    }
    event(
        "queued-replies",
        serde_json::json!({"blocked_peers": peers.len() - 1}),
    );
    Ok(())
}

/// Reserve a maximal assembly on each peer, leaving only a contiguous prefix present.
/// No malformed packet is completed or interpreted as an authorized operation.
fn partial_packets(peers: &mut [Client], round: usize) -> Result<()> {
    for (index, peer) in peers.iter_mut().enumerate() {
        peer.sequence += 1;
        let mut bytes = [0; xen_transport::MAX_PAYLOAD];
        let total = MAX_PACKET - (index + round) % 17;
        bytes[..4].copy_from_slice(&(total as u32).to_le_bytes());
        let frame = Message::new(Kind::Request, peer.sequence, &bytes)
            .map_err(|error| anyhow::anyhow!("partial packet: {error:?}"))?;
        let deadline = peer.channel.deadline_after(5_000_000_000);
        peer.channel
            .send(&frame, deadline)
            .map_err(|error| anyhow::anyhow!("partial send: {error:?}"))?;
    }
    Ok(())
}

/// Run admission, backpressure, retained mappings, reclamation and replacement stress.
/// The input is a bounded trusted console record for this disposable guest only.
pub(super) fn run(path: &Path, domain: u16, rounds: u16) -> Result<()> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(16 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 16 * 1024, "oversized laboratory endpoint");
    let endpoint: ClipboardEndpoint = serde_json::from_slice(&bytes)?;
    let guest = endpoint.domain;
    ensure!(
        (1..0x7ff0).contains(&guest) && guest != domain && endpoint.epoch > 0,
        "invalid laboratory endpoint"
    );
    let mut authority = Client::attach(endpoint)?;
    ensure!(
        matches!(authority.request(Request::Offer)?, Reply::Ok),
        "authority handshake failed"
    );
    let mut peers = Vec::new();
    for principal in 1..=LIVE_LIMIT {
        let mut peer = admit(&mut authority, principal as u64, domain, guest)?;
        peer.empty()?;
        peers.push(peer);
    }
    ensure!(
        provision(&mut authority, 1000, domain, guest)?.is_none(),
        "live endpoint limit bypassed"
    );
    event(
        "live-limit",
        serde_json::json!({"live": peers.len(), "rejected": true}),
    );

    let metadata = rich_formats(RAM_LIMIT);
    peers[0].publish(&metadata, false)?;
    backpressure(&mut peers, &metadata)?;
    partial_packets(&mut peers[1..], 0)?;
    peers[0].verify(&metadata)?;

    // Supersede each partial peer while retaining its Linux mappings. Closing the
    // old grant must remain Busy, so its service-side reservation stays charged.
    let mut retained = Vec::new();
    for index in 1..LIVE_LIMIT {
        let replacement = admit(&mut authority, (index + 1) as u64, domain, guest)?;
        retained.push(std::mem::replace(&mut peers[index], replacement));
    }
    ensure!(
        peers.len() + retained.len() == SLOT_LIMIT,
        "test does not reach total endpoint limit"
    );
    ensure!(
        provision(&mut authority, 1000, domain, guest)?.is_none(),
        "retained mappings lost their charges"
    );
    // A rejected reconnection revokes the superseded incarnation but must leave
    // unrelated peers, the authority and the published offer operational.
    ensure!(
        provision(&mut authority, LIVE_LIMIT as u64, domain, guest)?.is_none(),
        "full-pool reconnect succeeded"
    );
    let old = peers.pop().context("missing superseded peer")?;
    retained.push(old);
    peers[0].verify(&metadata)?;
    event(
        "retained-limit",
        serde_json::json!({"live": peers.len(), "retiring": retained.len(), "rejected": true}),
    );
    drop(retained);
    peers.push(readmit(&mut authority, LIVE_LIMIT as u64, domain, guest)?);
    peers[0].verify(&metadata)?;
    event("reclaimed", serde_json::json!({"live": peers.len()}));

    // Vary metadata and packet allocation sizes around the RAM/disk threshold.
    // Retiring partial assemblies create holes while the next maximum RAM offer
    // is allocated. Every round verifies bytes before and after source changes.
    for round in 0..usize::from(rounds) {
        let size = match round % 4 {
            0 => RAM_LIMIT,
            1 => RAM_LIMIT + 1,
            2 => 4097 + round,
            _ => RAM_LIMIT - 1 - round,
        };
        let layout = if round % 2 == 0 {
            rich_formats(size)
        } else {
            formats(size)
        };
        peers[0].publish(&layout, false)?;
        peers[1].verify(&layout)?;
        partial_packets(&mut peers[2..], round)?;
        for index in 2..peers.len() {
            // Only one old mapping is retained during this churn; capacity is
            // retried exclusively after its confirmed local owner is dropped.
            let replacement = readmit(&mut authority, (index + 1) as u64, domain, guest)?;
            drop(std::mem::replace(&mut peers[index], replacement));
        }
        peers[0].verify(&layout)?;
        event(
            "replacement",
            serde_json::json!({"round": round, "size": size, "formats": layout.len()}),
        );
    }
    peers[0].copy(DEFAULT_CAPACITY, false)?;
    peers[1].read(DEFAULT_CAPACITY)?;
    peers[0].faults()?;
    peers[0].copy(RAM_LIMIT, false)?;
    peers[1].read(RAM_LIMIT)?;
    let generation = peers[0].reserve()?;
    peers[0].mutate(Request::Declare {
        generation,
        formats: Vec::new(),
    })?;
    peers[1].empty()?;
    drop(peers);
    // Continue using the authority after the data mappings have been withdrawn.
    let mut fresh = readmit(&mut authority, 2000, domain, guest)?;
    fresh.empty()?;
    fresh.copy(8193, false)?;
    fresh.read(8193)?;
    event(
        "complete",
        serde_json::json!({"status": "passed", "rounds": rounds,
        "live_limit": LIVE_LIMIT, "data_slot_limit": SLOT_LIMIT, "linux_peer_domains": 1}),
    );
    Ok(())
}

/// Emit structured counts and phase names, never synthetic clipboard bytes or names.
fn event(phase: &str, detail: serde_json::Value) {
    println!(
        "{record}",
        record = serde_json::json!({"event": "clipboard-stress", "phase": phase, "detail": detail})
    );
}
