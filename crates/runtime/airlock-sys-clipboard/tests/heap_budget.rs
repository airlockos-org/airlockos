//! Run real clipboard policy and framing under the same fixed global heap as Hermit.
//! The native test harness shares the arena, providing additional allocation pressure.

use airlock_clipboard_core::{
    resources::SLOT_LIMIT,
    shared::{
        Clipboard, Error, Format, MAX_FORMAT_NAME, MAX_FORMATS, Participant, storage::RAM_LIMIT,
    },
};
use airlock_sys_clipboard::{
    heap::{APP_HEAP_BYTES, FixedHeap},
    shared::{self, Incoming, MAX_PACKET},
};
use xen_transport::Kind;

/// Every Rust allocation in this test executable is charged to the application arena.
#[global_allocator]
static HEAP: FixedHeap<APP_HEAP_BYTES> = FixedHeap::new();

#[test]
fn maximum_connection_framing_payload_and_exhaustion_recover() {
    let packet = vec![0; MAX_PACKET];
    let frames = shared::frames(Kind::Request, 1, &packet).unwrap();
    let mut connections = Vec::new();
    let mut responses = Vec::new();
    for _ in 0..=SLOT_LIMIT {
        let mut incoming = Incoming::default();
        for frame in &frames[..frames.len() - 1] {
            assert!(incoming.push(frame).unwrap().is_none());
        }
        connections.push(incoming);
        responses.push(shared::frames(Kind::Response, 1, &packet).unwrap());
    }
    let caller = Participant {
        principal: 1,
        epoch: 1,
    };
    let mut clipboard = Clipboard::new(RAM_LIMIT);
    let generation = clipboard.reserve(1, caller).unwrap();
    clipboard
        .declare(
            1,
            caller,
            generation,
            (0..MAX_FORMATS)
                .map(|index| Format {
                    name: format!(
                        "{index:03}{suffix}",
                        suffix = "x".repeat(MAX_FORMAT_NAME - 3)
                    ),
                    size: RAM_LIMIT / MAX_FORMATS,
                })
                .collect(),
        )
        .unwrap();
    let chunk = [7; shared::DATA_CHUNK];
    for format in 0..MAX_FORMATS {
        for offset in (0..RAM_LIMIT / MAX_FORMATS).step_by(chunk.len()) {
            clipboard
                .write(2, caller, generation, format, offset, &chunk)
                .unwrap();
        }
    }
    clipboard.complete(2, caller, generation).unwrap();
    let reply = shared::execute(&mut clipboard, 2, caller, shared::Request::Offer);
    let encoded = reply.encode();
    let output = shared::frames(Kind::Response, 2, &encoded).unwrap();
    assert!(!output.is_empty());
    drop(output);
    drop(encoded);
    drop(reply);
    let (live, peak) = HEAP.usage();
    assert!(live >= RAM_LIMIT);
    assert!(peak <= APP_HEAP_BYTES);
    println!("APP_HEAP_STRESS cap={APP_HEAP_BYTES} live={live} peak={peak}");

    // Exhaust the remaining arena through a fallible API; no kernel fallback exists.
    let mut pressure = Vec::<u8>::new();
    assert!(pressure.try_reserve_exact(APP_HEAP_BYTES).is_err());
    assert_eq!(HEAP.usage().0, live);
    // Keep allocator pressure itself on the stack, so rejection needs no heap growth.
    let mut pressure: [Option<Vec<u8>>; 1024] = core::array::from_fn(|_| None);
    let mut exhausted = false;
    for entry in &mut pressure {
        let mut block = Vec::<u8>::new();
        if block.try_reserve_exact(1024).is_err() {
            exhausted = true;
            break;
        }
        *entry = Some(block);
    }
    assert!(exhausted);
    assert!(Incoming::default().push(&frames[0]).is_err());
    assert!(shared::Reply::Error(Error::Capacity).try_encode().is_err());
    assert!(matches!(clipboard.offer(caller), Err(Error::Capacity)));
    drop(pressure);
    assert!(clipboard.offer(caller).is_ok());
    clipboard.reserve(2, caller).unwrap();
    drop(connections);
    drop(responses);
    assert!(HEAP.usage().0 < live - RAM_LIMIT);

    // Previously pressured storage can again reserve its maximum bounded RAM offer.
    let generation = clipboard.reserve(3, caller).unwrap();
    clipboard
        .declare(
            3,
            caller,
            generation,
            vec![Format {
                name: "text/plain".into(),
                size: RAM_LIMIT,
            }],
        )
        .unwrap();
    clipboard.reserve(4, caller).unwrap();
}
