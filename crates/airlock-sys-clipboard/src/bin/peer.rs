//! Trusted dom0 test authority exercising the actual clipboard guest over Xen.
use airlock_clipboard_core::{Action, CHUNK_SIZE, Chunk, Error, MAX_CONTENT, Request, Response};
use airlock_sys_clipboard::{
    laboratory::Provision,
    protocol::{Operation, Reply},
};
use xen_transport::{Channel, Kind, Message, Offer, Peer, Wire, linux::Linux};

/// Sequential test driver with independently monotonic request and approval IDs.
struct Driver {
    /// Grant/event endpoint provisioned by the disposable Xen controller.
    channel: Channel<Linux>,
    /// High-water mark of sent requests, including authority messages.
    sequence: u64,
    /// High-water mark of installed clipboard policy decisions.
    decision: u64,
}

impl Driver {
    /// Send a typed frame and verify its correlated response before continuing.
    fn exchange<T: Wire>(&mut self, request: &T) -> Result<Response, Error> {
        self.sequence += 1;
        self.channel
            .send_typed(
                self.sequence,
                request,
                self.channel.deadline_after(2_000_000_000),
            )
            .unwrap();
        self.receive()
    }

    /// Receive one exact reply; transport errors and wrong correlations fail the test.
    fn receive(&mut self) -> Result<Response, Error> {
        let (id, reply) = self
            .channel
            .recv_typed::<Reply>(self.channel.deadline_after(2_000_000_000))
            .unwrap();
        assert_eq!(id, self.sequence);
        reply.0
    }

    /// Simulate a Qubes GUI decision only on this explicitly trusted laboratory peer.
    fn approve(&mut self, action: Action, lifetime_ns: u64) -> u64 {
        self.decision += 1;
        assert_eq!(
            self.exchange(&Provision {
                id: self.decision,
                principal: 7,
                action,
                lifetime_ns
            }),
            Ok(Response::Ok)
        );
        self.decision
    }

    /// Send a normal data-plane request, which contains no identity or approval flag.
    fn request(&mut self, request: Request) -> Result<Response, Error> {
        self.exchange(&Operation(request))
    }

    /// Commit a payload spanning as many transport frames as necessary.
    fn copy(&mut self, bytes: &[u8], lifetime_ns: u64) -> u64 {
        let transfer = self.approve(Action::Copy, lifetime_ns);
        assert_eq!(
            self.request(Request::Copy {
                transfer,
                size: bytes.len()
            }),
            Ok(Response::Ok)
        );
        for (index, data) in bytes.chunks(CHUNK_SIZE).enumerate() {
            assert_eq!(
                self.request(Request::Write {
                    transfer,
                    offset: index * CHUNK_SIZE,
                    data: Chunk::new(data).unwrap()
                }),
                Ok(Response::Ok)
            );
        }
        assert_eq!(
            self.request(Request::Complete { transfer }),
            Ok(Response::Ok)
        );
        transfer
    }

    /// Compare every byte of a claimed paste and explicitly complete its transfer.
    fn paste(&mut self, content: u64, expected: &[u8]) {
        let transfer = self.approve(Action::Paste { content }, 20_000_000_000);
        assert_eq!(
            self.request(Request::Paste { transfer }),
            Ok(Response::Size(expected.len()))
        );
        for offset in (0..expected.len()).step_by(CHUNK_SIZE) {
            let Ok(Response::Data(data)) = self.request(Request::Read { transfer, offset }) else {
                panic!("paste frame missing")
            };
            assert_eq!(
                data.bytes(),
                &expected[offset..(offset + CHUNK_SIZE).min(expected.len())]
            );
        }
        assert_eq!(
            self.request(Request::Complete { transfer }),
            Ok(Response::Ok)
        );
    }

    /// Confirm the generation cannot be claimed under a fresh authorized paste.
    fn unavailable(&mut self, content: u64) {
        let transfer = self.approve(Action::Paste { content }, 20_000_000_000);
        assert_eq!(
            self.request(Request::Paste { transfer }),
            Err(Error::Unavailable)
        );
    }

    /// Emit only scenario names and success state; never log clipboard data.
    fn event(name: &str) {
        println!("{{\"event\":\"{name}\",\"passed\":true}}");
    }

    /// Exercise policy and framing boundaries over the actual grant-backed queues.
    fn scenarios(&mut self) {
        assert_eq!(
            self.request(Request::Copy {
                transfer: 1,
                size: 1
            }),
            Err(Error::Unauthorized)
        );
        Self::event("unauthorized");
        for size in [
            0,
            1,
            CHUNK_SIZE - 1,
            CHUNK_SIZE,
            CHUNK_SIZE + 1,
            MAX_CONTENT,
        ] {
            let bytes: Vec<_> = (0..size)
                .map(|i| (i.wrapping_mul(17) % 251) as u8)
                .collect();
            let content = self.copy(&bytes, 20_000_000_000);
            self.paste(content, &bytes);
            self.unavailable(content);
        }
        Self::event("boundary_multiframe_one_shot");

        let content = self.copy(b"expiry", 150_000_000);
        std::thread::sleep(std::time::Duration::from_millis(200));
        self.unavailable(content);
        Self::event("expired");

        let transfer = self.approve(Action::Copy, 20_000_000_000);
        assert_eq!(
            self.request(Request::Copy {
                transfer,
                size: MAX_CONTENT + 1
            }),
            Err(Error::Bounds)
        );
        let transfer = self.approve(Action::Copy, 20_000_000_000);
        self.request(Request::Copy { transfer, size: 2 }).unwrap();
        self.request(Request::Write {
            transfer,
            offset: 0,
            data: Chunk::new(b"x").unwrap(),
        })
        .unwrap();
        self.request(Request::Cancel { transfer }).unwrap();
        self.unavailable(transfer);
        Self::event("cancelled_copy_and_size_bound");

        let content = self.copy(b"cancel paste", 20_000_000_000);
        let transfer = self.approve(Action::Paste { content }, 20_000_000_000);
        self.request(Request::Paste { transfer }).unwrap();
        self.request(Request::Cancel { transfer }).unwrap();
        self.unavailable(content);
        Self::event("cancelled_paste_consumes");

        let transfer = self.approve(Action::Copy, 20_000_000_000);
        self.request(Request::Copy { transfer, size: 2 }).unwrap();
        let write = Operation(Request::Write {
            transfer,
            offset: 0,
            data: Chunk::new(b"x").unwrap(),
        });
        self.exchange(&write).unwrap();
        self.channel
            .send_typed(
                self.sequence,
                &write,
                self.channel.deadline_after(2_000_000_000),
            )
            .unwrap();
        assert_eq!(self.receive(), Err(Error::Replay));
        assert_eq!(self.exchange(&write), Err(Error::Order));
        self.unavailable(transfer);
        let transfer = self.approve(Action::Copy, 20_000_000_000);
        self.request(Request::Copy { transfer, size: 2 }).unwrap();
        assert_eq!(
            self.request(Request::Write {
                transfer,
                offset: 1,
                data: Chunk::new(b"x").unwrap()
            }),
            Err(Error::Order)
        );
        self.unavailable(transfer);
        Self::event("duplicate_replay_and_out_of_order");

        let content = self.copy(b"old", 20_000_000_000);
        let replacement = self.copy(b"new", 20_000_000_000);
        self.unavailable(content);
        self.paste(replacement, b"new");
        Self::event("stale_generation");

        let transfer = self.approve(Action::Copy, 20_000_000_000);
        self.request(Request::Copy { transfer, size: 2 }).unwrap();
        self.sequence += 1;
        self.channel
            .send(
                &Message::new(Kind::Request, self.sequence, &[1, 2, 255]).unwrap(),
                self.channel.deadline_after(2_000_000_000),
            )
            .unwrap();
        assert_eq!(self.receive(), Err(Error::Malformed));
        self.unavailable(transfer);
        Self::event("malformed_clears_transfer");
    }
}

/// Connect using controller-provided capability coordinates and run a bounded case.
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(
        args.len(),
        6,
        "clipboard-peer DOMID PORT GRANT SESSION CASE"
    );
    let backend = Linux::open(
        Peer {
            domain: args[1].parse().unwrap(),
        },
        Offer {
            port: args[2].parse().unwrap(),
            grant: args[3].parse().unwrap(),
            session: args[4].parse().unwrap(),
        },
    )
    .unwrap();
    let mut driver = Driver {
        channel: Channel::new(backend),
        sequence: 0,
        decision: 0,
    };
    if args[5] == "peer-failure" {
        let transfer = driver.approve(Action::Copy, 20_000_000_000);
        driver
            .request(Request::Copy {
                transfer,
                size: MAX_CONTENT,
            })
            .unwrap();
        driver
            .request(Request::Write {
                transfer,
                offset: 0,
                data: Chunk::new(b"interrupted").unwrap(),
            })
            .unwrap();
        Driver::event("intentional_peer_exit_with_incomplete_copy");
        // No Rust destructors: the Xen adapter must observe process death/unmapping.
        std::process::exit(42);
    }
    driver.scenarios();
    // Shut down with an incomplete transfer, verifying the same cleanup path as failure.
    let transfer = driver.approve(Action::Copy, 20_000_000_000);
    driver.request(Request::Copy { transfer, size: 1 }).unwrap();
    driver.sequence += 1;
    driver
        .channel
        .send(
            &Message::new(Kind::Close, driver.sequence, &[]).unwrap(),
            driver.channel.deadline_after(2_000_000_000),
        )
        .unwrap();
    assert_eq!(driver.receive(), Ok(Response::Ok));
    driver
        .channel
        .close(driver.channel.deadline_after(2_000_000_000))
        .unwrap();
    Driver::event("resources_released");
    println!("AIRLOCK_CLIPBOARD_PEER_PASS");
}
