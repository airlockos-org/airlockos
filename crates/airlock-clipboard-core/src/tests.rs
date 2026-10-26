//! Policy tests use injected identities and time; no platform or transport is needed.
use super::*;

const OWNER: Caller = Caller {
    principal: 7,
    epoch: 11,
};

/// Session driver allocating monotonic request and policy IDs independently.
struct Session {
    /// State under test, including private cleanup invariants.
    clipboard: Clipboard,
    /// Next request sequence on this authenticated connection.
    sequence: u64,
    /// Next trusted policy decision ID.
    decision: u64,
    /// Injected monotonic nanoseconds.
    now: u64,
}

impl Session {
    /// Start with a nonzero clock so zero-deadline mistakes are visible.
    fn new() -> Self {
        Self {
            clipboard: Clipboard::new(),
            sequence: 0,
            decision: 0,
            now: 100,
        }
    }

    /// Install a decision for OWNER, expiring at the maximum allowed lifetime.
    fn approve(&mut self, action: Action) -> u64 {
        self.decision += 1;
        self.clipboard
            .authorize(
                self.now,
                Authorization {
                    id: self.decision,
                    caller: OWNER,
                    action,
                    expires: self.now + MAX_LIFETIME,
                },
            )
            .unwrap();
        self.decision
    }

    /// Execute as OWNER with a fresh sequence; failures still consume sequence IDs.
    fn request(&mut self, request: Request) -> Result<Response, Error> {
        self.sequence += 1;
        self.clipboard
            .handle(self.now, OWNER, self.sequence, request)
    }

    /// Commit deterministic content, verifying that no partially written copy is ready.
    fn copy(&mut self, size: usize) -> u64 {
        let transfer = self.approve(Action::Copy);
        assert_eq!(
            self.request(Request::Copy { transfer, size }),
            Ok(Response::Ok)
        );
        let data = [0x8b; CHUNK_SIZE];
        for offset in (0..size).step_by(CHUNK_SIZE) {
            assert_eq!(
                self.request(Request::Write {
                    transfer,
                    offset,
                    data: Chunk::new(&data[..(size - offset).min(CHUNK_SIZE)]).unwrap()
                }),
                Ok(Response::Ok)
            );
            assert_eq!(self.clipboard.phase, Phase::Copying);
        }
        assert_eq!(
            self.request(Request::Complete { transfer }),
            Ok(Response::Ok)
        );
        transfer
    }

    /// Verify terminal state and physical buffer clearing, not only API unavailability.
    fn erased(&self) {
        assert_eq!(self.clipboard.phase, Phase::Empty);
        assert_eq!(self.clipboard.len, 0);
        assert!(self.clipboard.bytes.iter().all(|byte| *byte == 0));
    }
}

#[test]
fn boundary_roundtrips_are_exclusive_and_one_shot() {
    for size in [
        0,
        1,
        CHUNK_SIZE - 1,
        CHUNK_SIZE,
        CHUNK_SIZE + 1,
        MAX_CONTENT,
    ] {
        let mut s = Session::new();
        let content = s.copy(size);
        let transfer = s.approve(Action::Paste { content });
        assert_eq!(
            s.request(Request::Paste { transfer }),
            Ok(Response::Size(size))
        );
        assert_eq!(s.clipboard.phase, Phase::Pasting);
        for offset in (0..size).step_by(CHUNK_SIZE) {
            let Ok(Response::Data(data)) = s.request(Request::Read { transfer, offset }) else {
                panic!("missing data")
            };
            assert_eq!(
                data.bytes(),
                &[0x8b; CHUNK_SIZE][..(size - offset).min(CHUNK_SIZE)]
            );
            assert!(
                s.clipboard.bytes[..s.clipboard.position]
                    .iter()
                    .all(|b| *b == 0)
            );
        }
        assert_eq!(s.request(Request::Complete { transfer }), Ok(Response::Ok));
        s.erased();
        let transfer = s.approve(Action::Paste { content });
        assert_eq!(
            s.request(Request::Paste { transfer }),
            Err(Error::Unavailable)
        );
    }
}

#[test]
fn authority_cannot_be_supplied_by_requests_or_rebound_to_another_identity() {
    let mut s = Session::new();
    assert_eq!(
        s.request(Request::Copy {
            transfer: 1,
            size: 1
        }),
        Err(Error::Unauthorized)
    );
    let transfer = s.approve(Action::Copy);
    for caller in [
        Caller {
            principal: 8,
            ..OWNER
        },
        Caller { epoch: 12, ..OWNER },
    ] {
        s.sequence += 1;
        assert_eq!(
            s.clipboard.handle(
                s.now,
                caller,
                s.sequence,
                Request::Copy { transfer, size: 1 }
            ),
            Err(Error::Unauthorized)
        );
    }
    assert_eq!(
        s.request(Request::Paste { transfer }),
        Err(Error::Unauthorized)
    );
    assert_eq!(
        s.request(Request::Copy { transfer, size: 1 }),
        Ok(Response::Ok)
    );
    s.sequence += 1;
    assert_eq!(
        s.clipboard.handle(
            s.now,
            Caller {
                principal: 8,
                ..OWNER
            },
            s.sequence,
            Request::Cancel { transfer }
        ),
        Err(Error::Unauthorized)
    );
    assert_eq!(s.clipboard.phase, Phase::Copying);
    assert_eq!(s.request(Request::Cancel { transfer }), Ok(Response::Ok));
    s.erased();
}

#[test]
fn stale_paste_approval_cannot_read_replacement_content() {
    let mut s = Session::new();
    let old = s.copy(5);
    let new = s.copy(9);
    let transfer = s.approve(Action::Paste { content: old });
    assert_eq!(
        s.request(Request::Paste { transfer }),
        Err(Error::Unavailable)
    );
    let transfer = s.approve(Action::Paste { content: new });
    assert_eq!(
        s.request(Request::Paste { transfer }),
        Ok(Response::Size(9))
    );
    assert_eq!(s.request(Request::Cancel { transfer }), Ok(Response::Ok));
    s.erased();
    let transfer = s.approve(Action::Paste { content: new });
    assert_eq!(
        s.request(Request::Paste { transfer }),
        Err(Error::Unavailable)
    );
}

#[test]
fn duplicate_and_out_of_order_frames_cannot_restore_or_extend_transfers() {
    let mut s = Session::new();
    let transfer = s.approve(Action::Copy);
    s.request(Request::Copy { transfer, size: 2 }).unwrap();
    let frame = Request::Write {
        transfer,
        offset: 0,
        data: Chunk::new(b"x").unwrap(),
    };
    s.request(frame.clone()).unwrap();
    assert_eq!(
        s.clipboard.handle(s.now, OWNER, s.sequence, frame.clone()),
        Err(Error::Replay)
    );
    assert_eq!(s.clipboard.position, 1);
    assert_eq!(s.request(frame), Err(Error::Order));
    s.erased();
    assert_eq!(
        s.request(Request::Complete { transfer }),
        Err(Error::Unavailable)
    );
    assert_eq!(
        s.clipboard.authorize(
            s.now,
            Authorization {
                id: transfer,
                caller: OWNER,
                action: Action::Copy,
                expires: s.now + 100
            }
        ),
        Err(Error::Replay)
    );

    let transfer = s.approve(Action::Copy);
    s.request(Request::Copy { transfer, size: 3 }).unwrap();
    assert_eq!(
        s.request(Request::Write {
            transfer,
            offset: usize::MAX,
            data: Chunk::new(b"x").unwrap()
        }),
        Err(Error::Order)
    );
    s.erased();
    let content = s.copy(3);
    let transfer = s.approve(Action::Paste { content });
    s.request(Request::Paste { transfer }).unwrap();
    assert_eq!(
        s.request(Request::Read {
            transfer,
            offset: 1
        }),
        Err(Error::Order)
    );
    s.erased();
}

#[test]
fn incomplete_completion_and_wrong_direction_erase_owned_transfer() {
    let mut s = Session::new();
    let transfer = s.approve(Action::Copy);
    s.request(Request::Copy { transfer, size: 2 }).unwrap();
    s.request(Request::Write {
        transfer,
        offset: 0,
        data: Chunk::new(b"x").unwrap(),
    })
    .unwrap();
    assert_eq!(s.request(Request::Complete { transfer }), Err(Error::Order));
    s.erased();
    let transfer = s.approve(Action::Copy);
    s.request(Request::Copy { transfer, size: 1 }).unwrap();
    assert_eq!(
        s.request(Request::Read {
            transfer,
            offset: 0
        }),
        Err(Error::Order)
    );
    s.erased();
}

#[test]
fn expiration_is_exact_and_idle_cleanup_covers_every_phase() {
    let mut s = Session::new();
    let content = s.copy(3);
    let expiry = s.clipboard.deadline().unwrap();
    s.clipboard.tick(expiry - 1).unwrap();
    assert_eq!(s.clipboard.phase, Phase::Ready);
    s.clipboard.tick(expiry).unwrap();
    s.erased();
    s.now = expiry;
    let transfer = s.approve(Action::Paste { content });
    assert_eq!(
        s.request(Request::Paste { transfer }),
        Err(Error::Unavailable)
    );

    for paste in [false, true] {
        let mut s = Session::new();
        if paste {
            let content = s.copy(3);
            let transfer = s.approve(Action::Paste { content });
            s.request(Request::Paste { transfer }).unwrap();
        } else {
            let transfer = s.approve(Action::Copy);
            s.request(Request::Copy { transfer, size: 3 }).unwrap();
            s.now += TRANSFER_LIFETIME - 1;
            s.request(Request::Write {
                transfer,
                offset: 0,
                data: Chunk::new(b"x").unwrap(),
            })
            .unwrap();
        }
        s.clipboard.tick(100 + TRANSFER_LIFETIME).unwrap();
        s.erased();
    }
    let mut s = Session::new();
    let transfer = s.approve(Action::Copy);
    s.now += MAX_LIFETIME;
    assert_eq!(
        s.request(Request::Copy { transfer, size: 1 }),
        Err(Error::Unauthorized)
    );
}

#[test]
fn bounds_busy_clock_regression_and_disconnect_fail_closed() {
    let mut s = Session::new();
    let transfer = s.approve(Action::Copy);
    assert_eq!(
        s.clipboard.authorize(
            s.now,
            Authorization {
                id: 2,
                caller: OWNER,
                action: Action::Copy,
                expires: s.now + 100
            }
        ),
        Err(Error::Busy)
    );
    assert_eq!(
        s.request(Request::Copy {
            transfer,
            size: MAX_CONTENT + 1
        }),
        Err(Error::Bounds)
    );
    assert!(Chunk::new(&[]).is_err());
    assert!(Chunk::new(&[0; CHUNK_SIZE + 1]).is_err());
    for expires in [0, s.now, s.now + MAX_LIFETIME + 1, u64::MAX] {
        assert_eq!(
            s.clipboard.authorize(
                s.now,
                Authorization {
                    id: 2,
                    caller: OWNER,
                    action: Action::Copy,
                    expires
                }
            ),
            Err(Error::Bounds)
        );
    }
    s.copy(1);
    assert_eq!(s.clipboard.tick(s.now - 1), Err(Error::Clock));
    s.erased();
    assert_eq!(s.clipboard.tick(s.now - 1), Err(Error::Clock));
    s.copy(1);
    s.clipboard.clear();
    s.erased();
    assert!(s.clipboard.authorization.is_none());
    assert_eq!(
        s.clipboard
            .handle(s.now, OWNER, 1, Request::Paste { transfer: 1 }),
        Err(Error::Replay)
    );
}

#[test]
fn sequence_exhaustion_never_wraps_and_deadlines_saturate_safely() {
    let mut s = Session::new();
    s.now = u64::MAX - 100;
    s.clipboard
        .authorize(
            s.now,
            Authorization {
                id: u64::MAX,
                caller: OWNER,
                action: Action::Copy,
                expires: u64::MAX,
            },
        )
        .unwrap();
    assert_eq!(
        s.clipboard.handle(
            s.now,
            OWNER,
            u64::MAX,
            Request::Copy {
                transfer: u64::MAX,
                size: 0
            }
        ),
        Ok(Response::Ok)
    );
    assert_eq!(s.clipboard.deadline(), Some(u64::MAX));
    assert_eq!(
        s.clipboard
            .handle(s.now, OWNER, 0, Request::Complete { transfer: u64::MAX }),
        Err(Error::Replay)
    );
    s.clipboard.tick(u64::MAX).unwrap();
    s.erased();
}
