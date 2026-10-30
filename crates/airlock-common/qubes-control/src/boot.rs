//! Minimal native control-service startup contract. It contains only a current-boot
//! challenge; dom0 and native QubesDB port 111 are fixed by the protocol adapter.
//! Unknown/duplicate Airlock fields fail startup. Other Hermit arguments remain
//! owned by the kernel. No command line can enable a shell or general qrexec.

use airlock_boot_core::Challenge;
#[cfg(verus_keep_ghost)]
use airlock_boot_core::challenge_bytes;
use vstd::prelude::*;

use crate::bytes::prefix;

verus! {

/// Partial startup state with terminal failure; related flags cannot disagree.
enum Stage {
    /// No boot challenge has been provided.
    Pending,
    /// Exact validated challenge, with no duplicate allowed.
    Chosen(/// Original validated deployment challenge, not an authority token.
        Challenge),
    /// Rejected argument; later arguments cannot revive this parser.
    Failed,
}

/// Bounded startup parser whose only accepted Airlock field is `airlock.boot`.
pub struct Parser {
    /// Challenge selection or terminal rejection, owned until finish consumes it.
    stage: Stage,
}

impl Parser {
    /// Any chosen challenge satisfies the shared boot grammar.
    pub closed spec fn valid(&self) -> bool {
        match self.stage { Stage::Chosen(value) => challenge_bytes(value.value()), _ => true }
    }

    /// Start without an observed challenge or any runtime authority.
    pub fn empty() -> (parser: Self)
        ensures parser.valid(), parser.stage is Pending,
    { Self { stage: Stage::Pending } }

    /// Consume a bounded kernel argument. Exactly one valid boot key succeeds;
    /// unknown Airlock keys, duplicates and malformed challenges latch failure.
    pub fn push(&mut self, argument: &[u8]) -> (accepted: bool)
        requires old(self).valid(),
        ensures final(self).valid(),
            !accepted ==> final(self).stage is Failed,
            old(self).stage is Failed ==> !accepted,
            accepted && prefix_key(argument@, b"airlock.boot="@) ==>
                final(self).stage is Chosen
                && final(self).stage->Chosen_0.value() == argument@.subrange(13, argument@.len() as int),
            accepted && !prefix_key(argument@, b"airlock.boot="@) ==> final(self).stage == old(self).stage,
    {
        if matches!(self.stage, Stage::Failed) { return false; }
        if argument.len() > 4096 { self.stage = Stage::Failed; return false; }
        if prefix(argument, b"airlock.boot=") {
            if !matches!(self.stage, Stage::Pending) { self.stage = Stage::Failed; return false; }
            let challenge = match Challenge::parse(&argument[13..]) { Some(value) => value, None => { self.stage = Stage::Failed; return false; } };
            self.stage = Stage::Chosen(challenge);
            true
        } else if prefix(argument, b"airlock.") {
            self.stage = Stage::Failed;
            false
        } else { true }
    }

    /// Consume partial state. Missing/failed selection yields no startup value.
    pub fn finish(self) -> (challenge: Option<Challenge>)
        requires self.valid(),
        ensures match challenge {
            Some(value) => self.stage == Stage::Chosen(value) && challenge_bytes(value.value()),
            None => !(self.stage is Chosen),
        },
    { match self.stage { Stage::Chosen(value) => Some(value), _ => None } }
}

/// Reserved-key prefix relation, independent of executable matching order.
pub open spec fn prefix_key(argument: Seq<u8>, key: Seq<u8>) -> bool {
    argument.len() >= key.len() && argument.subrange(0, key.len() as int) == key
}

}
