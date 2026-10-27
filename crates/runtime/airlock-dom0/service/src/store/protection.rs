//! Decode explicit collection protections before acquiring any deletion permission.

use crate::model::{GenerationId, StorePath};
use airlock_deployment_core::retention::{Generation, Protection};
use airlock_nix_core::identity::StoreNamespace;
use anyhow::{Context, Result};
use std::str::FromStr;

/// Exact storage namespace and generation transported by the coordinator.
#[derive(Clone, Debug)]
pub(super) struct GenerationPin {
    // Validated pool namespace; never a filesystem path.
    domain: StoreNamespace,
    // Positive numeric generation, not a mutable current selection.
    generation: GenerationId,
}

impl FromStr for GenerationPin {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let (domain, generation) = value
            .split_once(':')
            .context("invalid generation protection")?;
        Ok(Self {
            domain: domain.parse()?,
            generation: generation.parse()?,
        })
    }
}

/// Effective unpinned system whose matching committed generations remain protected.
#[derive(Clone, Debug)]
pub(super) struct SystemPin {
    // Validated pool namespace consuming the source.
    domain: StoreNamespace,
    // Canonical immutable system source.
    system: StorePath,
}

impl FromStr for SystemPin {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let (domain, system) = value.split_once(':').context("invalid system protection")?;
        Ok(Self {
            domain: domain.parse()?,
            system: system.parse()?,
        })
    }
}

/// Preserve all parsed coordinates and source protections at the verified boundary.
pub(super) fn decode(generations: Vec<GenerationPin>, systems: Vec<SystemPin>) -> Vec<Protection> {
    generations
        .into_iter()
        .map(|g| {
            Protection::Exact(Generation {
                domain: g.domain.to_string(),
                number: g.generation.get(),
            })
        })
        .chain(systems.into_iter().map(|s| Protection::System {
            domain: s.domain.to_string(),
            system: s.system.to_string(),
        }))
        .collect()
}
