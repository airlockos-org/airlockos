//! Configuration contracts shared by machine authors and installed VM services.
//! These records describe service inputs; Qubes policy still controls permission to act.

use airlock_nix_core::identity::GuestName;
use serde::{Deserialize, Serialize};

/// Installed policy-directory contract shared by machine authoring and dom0 publication.
pub use airlock_machine_planning::ipc_policy::directory as policy_directory;

/// Exact topology-owned policy filename, separate from immutable bootstrap permissions.
pub use airlock_machine_planning::ipc_policy::filename as policy_filename;

/// Selects the personal VM receiving completed screen captures from a GUI VM.
/// Authoring serializes this record into NixOS configuration; the sender validates
/// the same record before using capture RPCs. The target excludes dom0.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureSenderConfig {
    /// Destination VM, which must also be permitted by the machine's Qubes policy.
    pub target: GuestName,
}

impl Default for CaptureSenderConfig {
    /// Retains the established destination for callers without a configuration file.
    fn default() -> Self {
        Self {
            target: "usr-home"
                .parse()
                .expect("the default capture VM has a valid name"),
        }
    }
}

/// Media categories accepted by the capture protocol and its Qubes policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaptureKind {
    /// PNG screenshot delivered to the user's screenshot directory.
    Image,
    /// WebM or MP4 recording delivered to the user's screencast directory.
    Video,
}

impl CaptureKind {
    /// All supported media arguments, used when constructing exact Qubes permissions.
    pub const ALL: [Self; 2] = [Self::Image, Self::Video];

    /// Returns the spelling shared by JSON, command arguments and Qubes RPCs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::Video => "video",
        }
    }

    /// Checks the filename extension without trusting a remote MIME type.
    pub fn accepts(self, path: &std::path::Path) -> bool {
        let extension = path
            .extension()
            .and_then(|v| v.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        match self {
            Self::Image => extension == "png",
            Self::Video => extension == "webm" || extension == "mp4",
        }
    }
}

impl std::fmt::Display for CaptureKind {
    /// Emits the protocol argument accepted by the receiver.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for CaptureKind {
    type Err = String;

    /// Rejects media categories outside the capture protocol.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.as_str() == value)
            .ok_or_else(|| format!("unsupported capture kind: {value}"))
    }
}

/// Narrow operations that Qubes may dispatch to the capture receiver.
#[derive(Clone, Copy, Debug)]
pub enum CaptureOperation {
    /// Publish a completed capture after checking its metadata and bytes.
    Import,
    /// Open or reveal an already received capture by its receipt identity.
    Open,
}

impl CaptureOperation {
    /// Operations authorized independently for each connection and media category.
    pub const ALL: [Self; 2] = [Self::Import, Self::Open];

    /// Returns the Qubes service identity shared by policy, sender and receiver wiring.
    pub fn service(self) -> &'static str {
        match self {
            Self::Import => "airlock.CaptureImport",
            Self::Open => "airlock.CaptureOpen",
        }
    }

    /// Returns the installed receiver command implementing this operation.
    pub fn command(self) -> &'static str {
        match self {
            Self::Import => "capture-receive",
            Self::Open => "capture-open",
        }
    }

    /// Selects one exact service and media argument for a Qubes request.
    pub fn request(self, kind: CaptureKind) -> String {
        format!("{}+{}", self.service(), kind.as_str())
    }
}

/// A resolved screen-capture connection used to derive both endpoint contracts and policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureConnection {
    /// GUI VM allowed to submit and open captures on the destination.
    pub source: GuestName,
    /// Personal VM receiving the completed files.
    pub target: GuestName,
}

/// Exact callers accepted by the receiving service in addition to Qubes policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureReceiverConfig {
    /// Validated GUI identities; an empty list permits no caller.
    pub sources: Vec<GuestName>,
}

impl CaptureReceiverConfig {
    /// Checks the authenticated Qubes caller against the configured source identities.
    pub fn permits(&self, caller: &str) -> bool {
        self.sources.iter().any(|source| source.as_str() == caller)
    }
}
