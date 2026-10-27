//! Structured failures at VM declaration, registration and machine finalization.

use std::fmt;

/// An authoring failure with enough context to identify the VM and relationship.
#[derive(Debug, PartialEq, Eq)]
pub enum AuthoringError {
    /// Clipboard endpoints or membership cannot form a valid service connection.
    InvalidClipboard {
        /// Explanation of the inconsistent relationship or missing capability.
        reason: String,
    },
    /// A diagnostic source or frozen endpoint contract is inconsistent.
    InvalidDiagnostics {
        /// Explanation naming the invalid source or contract.
        reason: String,
    },
    /// A custom feature name is invalid or would replace a role-owned invariant.
    InvalidFeature {
        /// VM whose additional feature was rejected.
        vm: String,
        /// Requested Qubes feature key.
        name: String,
    },
    /// A screen-capture connection cannot be implemented by the selected desktop.
    InvalidCapture {
        /// GUI VM whose capture configuration is inconsistent.
        vm: String,
        /// Capability requirement that the author must satisfy.
        reason: &'static str,
    },
    /// The common runtime dependency analysis rejected the authored machine.
    InvalidDependencies {
        /// Explanation from the shared dependency validator.
        reason: String,
    },
    /// The existing Airlock identity parser rejected a proposed VM name.
    InvalidName {
        /// User-supplied identity before validation.
        name: String,
        /// Explanation from the shared identity parser.
        reason: String,
    },
    /// Another declaration already uses this external identity.
    DuplicateName {
        /// Identity shared by distinct declarations.
        name: String,
    },
    /// This exact declaration has already been added to the machine.
    AlreadyRegistered {
        /// Identity of the repeated declaration.
        name: String,
    },
    /// A referenced declaration belongs to a different machine.
    ForeignMachine {
        /// VM or host configuration using the reference.
        vm: String,
        /// Connection being checked, such as network or display.
        relation: &'static str,
        /// Referenced VM whose owner differs.
        target: String,
    },
    /// A dependency has not been registered, or a weak display reference expired.
    MissingDependency {
        /// VM or host configuration using the reference.
        vm: String,
        /// Connection whose target must be added first.
        relation: &'static str,
        /// Identity of the missing declaration.
        target: String,
    },
    /// A VM requests a host default that the machine has not configured.
    MissingHostReference {
        /// VM requiring the host setting.
        vm: String,
        /// Required setting, such as the default GUI.
        relation: &'static str,
    },
    /// Resource choices cannot form a valid VM allocation.
    InvalidResources {
        /// VM with the invalid allocation.
        vm: String,
        /// Constraint violated by its settings.
        reason: &'static str,
    },
    /// An existing upstream implementation requires a particular identity.
    RequiredIdentity {
        /// Upstream role or operation imposing the identity requirement.
        role: &'static str,
        /// Identity expected by the reused implementation.
        expected: &'static str,
        /// Identity selected by the author.
        actual: String,
    },
}

impl fmt::Display for AuthoringError {
    /// Renders a contextual diagnostic without discarding its structured category.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidClipboard { reason } => write!(formatter, "invalid clipboard: {reason}"),
            Self::InvalidDiagnostics { reason } => {
                write!(formatter, "invalid diagnostics: {reason}")
            }
            Self::InvalidFeature { vm, name } => {
                write!(formatter, "{vm}: invalid or role-owned feature {name}")
            }
            Self::InvalidCapture { vm, reason } => write!(formatter, "{vm}: {reason}"),
            Self::InvalidDependencies { reason } => {
                write!(formatter, "invalid machine dependencies: {reason}")
            }
            Self::InvalidName { name, reason } => {
                write!(formatter, "invalid VM name {name:?}: {reason}")
            }
            Self::DuplicateName { name } => write!(formatter, "duplicate VM: {name}"),
            Self::AlreadyRegistered { name } => {
                write!(formatter, "{name}: VM is already registered")
            }
            Self::ForeignMachine {
                vm,
                relation,
                target,
            } => write!(
                formatter,
                "{vm}: {relation} target {target} belongs to another machine"
            ),
            Self::MissingDependency {
                vm,
                relation,
                target,
            } => write!(
                formatter,
                "{vm}: {relation} target {target} must be added to this machine"
            ),
            Self::MissingHostReference { vm, relation } => write!(
                formatter,
                "{vm}: configure the host {relation} before finishing"
            ),
            Self::InvalidResources { vm, reason } => write!(formatter, "{vm}: {reason}"),
            Self::RequiredIdentity {
                role,
                expected,
                actual,
            } => write!(formatter, "{role} requires {expected}, got {actual}"),
        }
    }
}

impl std::error::Error for AuthoringError {}
