//! Shared process transport, source identities and structured command diagnostics.
//! Executable command parsing and orchestration belong to the CLI or VM service.

pub mod process;

/// Structured observational stages shared by workers, dom0 and request status.
pub mod progress;

pub mod protocol;

#[cfg(feature = "artifacts")]
pub mod source;

use crate::{Error as CoreError, job::StopReason};

use serde_json::{Value, json};
use std::{io, path::Path, process::ExitCode};

/// Result of shared transport, source validation or command reporting.
pub type Result<T> = std::result::Result<T, Error>;

/// Structured transport and helper failures shared by executable adapters.
///
/// Use [`report`] at a command boundary to retain machine-readable context and exit codes.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A validated record or protected local-state operation failed.
    #[error(transparent)]
    Core(
        /// Typed validation or state-store failure from the shared library.
        #[from]
        CoreError,
    ),
    /// A local stream or filesystem operation failed.
    #[error(transparent)]
    Io(
        /// Local transport or filesystem I/O failure.
        #[from]
        io::Error,
    ),
    /// An external helper could not be started.
    #[error("could not start {program}: {source}")]
    Command {
        /// Executable that could not be started.
        program: String,
        /// Operating-system error returned while starting the helper.
        #[source]
        source: io::Error,
    },
    /// Encoding or decoding transport JSON failed.
    #[error(transparent)]
    Json(
        /// Serialization or decoding failure at the runtime boundary.
        #[from]
        serde_json::Error,
    ),
    /// A transport precondition failed with a contextual diagnostic.
    #[error("{0}")]
    Message(
        /// Contextual diagnostic for a failed runtime precondition.
        String,
    ),
    /// A request stopped with a typed feedback reason and corresponding exit status.
    #[error("request stopped: {}", .0.as_str())]
    Stopped(
        /// Terminal controller outcome mapped to the submission exit status.
        StopReason,
    ),
    /// A remote operation failed, retaining its structured response.
    #[error("{operation} failed: {message}")]
    Remote {
        /// Remote operation whose reply reported failure.
        operation: String,
        /// Remote human-readable failure explanation.
        message: String,
        /// Original structured failure reply retained for the calling agent.
        details: Box<Value>,
    },
}

/// Reject a false transport precondition with a contextual diagnostic.
pub fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Error::Message(message.to_owned()))
    }
}

/// Decode one duplicate-key-free JSON record from caller-bounded transport bytes.
pub fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    Ok(crate::state::parse_json(bytes, Path::new("<protocol>"))?)
}

/// Write one compact JSON response line to stdout and flush it.
pub fn emit(value: &impl serde::Serialize) -> Result<()> {
    use io::Write;

    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, value)?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

/// Return fractional Unix seconds, falling back to zero before the epoch.
pub fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// Return a successful command status or emit structured failure feedback.
///
/// Busy exclusion returns 24; stopped requests retain their feedback exit codes.
pub fn report(result: Result<u8>) -> ExitCode {
    match result {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            let code = match &error {
                Error::Core(CoreError::Busy { .. }) => 24,
                Error::Stopped(reason) => reason.exit_code(),
                _ => 1,
            };
            let details = match &error {
                Error::Core(e) => serde_json::to_value(e.report()).unwrap_or(Value::Null),
                Error::Remote { details, .. } => (**details).clone(),
                Error::Command { program, source } => {
                    json!({"program":program,"os_error":source.raw_os_error()})
                }
                Error::Io(source) => {
                    json!({"os_error":source.raw_os_error(),"kind":source.kind().to_string()})
                }
                _ => Value::Null,
            };

            let _ = emit(
                &json!({"schema":"airlock.nix-runtime-error.v1", "status": if code==24 {"busy"} else {"failed"}, "error":error.to_string(), "details":details}),
            );
            eprintln!("airlock-nix: {error}");
            ExitCode::from(code)
        }
    }
}

/// Resolve HOME without creating directories; reject an unset environment variable.
pub fn home() -> Result<std::path::PathBuf> {
    Ok(std::path::PathBuf::from(
        std::env::var_os("HOME").ok_or_else(|| Error::Message("HOME is unavailable".into()))?,
    ))
}
