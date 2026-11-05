//! Select disposable workstation artifact directories without writing into source checkouts.
//! Production services keep their own persistent state paths.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::{
    ffi::OsString,
    io,
    path::{Path, PathBuf},
};

/// Read a nonempty explicit directory override.
fn value(variable: &str) -> Option<OsString> {
    std::env::var_os(variable).filter(|value| !value.is_empty())
}

/// Reject relative artifact paths instead of interpreting them inside a checkout.
fn absolute(path: PathBuf, variable: &str) -> io::Result<PathBuf> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{variable} must be absolute"),
        ));
    }

    Ok(path)
}

/// Select an explicit root or the existing development volume; the root itself may be absent.
fn select_root(configured: Option<OsString>, volume: &Path) -> io::Result<PathBuf> {
    if let Some(configured) = configured {
        return absolute(configured.into(), "AIRLOCK_DATA_ROOT");
    }
    if volume.is_dir() {
        return Ok(volume.join("airlock"));
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "development volume is unavailable; set AIRLOCK_DATA_ROOT to an absolute disposable data directory",
    ))
}

/// Return the disposable development root, requiring an explicit selection on other machines.
///
/// Missing generated directories are valid: callers create the directories they need.
/// The default requires `/run/media/user/data` to exist and never uses a checkout.
pub fn root() -> io::Result<PathBuf> {
    select_root(
        value("AIRLOCK_DATA_ROOT"),
        Path::new("/run/media/user/data"),
    )
}

/// Resolve an explicit artifact directory or a relative location under the development root.
///
/// Explicit overrides must be absolute. This only selects a path; writers create it
/// when needed, and read-only consumers can report missing preparation artifacts.
pub fn path(variable: &str, relative: impl AsRef<Path>) -> io::Result<PathBuf> {
    match value(variable) {
        Some(configured) => absolute(configured.into(), variable),
        None => Ok(root()?.join(relative)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Missing default volumes never produce checkout paths; explicit roots may be regenerated.
    #[test]
    fn root_selection_requires_a_volume_or_an_absolute_override() {
        let missing = Path::new("/nonexistent-airlock-development-volume");
        assert!(select_root(None, missing).is_err());
        assert!(select_root(Some("relative".into()), missing).is_err());
        assert_eq!(
            select_root(Some("/explicit data/airlock".into()), missing).unwrap(),
            Path::new("/explicit data/airlock")
        );
        assert_eq!(
            select_root(None, Path::new("/")).unwrap(),
            Path::new("/airlock")
        );
    }
}
