//! Receive completed screen captures without overwriting personal files.
//! A durable receipt reserves the destination before publication, so retrying a lost acknowledgement is safe.

use crate::support;
pub use airlock_machine_core::services::CaptureKind as Kind;
use anyhow::{Context, Result, ensure};
use rustix::fs::{Mode, OFlags, open};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{BufRead, Read, Write},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

/// Resolve GNOME's capture directory from the current user's XDG configuration.
pub fn directory(kind: Kind) -> Result<PathBuf> {
    let (variable, folder) = match kind {
        Kind::Image => ("PICTURES", "Screenshots"),
        Kind::Video => ("VIDEOS", "Screencasts"),
    };
    let root = support::text(
        Command::new(support::tool("AIRLOCK_XDG_USER_DIR", "xdg-user-dir")).arg(variable),
        Duration::from_secs(10),
    )?;
    ensure!(
        Path::new(&root).is_absolute(),
        "XDG media directory must be absolute"
    );
    Ok(PathBuf::from(root).join(folder))
}

/// Completed-file metadata preceding the exact byte stream in capture import RPCs.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    /// Capture protocol version accepted by this importer.
    pub schema: String,
    /// Stable source-file identity used for acknowledgement deduplication.
    pub id: String,
    /// Single destination filename, never a path supplied by another VM.
    pub name: String,
    /// Exact payload length, limited to one TiB and required to be nonzero.
    pub size: u64,
    /// Lowercase SHA-256 digest checked before publication.
    pub sha256: String,
}

/// Durable delivery acknowledgement; the sender retains its original file.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Receipt {
    /// Source identity covered by this acknowledgement.
    pub id: String,
    /// Destination selected locally inside the matching media directory.
    pub path: PathBuf,
    /// Digest of the bytes whose publication was acknowledged.
    pub sha256: String,
    /// Category restricting how this imported file may later be opened.
    pub kind: Kind,
}

/// Require a lowercase hexadecimal SHA-256 identity before using it in state paths.
pub fn digest_id(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid capture identity or digest"
    );
    Ok(())
}

impl Header {
    /// Reject unsupported versions, unsafe names, mismatched media and excessive sizes.
    pub fn validate(&self, kind: Kind) -> Result<()> {
        ensure!(
            self.schema == "airlock.capture.v1",
            "unsupported capture protocol"
        );
        digest_id(&self.id)?;
        digest_id(&self.sha256)?;
        ensure!(
            !self.name.is_empty()
                && self.name.len() <= 240
                && self.name != "."
                && self.name != ".."
                && !self.name.contains(['/', '\\'])
                && !self.name.chars().any(char::is_control),
            "invalid capture filename"
        );
        ensure!(
            kind.accepts(Path::new(&self.name)),
            "unexpected capture format"
        );
        ensure!(
            self.size > 0 && self.size <= 1024_u64.pow(4),
            "invalid capture size"
        );
        Ok(())
    }
}

/// Read one bounded JSON line without consuming any following capture bytes.
pub fn header<T: serde::de::DeserializeOwned>(input: &mut impl BufRead) -> Result<T> {
    let mut bytes = Vec::new();
    input.take(8193).read_until(b'\n', &mut bytes)?;
    ensure!(
        bytes.len() <= 8192 && bytes.last() == Some(&b'\n'),
        "invalid capture header"
    );
    Ok(airlock_nix_core::state::parse_json(
        &bytes,
        Path::new("<capture header>"),
    )?)
}

/// Return this VM's capture state root; outgoing queues are separated by destination VM.
pub fn state_root() -> Result<PathBuf> {
    support::state_root("airlock/captures")
}

/// Open a regular file without following a final symlink or blocking on a FIFO.
pub fn open_file(path: &Path) -> Result<File> {
    let file = File::from(open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    ensure!(file.metadata()?.is_file(), "capture must be a regular file");
    Ok(file)
}

/// Hash the remaining bytes of a regular capture stream.
pub fn hash(input: &mut impl Read) -> Result<String> {
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn existing(receipt: &Receipt, metadata: &Header, kind: Kind, directory: &Path) -> Result<bool> {
    ensure!(
        receipt.id == metadata.id && receipt.sha256 == metadata.sha256 && receipt.kind == kind,
        "capture identity conflict"
    );
    ensure!(
        receipt
            .path
            .parent()
            .map(fs::canonicalize)
            .transpose()?
            .as_deref()
            == Some(directory),
        "capture receipt escaped its media directory"
    );
    match open_file(&receipt.path) {
        Ok(mut file) => {
            Ok(file.metadata()?.len() == metadata.size && hash(&mut file)? == metadata.sha256)
        }
        Err(_) => Ok(false),
    }
}

fn collision_name(original: &Path, id: &str, suffix: u32) -> Result<String> {
    let stem = original
        .file_stem()
        .context("missing capture stem")?
        .to_str()
        .context("capture stem is not UTF-8")?;
    let extension = original
        .extension()
        .context("missing capture extension")?
        .to_str()
        .context("capture extension is not UTF-8")?;
    let tail = format!("-{}-{suffix}.{extension}", &id[..12]);
    // Linux limits a filename to 255 bytes, including collision disambiguation.
    // Truncate only at a UTF-8 boundary so long localized GNOME names remain valid.
    let mut end = stem.len().min(255 - tail.len());
    while !stem.is_char_boundary(end) {
        end -= 1;
    }
    Ok(format!("{}{tail}", &stem[..end]))
}

/// Validate and atomically publish one import, returning the existing receipt on an identical retry.
pub fn receive(kind: Kind, input: &mut impl BufRead) -> Result<Receipt> {
    let metadata: Header = header(input)?;
    metadata.validate(kind)?;
    let directory = directory(kind)?;
    fs::create_dir_all(&directory)?;
    let directory = fs::canonicalize(directory)?;
    let mut temporary = tempfile::NamedTempFile::new_in(&directory)?;
    let mut digest = Sha256::new();
    let mut remaining = metadata.size;
    let mut buffer = [0u8; 64 * 1024];
    while remaining > 0 {
        let length = remaining.min(buffer.len() as u64) as usize;
        let count = input.read(&mut buffer[..length])?;
        ensure!(count != 0, "incomplete capture");
        temporary.write_all(&buffer[..count])?;
        digest.update(&buffer[..count]);
        remaining -= count as u64;
    }
    ensure!(
        input.read(&mut buffer[..1])? == 0,
        "unexpected data after capture"
    );
    ensure!(
        format!("{:x}", digest.finalize()) == metadata.sha256,
        "capture checksum mismatch"
    );
    temporary.as_file().sync_all()?;

    let root = state_root()?;
    let _lock = support::lock(
        &root,
        "receiver",
        "publish one verified incoming screen capture",
    )?;
    let record = root.join("imported").join(format!("{}.json", metadata.id));
    if let Some(receipt) = support::read::<Receipt>(&record)?
        && existing(&receipt, &metadata, kind, &directory)?
    {
        support::sync(&directory)?;
        return Ok(receipt);
    }

    let original = Path::new(&metadata.name);
    let mut destination = directory.join(original);
    for suffix in 0..10_000_u32 {
        if suffix != 0 {
            destination = directory.join(collision_name(original, &metadata.id, suffix)?);
        }
        let receipt = Receipt {
            id: metadata.id.clone(),
            path: destination.clone(),
            sha256: metadata.sha256.clone(),
            kind,
        };
        // A durable reservation closes the publication/acknowledgement crash window.
        support::save(&record, &receipt)?;
        match fs::hard_link(temporary.path(), &destination) {
            Ok(()) => {
                support::sync(&directory)?;
                return Ok(receipt);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    anyhow::bail!("too many capture filename collisions")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenRequest {
    // Receipt identity; another VM cannot select a filesystem path directly.
    id: String,
    // Fixed user action invoked after looking up and validating the receipt.
    action: OpenAction,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum OpenAction {
    Open,
    Show,
}

/// Open only the locally recorded capture selected by a narrow receipt identity.
pub fn open_received(kind: Kind, input: &mut impl BufRead) -> Result<()> {
    let request: OpenRequest = header(input)?;
    digest_id(&request.id)?;
    let receipt: Receipt = support::read(
        &state_root()?
            .join("imported")
            .join(format!("{}.json", request.id)),
    )?
    .context("unknown capture")?;
    ensure!(
        receipt.id == request.id && receipt.kind == kind,
        "capture receipt identity or kind mismatch"
    );
    let directory = fs::canonicalize(directory(kind)?)?;
    ensure!(
        receipt
            .path
            .parent()
            .map(fs::canonicalize)
            .transpose()?
            .as_deref()
            == Some(&directory),
        "capture is outside its media directory"
    );
    open_file(&receipt.path)?;

    let mut command = match request.action {
        OpenAction::Open => {
            let mut c = Command::new(support::tool("AIRLOCK_GIO", "gio"));
            c.arg("open").arg(&receipt.path);
            c
        }
        OpenAction::Show => {
            let uri = file_uri(&receipt.path)?;
            let mut c = Command::new(support::tool("AIRLOCK_GDBUS", "gdbus"));
            c.args([
                "call",
                "--session",
                "--dest",
                "org.freedesktop.FileManager1",
                "--object-path",
                "/org/freedesktop/FileManager1",
                "--method",
                "org.freedesktop.FileManager1.ShowItems",
            ])
            .arg(serde_json::to_string(&vec![uri])?)
            .arg("");
            c
        }
    };
    command.envs(crate::session::environment(Duration::from_secs(35), None)?);
    support::run(&mut command, None, Duration::from_secs(30))?.checked()?;
    Ok(())
}

/// Encode an absolute local path as a file URI without allowing GVariant quoting injection.
pub fn file_uri(path: &Path) -> Result<String> {
    use std::os::unix::ffi::OsStrExt;
    ensure!(path.is_absolute(), "file URI requires an absolute path");
    let mut uri = String::from("file://");
    for byte in path.as_os_str().as_bytes() {
        if byte.is_ascii_alphanumeric() || b"/-._~".contains(byte) {
            uri.push(*byte as char);
        } else {
            uri.push_str(&format!("%{byte:02X}"));
        }
    }
    Ok(uri)
}
