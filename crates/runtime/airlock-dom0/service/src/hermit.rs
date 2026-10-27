//! Authenticate a Hermit executable at admission and immediately before Xen loads it.
//! These checks supply evidence; only the existing deployment plan grants start authority.

use airlock_nix_core::hermit_artifact::{AuthorityMode, Descriptor, Image};
use anyhow::{Context, Result, ensure};
use std::{fs, io::Read, os::unix::fs::MetadataExt, path::Path};

/// Validate a store-resident regular executable without following artifact symlinks.
/// Reading is bounded by the descriptor, including one byte to detect concurrent growth.
pub fn verify(artifact: &Descriptor, memory_mib: u64) -> Result<Image> {
    verify_owned(artifact, memory_mib, 0)
}

/// Authenticate build outputs owned by root or the current unprivileged Nix builder.
/// This image check supplies no runtime admission or permission to start a VM.
pub(crate) fn verify_image(artifact: &Descriptor, memory_mib: u64) -> Result<Image> {
    verify_owned(artifact, memory_mib, rustix::process::geteuid().as_raw())
}

/// Keep descriptor, digest and loader checks identical across build and runtime verification.
fn verify_owned(artifact: &Descriptor, memory_mib: u64, owner: u32) -> Result<Image> {
    artifact.validate(false)?;
    ensure!(
        (16..=256).contains(&memory_mib)
            && (artifact.authority != AuthorityMode::Normal || memory_mib >= 128),
        "invalid Hermit memory allocation"
    );

    let file = open_executable(
        Path::new(artifact.executable.as_str()),
        artifact.bytes,
        owner,
    )?;
    let mut bytes = Vec::with_capacity(artifact.bytes as usize);
    file.take(artifact.bytes + 1).read_to_end(&mut bytes)?;

    Ok(artifact.verify(&bytes, memory_mib * 1024 * 1024, false)?)
}

/// Open an exact regular read-only file owned by root or the explicitly selected builder.
fn open_executable(path: &Path, bytes: u64, owner: u32) -> Result<fs::File> {
    ensure!(
        fs::canonicalize(path)? == path,
        "Hermit executable must not be a symlink"
    );

    let file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.len() == bytes
            && (metadata.uid() == 0 || metadata.uid() == owner)
            && metadata.mode() & 0o222 == 0,
        "Hermit executable is not an immutable admitted file"
    );

    Ok(file)
}

/// Current-boot console boundary captured before the guest is spawned.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Execution {
    /// Host boot UUID, excluding records from an earlier host session.
    boot_id: String,
    /// Fresh unpredictable challenge emitted by this application boot.
    nonce: String,
    /// Executable selected and authenticated before spawn.
    artifact: Descriptor,
    /// Immutable topology path associated with the machine generation.
    generation: String,
    /// Xen domain ID assigned by the upstream Qubes start operation.
    xid: Option<u32>,
    /// Existing console inode; rotation during startup invalidates this evidence.
    inode: Option<u64>,
    /// Byte boundary separating retained historical output from this boot.
    offset: u64,
    /// Current GUI domain allowed to receive the production control offer.
    #[serde(default)]
    authority: Option<u16>,
}

/// Fixed protected runtime record, addressed only with a validated VM name.
fn record(name: &airlock_nix_core::identity::GuestName) -> std::path::PathBuf {
    Path::new("/run/airlock/hermit").join(format!("{name}.json"))
}

/// Existing Xen console log; this observer never writes guest console data.
fn console(name: &airlock_nix_core::identity::GuestName) -> std::path::PathBuf {
    Path::new("/var/log/airlock-xen-console").join(format!("guest-{name}.log"))
}

/// Capture a console boundary before Xen starts an already authenticated executable.
pub fn preparing(name: &str, artifact: &Descriptor, generation: &str) -> Result<String> {
    preparing_with_authority(name, artifact, generation, None)
}

/// Capture execution identity together with the already resolved GUI authority domain.
pub fn preparing_with_authority(
    name: &str,
    artifact: &Descriptor,
    generation: &str,
    authority: Option<u16>,
) -> Result<String> {
    ensure!(
        (artifact.authority == AuthorityMode::Normal) == authority.is_some(),
        "Hermit authority does not match artifact"
    );
    let name = name.parse()?;
    let metadata = match fs::symlink_metadata(console(&name)) {
        Ok(metadata) => {
            crate::state::trusted(&console(&name))?;
            ensure!(metadata.is_file(), "Hermit console is not a regular file");
            Some(metadata)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let path = record(&name);
    crate::state::directory(path.parent().unwrap())?;
    let nonce = fs::read_to_string("/proc/sys/kernel/random/uuid")?
        .trim()
        .to_owned();
    crate::state::save(
        &path,
        &Execution {
            nonce: nonce.clone(),
            boot_id: crate::state::boot_id()?.to_string(),
            artifact: artifact.clone(),
            generation: generation.into(),
            xid: None,
            inode: metadata.as_ref().map(MetadataExt::ino),
            offset: metadata.as_ref().map_or(0, fs::Metadata::len),
            authority,
        },
    )?;
    Ok(nonce)
}

/// Associate the prepared observation with the Xen domain that Qubes actually started.
pub fn started(name: &str, xid: u32) -> Result<()> {
    let path = record(&name.parse()?);
    crate::state::trusted(&path)?;
    let mut execution: Execution = crate::state::read(&path)?;
    ensure!(
        execution.boot_id == crate::state::boot_id()?.to_string()
            && execution.xid.is_none()
            && xid > 0,
        "stale Hermit start observation"
    );
    execution.xid = Some(xid);
    crate::state::save(&path, &execution)
}

/// Remove running evidence on stop or failed activation; console history remains available.
pub fn stopped(name: &str) -> Result<()> {
    match fs::remove_file(record(&name.parse()?)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Require execution evidence from this boot and this Xen domain, independently of process state.
/// The isolated readiness marker means the service is executing with IPC disabled.
pub fn ready(name: &str, artifact: &Descriptor, xid: u32) -> Result<()> {
    use std::io::{Seek, SeekFrom};

    let name = name.parse()?;
    let path = record(&name);
    crate::state::trusted(&path)?;
    let execution: Execution = crate::state::read(&path)?;
    ensure!(
        execution.boot_id == crate::state::boot_id()?.to_string()
            && execution.xid == Some(xid)
            && execution.artifact == *artifact,
        "Hermit execution identity differs from selected generation"
    );
    let path = console(&name);
    crate::state::trusted(&path)?;
    let mut file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.len() >= execution.offset
            && execution.inode.is_none_or(|inode| inode == metadata.ino()),
        "Hermit console rotated during startup"
    );
    file.seek(SeekFrom::Start(execution.offset))?;
    let mut output = String::new();
    file.take(256 * 1024).read_to_string(&mut output)?;
    let mode = match artifact.authority {
        AuthorityMode::Disconnected => "authority=disconnected readiness=isolated",
        AuthorityMode::Normal => "authority=normal readiness=connected",
        AuthorityMode::Laboratory => anyhow::bail!("laboratory artifact is not production-ready"),
    };
    ensure!(
        output.lines().any(|line| console_line(line).trim_end()
            == format!(
                "AIRLOCK_CLIPBOARD_EXECUTING {mode} boot={nonce}",
                nonce = execution.nonce
            )),
        "Hermit application has not reported current-boot readiness"
    );
    Ok(())
}

/// Remove Xen's optional console timestamp, without accepting arbitrary log prefixes.
/// The timestamp is formatting only; boot identity comes from the protected nonce.
fn console_line(line: &str) -> &str {
    let prefix = b"[0000-00-00 00:00:00] ";
    let timestamp = line.as_bytes().get(..prefix.len()).is_some_and(|bytes| {
        bytes.iter().zip(prefix).all(|(byte, expected)| {
            if *expected == b'0' {
                byte.is_ascii_digit()
            } else {
                byte == expected
            }
        })
    });
    if timestamp {
        &line[prefix.len()..]
    } else {
        line
    }
}

/// Read a boot-bound control offer for the authenticated configured GUI caller.
/// This observer returns transport coordinates only; it never sees clipboard data.
pub fn endpoint(config: &Path) -> Result<airlock_machine_core::services::ClipboardEndpoint> {
    use airlock_machine_core::services::{ClipboardConnection, ClipboardEndpoint};
    use std::io::{Seek, SeekFrom};

    let connections: Vec<ClipboardConnection> = crate::state::immutable_configuration(config)?;
    let caller = std::env::var("QREXEC_REMOTE_DOMAIN")?;
    let matches: Vec<_> = connections
        .iter()
        .filter(|connection| connection.gui.as_str() == caller)
        .collect();
    let [connection] = matches.as_slice() else {
        anyhow::bail!("caller has no unique clipboard authority");
    };
    ensure!(connection.validate(), "invalid clipboard contract");
    let path = record(&connection.service);
    crate::state::trusted(&path)?;
    let execution: Execution = crate::state::read(&path)?;
    ensure!(
        execution.boot_id == crate::state::boot_id()?.to_string()
            && execution.artifact.authority == AuthorityMode::Normal,
        "stale clipboard execution"
    );
    let xid = execution.xid.context("clipboard has not started")?;
    let authority = execution
        .authority
        .context("clipboard has no GUI authority")?;
    for (name, expected) in [
        (connection.service.as_str(), xid),
        (connection.gui.as_str(), u32::from(authority)),
    ] {
        let output = std::process::Command::new("qvm-prefs")
            .args(["--", name, "xid"])
            .output()?;
        ensure!(
            output.status.success()
                && std::str::from_utf8(&output.stdout)?.trim().parse::<u32>()? == expected,
            "clipboard endpoint domain changed"
        );
    }
    let path = console(&connection.service);
    crate::state::trusted(&path)?;
    let mut file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.len() >= execution.offset
            && execution.inode.is_none_or(|inode| inode == metadata.ino()),
        "clipboard console identity changed"
    );
    file.seek(SeekFrom::Start(execution.offset))?;
    let mut output = String::new();
    file.take(256 * 1024).read_to_string(&mut output)?;
    let prefix = format!(
        "AIRLOCK_CLIPBOARD_OFFER boot={nonce} authority={authority} ",
        nonce = execution.nonce
    );
    let offers: Vec<_> = output
        .lines()
        .filter_map(|line| console_line(line).strip_prefix(&prefix))
        .collect();
    let [offer] = offers.as_slice() else {
        anyhow::bail!("clipboard control offer is unavailable or ambiguous");
    };
    let fields: Vec<_> = offer.split_whitespace().collect();
    ensure!(fields.len() == 3, "malformed clipboard control offer");
    let port = fields[0]
        .strip_prefix("port=")
        .context("missing event port")?
        .parse()?;
    let grant = fields[1]
        .strip_prefix("grant=")
        .context("missing grant")?
        .parse()?;
    let epoch = fields[2]
        .strip_prefix("session=")
        .context("missing epoch")?
        .parse()?;
    Ok(ClipboardEndpoint {
        domain: u16::try_from(xid)?,
        port,
        grant,
        epoch,
        principal: 0,
    })
}

/// Bind the upstream XML to the authenticated executable and a fresh execution challenge.
/// Reuse Qubes' full domain configuration while refusing devices or loader substitutions.
pub fn boot_xml(xml: &str, artifact: &Descriptor, memory: u64, nonce: &str) -> Result<String> {
    boot_xml_with_authority(xml, artifact, memory, nonce, None)
}

/// Supply only the GUI domain resolved by Qubes, never a peer's claimed identity.
pub fn boot_xml_with_authority(
    xml: &str,
    artifact: &Descriptor,
    memory: u64,
    nonce: &str,
    authority: Option<u16>,
) -> Result<String> {
    ensure!(
        (artifact.authority == AuthorityMode::Normal) == authority.is_some(),
        "Hermit authority does not match artifact"
    );
    ensure!(
        authority.is_none_or(|domain| domain > 0 && domain < 0x7ff0),
        "invalid GUI authority domain"
    );
    let authority_argument =
        authority.map_or_else(String::new, |domain| format!(" airlock.authority={domain}"));
    use quick_xml::{
        Reader, Writer,
        events::{BytesEnd, BytesStart, BytesText, Event},
    };

    ensure!(
        xml.len() <= 1024 * 1024
            && nonce.len() == 36
            && nonce
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-'),
        "invalid Hermit boot inputs"
    );
    let mut reader = Reader::from_str(xml);
    let mut writer = Writer::new(Vec::new());
    let mut path = Vec::<String>::new();
    let mut kernel = 0;
    let mut pvh = 0;
    let mut command = 0;
    let mut memories = 0;
    let mut current_memories = 0;
    let mut domains = 0;
    let mut cpus = 0;
    loop {
        let event = reader.read_event()?;
        match &event {
            Event::Start(tag) | Event::Empty(tag) => {
                let name = String::from_utf8(tag.name().as_ref().to_vec())?;
                ensure!(
                    !matches!(
                        name.as_str(),
                        "initrd"
                            | "disk"
                            | "interface"
                            | "hostdev"
                            | "cmdline"
                            | "loader"
                            | "maxMemory"
                            | "emulator"
                            | "graphics"
                            | "video"
                            | "sound"
                            | "filesystem"
                            | "redirdev"
                    ),
                    "unsupported Hermit XML device or boot option"
                );
                let attributes = tag
                    .attributes()
                    .map(|attribute| {
                        let attribute = attribute?;
                        Ok((
                            String::from_utf8(attribute.key.as_ref().to_vec())?,
                            attribute
                                .decoded_and_normalized_value(
                                    quick_xml::XmlVersion::Implicit1_0,
                                    reader.decoder(),
                                )?
                                .into_owned(),
                        ))
                    })
                    .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
                match name.as_str() {
                    "domain" => {
                        ensure!(
                            path.is_empty()
                                && attributes.get("type").map(String::as_str) == Some("xen"),
                            "Hermit requires a Xen domain"
                        );
                        domains += 1;
                    }
                    "memory" | "currentMemory" => {
                        ensure!(
                            path == ["domain"]
                                && attributes.len() == 1
                                && attributes.get("unit").map(String::as_str) == Some("MiB"),
                            "Hermit memory must use MiB"
                        );
                    }
                    "vcpu" => ensure!(
                        path == ["domain"]
                            && attributes
                                .iter()
                                .all(|(key, value)| key == "placement" && value == "static"),
                        "unsupported Hermit CPU configuration"
                    ),
                    "type" if path == ["domain", "os"] => {
                        ensure!(
                            attributes.len() == 2
                                && attributes.get("arch").map(String::as_str) == Some("x86_64")
                                && attributes.get("machine").map(String::as_str) == Some("xenpvh"),
                            "Hermit requires x86_64 PVH"
                        );
                    }
                    "kernel" => ensure!(
                        attributes.is_empty(),
                        "unsupported Hermit kernel attributes"
                    ),
                    _ => {}
                }
                if matches!(event, Event::Start(_)) {
                    path.push(name);
                }
            }
            Event::Text(text) => {
                let text = text.decode()?;
                if !text.trim().is_empty() {
                    match path.last().map(String::as_str) {
                        Some("kernel") => {
                            ensure!(
                                path == ["domain", "os", "kernel"]
                                    && text == artifact.executable.as_str(),
                                "Hermit kernel substitution"
                            );
                            kernel += 1;
                        }
                        Some("type") if path == ["domain", "os", "type"] => {
                            ensure!(text == "xenpvh", "Hermit requires PVH");
                            pvh += 1;
                        }
                        Some("memory" | "currentMemory") => {
                            ensure!(text.parse::<u64>()? == memory, "Hermit XML memory differs");
                            if path.last().unwrap() == "memory" {
                                memories += 1;
                            } else {
                                current_memories += 1;
                            }
                        }
                        Some("vcpu") => {
                            ensure!(text == "1", "Hermit XML CPU count differs");
                            cpus += 1;
                        }
                        _ => {}
                    }
                }
            }
            Event::End(tag) => {
                if tag.name().as_ref() == b"os" {
                    ensure!(path == ["domain", "os"], "unexpected Hermit OS node");
                    writer.write_event(Event::Start(BytesStart::new("cmdline")))?;
                    writer.write_event(Event::Text(BytesText::new(&format!(
                        "-- airlock.boot={nonce}{authority_argument}"
                    ))))?;
                    writer.write_event(Event::End(BytesEnd::new("cmdline")))?;
                    command += 1;
                }
                path.pop();
            }
            Event::DocType(_) | Event::GeneralRef(_) | Event::CData(_) => {
                anyhow::bail!("unsupported Hermit XML encoding")
            }
            Event::Eof => break,
            _ => {}
        }
        writer.write_event(event)?;
    }
    ensure!(
        domains == 1
            && kernel == 1
            && pvh == 1
            && command == 1
            && memories == 1
            && current_memories == 1
            && cpus == 1
            && path.is_empty(),
        "incomplete Hermit XML"
    );
    Ok(String::from_utf8(writer.into_inner())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Image verification admits the builder's sealed output while runtime keeps root ownership.
    #[test]
    fn image_ownership_does_not_grant_runtime_admission() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir()?;
        let path = directory.path().join("kernel.elf");
        fs::write(&path, b"build output")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o555))?;
        let owner = rustix::process::geteuid().as_raw();
        assert!(open_executable(&path, 12, owner).is_ok());
        assert_eq!(open_executable(&path, 12, 0).is_ok(), owner == 0);

        // Build ownership never permits writable, substituted or incorrectly sized files.
        assert!(open_executable(&path, 13, owner).is_err());
        let link = directory.path().join("linked.elf");
        std::os::unix::fs::symlink(&path, &link)?;
        assert!(open_executable(&link, 12, owner).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
        assert!(open_executable(&path, 12, owner).is_err());
        Ok(())
    }

    /// Real Xen console decoration must preserve exact challenge matching.
    #[test]
    fn xen_timestamps_do_not_hide_application_execution() {
        let marker = "AIRLOCK_CLIPBOARD_EXECUTING authority=disconnected readiness=isolated boot=01234567-89ab-cdef-0123-456789abcdef";
        assert_eq!(console_line(marker), marker);
        assert_eq!(
            console_line(&format!("[2026-10-26 19:03:59] {marker}")),
            marker
        );
        for prefix in ["kernel arguments: ", "[guest] ", "[2026-10-26x19:03:59] "] {
            assert_ne!(console_line(&format!("{prefix}{marker}")), marker);
        }
        assert_ne!(
            console_line(&format!("[2026-10-26 19:03:59] {marker} stale")),
            marker
        );
    }

    /// A structurally valid identity; XML checks do not open this test artifact.
    fn artifact() -> Descriptor {
        serde_json::from_value(serde_json::json!({
            "schema":"airlock.hermit-pvh.v1", "executable":"/nix/store/00000000000000000000000000000000-clipboard/kernel.elf",
            "sha256":"a".repeat(64), "bytes":1024, "source_revision":"b".repeat(40),
            "integration_revision":"c".repeat(40), "build_lock":"d".repeat(64), "authority":"disconnected"
        })).unwrap()
    }

    /// Minimal upstream PVH XML with the same units and boot elements as Qubes.
    fn xml() -> String {
        format!(
            r#"<domain type="xen"><name>sys-clipboard</name>
            <memory unit="MiB">32</memory><currentMemory unit="MiB">32</currentMemory>
            <vcpu placement="static">1</vcpu><os><type arch="x86_64" machine="xenpvh">xenpvh</type>
            <kernel>{executable}</kernel></os><devices><console type="pty"><target type="xen" port="0"/></console></devices></domain>"#,
            executable = artifact().executable
        )
    }

    /// Exercise the admission adapter against an explicitly built immutable PVH executable.
    #[test]
    #[ignore = "requires AIRLOCK_HERMIT_ARTIFACT from the production Nix constructor"]
    fn built_executable_passes_admission() {
        let path = std::env::var_os("AIRLOCK_HERMIT_ARTIFACT").expect("artifact.json path");
        let descriptor: Descriptor = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let image = verify_image(&descriptor, 32).unwrap();
        assert!(image.entry > 0 && image.memory_end <= 32 * 1024 * 1024);
        let root_owned = fs::metadata(descriptor.executable.as_str()).unwrap().uid() == 0;
        assert_eq!(verify(&descriptor, 32).is_ok(), root_owned);
        let mut substituted = descriptor;
        substituted.sha256 = "0".repeat(64).parse().unwrap();
        assert!(verify_image(&substituted, 32).is_err());
    }

    #[test]
    fn challenge_is_bound_without_changing_upstream_devices() {
        let nonce = "01234567-89ab-cdef-0123-456789abcdef";
        let output = boot_xml(&xml(), &artifact(), 32, nonce).unwrap();
        assert!(output.contains(&format!("<cmdline>-- airlock.boot={nonce}</cmdline>")));
        assert!(output.contains(r#"<console type="pty">"#));
        assert!(boot_xml(&output, &artifact(), 32, nonce).is_err());
        assert!(boot_xml_with_authority(&xml(), &artifact(), 32, nonce, Some(7)).is_err());
        let mut normal = artifact();
        normal.authority = AuthorityMode::Normal;
        let xml = xml().replace(">32<", ">128<");
        assert!(boot_xml(&xml, &normal, 128, nonce).is_err());
        assert!(boot_xml_with_authority(&xml, &normal, 128, nonce, Some(0)).is_err());
        assert!(
            boot_xml_with_authority(&xml, &normal, 128, nonce, Some(7))
                .unwrap()
                .contains("airlock.authority=7")
        );
    }

    #[test]
    fn boot_substitutions_and_resource_expansion_fail_closed() {
        for (from, to) in [
            ("kernel.elf", "other.elf"),
            ("MiB", "GiB"),
            (">32<", ">64<"),
            (">1</vcpu>", ">2</vcpu>"),
            ("x86_64", "aarch64"),
            ("<devices>", "<devices><disk/>"),
            ("<devices>", "<devices><interface/>"),
            ("<devices>", "<devices><hostdev/>"),
            ("</os>", "<initrd>/other</initrd></os>"),
            ("<devices>", "<devices><emulator>/other</emulator>"),
            ("<currentMemory", "<memory"),
            ("</currentMemory>", "</memory>"),
        ] {
            assert!(
                boot_xml(
                    &xml().replace(from, to),
                    &artifact(),
                    32,
                    "01234567-89ab-cdef-0123-456789abcdef"
                )
                .is_err(),
                "{from} -> {to}"
            );
        }
    }
}
