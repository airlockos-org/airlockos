//! Authenticate a Hermit executable at admission and immediately before Xen loads it.
//! These checks supply evidence; only the existing deployment plan grants start authority.

use airlock_nix_core::hermit_artifact::{Descriptor, Image};
use anyhow::{Result, ensure};
use std::{fs, io::Read, os::unix::fs::MetadataExt, path::Path};

/// Validate a store-resident regular executable without following artifact symlinks.
/// Reading is bounded by the descriptor, including one byte to detect concurrent growth.
pub fn verify(artifact: &Descriptor, memory_mib: u64) -> Result<Image> {
    artifact.validate(false)?;
    ensure!(
        (16..=256).contains(&memory_mib),
        "invalid Hermit memory allocation"
    );
    let path = Path::new(artifact.executable.as_str());
    ensure!(
        fs::canonicalize(path)? == path,
        "Hermit executable must not be a symlink"
    );
    let file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.len() == artifact.bytes
            && metadata.uid() == 0
            && metadata.mode() & 0o222 == 0,
        "Hermit executable is not an immutable admitted file"
    );
    let mut bytes = Vec::with_capacity(artifact.bytes as usize);
    file.take(artifact.bytes + 1).read_to_end(&mut bytes)?;
    Ok(artifact.verify(&bytes, memory_mib * 1024 * 1024, false)?)
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
}

/// Fixed protected runtime record, addressed only with a validated VM name.
fn record(name: &airlock_nix_core::identity::GuestName) -> std::path::PathBuf {
    Path::new("/run/airlock/hermit").join(format!("{name}.json"))
}

/// Existing Xen console log; this observer never writes guest console data.
fn console(name: &airlock_nix_core::identity::GuestName) -> std::path::PathBuf {
    Path::new("/var/log/xen/console").join(format!("guest-{name}.log"))
}

/// Capture a console boundary before Xen starts an already authenticated executable.
pub fn preparing(name: &str, artifact: &Descriptor, generation: &str) -> Result<String> {
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
    ensure!(
        output.lines().any(|line| line.trim_end()
            == format!("AIRLOCK_CLIPBOARD_EXECUTING authority=disconnected readiness=isolated boot={nonce}", nonce = execution.nonce)),
        "Hermit application has not reported isolated readiness"
    );
    Ok(())
}

/// Bind the upstream XML to the authenticated executable and a fresh execution challenge.
/// Reuse Qubes' full domain configuration while refusing devices or loader substitutions.
pub fn boot_xml(xml: &str, artifact: &Descriptor, memory: u64, nonce: &str) -> Result<String> {
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
                        "-- airlock.boot={nonce}"
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
        let image = verify(&descriptor, 32).unwrap();
        assert!(image.entry > 0 && image.memory_end <= 32 * 1024 * 1024);
        let mut substituted = descriptor;
        substituted.sha256 = "0".repeat(64).parse().unwrap();
        assert!(verify(&substituted, 32).is_err());
    }

    #[test]
    fn challenge_is_bound_without_changing_upstream_devices() {
        let nonce = "01234567-89ab-cdef-0123-456789abcdef";
        let output = boot_xml(&xml(), &artifact(), 32, nonce).unwrap();
        assert!(output.contains(&format!("<cmdline>-- airlock.boot={nonce}</cmdline>")));
        assert!(output.contains(r#"<console type="pty">"#));
        assert!(boot_xml(&output, &artifact(), 32, nonce).is_err());
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
