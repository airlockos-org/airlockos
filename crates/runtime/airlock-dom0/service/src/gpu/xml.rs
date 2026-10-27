//! Add a checked PCI destination and ACPI table without rebuilding upstream XML.
//! Insertions leave existing disks, device flags and unrelated XML bytes untouched.

use super::firmware::Prepared;
use anyhow::{Context, Result, ensure};
use quick_xml::{Reader, events::Event};
use std::collections::BTreeMap;

struct Element {
    // Absolute element path used to distinguish source and destination addresses.
    path: String,
    // Decoded attributes; duplicate names are rejected by the XML parser.
    attributes: BTreeMap<String, String>,
    // Direct character content, used for domain UUID and virtualization type.
    text: String,
    // Byte position before the closing tag; absent for self-closing elements.
    end: Option<usize>,
}

fn elements(xml: &str) -> Result<Vec<Element>> {
    ensure!(xml.len() <= 8 * 1024 * 1024, "GPU XML exceeds limit");
    let mut reader = Reader::from_str(xml);
    let mut values: Vec<Element> = Vec::new();
    let mut stack: Vec<usize> = Vec::new();
    let mut roots = 0;
    loop {
        let position = reader.buffer_position() as usize;
        let event = reader.read_event()?;
        let empty = matches!(event, Event::Empty(_));
        match event {
            Event::Start(start) | Event::Empty(start) => {
                ensure!(
                    stack.len() < 128 && values.len() < 65536,
                    "GPU XML exceeds structural limits"
                );
                let name = std::str::from_utf8(start.name().as_ref())?.to_owned();
                let parent = stack
                    .last()
                    .map(|i| values[*i].path.clone())
                    .unwrap_or_default();
                if stack.is_empty() {
                    roots += 1;
                }
                // libvirt metadata can contain namespaced application data;
                // it never participates in domain/OS/device interpretation.
                let metadata = parent == "/domain/metadata"
                    || parent.starts_with("/domain/metadata/")
                    || (parent == "/domain" && name == "metadata");
                let mut attributes = BTreeMap::new();
                for attribute in start.attributes() {
                    let attribute = attribute?;
                    let name = std::str::from_utf8(attribute.key.as_ref())?.to_owned();
                    let value = attribute
                        .decoded_and_normalized_value(
                            quick_xml::XmlVersion::Implicit1_0,
                            reader.decoder(),
                        )?
                        .into_owned();
                    ensure!(
                        name != "xmlns" || value.is_empty() || metadata,
                        "default XML namespaces are unsupported for libvirt domain elements"
                    );
                    ensure!(
                        attributes.insert(name, value).is_none(),
                        "duplicate XML attribute"
                    );
                }
                let index = values.len();
                values.push(Element {
                    path: format!("{parent}/{name}"),
                    attributes,
                    text: String::new(),
                    end: None,
                });
                if !empty {
                    stack.push(index);
                }
            }
            Event::End(_) => {
                let index = stack.pop().context("unexpected XML closing tag")?;
                values[index].end = Some(position);
            }
            Event::Text(text) => {
                let text = quick_xml::escape::unescape(&text.decode()?)?.into_owned();
                if let Some(index) = stack.last() {
                    values[*index].text.push_str(&text);
                } else {
                    ensure!(text.trim().is_empty(), "text outside domain XML");
                }
            }
            Event::CData(text) => {
                let index = stack.last().context("CDATA outside domain XML")?;
                values[*index].text.push_str(&text.decode()?);
            }
            Event::GeneralRef(reference) => {
                // Only predefined XML references and numeric character entities
                // are allowed; external/entity declarations are never expanded.
                let entity = format!("&{};", reference.decode()?);
                let text = quick_xml::escape::unescape(&entity)?;
                let index = stack.last().context("entity outside domain XML")?;
                values[*index].text.push_str(&text);
            }
            Event::DocType(_) => anyhow::bail!("custom XML declarations are unsupported"),
            Event::Eof => break,
            Event::Decl(_) | Event::Comment(_) | Event::PI(_) => {}
        }
    }
    ensure!(
        roots == 1 && stack.is_empty(),
        "expected one complete domain XML document"
    );
    Ok(values)
}

fn one<'a>(values: &'a [Element], path: &str) -> Result<&'a Element> {
    let matches: Vec<_> = values.iter().filter(|v| v.path == path).collect();
    ensure!(
        matches.len() == 1,
        "expected exactly one XML element {path}"
    );
    Ok(matches[0])
}

fn address(element: &Element) -> Result<[u32; 4]> {
    let mut values = [0; 4];
    for (i, key) in ["domain", "bus", "slot", "function"].iter().enumerate() {
        let text = element
            .attributes
            .get(*key)
            .map(String::as_str)
            .unwrap_or("0");
        values[i] = if let Some(hex) = text.strip_prefix("0x") {
            u32::from_str_radix(hex, 16)?
        } else {
            text.parse()?
        };
    }
    Ok(values)
}

pub(super) fn inject(xml: &str, report: &Prepared) -> Result<String> {
    let values = elements(xml)?;
    ensure!(
        one(&values, "/domain")?
            .attributes
            .get("type")
            .map(String::as_str)
            == Some("xen"),
        "AMD VFCT requires a Xen domain definition"
    );
    ensure!(
        one(&values, "/domain/uuid")?.text == report.domain_uuid,
        "AMD VFCT domain identity changed during preparation"
    );
    ensure!(
        one(&values, "/domain/os/type")?.text == "hvm",
        "AMD VFCT requires HVM XML"
    );
    ensure!(
        !values.iter().any(|v| v.path == "/domain/os/acpi"),
        "AMD VFCT refuses to replace existing custom ACPI tables"
    );
    let hostdev = one(&values, "/domain/devices/hostdev")?;
    ensure!(
        hostdev.attributes.get("type").map(String::as_str) == Some("pci"),
        "AMD VFCT XML must contain exactly one PCI host device"
    );
    let bdf = report.firmware.host_bdf;
    ensure!(
        address(one(&values, "/domain/devices/hostdev/source/address")?)?
            == [
                0,
                u32::from(bdf.bus),
                u32::from(bdf.device),
                u32::from(bdf.function)
            ],
        "AMD VFCT XML does not match the prepared GPU"
    );
    ensure!(
        !values
            .iter()
            .any(|v| v.path == "/domain/devices/hostdev/address"),
        "AMD VFCT refuses to overwrite an existing VM PCI address"
    );
    for element in values.iter().filter(|v| {
        v.path.starts_with("/domain/devices/")
            && v.path.matches('/').count() == 4
            && v.path.ends_with("/address")
            && v.attributes.get("type").map(String::as_str) == Some("pci")
    }) {
        ensure!(
            address(element)?[..3] != [0, 0, u32::from(report.guest_slot)],
            "AMD VFCT VM PCI slot is already occupied"
        );
    }

    let table = report
        .table_path
        .to_str()
        .context("non-UTF-8 firmware path")?;
    let mut edits = vec![
        (
            hostdev.end.context("PCI hostdev has no closing tag")?,
            format!(
                "<address type=\"pci\" domain=\"0x0000\" bus=\"0x00\" slot=\"0x{:02x}\" function=\"0x0\"/>",
                report.guest_slot
            ),
        ),
        (
            one(&values, "/domain/os")?
                .end
                .context("OS has no closing tag")?,
            format!(
                "<acpi><table type=\"slic\">{}</table></acpi>",
                quick_xml::escape::escape(table)
            ),
        ),
    ];
    edits.sort_by_key(|(offset, _)| std::cmp::Reverse(*offset));
    let mut output = xml.to_owned();
    for (offset, text) in edits {
        output.insert_str(offset, &text);
    }
    Ok(output)
}

pub(super) fn verify(native: &str, report: &Prepared) -> Result<()> {
    ensure!(
        native.len() <= 8 * 1024 * 1024,
        "libvirt native output exceeds limit"
    );
    let field = |name: &str| -> Result<&str> {
        let values: Vec<_> = native
            .lines()
            .filter_map(|line| line.split_once('='))
            .filter(|(key, _)| key.trim() == name)
            .map(|(_, v)| v.trim())
            .collect();
        ensure!(values.len() == 1, "libvirt did not preserve {name}");
        Ok(values[0])
    };
    let pci = field("pci")?;
    ensure!(
        pci.starts_with('[') && pci.ends_with(']'),
        "invalid native PCI list"
    );
    let entries: Vec<String> = serde_json::from_str(pci).context("invalid native PCI list")?;
    let expected = format!("{}@{:02x}", report.firmware.host_bdf, report.guest_slot);
    ensure!(
        entries.len() == 1 && entries[0].split(',').next() == Some(expected.as_str()),
        "libvirt did not preserve the sole GPU and explicit guest slot; install Airlock's libxl slot patch"
    );
    let path = report.table_path.to_str().context("non-UTF-8 VFCT path")?;
    ensure!(
        serde_json::from_str::<String>(field("acpi_firmware")?)? == path,
        "libvirt did not preserve the prepared VFCT path"
    );
    Ok(())
}
