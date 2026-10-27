//! Relocate Qubes' two file pools without changing VM features or other metadata.

use anyhow::{Context, Result, ensure};
use quick_xml::{
    Reader, Writer, XmlVersion,
    events::{BytesStart, Event},
};
use std::{collections::BTreeSet, path::Path};

pub(crate) fn installed(text: &str, source: &Path) -> Result<Vec<u8>> {
    let mut reader = Reader::from_str(text);
    let mut writer = Writer::new(Vec::new());
    let mut stack: Vec<Vec<u8>> = Vec::new();
    let mut relocated = BTreeSet::new();
    let mut roots = 0;

    loop {
        let event = reader.read_event()?;
        let empty = matches!(event, Event::Empty(_));
        match event {
            Event::Start(start) | Event::Empty(start) => {
                ensure!(stack.len() < 128, "Qubes XML nesting is too deep");
                if stack.is_empty() {
                    roots += 1;
                    ensure!(
                        roots == 1 && start.name().as_ref() == b"qubes",
                        "invalid Qubes XML root"
                    );
                }

                let pool = stack.len() == 2
                    && stack[0] == b"qubes"
                    && stack[1] == b"pools"
                    && start.name().as_ref() == b"pool";
                let mut updated =
                    BytesStart::new(std::str::from_utf8(start.name().as_ref())?.to_owned());
                let mut name = None;
                let mut path = None;
                for attribute in start.attributes() {
                    let attribute = attribute?;
                    if pool && attribute.key.as_ref() == b"name" {
                        name = Some(
                            attribute
                                .decoded_and_normalized_value(
                                    XmlVersion::Implicit1_0,
                                    reader.decoder(),
                                )?
                                .into_owned(),
                        );
                    }
                    if pool && attribute.key.as_ref() == b"dir_path" {
                        path = Some(
                            attribute
                                .decoded_and_normalized_value(
                                    XmlVersion::Implicit1_0,
                                    reader.decoder(),
                                )?
                                .into_owned(),
                        );
                    } else {
                        updated.push_attribute(attribute);
                    }
                }

                if pool && let Some(path) = path {
                    let name = name.context("Qubes file pool has no name")?;
                    let relative = match name.as_str() {
                        "varlibqubes" => "",
                        "linux-kernel" => "vm-kernels",
                        _ => anyhow::bail!("unexpected Qubes file pool: {name}"),
                    };
                    ensure!(
                        Path::new(&path) == source.join(relative),
                        "unexpected prepared Qubes pool path: {name}"
                    );
                    ensure!(relocated.insert(name), "duplicate Qubes file pool");
                    let target = if relative.is_empty() {
                        Path::new("/var/lib/qubes").to_owned()
                    } else {
                        Path::new("/var/lib/qubes").join(relative)
                    };
                    updated.push_attribute((
                        "dir_path",
                        target.to_str().context("installed pool path")?,
                    ));
                }

                if !empty {
                    stack.push(start.name().as_ref().to_vec());
                }
                writer.write_event(if empty {
                    Event::Empty(updated)
                } else {
                    Event::Start(updated)
                })?;
            }
            Event::End(end) => {
                ensure!(
                    stack.pop().as_deref() == Some(end.name().as_ref()),
                    "unbalanced Qubes XML"
                );
                writer.write_event(Event::End(end))?;
            }
            Event::Text(ref text) if stack.is_empty() => {
                ensure!(
                    text.as_ref().iter().all(u8::is_ascii_whitespace),
                    "Text outside Qubes XML root"
                );
                writer.write_event(event)?;
            }
            Event::CData(_) if stack.is_empty() => anyhow::bail!("CDATA outside Qubes XML root"),
            Event::DocType(_) => anyhow::bail!("Qubes XML must not contain a document type"),
            Event::Eof => break,
            other => writer.write_event(other)?,
        }
    }

    ensure!(
        roots == 1 && stack.is_empty() && relocated.len() == 2,
        "Qubes XML is missing its prepared file pools"
    );

    Ok(writer.into_inner())
}

#[cfg(test)]
mod tests;
