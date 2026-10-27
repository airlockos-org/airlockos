//! Read explicit database properties without taking ownership of Qubes persistence.

use airlock_nix_core::identity::GuestName;
use anyhow::{Context, Result, ensure};
use quick_xml::{Reader, events::Event};
use std::{fs::File, io::Read, path::Path};

/// Resolve explicit global or VM properties after validating the complete XML document.
pub(super) fn explicit(path: &Path, domain: Option<&GuestName>, property: &str) -> Result<bool> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 16 * 1024 * 1024,
        "Qubes database exceeds inspection limit"
    );

    let mut reader = Reader::from_reader(bytes.as_slice());
    let mut stack = Vec::<Vec<u8>>::new();
    let mut domain_name = String::new();
    let mut in_name = false;
    let mut found_in_domain = false;
    let mut found = false;
    let mut roots = 0;
    loop {
        let event = reader.read_event()?;
        let empty = matches!(&event, Event::Empty(_));
        match event {
            Event::Start(element) | Event::Empty(element) => {
                let name = element.name().as_ref().to_vec();
                if stack.is_empty() {
                    roots += 1;
                    ensure!(
                        roots == 1 && name == b"qubes",
                        "expected one Qubes XML root"
                    );
                }
                stack.push(name);
                let names: Vec<_> = stack.iter().map(Vec::as_slice).collect();
                if names == [b"qubes".as_slice(), b"domains", b"domain"] {
                    domain_name.clear();
                    found_in_domain = false;
                }
                if names == [b"qubes".as_slice(), b"properties", b"property"]
                    || names
                        == [
                            b"qubes".as_slice(),
                            b"domains",
                            b"domain",
                            b"properties",
                            b"property",
                        ]
                {
                    let mut property_name = String::new();
                    for attribute in element.attributes() {
                        let attribute = attribute?;
                        if attribute.key.as_ref() == b"name" {
                            property_name = attribute
                                .decoded_and_normalized_value(
                                    quick_xml::XmlVersion::Implicit1_0,
                                    reader.decoder(),
                                )?
                                .into_owned();
                        }
                    }
                    if names.len() == 3 && domain.is_none() && property_name == property {
                        found = true;
                    }
                    if names.len() == 5 {
                        found_in_domain |= property_name == property;
                        in_name = property_name == "name" && !empty;
                    }
                }
                if empty {
                    stack.pop();
                }
            }
            Event::Text(text) if in_name => {
                domain_name.push_str(&quick_xml::escape::unescape(&text.decode()?)?);
            }
            Event::End(element) => {
                if stack.len() == 5 {
                    in_name = false;
                }
                if stack.len() == 3 && element.name().as_ref() == b"domain" {
                    found |=
                        domain.is_some_and(|name| name.as_str() == domain_name) && found_in_domain;
                }
                stack.pop().context("unexpected XML closing element")?;
            }
            Event::DocType(_) => anyhow::bail!("Qubes database declarations are unsupported"),
            Event::Eof => break,
            _ => {}
        }
    }
    ensure!(
        roots == 1 && stack.is_empty(),
        "incomplete Qubes database XML"
    );
    Ok(found)
}
