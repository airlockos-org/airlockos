//! Pool relocation preserves metadata outside the two upstream file pools.

use super::*;

/// Escaped paths and both XML element spellings have the same relocation semantics.
#[test]
fn only_file_pool_paths_are_relocated() -> Result<()> {
    let source = "/build/output & 'test'/qubes";
    let escaped = quick_xml::escape::escape(source);
    let xml = format!(
        r#"<qubes>
<pools>
<pool name="varlibqubes" dir_path="{escaped}" />
<pool name="linux-kernel" dir_path="{escaped}/vm-kernels" />
<pool name="airlock-closure" root_dir="/var/lib/airlock/closure-store" />
</pools>
<domains><feature name="source">{escaped}</feature></domains>
</qubes>"#
    );

    for input in [xml.clone(), xml.replace(" />", "></pool>")] {
        let relocated = String::from_utf8(installed(&input, Path::new(source))?)?;
        let mut reader = Reader::from_str(&relocated);
        let mut pools = Vec::new();
        let mut feature = false;
        loop {
            match reader.read_event()? {
                Event::Start(element) | Event::Empty(element)
                    if element.name().as_ref() == b"pool" =>
                {
                    let attributes: BTreeSet<_> = element
                        .attributes()
                        .map(|attribute| {
                            let attribute = attribute.unwrap();
                            (
                                String::from_utf8(attribute.key.as_ref().to_vec()).unwrap(),
                                attribute
                                    .normalized_value(XmlVersion::Implicit1_0)
                                    .unwrap()
                                    .into_owned(),
                            )
                        })
                        .collect();
                    pools.push(attributes);
                }
                Event::Start(element) if element.name().as_ref() == b"feature" => {
                    let text = reader.read_text(element.name())?;
                    assert_eq!(quick_xml::escape::unescape(&text.decode()?)?, source);
                    feature = true;
                }
                Event::Eof => break,
                _ => {}
            }
        }

        assert!(feature);
        assert_eq!(pools.len(), 3);
        for (index, expected) in ["/var/lib/qubes", "/var/lib/qubes/vm-kernels"]
            .iter()
            .enumerate()
        {
            assert!(pools[index].contains(&("dir_path".into(), (*expected).into())));
        }
        assert!(pools[2].contains(&("root_dir".into(), "/var/lib/airlock/closure-store".into())));
    }
    Ok(())
}

/// Malformed or ambiguous pool definitions must never be published into an image.
#[test]
fn invalid_pool_xml_is_rejected() {
    for xml in [
        "<qubes/>",
        "<!DOCTYPE qubes><qubes/>",
        r#"<qubes><pools><pool name="varlibqubes" dir_path="/wrong"/></pools></qubes>"#,
        r#"<qubes><pools><pool name="varlibqubes" dir_path="/source"/><pool name="varlibqubes" dir_path="/source"/></pools></qubes>"#,
        "<qubes><pools></qubes>",
    ] {
        assert!(installed(xml, Path::new("/source")).is_err(), "{xml}");
    }
}
