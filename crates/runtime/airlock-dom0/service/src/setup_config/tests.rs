//! Keep setup reads and admin mutations faithful to upstream identity and explicit-state semantics.

use super::*;
use std::fs;

/// Global defaults, neighbouring VMs and property order must not manufacture an explicit setting.
#[test]
fn explicit_properties_are_scoped_to_the_requested_owner() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("qubes.xml");
    fs::write(
        &path,
        r#"
        <qubes>
          <properties><property name="default_netvm">sys-net</property></properties>
          <domains>
            <domain><properties>
              <property name="netvm"/><property name="name">usr-home</property>
            </properties></domain>
            <domain><properties><property name="name">usr-browser</property></properties></domain>
          </domains>
        </qubes>
    "#,
    )?;
    assert!(xml::explicit(&path, None, "default_netvm")?);
    assert!(!xml::explicit(&path, None, "netvm")?);
    assert!(xml::explicit(&path, Some(&"usr-home".parse()?), "netvm")?);
    assert!(!xml::explicit(
        &path,
        Some(&"usr-browser".parse()?),
        "netvm"
    )?);
    assert!(!xml::explicit(&path, Some(&"missing".parse()?), "netvm")?);

    for invalid in [
        "<qubes>",
        "<qubes/><qubes/>",
        "<other/>",
        "<qubes><domains></qubes>",
    ] {
        fs::write(&path, invalid)?;
        assert!(xml::explicit(&path, None, "netvm").is_err(), "{invalid}");
    }
    Ok(())
}

/// Device descriptions may contain escaped quotes; selection depends on encoded interfaces only.
#[test]
fn network_inventory_uses_upstream_interface_identity() -> Result<()> {
    let reply = r#"00_08.1-00_00.0 vendor='Display controller' interfaces='p030000'
00_1c.0-00_00.0:8086:1234::020000 vendor='A \'quoted\' device' interfaces='p020000' port_id='00_1c.0-00_00.0'
03_00.0 interfaces='p028000p020000'
04_00.0 vendor='not an interface'
"#;
    assert_eq!(network_ports(reply)?, ["00_1c.0-00_00.0", "03_00.0"]);
    for invalid in [
        "02_00.0 interfaces='p02'",
        "02_00.0 interfaces='p020000' interfaces='p030000'",
        "../escape interfaces='p020000'",
        "02_00.0 interfaces='p020000",
    ] {
        assert!(network_ports(invalid).is_err(), "{invalid}");
    }
    Ok(())
}

/// Creating a missing label, verifying one and refusing colour changes are separate admin outcomes.
#[test]
fn label_reconciliation_only_creates_missing_declared_colours() -> Result<()> {
    for (labels, current, color, accepted, writes) in [
        ("red\n", "", "0xF0E68C", true, 1),
        ("red\nkhaki\n", "#f0e68c", "0xF0E68C", true, 0),
        ("khaki\n", "#000000", "0xF0E68C", false, 0),
        ("", "", "not-a-colour", false, 0),
    ] {
        let mut mutations = Vec::new();
        let result = ensure_label("khaki", color, &mut |method, argument, payload| {
            Ok(match method {
                "admin.label.List" => labels.as_bytes().to_vec(),
                "admin.label.Get" => current.as_bytes().to_vec(),
                "admin.label.Create" => {
                    mutations.push((argument.to_owned(), payload.to_vec()));
                    Vec::new()
                }
                other => panic!("unexpected admin call: {other}"),
            })
        });
        assert_eq!(result.is_ok(), accepted);
        assert_eq!(mutations.len(), writes);
        if writes != 0 {
            assert_eq!(mutations[0], ("khaki".into(), color.as_bytes().to_vec()));
        }
    }

    ensure!(
        ensure_label("red", "0xff0000", &mut |_, _, _| {
            panic!("unsupported labels must fail before calling Qubes")
        })
        .is_err()
    );
    ensure!(
        ensure_label("khaki", "0xf0e68c", &mut |_, _, _| {
            anyhow::bail!("Qubes admin unavailable")
        })
        .is_err()
    );
    Ok(())
}
