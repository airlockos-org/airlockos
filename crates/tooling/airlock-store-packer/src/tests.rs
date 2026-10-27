//! Freeze the existing artifact wire identity while the packer moves to an independent build.

use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};

/// File types, hard links and executable modes preserve the pre-extraction canonical representation.
#[test]
fn fragment_keeps_existing_wire_identity() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let logical = "/nix/store/00000000000000000000000000000000-packing-fixture";
    let source = temporary.path().join(entry(logical)?);
    fs::create_dir(&source)?;
    fs::set_permissions(&source, fs::Permissions::from_mode(0o755))?;
    fs::create_dir(source.join("nested"))?;
    fs::set_permissions(source.join("nested"), fs::Permissions::from_mode(0o755))?;
    fs::write(source.join("a"), b"payload\n")?;
    fs::set_permissions(source.join("a"), fs::Permissions::from_mode(0o644))?;
    fs::write(source.join("nested/run"), b"#!/bin/true\n")?;
    fs::set_permissions(source.join("nested/run"), fs::Permissions::from_mode(0o755))?;
    symlink("a", source.join("link"))?;
    fs::hard_link(source.join("a"), source.join("hard"))?;

    let first = temporary.path().join("first");
    let value = pack(logical, &source, &first)?;
    // Recorded using the original airlock-store-cache executable before extraction.
    assert_eq!(
        value.tree_hash,
        "6416e1e1b7f070fa2adc3326e8f358f5ef53f288ca87a11d9f3c20c152f57a90"
    );
    assert_eq!(value.size, 4608);
    assert_eq!(
        value.sha256,
        "bc98ead3081a2318ca964d80e58f15d326fcf6340bbbfb07c149993494c13a05"
    );
    assert_eq!(fragment(&first, logical)?.sha256, value.sha256);

    let times = fs::FileTimes::new().set_modified(std::time::UNIX_EPOCH);
    File::open(source.join("a"))?.set_times(times)?;
    let second = temporary.path().join("second");
    assert_eq!(pack(logical, &source, &second)?.sha256, value.sha256);
    assert_eq!(
        fs::read(first.join("object.tar"))?,
        fs::read(second.join("object.tar"))?
    );
    Ok(())
}
