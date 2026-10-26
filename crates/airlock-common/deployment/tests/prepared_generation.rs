//! Prepared-generation selection retains both durable records and the independently requested identity.

use airlock_deployment_core::attachment::prepared::{
    Boot, CheckedGeneration, Descriptor, Expected, Layout, Manifest,
};

/// Original installed boot coordinates shared by the valid fixture records.
fn boot() -> Boot {
    Boot {
        pool: "/pool".into(),
        namespace: "usr-home-runtime-store".into(),
        system: "/nix/store/system".into(),
        root: "/nix/store/root".into(),
        kernel: "linux".into(),
        closure: "closure-hash".into(),
    }
}

/// Guest-visible frontends and original source, distinct from physical artifact paths.
fn layout() -> Layout {
    Layout {
        source: "/nix/store/source".into(),
        device: "/dev/xvde".into(),
        blob_device: "/dev/xvdf".into(),
        mountpoint: "/nix/store".into(),
        backend: "erofs-objectmap".into(),
    }
}

/// Pinned caller identity, established independently of the prepared descriptor.
fn expected() -> Expected {
    Expected {
        boot: boot(),
        layout: layout(),
        number: Some(7),
    }
}

/// Descriptor identity authenticated by the adapter's checksummed file inventory.
fn descriptor() -> Descriptor {
    Descriptor {
        boot: boot(),
        number: 7,
    }
}

/// Independently loaded committed manifest at the descriptor's addressed generation.
fn manifest() -> Manifest {
    Manifest {
        boot: boot(),
        layout: layout(),
        number: 7,
    }
}

/// Both pinned and unpinned selection carry the exact original manifest coordinates.
#[test]
fn matching_generation_preserves_the_loader_coordinates() {
    let mut requested = expected();
    for pin in [Some(7), None] {
        requested.number = pin;
        let checked = CheckedGeneration::check(&requested, &descriptor(), manifest()).unwrap();
        assert_eq!(checked.namespace(), "usr-home-runtime-store");
        assert_eq!(checked.number(), 7);
    }
}

/// A different boot source or namespace in either durable record refuses selection.
#[test]
fn neither_durable_record_can_substitute_boot_identity() {
    let changes: [fn(&mut Boot); 6] = [
        |b| b.pool = "/other-pool".into(),
        |b| b.namespace = "usr-other-runtime-store".into(),
        |b| b.system = "/nix/store/other-system".into(),
        |b| b.root = "/nix/store/other-root".into(),
        |b| b.kernel = "other-kernel".into(),
        |b| b.closure = "other-closure".into(),
    ];
    for change in changes {
        let mut described = descriptor();
        change(&mut described.boot);
        assert!(CheckedGeneration::check(&expected(), &described, manifest()).is_none());
        let mut loaded = manifest();
        change(&mut loaded.boot);
        assert!(CheckedGeneration::check(&expected(), &descriptor(), loaded).is_none());
    }
}

/// Software equivalence cannot hide redirected frontends or a substituted source.
#[test]
fn every_requested_frontend_and_source_must_match() {
    let changes: [fn(&mut Layout); 5] = [
        |l| l.source = "/nix/store/other-source".into(),
        |l| l.device = "/dev/xvdg".into(),
        |l| l.blob_device = "/dev/xvdh".into(),
        |l| l.mountpoint = "/other".into(),
        |l| l.backend = "unknown".into(),
    ];
    for change in changes {
        let mut loaded = manifest();
        change(&mut loaded.layout);
        assert!(CheckedGeneration::check(&expected(), &descriptor(), loaded).is_none());
    }
}

/// Invalid, conflicting or stale numbers cannot become a successful typed selection.
#[test]
fn positive_generation_and_original_pin_are_required() {
    let mut requested = expected();
    requested.number = Some(8);
    assert!(CheckedGeneration::check(&requested, &descriptor(), manifest()).is_none());
    let mut described = descriptor();
    described.number = 8;
    assert!(CheckedGeneration::check(&expected(), &described, manifest()).is_none());
    let mut loaded = manifest();
    loaded.number = 0;
    described.number = 0;
    requested.number = None;
    assert!(CheckedGeneration::check(&requested, &described, loaded).is_none());
}
