//! Prepared image stores remain usable without source packages and keep host recovery independent.

use crate::{
    common::{self, store::Store},
    host_store::pe,
    storage_integrity::snapshot,
};
use anyhow::Result;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

/// Own two prepared system variants sharing one immutable package and a private installed pool.
struct Seed {
    // Supplies inert EROFS indexing and the real native image/storage command.
    store: Store,
    // Authoritative per-variant declarations passed through the native JSON boundary.
    specs: Value,
    // Separately cacheable output describing the sealed pool.
    descriptors: PathBuf,
    // Final pool location, already reflected in generated metadata.
    installed: PathBuf,
}

impl Seed {
    /// Prepare sparse source files and two variants without evaluating or building a Nix system.
    fn new() -> Result<Self> {
        Self::create(false)
    }

    /// Optionally include distinct builder identities over the same union of immutable packages.
    fn create(builders: bool) -> Result<Self> {
        let store = Store::new()?;
        let root = store.temporary.path();
        let installed = root.join("installed-pool");
        let descriptors = root.join("descriptors");
        let root_source = format!("/nix/store/{hash}-root/root.img", hash = "d".repeat(32));
        let root_image = store.physical.join("d".repeat(32) + "-root/root.img");
        fs::create_dir_all(root_image.parent().unwrap())?;
        fs::copy(&store.root, &root_image)?;
        let mut specs = Vec::new();
        for (index, hash) in ["b", "c"].into_iter().enumerate() {
            let system = format!("/nix/store/{hash}-system", hash = hash.repeat(32));
            let package = store.physical.join(system.rsplit('/').next().unwrap());
            fs::create_dir(&package)?;
            fs::write(package.join("payload"), system.repeat(20))?;
            let closure = root.join(format!("closure-{index}"));
            fs::create_dir(&closure)?;
            fs::write(closure.join("manifest.json"), "{}")?;
            fs::write(
                closure.join("store-paths"),
                format!("{common}\n{system}\n", common = store.system),
            )?;
            specs.push(
                json!({"name": format!("variant-{index}"), "domain": "sys-gui-runtime-store", "system": system,
                "root_source": root_source, "kernel_name": "test-kernel", "closure_source": closure,
                "physical_store_root": store.physical}),
            );
        }

        if builders {
            let closure = root.join("builder-closure");
            fs::create_dir(&closure)?;
            let paths = [
                store.system.clone(),
                specs[0]["system"].as_str().unwrap().into(),
                specs[1]["system"].as_str().unwrap().into(),
            ];
            fs::write(closure.join("manifest.json"), "{}")?;
            fs::write(
                closure.join("store-paths"),
                format!("{paths}\n", paths = paths.join("\n")),
            )?;
            fs::write(
                closure.join("registration"),
                paths
                    .iter()
                    .map(|path| format!("{path}\n{hash}\n42\n\n0\n", hash = "0".repeat(64)))
                    .collect::<String>(),
            )?;
            for (index, role) in ["sys-ctrl", "usr-assistant"].into_iter().enumerate() {
                specs.push(json!({"name":role,"domain":format!("{role}-build-store"),"system":specs[index]["system"],"root_source":"","kernel_name":"","closure_source":closure,"physical_store_root":store.physical,"builder":true}));
            }
        }

        let seed = Self {
            store,
            specs: json!(specs),
            descriptors,
            installed,
        };
        seed.prepare(&seed.store.pool, &seed.descriptors)?;
        Ok(seed)
    }

    /// Produce both outputs with the same logical runtime location.
    fn prepare(&self, pool: &Path, descriptors: &Path) -> Result<()> {
        common::run(&mut self.prepare_command(pool, descriptors)?, None)?.checked()?;
        Ok(())
    }

    /// Allow an explicitly prepared real index tool at the same native command boundary.
    fn prepare_command(&self, pool: &Path, descriptors: &Path) -> Result<Command> {
        let path = self.store.temporary.path().join("specs.json");
        fs::write(&path, serde_json::to_vec(&self.specs)?)?;
        let mut command = self.store.command(&["image", "prepare-pool"]);
        command
            .arg(pool)
            .arg(descriptors)
            .arg(path)
            .arg(&self.installed)
            .env(
                "AIRLOCK_TEST_EROFS_CALLS",
                self.store.temporary.path().join("indexes.jsonl"),
            );
        Ok(command)
    }

    /// Build reusable fragment and common-index outputs without retaining any pool placement.
    fn cache(&self, real_mkfs: Option<&std::ffi::OsStr>) -> Result<PathBuf> {
        let root = self.store.temporary.path().join("artifact-cache");
        fs::create_dir(&root)?;
        let mut fragments = BTreeMap::new();
        let mut closures = Vec::new();
        for spec in self.specs.as_array().unwrap() {
            let paths: Vec<String> = fs::read_to_string(
                Path::new(spec["closure_source"].as_str().unwrap()).join("store-paths"),
            )?
            .lines()
            .map(str::to_owned)
            .collect();
            for logical in &paths {
                if fragments.contains_key(logical) {
                    continue;
                }
                let name = Path::new(logical).file_name().unwrap();
                let directory = root.join(name);
                airlock_nix_core::artifact::cache::pack(
                    logical,
                    &self.store.physical.join(name),
                    &directory,
                )?;
                fragments.insert(logical.clone(), directory);
            }
            closures.push(paths);
        }
        let tool = common::binary("AIRLOCK_STORE_CACHE_BIN", "airlock-store-cache");
        let mut indexes = Vec::new();
        for (number, paths) in closures.iter().enumerate() {
            let input = root.join(format!("index-{number}.json"));
            fs::write(
                &input,
                serde_json::to_vec(
                    &paths
                        .iter()
                        .map(|path| (path, &fragments[path]))
                        .collect::<BTreeMap<_, _>>(),
                )?,
            )?;
            let index = root.join(format!("index-{number}"));
            common::run(
                Command::new(&tool)
                    .arg("index")
                    .arg(&input)
                    .arg(&index)
                    .arg(
                        real_mkfs
                            .unwrap_or(self.store.temporary.path().join("mkfs.erofs").as_os_str()),
                    ),
                None,
            )?
            .checked()?;
            indexes.push(index);
        }
        let manifest = root.join("manifest.json");
        fs::write(
            &manifest,
            serde_json::to_vec(
                &json!({"schema":"airlock.image-cache.v1","fragments":fragments,"indexes":indexes}),
            )?,
        )?;
        Ok(manifest)
    }

    /// Install the sealed pool and remove all source packages before boot-adoption assertions.
    fn install(&self) -> Result<()> {
        fs::rename(&self.store.pool, &self.installed)?;
        fs::remove_dir_all(&self.store.physical)?;
        Ok(())
    }

    /// Bind runtime adoption to the selected variant's exact identity and devices.
    fn request(&self, index: usize) -> Value {
        let spec = &self.specs[index];
        json!({"artifact": self.descriptors.join(format!("variant-{index}")),
            "source": self.descriptors.join(format!("variant-{index}")), "pool_root": self.installed,
            "domain": "sys-gui", "system": spec["system"], "root": spec["root_source"], "kernel": "test-kernel",
            "device": "/dev/xvde", "blob_device": "/dev/xvdf", "mountpoint": "/nix/store", "view_backend": "erofs-objectmap"})
    }

    /// Use the real prepared descriptor verifier and keep rejection diagnostics for corruption cases.
    fn verify(&self, request: &Value) -> Result<airlock_vm_service::support::Output> {
        common::run(
            &mut self
                .store
                .command(&["image", "verify-prepared", "--request", "-"]),
            Some(serde_json::to_vec(request)?),
        )
    }

    /// Fully validate stored bytes independently from the cheaper trusted-image boot-adoption check.
    fn outputs(&self) -> Result<airlock_vm_service::support::Output> {
        common::run(
            self.store
                .command(&["image", "verify-outputs"])
                .arg(&self.installed)
                .arg(&self.descriptors),
            None,
        )
    }
}

/// Shared payloads are read once per verification, conflicting expectations fail, and later corruption is detected.
#[test]
fn prepared_image_verification_deduplicates_shared_files() -> Result<()> {
    use rustix::fs::inotify;
    use std::mem::MaybeUninit;

    let seed = Seed::new()?;
    seed.install()?;
    let first: Value =
        serde_json::from_slice(&fs::read(seed.descriptors.join("variant-0/prepared.json"))?)?;
    let second_path = seed.descriptors.join("variant-1/prepared.json");
    let second: Value = serde_json::from_slice(&fs::read(&second_path)?)?;
    let first_files = first["files"].as_object().unwrap();
    let second_files = second["files"].as_object().unwrap();
    let shared = first_files
        .keys()
        .find(|path| path.ends_with(".blob") && second_files.contains_key(*path))
        .unwrap();
    let unique = first_files
        .keys()
        .chain(second_files.keys())
        .collect::<BTreeSet<_>>()
        .len();
    let blob = seed.installed.join(shared);

    let watch = inotify::init(inotify::CreateFlags::NONBLOCK | inotify::CreateFlags::CLOEXEC)?;
    // Close events separate opens so the kernel cannot coalesce repeated reads into one event.
    inotify::add_watch(
        &watch,
        &blob,
        inotify::WatchFlags::OPEN | inotify::WatchFlags::CLOSE_NOWRITE,
    )?;
    let mut buffer = [MaybeUninit::uninit(); 512];
    let mut events = inotify::Reader::new(&watch, &mut buffer);
    for invocation in 0..2 {
        let report: Value = serde_json::from_slice(&seed.outputs()?.checked()?)?;
        assert_eq!(report["variants"], 2);
        assert_eq!(report["files"], unique);
        let mut opens = 0;
        loop {
            match events.next() {
                Ok(event) => {
                    assert!(!event.events().contains(inotify::ReadFlags::QUEUE_OVERFLOW));
                    if event.events().contains(inotify::ReadFlags::OPEN) {
                        opens += 1;
                    }
                }
                Err(rustix::io::Errno::AGAIN) => break,
                Err(error) => return Err(error.into()),
            }
        }
        assert_eq!(opens, 1, "verification invocation {invocation}");
    }

    for (field, invalid) in [
        (
            "size",
            json!(first["files"][shared]["size"].as_u64().unwrap() + 1),
        ),
        ("sha256", json!("0".repeat(64))),
    ] {
        let mut conflicting = second.clone();
        conflicting["files"][shared][field] = invalid;
        fs::write(&second_path, serde_json::to_vec(&conflicting)?)?;
        let failed = seed.outputs()?;
        assert!(!failed.status.success());
        let report: Value = serde_json::from_slice(&failed.stdout)?;
        let error = report["error"].as_str().unwrap();
        assert!(
            error.contains("conflicting prepared fingerprints"),
            "{error}"
        );
        assert!(error.contains(shared), "{error}");
    }
    fs::write(second_path, serde_json::to_vec(&second)?)?;

    fs::set_permissions(&blob, fs::Permissions::from_mode(0o600))?;
    let mut bytes = fs::read(&blob)?;
    bytes[0] ^= 1;
    fs::write(blob, bytes)?;
    let failed = seed.outputs()?;
    assert!(!failed.status.success());
    let report: Value = serde_json::from_slice(&failed.stdout)?;
    let error = report["error"].as_str().unwrap();
    assert!(error.contains("prepared integrity check failed"), "{error}");
    Ok(())
}

/// Independent cached artifacts reproduce the original pool without rehashing or repacking package trees.
#[test]
fn prepared_image_reuses_cached_artifacts_and_rejects_corruption() -> Result<()> {
    let seed = Seed::create(true)?;
    let cache = seed.cache(None)?;
    let root = seed.store.temporary.path();
    // Preserve the root image, but make every original package unavailable to the preparer.
    for path in fs::read_dir(&seed.store.physical)? {
        let path = path?.path();
        if path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with("-system")
        {
            fs::remove_dir_all(path)?;
        }
    }
    let pool = root.join("cached-pool");
    let descriptors = root.join("cached-descriptors");
    let calls = root.join("cached-indexes.jsonl");
    common::run(
        seed.prepare_command(&pool, &descriptors)?
            .arg("--cache")
            .arg(&cache)
            .env("AIRLOCK_TEST_EROFS_CALLS", &calls),
        None,
    )?
    .checked()?;
    let calls = fs::read_to_string(calls)?;
    assert!(
        !calls.contains("--tar=i"),
        "cached preparation rebuilt a common index: {calls}"
    );
    assert_eq!(
        common::json(
            seed.store
                .command(&["image", "verify-outputs"])
                .arg(&pool)
                .arg(&descriptors),
            None
        )?["status"],
        "passed"
    );

    let manifest: Value = serde_json::from_slice(&fs::read(&cache)?)?;
    let fragment =
        Path::new(manifest["fragments"][&seed.store.system].as_str().unwrap()).join("object.tar");
    let original = fs::read(&fragment)?;
    let mut damaged = original.clone();
    damaged[0] ^= 0xff;
    fs::write(&fragment, damaged)?;
    let result = common::run(
        seed.prepare_command(
            &root.join("damaged-pool"),
            &root.join("damaged-descriptors"),
        )?
        .arg("--cache")
        .arg(&cache),
        None,
    )?;
    assert!(!result.status.success());
    let diagnostic = format!(
        "{stdout}{stderr}",
        stdout = String::from_utf8_lossy(&result.stdout),
        stderr = String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        diagnostic.contains("cached fragment checksum mismatch"),
        "{diagnostic}"
    );
    fs::write(fragment, original)?;

    let index = Path::new(manifest["indexes"][0].as_str().unwrap()).join("store.erofs");
    fs::write(index, b"corrupt cached index")?;
    let result = common::run(
        seed.prepare_command(
            &root.join("damaged-index-pool"),
            &root.join("damaged-index-descriptors"),
        )?
        .arg("--cache")
        .arg(&cache),
        None,
    )?;
    assert!(!result.status.success());
    let diagnostic = format!(
        "{stdout}{stderr}",
        stdout = String::from_utf8_lossy(&result.stdout),
        stderr = String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        diagnostic.contains("cached image index checksum mismatch"),
        "{diagnostic}"
    );
    Ok(())
}

/// The build-time command decodes the complete boot topology before any Qubes work is attempted.
#[test]
fn prepared_topology_uses_runtime_validation() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("topology.json");
    let object = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-prepared";
    let mut topology = json!({
        "schema":"airlock.qubes-topology.v1", "domains":{"sys-gui":{
            "class":"StandaloneVM", "backend":{
                "type":"nix-closure", "system":{"source":object},
                "root":{"source":format!("{object}/root.img")}, "kernel":{"name":"test"},
                "store":{"source":format!("{object}/sys-gui"), "mode":"shared-closure",
                    "mountpoint":"/nix/store", "device":"/dev/xvde",
                    "blobDevice":"/dev/xvdf", "viewBackend":"erofs-objectmap"},
            },
        }},
    });
    let check = |topology: &Value| -> Result<airlock_vm_service::support::Output> {
        fs::write(&path, serde_json::to_vec(topology)?)?;
        common::run(
            Command::new(common::binary("AIRLOCK_DOM0_BIN", "airlock-dom0-service"))
                .args(["storage", "image", "verify-topology"])
                .arg(&path),
            None,
        )
    };
    let result: Value = serde_json::from_slice(&check(&topology)?.checked()?)?;
    assert_eq!(result["domains"], 1);

    topology["domains"]["sys-gui"]["backend"]["store"]["source"] =
        json!(format!("{object}/../sys-gui"));
    assert!(!check(&topology)?.status.success());
    topology["domains"]["sys-gui"]["backend"]["store"]["source"] = json!(object);
    topology["schema"] = json!("airlock.qubes-topology.v999");
    assert!(!check(&topology)?.status.success());
    topology["schema"] = json!("airlock.qubes-topology.v1");
    topology["domains"]["sys-gui"]["backend"]["kernel"]["name"] = json!("../invalid");
    assert!(!check(&topology)?.status.success());
    Ok(())
}

/// Rebuilding deterministic outputs can reuse either cache half despite changed source timestamps.
#[test]
fn prepared_image_outputs_are_independently_reusable() -> Result<()> {
    let seed = Seed::create(true)?;
    let indexes = seed.store.temporary.path().join("indexes.jsonl");
    let builds = || -> Result<usize> {
        Ok(fs::read_to_string(&indexes)?
            .lines()
            .map(serde_json::from_str::<Vec<String>>)
            .collect::<std::result::Result<Vec<_>, _>>()?
            .iter()
            .filter(|args| args.iter().any(|arg| arg == "--tar=i"))
            .count())
    };
    // Two distinct guest closures and one shared builder layout require three indexes, not four.
    assert_eq!(builds()?, 3);
    let builder = |role| -> Result<Value> {
        let path = seed.store.pool.join(format!(
            "domains/{role}-build-store/generations/1/manifest.json"
        ));
        Ok(serde_json::from_slice(&fs::read(path)?)?)
    };
    let control = builder("sys-ctrl")?;
    let assistant = builder("usr-assistant")?;
    assert_ne!(control["builder"]["domain"], assistant["builder"]["domain"]);
    assert_ne!(
        control["builder"]["metadata_image"],
        assistant["builder"]["metadata_image"]
    );
    assert_ne!(
        control["store"]["closure_hash"],
        assistant["store"]["closure_hash"]
    );
    assert_eq!(
        control["store"]["integrity"]["layout_sha256"],
        assistant["store"]["integrity"]["layout_sha256"]
    );
    assert_eq!(
        control["store"]["integrity"]["metadata_sha256"],
        assistant["store"]["integrity"]["metadata_sha256"]
    );
    let old_pool = seed.store.temporary.path().join("cached-pool");
    let old_descriptors = seed.store.temporary.path().join("cached-descriptors");
    fs::rename(&seed.store.pool, &old_pool)?;
    fs::rename(&seed.descriptors, &old_descriptors)?;
    let original = snapshot(&seed.store.physical)?;
    for path in original.keys() {
        File::options()
            .write(true)
            .open(seed.store.physical.join(path))?
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(3))?;
    }
    seed.prepare(&seed.store.pool, &seed.descriptors)?;
    // A separate preparation command must construct and validate its own indexes.
    assert_eq!(builds()?, 6);
    let content = |root: &Path| -> Result<BTreeMap<PathBuf, Vec<u8>>> {
        Ok(snapshot(root)?
            .into_iter()
            .map(|(path, (bytes, _))| (path, bytes))
            .collect())
    };
    assert_eq!(content(&old_pool)?, content(&seed.store.pool)?);
    assert_eq!(content(&old_descriptors)?, content(&seed.descriptors)?);
    fs::write(
        old_descriptors.join("cached-validation.json"),
        "{\"status\":\"passed\"}",
    )?;
    for (pool, descriptors) in [
        (&seed.store.pool, &old_descriptors),
        (&old_pool, &seed.descriptors),
    ] {
        let result = common::json(
            seed.store
                .command(&["image", "verify-outputs"])
                .arg(pool)
                .arg(descriptors),
            None,
        )?;
        assert_eq!(result["status"], "passed");
    }
    Ok(())
}

/// Real shared indexes serve the complete packages while each builder retains its own injected identity.
#[test]
#[ignore = "requires explicitly prepared AIRLOCK_EROFS_MKFS and fsck.erofs"]
fn packaged_image_indexes_preserve_both_builder_identities() -> Result<()> {
    let seed = Seed::create(true)?;
    let root = seed.store.temporary.path();
    let pool = root.join("real-pool");
    let descriptors = root.join("real-descriptors");
    let mkfs = std::env::var_os("AIRLOCK_EROFS_MKFS").expect("prepare EROFS explicitly");
    let cache = seed.cache(Some(&mkfs))?;
    let output = common::run(
        seed.prepare_command(&pool, &descriptors)?
            .arg("--cache")
            .arg(cache)
            .env("AIRLOCK_MKFS_EROFS", mkfs),
        None,
    )?;
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Reusing verified shared EROFS index")
    );
    output.checked()?;
    fs::rename(&pool, &seed.installed)?;

    for role in ["sys-ctrl", "usr-assistant"] {
        let manifest: Value = serde_json::from_slice(&fs::read(seed.installed.join(format!(
            "domains/{role}-build-store/generations/1/manifest.json"
        )))?)?;
        let receipt = json!({"canonical_metadata_image":manifest["builder"]["metadata_image"],"canonical_blob_map":manifest["store"]["canonical_blob_map"]});
        let extracted = crate::storage_integrity::extract(&seed.store, &receipt)?;
        let identity: Value =
            serde_json::from_slice(&fs::read(extracted.join(".airlock-builder/identity.json"))?)?;
        assert_eq!(identity["domain"], format!("{role}-build-store"));
        for spec in seed.specs.as_array().unwrap().iter().take(2) {
            let name = Path::new(spec["system"].as_str().unwrap())
                .file_name()
                .unwrap();
            assert_eq!(
                fs::read(extracted.join(name).join("payload"))?,
                fs::read(seed.store.physical.join(name).join("payload"))?
            );
        }
        fs::remove_dir_all(extracted)?;
    }
    Ok(())
}

/// Both sealed variants adopt without original packages, repacking or mutating stored blobs.
#[test]
fn prepared_image_adoption_needs_no_source_or_repacking() -> Result<()> {
    let seed = Seed::new()?;
    seed.install()?;
    let before: BTreeMap<_, _> = snapshot(&seed.installed)?
        .into_iter()
        .filter(|(path, _)| {
            path.extension()
                .is_some_and(|extension| extension == "blob")
        })
        .collect();
    for index in 0..2 {
        let result: Value = serde_json::from_slice(&seed.verify(&seed.request(index))?.checked()?)?;
        assert_eq!(result, json!(index + 1));
        let mut pinned = seed.request(index);
        pinned["generation"] = json!(index + 1);
        assert!(seed.verify(&pinned)?.status.success());
        pinned["generation"] = json!(2 - index);
        assert!(!seed.verify(&pinned)?.status.success());
        pinned["generation"] = json!(0);
        assert!(!seed.verify(&pinned)?.status.success());
    }
    assert_eq!(
        fs::read_dir(seed.installed.join("objects/metadata"))?.count(),
        3
    );
    let after: BTreeMap<_, _> = snapshot(&seed.installed)?
        .into_iter()
        .filter(|(path, _)| {
            path.extension()
                .is_some_and(|extension| extension == "blob")
        })
        .collect();
    assert_eq!(before, after);
    Ok(())
}

/// Boot-adoption checks metadata and identity, while complete validation additionally authenticates trusted image payload bytes.
#[test]
fn prepared_image_rejects_corruption_at_the_correct_boundary() -> Result<()> {
    for damage in [
        "truncated",
        "metadata",
        "missing",
        "identity",
        "escape",
        "manifest",
        "payload",
    ] {
        let seed = Seed::new()?;
        seed.install()?;
        let mut request = seed.request(0);
        let files = snapshot(&seed.installed)?;
        let blob = seed.installed.join(
            files
                .keys()
                .find(|path| {
                    path.extension()
                        .is_some_and(|extension| extension == "blob")
                })
                .unwrap(),
        );
        match damage {
            "truncated" | "payload" => {
                fs::set_permissions(&blob, fs::Permissions::from_mode(0o600))?;
                let mut bytes = fs::read(&blob)?;
                if damage == "truncated" {
                    bytes.pop();
                } else {
                    bytes[0] ^= 1;
                }
                fs::write(blob, bytes)?;
            }
            "metadata" => {
                let descriptor: Value = serde_json::from_slice(&fs::read(
                    seed.descriptors.join("variant-0/prepared.json"),
                )?)?;
                let relative = descriptor["files"]
                    .as_object()
                    .unwrap()
                    .keys()
                    .find(|path| path.ends_with("store.blob-map.json"))
                    .unwrap();
                fs::write(seed.installed.join(relative), "{}")?;
            }
            "missing" => fs::remove_file(blob)?,
            "identity" => {
                request["system"] = json!("/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-wrong")
            }
            "escape" => {
                let path = seed.descriptors.join("variant-0/prepared.json");
                let mut descriptor: Value = serde_json::from_slice(&fs::read(&path)?)?;
                descriptor["files"]["../outside"] = json!({"size": 0, "sha256": ""});
                fs::write(path, serde_json::to_vec(&descriptor)?)?;
            }
            _ => {
                let path = seed
                    .installed
                    .join("domains/sys-gui-runtime-store/generations/1/manifest.json");
                let mut manifest: Value = serde_json::from_slice(&fs::read(&path)?)?;
                manifest["transaction"] = json!("different-build-transaction");
                fs::write(path, serde_json::to_vec(&manifest)?)?;
            }
        }
        if damage == "payload" {
            assert!(seed.verify(&request)?.status.success());
            assert!(!seed.outputs()?.status.success());
        } else {
            assert!(!seed.verify(&request)?.status.success(), "{damage}");
        }
    }
    let store = Store::new()?;
    let result = common::json(
        &mut store.command(&["image", "verify-prepared", "--request", "-"]),
        Some(serde_json::to_vec(
            &json!({"artifact": store.temporary.path()}),
        )?),
    )?;
    assert!(result.is_null());
    Ok(())
}

/// Failed host preparation reopens only copied lock files and never changes the immutable seed.
#[test]
fn failed_host_image_preparation_keeps_input_immutable() -> Result<()> {
    let store = Store::new()?;
    let root = store.temporary.path();
    let seed = root.join("seed");
    let pool = seed.join("pool");
    fs::create_dir_all(pool.join("objects"))?;
    let names = [
        "admission.lock",
        "objects/segments.lock",
        "objects/sealed.blob",
        "index.erofs",
    ];
    for name in names {
        fs::write(pool.join(name), "seed")?;
        fs::set_permissions(pool.join(name), fs::Permissions::from_mode(0o444))?;
    }
    fs::set_permissions(pool.join("objects"), fs::Permissions::from_mode(0o555))?;
    fs::set_permissions(&pool, fs::Permissions::from_mode(0o555))?;
    fs::write(root.join("registration"), "invalid registration")?;
    fs::write(root.join("choices.json"), "{}")?;
    let output = root.join("output");
    let result = common::run(
        store
            .command(&["image", "prepare-host"])
            .arg(seed)
            .arg(&output)
            .arg(root.join("registration"))
            .arg(&store.system)
            .arg(root.join("choices.json")),
        None,
    )?;
    assert!(!result.status.success());
    for name in names {
        let path = output.join("pool").join(name);
        let lock = name.ends_with(".lock");
        assert_eq!(
            path.metadata()?.permissions().mode() & 0o777,
            if lock { 0o600 } else { 0o444 }
        );
        if lock {
            rustix::fs::flock(
                &File::options().read(true).write(true).open(path)?,
                rustix::fs::FlockOperation::NonBlockingLockExclusive,
            )?;
        } else {
            assert_eq!(fs::read(path)?, b"seed");
        }
        assert_eq!(
            pool.join(name).metadata()?.permissions().mode() & 0o777,
            0o444
        );
    }
    Ok(())
}

/// Removing the bootstrap store keeps only an independent, verified recovery closure and refuses unpublished or misbound entries.
#[test]
fn bootstrap_store_removal_preserves_only_verified_recovery() -> Result<()> {
    for damage in ["", "unpublished", "wrong-system"] {
        let store = Store::new()?;
        let root = store.temporary.path().join("image");
        let host = "/nix/store/00000000000000000000000000000000-host";
        let recovery = "/nix/store/11111111111111111111111111111111-recovery";
        for logical in [host, recovery] {
            let path = root.join(logical.trim_start_matches('/'));
            fs::create_dir_all(&path)?;
            fs::write(path.join("payload"), logical)?;
        }
        let pool = root.join("var/lib/airlock/closure-store");
        fs::create_dir_all(pool.join("host/boots"))?;
        fs::write(
            pool.join("generation.json"),
            serde_json::to_vec(&json!({"store": {"paths": [host, recovery]}}))?,
        )?;
        fs::write(
            pool.join("host/boots/host.json"),
            serde_json::to_vec(
                &json!({"manifest": "/var/lib/airlock/closure-store/generation.json", "system": host, "generation": 1}),
            )?,
        )?;
        let marker = root
            .join(recovery.trim_start_matches('/'))
            .join("etc/airlock");
        fs::create_dir_all(&marker)?;
        fs::write(marker.join("boot-role"), "recovery\n")?;
        fs::create_dir_all(root.join("boot/loader/entries"))?;
        fs::create_dir_all(root.join("boot/EFI/nixos"))?;
        fs::write(
            root.join("boot/loader/entries/xen-0123456789abcdef.conf"),
            "title Airlock (recovery)\nefi /EFI/nixos/xen-0123456789abcdef.efi\n",
        )?;
        let system = if damage == "wrong-system" {
            host
        } else {
            recovery
        };
        fs::write(
            root.join("boot/EFI/nixos/xen-0123456789abcdef.efi"),
            pe(&format!(
                "kernel=kernel init={system}/init\nramdisk=initrd\n"
            )),
        )?;
        for name in ["kernel", "initrd"] {
            fs::write(root.join("boot/EFI/nixos").join(name), "boot artifact")?;
        }
        if damage == "unpublished" {
            fs::create_dir(root.join("nix/store/unpublished"))?;
        }
        let paths = root.join("recovery-paths");
        fs::write(&paths, format!("{recovery}\n"))?;
        let result = common::run(
            store
                .command(&["image", "install-host"])
                .arg(&root)
                .arg(paths)
                .arg(recovery),
            None,
        )?;
        if damage.is_empty() {
            result.checked()?;
            assert_eq!(fs::read_dir(root.join("nix/store"))?.count(), 0);
            let retained = root.join("var/lib/airlock/recovery-store");
            assert_eq!(fs::read_dir(&retained)?.count(), 1);
            assert!(
                retained
                    .join(Path::new(recovery).file_name().unwrap())
                    .is_dir()
            );
        } else {
            assert!(!result.status.success());
            assert!(root.join(host.trim_start_matches('/')).exists());
            assert!(root.join(recovery.trim_start_matches('/')).exists());
        }
    }
    Ok(())
}

/// Execute the actual image-validation hook prefix against a valid pool, then corrupt metadata despite a cached success receipt.
pub(super) fn validation_hook(pre_vm: &str, check: &str) -> Result<()> {
    let seed = Seed::new()?;
    seed.install()?;
    let (prefix, remainder) = pre_vm
        .split_once(check)
        .ok_or_else(|| anyhow::anyhow!("image validation command missing from build hook"))?;
    assert!(!remainder.trim().is_empty());
    let quote = airlock_tests::process::quote;
    let checker = format!(
        "{service} storage image verify-outputs {pool} {descriptors}",
        service = quote(seed.store.service.to_str().unwrap()),
        pool = quote(seed.installed.to_str().unwrap()),
        descriptors = quote(seed.descriptors.to_str().unwrap())
    );
    let script = format!("{prefix}{checker}\necho ASSEMBLY_REACHED\n");
    let execute = || -> Result<airlock_vm_service::support::Output> {
        common::run(
            std::process::Command::new("bash").args(["-e", "-c", &script]),
            None,
        )
    };
    let success = execute()?.checked()?;
    assert!(String::from_utf8_lossy(&success).contains("ASSEMBLY_REACHED"));
    fs::write(
        seed.descriptors.join("cached-validation.json"),
        "{\"status\":\"passed\"}",
    )?;
    let metadata = fs::read_dir(seed.installed.join("objects/blob-metadata"))?
        .next()
        .unwrap()?
        .path();
    fs::write(metadata, "{}")?;
    let failed = execute()?;
    assert!(!failed.status.success());
    assert!(!String::from_utf8_lossy(&failed.stdout).contains("ASSEMBLY_REACHED"));
    Ok(())
}

/// A prepared upstream-Qubes Python runtime package is exercised as a real offline API boundary, with Rust owning image assertions.
#[test]
#[ignore = "explicitly prepare AIRLOCK_PREPARE_RUNTIME_PACKAGE with upstream Qubes and ext4 tools"]
fn external_tool_packaged_runtime_uses_upstream_qubes_offline_api() -> Result<()> {
    use std::{
        io::{Seek, SeekFrom, Write},
        os::unix::fs::MetadataExt,
        process::Command,
    };
    let executable = std::env::var_os("AIRLOCK_PREPARE_RUNTIME_PACKAGE").ok_or_else(|| {
        anyhow::anyhow!("set AIRLOCK_PREPARE_RUNTIME_PACKAGE to the prepared runtime wrapper")
    })?;
    for (role, label, color) in [
        ("sys-gui", "red", None),
        ("sys-gui", "khaki", Some("0x6b7a3d")),
        ("sys-ctrl", "light-gray", Some("0xd3d3d3")),
    ] {
        let seed = Seed::new()?;
        let root = seed.store.temporary.path();
        let image = root.join("runtime-root.img");
        let mut file = File::create(&image)?;
        file.set_len(16 * 1024 * 1024)?;
        file.seek(SeekFrom::Start(0))?;
        file.flush()?;
        common::run(
            Command::new(common::tool("mkfs.ext4")?)
                .args(["-q", "-F"])
                .arg(&image),
            None,
        )?
        .checked()?;
        let mut spec = seed.specs[0].clone();
        spec["domain"] = json!(format!("{role}-runtime-store"));
        spec["root_source"] = json!(image);
        let mut selected = vec![spec.clone()];
        if role == "sys-ctrl" {
            let closure = PathBuf::from(spec["closure_source"].as_str().unwrap());
            let registration = fs::read_to_string(closure.join("store-paths"))?
                .lines()
                .map(|path| format!("{path}\n{hash}\n42\n\n0\n", hash = "0".repeat(64)))
                .collect::<String>();
            fs::write(closure.join("registration"), registration)?;
            let mut builder = spec.clone();
            for (key, value) in [
                ("name", json!("builder")),
                ("domain", json!("sys-ctrl-build-store")),
                ("root_source", json!("")),
                ("kernel_name", json!("")),
                ("builder", json!(true)),
            ] {
                builder[key] = value;
            }
            selected.push(builder);
        }
        let specs = root.join("runtime-specs.json");
        fs::write(&specs, serde_json::to_vec(&selected)?)?;
        let pool = root.join("runtime-pool");
        let descriptors = root.join("runtime-descriptors");
        common::run(
            seed.store
                .command(&["image", "prepare-pool"])
                .arg(&pool)
                .arg(&descriptors)
                .arg(specs)
                .arg("/var/lib/airlock/closure-store"),
            None,
        )?
        .checked()?;
        let kernel = root.join("kernel");
        fs::create_dir(&kernel)?;
        for name in ["vmlinuz", "modules.img"] {
            fs::write(kernel.join(name), "fixture")?;
        }
        let mut domain = json!({"class": "StandaloneVM", "label": label, "netvm": null,
            "prefs": {"autostart": false, "guivm": null, "virt_mode": "hvm"}, "features": {"qrexec": true},
            "services": {"test-service": false}, "devices": {"pci": [{"backend": "dom0", "id": "00_08.1"}]},
            "backend": {"type": "nix-closure", "system": {"source": spec["system"]}, "root": {"source": image}, "kernel": {"name": "test-kernel"},
                "state": {"persistent_size": 32 * 1024 * 1024}, "store": {"source": descriptors.join(spec["name"].as_str().unwrap())}}});
        if let Some(color) = color {
            domain["features"]["airlock-label-color"] = json!(color);
        }
        let topology = json!({"kernels": {"test-kernel": {"source": kernel}}, "prefs": {"default_netvm": null}, "domains": {(role): domain}});
        let config = root.join("topology.json");
        fs::write(&config, serde_json::to_vec(&topology)?)?;
        let output = root.join("runtime");
        common::run(
            Command::new(&executable)
                .arg(&config)
                .arg(&pool)
                .arg(&output),
            None,
        )?
        .checked()?;
        let xml = fs::read_to_string(output.join("qubes/qubes.xml"))?;
        // Input filenames also start with "runtime"; only the staging Qubes root must disappear.
        assert!(!xml.contains(output.join("qubes").to_str().unwrap()));
        assert!(xml.contains("/var/lib/qubes"));
        assert!(xml.contains("airlock-root-source") && xml.contains(image.to_str().unwrap()));
        assert!(xml.contains("airlock-closure") && xml.contains("erofs-blob-map"));
        if let Some(color) = color {
            assert!(xml.contains(color));
        }
        if role == "sys-ctrl" {
            assert!(xml.contains("builder-store") && xml.contains("builder-data"));
        }
        // The runtime adapter must leave physical PCI assignment for boot-time authority.
        let mut reader = quick_xml::Reader::from_str(&xml);
        loop {
            match reader.read_event()? {
                quick_xml::events::Event::Start(element)
                | quick_xml::events::Event::Empty(element) => {
                    assert_ne!(element.name().as_ref(), b"device")
                }
                quick_xml::events::Event::Eof => break,
                _ => {}
            }
        }
        let installed = output.join(format!("qubes/appvms/{role}/root.img"));
        assert_eq!(fs::read(&installed)?, fs::read(&image)?);
        assert!(installed.metadata()?.blocks() * 512 < installed.metadata()?.len());
        assert_eq!(
            output
                .join(format!("qubes/appvms/{role}/private.img"))
                .metadata()?
                .len(),
            32 * 1024 * 1024
        );
        assert_eq!(
            fs::read_link(output.join(format!(
                "pool-selections/domains/{role}-runtime-store/current"
            )))?,
            Path::new("generations/1")
        );
        let again = common::run(
            Command::new(&executable).arg(config).arg(pool).arg(output),
            None,
        )?;
        assert!(!again.status.success());
        assert!(String::from_utf8_lossy(&again.stderr).contains("must not already exist"));
    }
    Ok(())
}
