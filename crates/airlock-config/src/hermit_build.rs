//! Build reviewed Hermit applications with one source, lock and artifact pipeline.
//! Application selection changes capabilities explicitly; it cannot enable Linux services.

use airlock_build::Workspace;
use rusix::{
    interop::{NixExpression, raw::NixValue},
    nix_record, nix_text,
};

/// Reviewed integration including native networking, secure entropy and Linux checksum support.
pub(crate) const INTEGRATION_REVISION: &str = "09d90ea081c7a98d406820733758d19efa3e7f6d";

/// Portable integration identity; local overrides must preserve its exact Git revision.
pub(crate) fn input() -> NixValue {
    nix_record! { "type": "git", "url": "https://github.com/airlockos-org/hermit-xen", "rev": INTEGRATION_REVISION, "submodules": true }
}

/// Replace only the reviewed transport dependency with the captured integration source.
fn dependencies(table: NixValue) -> NixValue {
    let old = table.clone().attr_or("xen-transport", NixValue::null());
    let pinned = old.clone().select("rev").equals(INTEGRATION_REVISION).and(
        old.clone()
            .select("git")
            .equals("https://github.com/airlockos-org/hermit-xen"),
    );
    let replacement = NixValue::builtin("removeAttrs")
        .call(old)
        .call(NixValue::list(["git".into(), "rev".into()]))
        .merge_attrs(nix_record! { "path": "../../../.hermit-xen/crates/xen-transport" });
    NixValue::if_else(
        NixValue::builtin("hasAttr")
            .call("xen-transport")
            .call(table.clone()),
        NixValue::if_else(
            pinned,
            table
                .clone()
                .merge_attrs(nix_record! { "xen-transport": replacement }),
            NixValue::builtin("throw")
                .call("Hermit transport manifest differs from the reviewed integration pin"),
        ),
        table,
    )
}

/// Capture production crates and project only the selected application workspace.
/// Cargo and TOML implementations own encoding and dependency resolution.
fn source(
    pkgs: &NixValue,
    workspace: &Workspace,
    integration: &NixValue,
    package: &str,
    members: &[&str],
) -> NixValue {
    let mut copies = Vec::new();
    for member in members {
        let original = NixValue::builtin("path")
            .call(nix_record! { "path": workspace.file(member), "name": member.replace('/', "-") });
        let manifest = NixValue::builtin("fromTOML").call(NixValue::builtin("readFile").call(
            nix_text!("{original}/Cargo.toml", original = original.clone()),
        ));
        let target_name = "cfg(target_os = \"hermit\")";
        let targets = manifest.clone().attr_or("target", nix_record! {});
        let target = targets.clone().attr_or(target_name, nix_record! {});
        let patched = manifest.clone().merge_attrs(nix_record! {
            "dependencies": dependencies(manifest.clone().attr_or("dependencies", nix_record! {})),
            "target": NixValue::if_else(NixValue::builtin("hasAttr").call(target_name).call(targets.clone()),
                targets.clone().merge_attrs(NixValue::record([(target_name, target.clone().merge_attrs(nix_record! {
                    "dependencies": dependencies(target.attr_or("dependencies", nix_record! {})),
                }))])), targets),
        });
        let manifest = pkgs
            .clone()
            .select("formats.toml")
            .call(nix_record! {})
            .select("generate")
            .call("Hermit-Cargo.toml")
            .call(patched);
        copies.push(nix_text!(
            r#"
            mkdir -p "$out/crates/{member}"
            cp -r {original}/src "$out/crates/{member}/"
            cp {manifest} "$out/crates/{member}/Cargo.toml"
        "#,
            member = *member,
            original = original,
            manifest = manifest
        ));
    }
    let root = pkgs.clone().select("formats.toml").call(nix_record! {}).select("generate").call("Hermit-workspace.toml").call(nix_record! {
        "workspace": nix_record! { "resolver": "3", "members": NixValue::list(members.iter().map(|member| format!("crates/{member}").into())), "exclude": NixValue::list([".hermit-xen/crates/xen-transport".into()]) },
        "profile": nix_record! { "release": nix_record! { "debug": 2_i64, "strip": false } },
    });
    let lock = NixValue::builtin("path").call(nix_record! { "path": workspace.file(&format!("runtime/{package}/lab.lock")), "name": format!("{package}-Cargo.lock") });
    pkgs.clone()
        .select("runCommand")
        .call("airlock-hermit-application-source")
        .call(nix_record! {})
        .call(nix_text!(
            r#"
        {copies}
        mkdir -p "$out/.hermit-xen/crates"
        cp -r {integration}/crates/xen-transport "$out/.hermit-xen/crates/"
        cp {root} "$out/Cargo.toml"
        cp {lock} "$out/Cargo.lock"
    "#,
            copies = NixValue::builtin("concatStringsSep")
                .call("\n")
                .call(NixValue::list(copies.into_iter().map(Into::into))),
            integration = integration.clone(),
            root = root,
            lock = lock
        ))
}

/// Build one immutable production executable through the shared external builder.
fn image(
    pkgs: &NixValue,
    workspace: &Workspace,
    integration: &NixValue,
    revision: &NixValue,
    bin: &str,
    members: &[&str],
    vendor_hash: NixValue,
) -> NixValue {
    let package = format!("airlock-{bin}");
    let lock = NixValue::builtin("path").call(nix_record! { "path": workspace.file(&format!("runtime/{package}/build.lock")), "name": format!("{package}-build.lock") });
    integration.clone().select("lib.x86_64-linux.buildHermitApplication").call(nix_record! {
        "src": source(pkgs, workspace, integration, &package, members), "bin": bin, "pname": package.clone(),
        "cargoVendorDir": pkgs.clone().select("rustPlatform.fetchCargoVendor").call(nix_record! {
            "name": format!("{package}-deps"), "hash": vendor_hash,
            "src": pkgs.clone().select("runCommand").call("airlock-hermit-dependency-lock").call(nix_record! {}).call(nix_text!(r#"
                mkdir -p "$out"
                cp {lock} "$out/Cargo.lock"
            "#, lock=lock)),
        }),
    }).select("overrideAttrs").call(NixValue::function(|_| nix_record! { "AIRLOCK_SOURCE_REVISION": revision.clone() }))
}

/// Produce an authenticated descriptor and domain definition for either application.
/// Legacy callers default to clipboard; networking requires an explicit firewall request.
pub(crate) fn constructor(
    pkgs: &NixValue,
    workspace: &Workspace,
    integration: NixValue,
    revision: NixValue,
) -> NixValue {
    NixValue::function_attrs(
        [
            "name",
            "application",
            "upstream",
            "memory",
            "vcpus",
            "autostart",
            "clipboardAuthority",
            "scratchMiB",
        ],
        |request| {
            let application = request.clone().select("application");
            let network = application.clone().equals("firewall");
            let images = NixValue::record(airlock_build::hermit::APPLICATIONS.into_iter().map(
                |source| {
                    (
                        source.profile,
                        image(
                            pkgs,
                            workspace,
                            &integration,
                            &revision,
                            source.binary,
                            source.members,
                            source.vendor_hash.into(),
                        ),
                    )
                },
            ));
            let image = NixValue::builtin("getAttr")
                .call(application.clone())
                .call(images);
            let authority = NixValue::if_else(
                request
                    .clone()
                    .select("clipboardAuthority")
                    .equals(NixValue::null()),
                "disconnected",
                "normal",
            );
            let image = image.bind(|image| pkgs.clone().select("runCommand").call("airlock-hermit-executable").call(nix_record! {
            "allowedReferences": NixValue::list(["out".into()]),
        }).call(nix_text!(r#"
            mkdir -p "$out"
            cp {image}/kernel.elf "$out/kernel.elf"
            chmod u+w "$out/kernel.elf"
            {binutils}/bin/strip --strip-debug "$out/kernel.elf"
            {nuke_references}/bin/nuke-refs "$out/kernel.elf"
            {jq}/bin/jq '.sources_base64 = (.sources | @base64) | del(.sources)' {image}/provenance.json > "$out/provenance.json"
            {jq}/bin/jq '.source_base64 = (.source | @base64) | del(.source)' {image}/application.json > "$out/application.json"
            cp {image}/Cargo.lock "$out/"
            digest=$(sha256sum "$out/kernel.elf" | cut -d' ' -f1)
            bytes=$(stat -c %s "$out/kernel.elf")
            {jq}/bin/jq -n --arg executable "$out/kernel.elf" --arg digest "$digest" --argjson bytes "$bytes" \
              --arg revision {revision} --arg integration {integration_revision} --arg lock {lock} \
              --arg authority {authority} --arg application {application} \
              '{{schema:"airlock.hermit-pvh.v1",executable:$executable,sha256:$digest,bytes:$bytes,
                source_revision:$revision,integration_revision:$integration,build_lock:$lock,
                authority:$authority,application:$application}}' > "$out/artifact.json"
        "#, image=image, binutils=pkgs.clone().select("binutils"), nuke_references=pkgs.clone().select("nukeReferences"), jq=pkgs.clone().select("jq"),
            revision=pkgs.clone().select("lib.escapeShellArg").call(revision.clone()), integration_revision=INTEGRATION_REVISION,
            lock=NixValue::builtin("hashFile").call("sha256").call(nix_text!("{integration}/flake.lock", integration=integration.clone())),
            authority=authority, application=pkgs.clone().select("lib.escapeShellArg").call(application.clone()))));
            let output = image.bind(|image| {
            let artifact = NixValue::builtin("fromJSON").call(NixValue::builtin("unsafeDiscardStringContext").call(NixValue::builtin("readFile").call(nix_text!("{image}/artifact.json", image=image.clone()))))
                .merge_attrs(nix_record! { "executable": nix_text!("{image}/kernel.elf", image=image.clone()) });
            nix_record! {
                "backendType": "hermit", "executable": image.clone(),
                "domain": nix_record! {
                    "class": "HermitVM", "label": NixValue::if_else(network.clone(), "green", "black"),
                    "netvm": request.clone().select("upstream"), "template": NixValue::null(),
                    "prefs": nix_record! {
                        "memory": request.clone().select("memory"), "maxmem": request.clone().select("memory"), "vcpus": request.clone().select("vcpus"),
                        "virt_mode": "pvh", "kernel": "", "provides_network": network.clone(),
                        "guivm": NixValue::null(), "audiovm": NixValue::null(), "autostart": request.clone().select("autostart"), "include_in_backups": false,
                    },
                    "features": nix_record! {
                        "airlock-managed": "1", "airlock-backend": "hermit", "airlock-role": NixValue::if_else(network.clone(), "firewall", "service"), "qrexec": "", "gui": "",
                    }.merge_attrs(NixValue::if_else(request.clone().select("clipboardAuthority").equals(NixValue::null()), nix_record! {}, nix_record! { "airlock-clipboard-authority": request.clone().select("clipboardAuthority") })),
                    "services": nix_record! {}, "devices": nix_record! {},
                    "backend": nix_record! { "type": "hermit", "system": nix_record! { "source": image.to_text() }, "artifact": artifact,
                        "scratch": NixValue::if_else(request.clone().select("scratchMiB").equals(NixValue::null()), NixValue::null(), nix_record! { "bytes": NixValue::builtin("mul").call(request.clone().select("scratchMiB")).call(1024_i64*1024) }),
                    },
                },
            }
        });
            let pinned = integration
                .clone()
                .attr_or("rev", "")
                .equals(INTEGRATION_REVISION)
                .and(NixValue::builtin("isString").call(revision.clone()));
            let capabilities = NixValue::if_else(
                network,
                NixValue::builtin("isString")
                    .call(request.clone().select("upstream"))
                    .and(
                        request
                            .clone()
                            .select("clipboardAuthority")
                            .equals(NixValue::null()),
                    )
                    .and(
                        request
                            .clone()
                            .select("scratchMiB")
                            .equals(NixValue::null()),
                    )
                    .and(request.clone().select("memory").equals(256_i64)),
                request.clone().select("upstream").equals(NixValue::null()),
            );
            (vec![("application", "clipboard".into()), ("upstream", NixValue::null()), ("autostart", false.into()), ("clipboardAuthority", NixValue::null()), ("scratchMiB", NixValue::null())],
            NixValue::if_else(pinned.and(capabilities), output, NixValue::builtin("throw").call("Hermit requires the reviewed integration, source identity and application capabilities")))
        },
    )
}
