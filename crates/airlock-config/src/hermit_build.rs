//! Build immutable Hermit executables through the pinned external Xen integration.
//! Linux images and the shared Nix store are deliberately absent from this recipe.

use airlock_build::Workspace;
use rusix::{
    interop::{NixExpression, raw::NixValue},
    nix_record, nix_text,
};

/// Portable integration pin; development overrides must select this exact local commit.
pub(crate) const INTEGRATION_REVISION: &str = "03bd87fad25d094f0a19c9ef936994683bc2e7e1";

/// Portable flake input; local development overrides must retain the pinned Git identity.
pub(crate) fn input() -> NixValue {
    nix_record! {
        "type": "git", "url": "https://github.com/airlockos-org/hermit-xen",
        "rev": INTEGRATION_REVISION, "submodules": true,
    }
}

/// Project the application workspace into the external builder's locked dependency set.
fn source(pkgs: &NixValue, workspace: &Workspace, integration: &NixValue) -> NixValue {
    // Converting input text to a path does not retain Nix string context. Capture each
    // crate explicitly so the sandbox and release closure retain its immutable source.
    let crate_source = |relative, name| {
        NixValue::builtin("path").call(nix_record! {
            "path": workspace.root().join_relative(relative).unwrap(),
            "name": name,
        })
    };
    let read = |relative| {
        NixValue::builtin("readFile").call(workspace.root().join_relative(relative).unwrap())
    };
    let manifest =
        NixValue::builtin("fromTOML").call(read("runtime/airlock-sys-clipboard/Cargo.toml"));
    let dependency = |old: NixValue| {
        let matches = old.clone().select("rev").equals(INTEGRATION_REVISION).and(
            old.clone()
                .select("git")
                .equals("https://github.com/airlockos-org/hermit-xen"),
        );
        let patched = NixValue::builtin("removeAttrs")
            .call(old)
            .call(NixValue::list(["git".into(), "rev".into()]))
            .merge_attrs(nix_record! { "path": "../../../.hermit-xen/crates/xen-transport" });
        NixValue::if_else(
            matches,
            patched,
            NixValue::builtin("throw")
                .call("Hermit transport manifest does not match the integration pin"),
        )
    };
    let target_name = "cfg(target_os = \"hermit\")";
    let target = manifest.clone().select("target").select(target_name);
    let patched = manifest.clone().merge_attrs(nix_record! {
        "dependencies": manifest.clone().select("dependencies").merge_attrs(nix_record! {
            "xen-transport": dependency(manifest.clone().select("dependencies.xen-transport")),
        }),
        "target": manifest.clone().select("target").merge_attrs(NixValue::record([(target_name,
            target.clone().merge_attrs(nix_record! {
                "dependencies": target.clone().select("dependencies").merge_attrs(nix_record! {
                    "xen-transport": dependency(target.select("dependencies.xen-transport")),
                }),
            })
        )])),
    });
    let manifest = pkgs
        .clone()
        .select("formats.toml")
        .call(nix_record! {})
        .select("generate")
        .call("clipboard-Cargo.toml")
        .call(patched);
    pkgs.clone().select("runCommand").call("airlock-hermit-application-source").call(nix_record! {}).call(nix_text!(r#"
        mkdir -p "$out/crates/airlock-common/clipboard" "$out/crates/runtime/airlock-sys-clipboard" "$out/.hermit-xen/crates"
        cp -r {core}/src {core}/Cargo.toml "$out/crates/airlock-common/clipboard/"
        cp -r {service}/src "$out/crates/runtime/airlock-sys-clipboard/"
        cp {manifest} "$out/crates/runtime/airlock-sys-clipboard/Cargo.toml"
        cp -r {integration}/crates/xen-transport "$out/.hermit-xen/crates/"
        cp {service}/lab.lock "$out/Cargo.lock"
        cat > "$out/Cargo.toml" <<'TOML'
        [workspace]
        resolver = "3"
        members = ["crates/airlock-common/clipboard", "crates/runtime/airlock-sys-clipboard"]
        exclude = [".hermit-xen/crates/xen-transport"]

        [profile.release]
        debug = 2
        strip = false
        TOML
    "#, core = crate_source("airlock-common/clipboard", "airlock-clipboard-core"),
        service = crate_source("runtime/airlock-sys-clipboard", "airlock-sys-clipboard"),
        manifest = manifest, integration = integration.clone()))
}

/// Export a service factory with an immutable image and no implicit Linux capabilities.
pub(crate) fn constructor(
    pkgs: &NixValue,
    workspace: &Workspace,
    integration: NixValue,
    revision: NixValue,
) -> NixValue {
    NixValue::function_attrs(
        ["name", "memory", "vcpus", "autostart", "clipboardAuthority"],
        |request| {
            let image = integration
                .clone()
                .select("lib.x86_64-linux.buildHermitApplication")
                .call(nix_record! {
                    "src": source(pkgs, workspace, &integration),
                    "bin": "sys-clipboard",
                    "pname": "airlock-sys-clipboard",
                })
                .select("overrideAttrs")
                .call(NixValue::function(|_| {
                    nix_record! {
                        "AIRLOCK_SOURCE_REVISION": revision.clone(),
                    }
                }));
            let authority = NixValue::if_else(
                request
                    .clone()
                    .select("clipboardAuthority")
                    .equals(NixValue::null()),
                "disconnected",
                "normal",
            );
            let image = image.bind(|image| {
            pkgs.clone().select("runCommand").call("airlock-hermit-clipboard").call(nix_record! {
                // Build paths in DWARF and panic strings must not import a compiler into dom0.
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
                  --arg revision {revision} --arg integration {integration_revision} --arg lock {lock} --arg authority {authority} \
                  '{{schema:"airlock.hermit-pvh.v1",executable:$executable,sha256:$digest,bytes:$bytes,
                    source_revision:$revision,integration_revision:$integration,build_lock:$lock,authority:$authority}}' > "$out/artifact.json"
            "#, image = image, jq = pkgs.clone().select("jq"),
                binutils = pkgs.clone().select("binutils"),
                nuke_references = pkgs.clone().select("nukeReferences"),
                revision = pkgs.clone().select("lib.escapeShellArg").call(revision.clone()),
                integration_revision = INTEGRATION_REVISION,
                authority = authority,
                lock = NixValue::builtin("hashFile").call("sha256").call(nix_text!("{integration}/flake.lock", integration = integration.clone()))))
        });
            let output = image.bind(|image| {
            // Nix JSON decoding requires context-free text; restore the executable's
            // dependency context explicitly so serialization retains the image closure.
            let artifact = NixValue::builtin("fromJSON").call(NixValue::builtin("unsafeDiscardStringContext").call(
                NixValue::builtin("readFile").call(nix_text!("{image}/artifact.json", image = image.clone()))))
                .merge_attrs(nix_record! { "executable": nix_text!("{image}/kernel.elf", image = image.clone()) });
            nix_record! {
                "backendType": "hermit",
                "executable": image.clone(),
                "domain": nix_record! {
                    "class": "HermitVM", "label": "black", "netvm": NixValue::null(), "template": NixValue::null(),
                    "prefs": nix_record! {
                        "memory": request.clone().select("memory"), "maxmem": request.clone().select("memory"),
                        "vcpus": request.clone().select("vcpus"), "virt_mode": "pvh", "kernel": "",
                        "guivm": NixValue::null(), "audiovm": NixValue::null(),
                        "autostart": request.clone().select("autostart"), "include_in_backups": false,
                    },
                    "features": nix_record! { "airlock-managed": "1", "airlock-backend": "hermit", "airlock-role": "service", "qrexec": "", "gui": "" }.merge_attrs(NixValue::if_else(request.clone().select("clipboardAuthority").equals(NixValue::null()), nix_record! {}, nix_record! { "airlock-clipboard-authority": request.clone().select("clipboardAuthority") })),
                    "services": nix_record! {}, "devices": nix_record! {},
                    "backend": nix_record! {
                        "type": "hermit", "system": nix_record! { "source": image.to_text() }, "artifact": artifact,
                    },
                },
            }
        });
            let pinned = integration
                .clone()
                .attr_or("rev", "")
                .equals(INTEGRATION_REVISION)
                .and(NixValue::builtin("isString").call(revision.clone()));
            (
                vec![
                    ("autostart", false.into()),
                    ("clipboardAuthority", NixValue::null()),
                ],
                NixValue::if_else(
                    pinned,
                    output,
                    NixValue::builtin("throw").call(
                        "Hermit requires the pinned Git integration and an application revision",
                    ),
                ),
            )
        },
    )
}
