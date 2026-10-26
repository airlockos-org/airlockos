//! Evaluate the production Hermit constructor with explicit, pinned development inputs.
//! This fixture emits build artifacts only and cannot authorize a physical deployment.

use super::*;

/// Generate a flake that exposes both the immutable executable and its machine descriptor.
pub(super) fn build(settings: &serde_json::Value) -> Result<NixValue, String> {
    let required = |key: &str| {
        settings[key]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("missing Hermit fixture input: {key}"))
    };
    let directory = required("output")?;
    std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    std::fs::write(
        std::path::Path::new(&directory).join("builders.nix"),
        airlock_config::vm_builders()?.source,
    )
    .map_err(|error| error.to_string())?;
    let integration = required("integration")?;
    let nixpkgs = required("nixpkgs")?;
    let applications = required("applications")?;
    let qubes = required("qubes")?;
    let libvirt = required("libvirt")?;
    let revision = required("revision")?;
    Ok(rusix::nix_record! {
        "inputs": rusix::nix_record! {
            "hermit-xen": rusix::nix_record! { "url": integration },
            "nixpkgs": rusix::nix_record! { "url": nixpkgs },
            "applications": rusix::nix_record! { "url": format!("path:{applications}"), "flake": false },
            "qubes": rusix::nix_record! { "url": format!("path:{qubes}"), "flake": false },
            "libvirt": rusix::nix_record! { "url": format!("path:{libvirt}"), "flake": false },
        },
        "outputs": NixValue::function_attrs(["self", "hermit-xen", "nixpkgs", "applications", "qubes", "libvirt"], |inputs| {
            let builders = NixValue::builtin("import").call(NixPath::from_expression(inputs.clone().select("self")).join_relative("builders.nix").unwrap());
            let entry = builders.select("builders").call(rusix::nix_record! {
                "nixpkgs": inputs.clone().select("nixpkgs"), "hermitXen": inputs.clone().select("hermit-xen"),
                "airlockAppsSource": inputs.clone().select("applications").to_text(), "applicationRevision": revision.clone(),
                "nixosQubesSource": inputs.clone().select("qubes").to_text(), "nixpkgsLibvirt105Source": inputs.clone().select("libvirt").to_text(),
                "airlockSupport": inputs.clone().select("self"),
            }).select("mkHermitDomain").call(rusix::nix_record! { "name": "sys-clipboard", "memory": 32_i64, "vcpus": 1_i64 });
            (Vec::<(&str, NixValue)>::new(), entry.bind(|entry| rusix::nix_record! {
                "packages": rusix::nix_record! { "x86_64-linux": rusix::nix_record! { "default": entry.clone().select("executable") } },
                "airlock": rusix::nix_record! { "domain": entry.select("domain") },
            }))
        }),
    })
}
