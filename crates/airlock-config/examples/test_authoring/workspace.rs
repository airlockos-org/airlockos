//! Inspect filtered application sources and real package identities without realizing build outputs.

use super::*;

/// Materialize feature-specific source sets and representative production derivations in an evaluation store.
pub(super) fn sources(inputs: NixValue, settings: &serde_json::Value) -> Result<NixValue, String> {
    let workspace = airlock_build::Workspace::new(NixPath::from_source_text(
        inputs
            .clone()
            .select("workspace")
            .to_text()
            .into_expr::<String>(),
    ));
    let pkgs = NixValue::builtin("import")
        .call(inputs.select("nixpkgs"))
        .call(rusix::nix_record! { "system": "x86_64-linux" });
    let mut sources = Vec::new();
    for case in settings["cases"]
        .as_array()
        .ok_or("expected source cases")?
    {
        let name = case["name"].as_str().ok_or("expected package name")?;
        let label = case["label"].as_str().ok_or("expected source label")?;
        let features: Vec<_> = case["features"]
            .as_array()
            .ok_or("expected features")?
            .iter()
            .map(|value| value.as_str().ok_or("expected feature name"))
            .collect::<Result<_, _>>()?;
        let defaults = case["defaults"]
            .as_bool()
            .ok_or("expected default feature flag")?;
        sources.push((
            label.to_owned(),
            workspace
                .source_with_features(&pkgs.clone().select("lib"), name, defaults, &features)
                .to_text(),
        ));
    }
    let packages = [
        ("init", airlock_build::Application::VmInit),
        ("cli", airlock_build::Application::Cli),
        ("gui", airlock_build::Application::ControllerGui),
        ("packer", airlock_build::Application::StorePacker),
    ]
    .map(|(name, application)| {
        (
            name,
            application
                .build(&pkgs, &workspace)
                .as_expression()
                .select("drvPath"),
        )
    });

    Ok(rusix::nix_record! {
        "sources": NixValue::record(sources),
        "derivations": NixValue::record(packages),
    })
}
