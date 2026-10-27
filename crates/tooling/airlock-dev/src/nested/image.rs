//! Stable development image resolution shared by baseline and multi-boot scenarios.

use super::*;

/// Build an immutable image once and publish a stable link for every phase of a test.
pub(super) fn resolve(
    context: &Context,
    attribute: Option<&str>,
    output: Option<&Path>,
) -> Result<PathBuf> {
    let attribute = attribute
        .map(str::to_owned)
        .unwrap_or_else(|| setting("AIRLOCK_VM_IMAGE_ATTR", "airlock-vm-gui-config-dev-image"));
    ensure!(
        !attribute.is_empty() && !attribute.contains('/'),
        "invalid image attribute"
    );
    let environment = environment::Environment::load()?;
    let links = environment.path(
        "AIRLOCK_RESULT_LINK_DIR",
        context.root.join(".airlock/result-links"),
    );
    let output = output.map(Path::to_owned).unwrap_or_else(|| {
        path(
            "AIRLOCK_VM_SHARED_IMAGE_LINK",
            links.join(format!("{attribute}-result")),
        )
    });
    let output_text = support::text(Command::new("nix").args([
        "build",
        &format!("{root}#{attribute}", root = context.root.display()),
        "--no-link",
        "--print-out-paths",
        "--print-build-logs",
        "--show-trace",
    ]))?;
    let output_path = output_text
        .lines()
        .rfind(|line| !line.trim().is_empty())
        .context("image build returned no output path")?;
    let source = environment::physical(Path::new(output_path));
    ensure!(
        source.is_dir(),
        "resolved VM image output is missing: {source}",
        source = source.display()
    );
    link(&source, &output)?;
    Ok(source)
}
