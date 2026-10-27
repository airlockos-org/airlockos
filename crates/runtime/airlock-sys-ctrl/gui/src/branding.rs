//! The shared desktop rendition of the Airlock emblem, exported once for native window pixels.

/// Decode the bundled logo into native window icon pixels.
pub fn logo() -> anyhow::Result<eframe::egui::IconData> {
    let image = image::load_from_memory(airlock_desktop::ICON_PNG)?.into_rgba8();
    Ok(eframe::egui::IconData {
        width: image.width(),
        height: image.height(),
        rgba: image.into_raw(),
    })
}
