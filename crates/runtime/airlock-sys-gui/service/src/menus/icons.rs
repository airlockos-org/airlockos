//! Convert the bounded Qubes RGBA wire format into local PNGs, preserving original pixels.

use crate::qubes;
use airlock_nix_core::identity::GuestName;
use anyhow::{Context, Result, ensure};
use std::time::Duration;

/// Fetch raw pixels through the source VM's existing image service; no encoded image parser runs here.
pub(super) fn fetch(name: &GuestName, icon: &str, timeout: Duration) -> Result<Vec<u8>> {
    let request = if icon.starts_with('/') {
        icon.to_owned()
    } else {
        format!("xdgicon:{icon}")
    };
    let bytes = qubes::image(name, format!("{request}\n").into_bytes(), timeout)?;
    encode(&bytes)
}

/// Require exact dimensions and pixel length before encoding trusted PNG structure around untrusted pixel values.
pub(super) fn encode(bytes: &[u8]) -> Result<Vec<u8>> {
    let newline = bytes
        .iter()
        .take(32)
        .position(|byte| *byte == b'\n')
        .context("missing icon dimensions")?;
    let header = std::str::from_utf8(&bytes[..newline])?;
    let (width, height) = header.split_once(' ').context("invalid icon dimensions")?;
    ensure!(
        width.bytes().all(|byte| byte.is_ascii_digit())
            && height.bytes().all(|byte| byte.is_ascii_digit()),
        "invalid icon dimension encoding"
    );
    let width: u32 = width.parse()?;
    let height: u32 = height.parse()?;
    ensure!(
        width > 0 && height > 0 && width <= 512 && height <= 512,
        "icon dimensions exceed limit"
    );
    let pixels = &bytes[newline + 1..];
    ensure!(
        pixels.len() == width as usize * height as usize * 4,
        "icon pixel length disagrees with dimensions"
    );

    let mut result = Vec::new();
    let mut encoder = png::Encoder::new(&mut result, width, height);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header()?;
    writer.write_image_data(pixels)?;
    writer.finish()?;

    Ok(result)
}
