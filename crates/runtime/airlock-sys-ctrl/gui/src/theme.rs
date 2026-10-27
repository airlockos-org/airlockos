//! Native adaptation of the Airlock landing page's palette and typography.
use eframe::egui::{self, Color32, FontData, FontFamily, FontId, Stroke, Vec2};

// website/app/globals.css: .airlock-site design tokens.
pub const BACKGROUND: Color32 = Color32::from_rgb(0x07, 0x10, 0x17);

pub const PANEL: Color32 = Color32::from_rgb(0x0a, 0x14, 0x1d);

pub const FOREGROUND: Color32 = Color32::from_rgb(0xd5, 0xe4, 0xf6);

pub const MUTED: Color32 = Color32::from_rgb(0xa4, 0xb8, 0xcd);

pub const BORDER: Color32 = Color32::from_rgb(0x25, 0x3b, 0x4d);

pub const ACCENT: Color32 = Color32::from_rgb(0xff, 0x58, 0x32);

pub const ACCENT_HOVER: Color32 = Color32::from_rgb(0xff, 0x76, 0x52);

pub const ACCENT_TINT: Color32 = Color32::from_rgb(0x2d, 0x20, 0x1d);

pub const BUTTON_TEXT: Color32 = Color32::from_rgb(0x16, 0x0c, 0x08);

pub const BRAND: Color32 = Color32::from_rgb(0x9f, 0xb8, 0xd2);

// Diff colours carry meaning independently of the brand accent.
pub const RED: Color32 = Color32::from_rgb(248, 148, 153);

pub const GREEN: Color32 = Color32::from_rgb(128, 222, 168);

/// Install the bundled typefaces and Airlock review palette into the GUI context.
pub fn apply(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    for (name, data) in [
        (
            "Inter Regular",
            include_bytes!("../assets/fonts/Inter-Regular.ttf").as_slice(),
        ),
        (
            "Inter Medium",
            include_bytes!("../assets/fonts/Inter-Medium.ttf").as_slice(),
        ),
        (
            "Inter SemiBold",
            include_bytes!("../assets/fonts/Inter-SemiBold.ttf").as_slice(),
        ),
    ] {
        fonts
            .font_data
            .insert(name.into(), FontData::from_static(data).into());
    }

    let fallbacks = fonts.families[&FontFamily::Proportional].clone();
    fonts
        .families
        .get_mut(&FontFamily::Proportional)
        .unwrap()
        .insert(0, "Inter Regular".into());
    for name in ["Inter Medium", "Inter SemiBold"] {
        let mut family = vec![name.to_owned()];
        family.extend(fallbacks.clone());
        fonts.families.insert(FontFamily::Name(name.into()), family);
    }
    ctx.set_fonts(fonts);

    let mut visuals = egui::Visuals::dark();
    visuals.override_text_color = Some(FOREGROUND);
    visuals.weak_text_color = Some(MUTED);
    visuals.panel_fill = PANEL;
    visuals.window_fill = PANEL;
    visuals.window_stroke = Stroke::new(1.0_f32, BORDER);
    visuals.window_corner_radius = 8.into();
    visuals.extreme_bg_color = BACKGROUND;
    visuals.faint_bg_color = PANEL;
    visuals.code_bg_color = BACKGROUND;
    visuals.hyperlink_color = ACCENT_HOVER;
    visuals.selection.bg_fill = ACCENT_TINT;
    visuals.selection.stroke = Stroke::new(1.0_f32, ACCENT);
    for widget in [
        &mut visuals.widgets.noninteractive,
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
        &mut visuals.widgets.open,
    ] {
        widget.bg_fill = PANEL;
        widget.weak_bg_fill = PANEL;
        widget.bg_stroke = Stroke::new(1.0_f32, BORDER);
        widget.fg_stroke.color = FOREGROUND;
        widget.corner_radius = 5.into();
    }
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(0x18, 0x26, 0x35);
    visuals.widgets.hovered.weak_bg_fill = visuals.widgets.hovered.bg_fill;
    visuals.widgets.hovered.bg_stroke.color = ACCENT_HOVER;
    visuals.widgets.active.bg_stroke.color = ACCENT;
    visuals.widgets.open.bg_stroke.color = ACCENT;
    ctx.set_visuals(visuals);

    ctx.style_mut(|style| {
        style.spacing.item_spacing = Vec2::new(10.0, 9.0);
        style.spacing.button_padding = Vec2::new(14.0, 8.0);

        style.text_styles.insert(
            egui::TextStyle::Heading,
            FontId::new(25.0, FontFamily::Name("Inter SemiBold".into())),
        );
        style
            .text_styles
            .insert(egui::TextStyle::Body, FontId::proportional(14.0));
        style.text_styles.insert(
            egui::TextStyle::Button,
            FontId::new(14.0, FontFamily::Name("Inter Medium".into())),
        );
        style
            .text_styles
            .insert(egui::TextStyle::Small, FontId::proportional(12.0));
        // Keep code columns aligned and use egui's bundled monospace font.
        style
            .text_styles
            .insert(egui::TextStyle::Monospace, FontId::monospace(13.0));
    });
}
