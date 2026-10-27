//! Small vector controls: no icon font or platform-dependent Unicode glyphs.
use crate::theme::{ACCENT, GREEN, MUTED};
use eframe::egui::{self, Color32, Stroke, Vec2};

pub const BUTTON_SIZE: f32 = 28.0;

/// Small vector glyph used for review actions, navigation and copy affordances.
#[derive(Clone, Copy)]
pub enum Icon {
    Previous,
    Next,
    CollapseAll,
    ExpandAll,
    Clear,
    More,
    Copy,
    Check,
    Info,
}

/// Construct a compact native-styled action button with the shared icon size.
pub fn control() -> egui::Button<'static> {
    egui::Button::new("")
        .min_size(Vec2::splat(BUTTON_SIZE))
        .frame_when_inactive(false)
}

/// Lay out the supplied controls in a horizontal row with the shared icon-control height.
pub fn row<R>(
    ui: &mut egui::Ui,
    content: impl FnOnce(&mut egui::Ui) -> R,
) -> egui::InnerResponse<R> {
    ui.scope(|ui| {
        ui.spacing_mut().interact_size.y = BUTTON_SIZE;
        ui.horizontal(content).inner
    })
}

/// Draw an icon action with its tooltip and requested enabled state.
pub fn button(ui: &mut egui::Ui, icon: Icon, label: &str, enabled: bool) -> egui::Response {
    let response = ui.add_enabled(enabled, control());
    decorate(ui, response, icon, label)
}

/// Paint the requested vector glyph inside a button response rectangle.
pub fn decorate(
    ui: &egui::Ui,
    response: egui::Response,
    icon: Icon,
    label: &str,
) -> egui::Response {
    let color = if !response.enabled() {
        MUTED.linear_multiply(0.35)
    } else if matches!(icon, Icon::Check) {
        GREEN
    } else if response.hovered() || response.has_focus() || response.is_pointer_button_down_on() {
        ACCENT
    } else {
        MUTED
    };
    paint(ui, response.rect.center(), icon, color);
    response.widget_info(|| {
        egui::WidgetInfo::labeled(egui::WidgetType::Button, response.enabled(), label)
    });
    response.on_hover_text(label).on_disabled_hover_text(label)
}

fn paint(ui: &egui::Ui, center: egui::Pos2, icon: Icon, color: Color32) {
    let stroke = Stroke::new(1.5_f32, color);
    let point = |x, y| center + Vec2::new(x, y);
    let line = |a, b| ui.painter().line_segment([a, b], stroke);
    match icon {
        Icon::Previous | Icon::Next => {
            let direction = if matches!(icon, Icon::Previous) {
                -1.0
            } else {
                1.0
            };
            ui.painter().add(egui::Shape::line(
                vec![
                    point(-4.5, -2.0 * direction),
                    point(0.0, 2.5 * direction),
                    point(4.5, -2.0 * direction),
                ],
                stroke,
            ));
        }
        Icon::CollapseAll | Icon::ExpandAll => {
            // Stacked tree levels, with a minus/plus in the front level.
            ui.painter().add(egui::Shape::line(
                vec![
                    point(-3.0, -4.0),
                    point(-3.0, -7.0),
                    point(7.0, -7.0),
                    point(7.0, 3.0),
                    point(4.0, 3.0),
                ],
                stroke,
            ));
            ui.painter().rect_stroke(
                egui::Rect::from_min_max(point(-7.0, -3.0), point(3.0, 7.0)),
                1.5,
                stroke,
                egui::StrokeKind::Inside,
            );
            line(point(-4.5, 2.0), point(0.5, 2.0));
            if matches!(icon, Icon::ExpandAll) {
                line(point(-2.0, -0.5), point(-2.0, 4.5));
            }
        }
        Icon::Clear => {
            line(point(-3.5, -3.5), point(3.5, 3.5));
            line(point(-3.5, 3.5), point(3.5, -3.5));
        }
        Icon::More => {
            for offset in [-4.5, 0.0, 4.5] {
                ui.painter().circle_filled(point(offset, 0.0), 1.3, color);
            }
        }
        Icon::Copy => {
            ui.painter().add(egui::Shape::line(
                vec![
                    point(-3.0, -4.0),
                    point(-3.0, -7.0),
                    point(6.0, -7.0),
                    point(6.0, 3.0),
                    point(3.0, 3.0),
                ],
                stroke,
            ));
            ui.painter().rect_stroke(
                egui::Rect::from_min_max(point(-7.0, -3.0), point(2.0, 7.0)),
                1.5,
                stroke,
                egui::StrokeKind::Inside,
            );
        }
        Icon::Check => {
            ui.painter().add(egui::Shape::line(
                vec![point(-5.0, 0.0), point(-1.5, 3.5), point(5.5, -4.0)],
                stroke,
            ));
        }
        Icon::Info => {
            ui.painter().circle_stroke(center, 7.0, stroke);
            ui.painter().circle_filled(point(0.0, -3.5), 1.0, color);
            line(point(0.0, -0.5), point(0.0, 4.0));
        }
    }
}
