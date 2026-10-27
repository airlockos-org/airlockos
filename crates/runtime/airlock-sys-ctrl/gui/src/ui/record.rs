//! Display source revisions and content identities for the review record.

use super::plan::plan_frame;
use super::*;

impl Controller {
    pub(super) fn record(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical()
            .id_salt("review-record")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.heading("Review record");
                ui.add_space(12.0);
                if ui.available_width() >= 1200.0 {
                    ui.columns(2, |columns| {
                        record_source(&mut columns[0], &self.review, &mut self.copy_feedback);
                        record_identities(&mut columns[1], &self.review, &mut self.copy_feedback);
                    });
                } else {
                    record_source(ui, &self.review, &mut self.copy_feedback);
                    record_identities(ui, &self.review, &mut self.copy_feedback);
                }
            });
    }
}

fn record_field(
    ui: &mut egui::Ui,
    label: &'static str,
    value: Option<&str>,
    placeholder: &str,
    feedback: &mut Option<(&'static str, f64)>,
) {
    ui.label(RichText::new(label).size(12.0).color(MUTED));
    let displayed = value.unwrap_or(placeholder);
    icons::row(ui, |ui| {
        let frame = egui::Frame::new()
            .fill(BACKGROUND)
            .stroke(Stroke::new(1.0_f32, BORDER))
            .corner_radius(4.0)
            .inner_margin(egui::Margin::symmetric(8, 3));
        let width =
            (ui.available_width() - icons::BUTTON_SIZE - ui.spacing().item_spacing.x).max(40.0);
        frame
            .show(ui, |ui| {
                ui.set_width((width - frame.total_margin().sum().x).max(24.0));
                read_only_text(ui, label, displayed, false);
            })
            .response
            .on_hover_text(displayed);
        copy_button(ui, label, value, feedback);
    });
}

fn record_source(ui: &mut egui::Ui, review: &Review, feedback: &mut Option<(&'static str, f64)>) {
    plan_frame(ui, 210.0, |ui| {
        ui.spacing_mut().item_spacing.y = 5.0;
        ui.label(RichText::new("Source revisions").strong().size(16.0));
        ui.add_space(5.0);
        record_field(
            ui,
            "Repository",
            review.repository.as_deref(),
            "Built-in example",
            feedback,
        );
        ui.add_space(5.0);
        record_field(
            ui,
            "Baseline commit",
            Some(&review.baseline.commit),
            "",
            feedback,
        );
        ui.add_space(5.0);
        record_field(
            ui,
            "Candidate commit",
            Some(&review.candidate.commit),
            "",
            feedback,
        );
    });
}

fn record_identities(
    ui: &mut egui::Ui,
    review: &Review,
    feedback: &mut Option<(&'static str, f64)>,
) {
    plan_frame(ui, 210.0, |ui| {
        ui.spacing_mut().item_spacing.y = 5.0;
        ui.label(RichText::new("Content identities").strong().size(16.0));
        ui.label(
            RichText::new("Binds source changes and the supplied plan.")
                .size(12.0)
                .color(MUTED),
        );
        ui.add_space(5.0);
        record_field(
            ui,
            "Review SHA-256",
            Some(&review.fingerprint),
            "",
            feedback,
        );
        ui.add_space(5.0);
        record_field(
            ui,
            "Candidate lock SHA-256",
            review.lock_hash.as_deref(),
            "No flake.lock",
            feedback,
        );
    });
}
