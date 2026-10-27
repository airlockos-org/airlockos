//! Display permitted deployment impact and the supplied lifecycle plan.

use super::*;

impl Controller {
    pub(super) fn plan(&mut self, ui: &mut egui::Ui) {
        if let Some(session) = &mut self.approval {
            ui.heading("Deployment impact");
            ui.label(RichText::new("The final deployment plan will be computed after building. Deployment stops if it exceeds the permitted VM impact. Approve includes changes that require a reboot.").color(MUTED));
            ui.add_space(16.0);
            ui.label("VMs allowed to change, start, stop or restart");
            let mut output = egui::TextEdit::multiline(&mut session.allowed_vms)
                .desired_width(f32::INFINITY)
                .desired_rows(3)
                .show(ui);
            let text = session.allowed_vms.clone();
            selection::text_edit_menu(&mut output, &text, true);
            ui.add_space(12.0);
            ui.label(
                RichText::new(format!(
                    "System reboot: {notice}",
                    notice = crate::approval::REBOOT_NOTICE
                ))
                .color(MUTED),
            );
            return;
        }

        egui::ScrollArea::vertical().id_salt("plan").auto_shrink([false, false]).show(ui, |ui| {
            ui.heading("Deployment effects");
            if self.review.mode == "demo" {
                ui.label(RichText::new("Example plan for this preview.").color(ACCENT));
            } else if self.review.deployment.is_some() {
                ui.label(RichText::new("Imported JSON · Machine state and candidate binding have not been verified.").color(MUTED));
            }
            ui.add_space(14.0);
            let Some(plan) = self.review.plan() else {
                reboot_badge(ui, None);
                ui.add_space(8.0);
                ui.label(RichText::new("No deployment plan loaded").strong());
                ui.label(RichText::new("Source changes alone do not establish which VMs will restart.").color(MUTED));
                return;
            };
            let effects = self.effects.as_ref().unwrap();
            if ui.available_width() >= 620.0 {
                ui.horizontal_top(|ui| {
                    let width = (ui.available_width() - 240.0).max(200.0);
                    ui.allocate_ui_with_layout(Vec2::new(width, 0.0), egui::Layout::top_down(egui::Align::Min), |ui| {
                        plan_row(ui, "Restarting", |ui| vm_names(ui, effects.restarting.iter().map(String::as_str)));
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                        reboot_badge(ui, effects.reboot);
                    });
                });
            } else {
                reboot_badge(ui, effects.reboot);
                ui.add_space(8.0);
                plan_row(ui, "Restarting", |ui| vm_names(ui, effects.restarting.iter().map(String::as_str)));
            }

            for (title, names) in [
                ("Starting", &effects.starting),
                ("Stopping", &effects.stopping),
            ] {
                if !names.is_empty() {
                    plan_row(ui, title, |ui| vm_names(ui, names.iter().map(String::as_str)));
                }
            }

            ui.add_space(12.0);
            ui.separator();
            ui.add_space(4.0);
            ui.label(RichText::new("Configuration changes").strong().size(16.0));
            for (key, title) in [("changed", "Changed"), ("retire", "Retired"), ("restore", "Restored")] {
                plan_row(ui, title, |ui| {
                    if let Some(names) = plan.get(key).and_then(|value| value.as_array()) {
                        vm_names(ui, names.iter().filter_map(|name| name.as_str()));
                    } else {
                        ui.label(RichText::new("Not reported").size(13.0).color(MUTED));
                    }
                });
            }
            ui.add_space(8.0);
            ui.separator();
            egui::CollapsingHeader::new("Technical details").default_open(false).show(ui, |ui| {
                ui.label(RichText::new("Stop and start sequences, in the supplied order.").color(MUTED).size(12.0));
                if ui.available_width() >= 600.0 {
                    ui.columns(2, |columns| {
                        ordered_plan(&mut columns[0], plan, "stop", "Stop VMs", RED);
                        ordered_plan(&mut columns[1], plan, "start", "Start VMs", GREEN);
                    });
                } else {
                    ordered_plan(ui, plan, "stop", "Stop VMs", RED);
                    ordered_plan(ui, plan, "start", "Start VMs", GREEN);
                }
                ui.add_space(8.0);
                ui.label(RichText::new("Complete supplied plan · JSON").strong());
                read_only_text(ui, "supplied-plan", &serde_json::to_string_pretty(self.review.deployment.as_ref().unwrap()).unwrap(), true);
            });
        });
    }
}

fn reboot_state(required: Option<bool>) -> (&'static str, Color32) {
    match required {
        Some(true) => ("Required", ACCENT),
        Some(false) => ("Not required", GREEN),
        None => ("Unknown", MUTED),
    }
}

pub(super) fn effects_summary(ui: &mut egui::Ui, effects: Option<&PlannedEffects>) {
    ui.spacing_mut().item_spacing.y = 5.0;
    let row = |ui: &mut egui::Ui, label: &str, names: &str| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("{label}:")).size(12.0).color(MUTED));
            ui.add(egui::Label::new(RichText::new(names).monospace().size(13.0)).truncate())
                .on_hover_text(names)
                .context_menu(|ui| {
                    if ui.button("Copy VM names").clicked() {
                        ui.ctx().copy_text(names.to_owned());
                        ui.close();
                    }
                });
        });
    };
    row(
        ui,
        "VMs restarting",
        &effects.map_or_else(
            || "Unknown (no plan)".to_owned(),
            |effects| names_text(&effects.restarting),
        ),
    );
    if let Some(effects) = effects {
        for (label, names) in [
            ("VMs starting", &effects.starting),
            ("VMs stopping", &effects.stopping),
        ] {
            if !names.is_empty() {
                row(ui, label, &names_text(names));
            }
        }
    }

    let (status, color) = reboot_state(effects.and_then(|effects| effects.reboot));
    ui.label(
        RichText::new(format!("System reboot: {status}"))
            .strong()
            .size(12.0)
            .color(color),
    )
    .context_menu(|ui| {
        if ui.button("Copy effects summary").clicked() {
            ui.ctx().copy_text(effects::summary(effects));
            ui.close();
        }
    });
}

fn plan_row(ui: &mut egui::Ui, label: &str, content: impl FnOnce(&mut egui::Ui)) {
    ui.horizontal_top(|ui| {
        ui.allocate_ui_with_layout(
            Vec2::new(120.0, 0.0),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                ui.set_width(120.0);
                ui.label(RichText::new(label).size(13.0).color(MUTED));
            },
        );
        ui.allocate_ui_with_layout(
            Vec2::new(ui.available_width(), 0.0),
            egui::Layout::top_down(egui::Align::Min),
            content,
        );
    });
}

fn reboot_badge(ui: &mut egui::Ui, required: Option<bool>) {
    let (status, color) = reboot_state(required);
    egui::Frame::new()
        .fill(color.linear_multiply(0.08))
        .corner_radius(4.0)
        .inner_margin(egui::Margin::symmetric(9, 5))
        .show(ui, |ui| {
            ui.label(
                RichText::new(format!("System reboot: {status}"))
                    .size(12.0)
                    .color(color),
            );
        });
}

fn vm_names<'a>(ui: &mut egui::Ui, names: impl IntoIterator<Item = &'a str>) {
    let mut names = names.into_iter().peekable();
    if names.peek().is_none() {
        ui.label(RichText::new("None").size(13.0).color(MUTED));
        return;
    }

    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing = Vec2::new(6.0, 4.0);
        while let Some(name) = names.next() {
            let display = format!(
                "{name}{separator}",
                name = visible_path(name),
                separator = if names.peek().is_some() { "," } else { "" }
            );
            ui.add(
                egui::Label::new(RichText::new(display).monospace().size(13.0))
                    .selectable(true)
                    .wrap(),
            )
            .context_menu(|ui| {
                if ui.button("Copy VM name").clicked() {
                    ui.ctx().copy_text(name.to_owned());
                    ui.close();
                }
            });
        }
    });
}

pub(super) fn plan_frame(
    ui: &mut egui::Ui,
    minimum_height: f32,
    content: impl FnOnce(&mut egui::Ui),
) {
    let width = ui.available_width();
    let frame = egui::Frame::new()
        .fill(PANEL)
        .stroke(Stroke::new(1.0_f32, BORDER))
        .inner_margin(14.0)
        .corner_radius(6.0);
    frame.show(ui, |ui| {
        ui.set_width((width - frame.total_margin().sum().x).max(0.0));
        ui.set_min_height(minimum_height);
        content(ui);
    });
}

fn ordered_plan(
    ui: &mut egui::Ui,
    plan: &serde_json::Value,
    key: &str,
    title: &str,
    color: Color32,
) {
    let names = plan.get(key).and_then(|value| value.as_array());
    ui.label(RichText::new(title).strong().color(color));
    let Some(names) = names else {
        ui.label(RichText::new("Not reported").color(MUTED));
        return;
    };
    if names.is_empty() {
        ui.label(RichText::new("None").color(MUTED));
    } else {
        for (index, name) in names.iter().enumerate() {
            let name = name.as_str().unwrap_or("[unexpected entry]");
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!("{number:02}", number = index + 1))
                        .monospace()
                        .size(12.0)
                        .color(MUTED),
                );
                copyable_label(ui, RichText::new(visible_path(name)).monospace(), name);
            });
        }
    }
}
