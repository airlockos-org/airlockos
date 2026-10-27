//! Render the review window chrome and decision dialogs.

use super::*;

impl Controller {
    pub(super) fn header(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("header")
            .frame(egui::Frame::new().fill(PANEL).inner_margin(20.0))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.add(egui::Image::new(&self.logo).fit_to_exact_size(Vec2::splat(44.0)));
                    ui.vertical(|ui| {
                        ui.heading(RichText::new("Airlock Control").color(BRAND));
                        ui.label(
                            RichText::new(
                                if self.approval.is_some() { "Approve the source and permitted impact before evaluation or building." }
                                else { "Compare configuration changes and inspect the deployment plan before approval." },
                            )
                            .color(MUTED),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if icons::button(ui, Icon::Info, "About Airlock Control", true).clicked() {
                            self.about_open = true;
                        }

                        let label = if self.approval.is_some() { "APPROVAL REQUIRED" } else if self.review.mode == "demo" {
                            "LOCAL PREVIEW"
                        } else {
                            "LOCAL REVIEW"
                        };
                        egui::Frame::new()
                            .fill(ACCENT_TINT)
                            .stroke(Stroke::new(1.0_f32, ACCENT))
                            .inner_margin(8.0)
                            .corner_radius(5.0)
                            .show(ui, |ui| {
                                ui.label(RichText::new(label).color(ACCENT).strong().size(12.0));
                            });
                    });
                });
            });
    }

    pub(super) fn footer(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("decision")
            .frame(egui::Frame::new().fill(PANEL).inner_margin(18.0))
            .show(ctx, |ui| {
                if let Some(notice) = &self.notice {
                    ui.label(RichText::new(notice).color(ACCENT));
                }

                ui.horizontal(|ui| {
                    let effects_width = (ui.available_width() - 190.0).max(100.0);
                    ui.allocate_ui_with_layout(
                        Vec2::new(effects_width, 0.0),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            if let Some(session) = &self.approval {
                                ui.label(
                                    RichText::new(format!(
                                        "Permitted VM changes: {names}",
                                        names = session.allowed_vms
                                    ))
                                    .size(12.0),
                                );
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(format!(
                                            "System reboot: {notice}",
                                            notice = crate::approval::REBOOT_NOTICE
                                        ))
                                        .size(12.0)
                                        .color(MUTED),
                                    )
                                    .wrap(),
                                );
                            } else {
                                effects_summary(ui, self.effects.as_ref());
                            }
                        },
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let enabled = self.receipt.is_none() && self.blocker().is_none();
                        if ui
                            .add_enabled(
                                enabled,
                                egui::Button::new(RichText::new("Approve").color(BUTTON_TEXT))
                                    .fill(ACCENT),
                            )
                            .clicked()
                        {
                            if let Some(session) = &self.approval {
                                match session.finish(&self.review, ApprovalDecision::Approve) {
                                    Ok(()) => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
                                    Err(error) => self.notice = Some(error.to_string()),
                                }
                            } else {
                                self.confirm = Some(Decision::Approve);
                            }
                        }

                        if ui
                            .add_enabled(self.receipt.is_none(), egui::Button::new("Reject"))
                            .clicked()
                        {
                            if let Some(session) = &self.approval {
                                match session.finish(&self.review, ApprovalDecision::Reject) {
                                    Ok(()) => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
                                    Err(error) => self.notice = Some(error.to_string()),
                                }
                            } else {
                                self.confirm = Some(Decision::Reject);
                            }
                        }
                    });
                });

                if self.receipt.is_none()
                    && let Some(reason) = self.blocker()
                {
                    ui.add(egui::Label::new(RichText::new(reason).size(12.0).color(ACCENT)).wrap());
                }
            });
    }

    pub(super) fn about(&mut self, ctx: &egui::Context) {
        if !self.about_open {
            return;
        }

        let frame = egui::Frame::new()
            .fill(PANEL)
            .stroke(Stroke::new(1.0_f32, BORDER))
            .corner_radius(10.0)
            .inner_margin(24.0)
            .shadow(ctx.style().visuals.window_shadow);
        let dialog = egui::Modal::new(egui::Id::new("about-airlock-control"))
            .frame(frame)
            .show(ctx, |ui| {
                ui.set_width(420.0);
                ui.spacing_mut().item_spacing.y = 6.0;
                ui.vertical_centered(|ui| {
                    ui.add(egui::Image::new(&self.logo).fit_to_exact_size(Vec2::splat(64.0)));
                    ui.add_space(6.0);
                    ui.heading(RichText::new("Airlock Control").color(BRAND));
                    ui.label(
                        RichText::new(format!("Version {version}", version = env!("CARGO_PKG_VERSION")))
                            .size(12.0)
                            .color(MUTED),
                    );
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("Compare configuration changes and inspect deployment effects.")
                            .size(13.0)
                            .color(MUTED),
                    );
                });
                ui.add_space(16.0);
                ui.separator();
                ui.add_space(12.0);
                for (title, description) in [
                    (
                        "Deployment effects",
                        if self.review.mode == "demo" {
                            "The deployment plan is an example."
                        } else if self.review.deployment.is_some() {
                            "Shown from the supplied deployment plan."
                        } else {
                            "No deployment plan is loaded."
                        },
                    ),
                    (
                        "Review decisions",
                        if self.approval.is_some() { "Approve permits evaluation, building and deployment of this source within the permitted VM impact, including changes that require a reboot. You choose when to restart. Reject returns feedback to the assistant." }
                        else { "No machine is connected. Approve and Reject record your decision locally without starting deployment." },
                    ),
                    (
                        "Decision storage",
                        if self.approval.is_some() { "The controller retains the request and outcome. Closing this window cancels approval." } else if self.review.mode == "demo" {
                            "Example decisions stay in memory for this session."
                        } else if self.decisions_dir.is_some() {
                            "Decision receipts are saved to the configured local directory."
                        } else {
                            "Decisions stay in memory for this session."
                        },
                    ),
                ] {
                    ui.label(RichText::new(title).strong().size(13.0));
                    ui.label(RichText::new(description).size(13.0).color(MUTED));
                    ui.add_space(10.0);
                }
                ui.add_space(4.0);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Close").clicked() {
                        ui.close();
                    }
                });
            });

        if dialog.should_close() {
            self.about_open = false;
        }
    }

    pub(super) fn confirmation(&mut self, ctx: &egui::Context) {
        let Some(decision) = self.confirm else {
            return;
        };

        let mut finish = false;
        let mut cancel = false;
        egui::Modal::new(egui::Id::new("confirm-decision")).show(ctx, |ui| {
            ui.set_width(440.0);
            ui.heading(match decision {
                Decision::Approve => "Approve this local review?",
                Decision::Reject => "Reject this candidate?",
            });
            ui.label(&self.review.candidate.subject);
            ui.monospace(&self.review.candidate.commit);
            ui.add_space(10.0);
            ui.label(if self.review.mode == "demo" {
                "This example decision stays in memory. No machine is connected."
            } else if self.decisions_dir.is_some() {
                "A receipt will be saved locally. This does not authorize or start deployment."
            } else {
                "This decision stays in memory. Supply --decisions-dir to save local receipts."
            });
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                cancel = ui.button("Back to review").clicked();
                finish = ui
                    .button(match decision {
                        Decision::Approve => "Confirm local approval",
                        Decision::Reject => "Confirm rejection",
                    })
                    .clicked();
            });
        });

        if cancel {
            self.confirm = None;
        }

        if finish {
            let result = self.review.receipt(decision).and_then(|receipt| {
                let path = if self.review.mode != "demo" {
                    self.decisions_dir
                        .as_ref()
                        .map(|directory| self.review.record_decision(decision, directory))
                        .transpose()?
                } else {
                    None
                };
                Ok((receipt, path))
            });
            match result {
                Ok((receipt, path)) => {
                    self.receipt = Some(receipt);
                    self.notice = Some(
                        path.map(|path| {
                            format!("Local decision saved: {path}", path = path.display())
                        })
                        .unwrap_or_else(|| {
                            "Local decision recorded in this window. No deployment started.".into()
                        }),
                    );
                    self.tab = Tab::Record;
                }
                Err(error) => self.notice = Some(format!("Decision was not recorded: {error:#}")),
            }
            self.confirm = None;
        }
    }
}
