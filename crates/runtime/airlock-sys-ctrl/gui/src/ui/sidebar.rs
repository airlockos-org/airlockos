//! Browse changed files and draw their hierarchical sidebar.

use super::*;

impl Controller {
    pub(super) fn review_title(&self, ui: &mut egui::Ui) {
        ui.add(
            egui::Label::new(
                RichText::new(&self.review.candidate.subject)
                    .strong()
                    .size(15.0),
            )
            .truncate(),
        )
        .on_hover_text(&self.review.candidate.subject)
        .context_menu(|ui| {
            if ui.button("Copy change title").clicked() {
                ui.ctx().copy_text(self.review.candidate.subject.clone());
                ui.close();
            }
        });
    }

    pub(super) fn sidebar(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("files")
            .default_width(330.0)
            .min_width(270.0)
            .max_width(520.0)
            .resizable(true)
            .frame(egui::Frame::new().fill(PANEL).inner_margin(14.0))
            .show(ctx, |ui| {
                let all_rows =
                    self.file_tree
                        .rows(&self.review.files, &self.filter, &BTreeSet::new());
                let matching: Vec<_> = all_rows
                    .iter()
                    .filter_map(|row| match row.kind {
                        RowKind::File { index } => Some(index),
                        _ => None,
                    })
                    .collect();
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Changed files").strong().size(15.0));
                    let count = if self.filter.trim().is_empty() {
                        self.review.files.len().to_string()
                    } else {
                        format!("{matching} / {total}", matching = matching.len(), total = self.review.files.len())
                    };
                    ui.label(RichText::new(count).size(12.0).color(MUTED));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let removed: usize =
                            self.review.files.iter().map(|file| file.deletions).sum();
                        let added: usize =
                            self.review.files.iter().map(|file| file.additions).sum();
                        ui.label(
                            RichText::new(format!("−{removed}"))
                                .monospace()
                                .size(11.0)
                                .color(RED),
                        );
                        ui.label(
                            RichText::new(format!("+{added}"))
                                .monospace()
                                .size(11.0)
                                .color(GREEN),
                        );
                    });
                });

                ui.allocate_ui_with_layout(Vec2::new(ui.available_width(), 36.0), egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    let clear_width = icons::BUTTON_SIZE;
                    let margin = egui::Margin::symmetric(10, 8);
                    let text_width = (ui.available_width() - clear_width - ui.spacing().item_spacing.x - margin.sum().x).max(40.0);
                    let filter_id = ui.make_persistent_id("file-filter");
                    let previous_cursor = egui::TextEdit::load_state(ui.ctx(), filter_id)
                        .and_then(|state| state.cursor.char_range());
                    let mut filter = egui::TextEdit::singleline(&mut self.filter)
                            .id(filter_id)
                            .hint_text("Find a file or folder…")
                            .margin(margin)
                            .min_size(Vec2::new(0.0, 36.0))
                            .vertical_align(egui::Align::Center)
                            .desired_width(text_width)
                            .show(ui);
                    self.filter_has_focus = filter.response.has_focus();
                    if filter.response.contains_pointer() && ui.input(|input| input.pointer.secondary_pressed()) {
                        filter.state.cursor.set_char_range(previous_cursor);
                        filter.state.clone().store(ui.ctx(), filter_id);
                    }
                    selection::text_edit_menu(&mut filter, &self.filter, true);
                    if icons::button(ui, Icon::Clear, "Clear file filter", !self.filter.is_empty()).clicked()
                    {
                        self.filter.clear();
                    }
                });

                icons::row(ui, |ui| {
                    let searching = !self.filter.trim().is_empty();
                    if icons::button(ui, Icon::CollapseAll, "Collapse all folders", !searching).clicked()
                    {
                        self.collapsed_folders = all_rows
                            .iter()
                            .filter_map(|row| match row.kind {
                                RowKind::Folder { .. } => Some(row.path.clone()),
                                _ => None,
                            })
                            .collect();
                    }
                    if icons::button(ui, Icon::ExpandAll, "Expand all folders", !searching).clicked()
                    {
                        self.collapsed_folders.clear();
                    }
                });
                ui.add_space(6.0);

                let visible =
                    self.file_tree
                        .rows(&self.review.files, &self.filter, &self.collapsed_folders);
                let mut select = None;
                let mut navigate = None;
                let tree_height = (ui.available_height() - icons::BUTTON_SIZE - 28.0).max(100.0);
                ui.scope(|ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    if visible.is_empty() {
                        ui.add_space(18.0);
                        ui.label(
                            RichText::new(if self.review.files.is_empty() {
                                "No changed files."
                            } else {
                                "No files match this filter."
                            })
                            .color(MUTED),
                        );
                    }

                    let mut scroll = egui::ScrollArea::vertical()
                        .id_salt("file-tree")
                        .auto_shrink([false, false])
                        .max_height(tree_height);
                    if self.scroll_to_selection {
                        if let Some(position) = visible.iter().position(|row| matches!(row.kind, RowKind::File { index } if index == self.selected)) {
                            scroll = scroll.vertical_scroll_offset((position as f32 * 29.0 - tree_height / 2.0).max(0.0));
                        }
                        self.scroll_to_selection = false;
                    }
                    scroll.show_rows(ui, 29.0, visible.len(), |ui, range| {
                            for index in range {
                                let row = &visible[index];
                                let response = tree_row(ui, row, &self.review.files, self.selected);
                                if response.clicked() {
                                    response.request_focus();
                                }
                                let activated = response.clicked()
                                    || response.has_focus()
                                        && ui.input(|input| {
                                            input.key_pressed(egui::Key::Enter)
                                                || input.key_pressed(egui::Key::Space)
                                        });
                                if response.has_focus() {
                                    if ui.input(|input| input.key_pressed(egui::Key::ArrowDown)) {
                                        navigate = Some(true);
                                    }
                                    if ui.input(|input| input.key_pressed(egui::Key::ArrowUp)) {
                                        navigate = Some(false);
                                    }
                                }
                                if activated {
                                    match row.kind {
                                        RowKind::File { index } => select = Some(index),
                                        RowKind::Folder { open, .. }
                                            if self.filter.trim().is_empty() =>
                                        {
                                            if open {
                                                self.collapsed_folders.insert(row.path.clone());
                                            } else {
                                                self.collapsed_folders.remove(&row.path);
                                            }
                                        }
                                        _ => (),
                                    }
                                }
                            }
                        });
                });

                ui.separator();
                icons::row(ui, |ui| {
                    let position = matching.iter().position(|index| *index == self.selected);
                    ui.label(
                        RichText::new(
                            position
                                .map(|position| format!("{number} of {count}", number = position + 1, count = matching.len()))
                                .unwrap_or_else(|| "No selection in filter".into()),
                        )
                        .size(11.0)
                        .color(MUTED),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if icons::button(ui, Icon::Next, "Next changed file",
                                !matching.is_empty()
                                    && position
                                        .is_none_or(|position| position + 1 < matching.len()),
                            ).clicked()
                        {
                            navigate = Some(true);
                        }
                        if icons::button(ui, Icon::Previous, "Previous changed file",
                                !matching.is_empty()
                                    && position.is_none_or(|position| position > 0),
                            ).clicked()
                        {
                            navigate = Some(false);
                        }
                    });

                    if let Some(forward) = navigate {
                        let position = match (forward, position) {
                            (true, Some(position)) => {
                                (position + 1).min(matching.len().saturating_sub(1))
                            }
                            (false, Some(position)) => position.saturating_sub(1),
                            (true, None) => 0,
                            (false, None) => matching.len().saturating_sub(1),
                        };
                        select = matching.get(position).copied();
                    }
                });

                if let Some(index) = select {
                    self.file_tree
                        .reveal(&self.review.files, index, &mut self.collapsed_folders);
                    self.select_file(index);
                    if navigate.is_some() {
                        self.scroll_to_selection = true;
                        ctx.memory_mut(|memory| memory.request_focus(tree_id(&self.review.files[index].path)));
                    }
                }
            });
    }
}

fn tree_row(
    ui: &mut egui::Ui,
    row: &TreeRow,
    files: &[FileChange],
    selected: usize,
) -> egui::Response {
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 29.0), egui::Sense::hover());
    let response = ui
        .interact(
            rect,
            match row.kind {
                RowKind::Folder { .. } => egui::Id::new("ctrl-file-tree-folder").with(&row.path),
                RowKind::File { .. } => tree_id(&row.path),
            },
            egui::Sense::click(),
        )
        .on_hover_cursor(egui::CursorIcon::PointingHand);
    let is_selected = matches!(row.kind, RowKind::File { index } if index == selected);
    response.widget_info(|| {
        egui::WidgetInfo::selected(
            egui::WidgetType::SelectableLabel,
            true,
            is_selected,
            visible_path(&row.label),
        )
    });

    if is_selected {
        ui.painter()
            .rect_filled(rect.shrink2(Vec2::new(0.0, 1.0)), 4.0, ACCENT_TINT);
        ui.painter().rect_filled(
            egui::Rect::from_min_size(rect.left_top() + Vec2::new(0.0, 5.0), Vec2::new(2.0, 19.0)),
            1.0,
            ACCENT,
        );
    } else if response.hovered() {
        ui.painter().rect_filled(
            rect.shrink2(Vec2::new(0.0, 1.0)),
            4.0,
            Color32::from_rgb(0x18, 0x26, 0x35),
        );
    }
    if response.has_focus() {
        ui.painter().rect_stroke(
            rect.shrink(1.0),
            4.0,
            Stroke::new(1.0_f32, BORDER),
            egui::StrokeKind::Inside,
        );
    }

    let indent = row.depth as f32 * 14.0;
    let center = rect.left_center() + Vec2::new(10.0 + indent, 0.0);
    for depth in 0..row.depth {
        let x = rect.left() + 10.0 + depth as f32 * 14.0;
        ui.painter().line_segment(
            [egui::pos2(x, rect.top()), egui::pos2(x, rect.bottom())],
            Stroke::new(1.0_f32, BORDER.linear_multiply(0.5)),
        );
    }

    let font = FontId::proportional(13.0);
    let text_left = center.x + 30.0;
    let reserved = match row.kind {
        RowKind::Folder { open, count } => {
            let offsets = if open {
                [
                    Vec2::new(-3.0, -2.0),
                    Vec2::new(0.0, 1.0),
                    Vec2::new(3.0, -2.0),
                ]
            } else {
                [
                    Vec2::new(-1.0, -3.0),
                    Vec2::new(2.0, 0.0),
                    Vec2::new(-1.0, 3.0),
                ]
            };
            ui.painter().add(egui::Shape::line(
                offsets.into_iter().map(|offset| center + offset).collect(),
                Stroke::new(1.3_f32, MUTED),
            ));
            let origin = center + Vec2::new(10.0, -6.0);
            let outline = [
                (0.0, 1.0),
                (5.0, 1.0),
                (7.0, 3.0),
                (14.0, 3.0),
                (14.0, 12.0),
                (0.0, 12.0),
                (0.0, 1.0),
            ];
            ui.painter().add(egui::Shape::line(
                outline
                    .into_iter()
                    .map(|(x, y)| origin + Vec2::new(x, y))
                    .collect(),
                Stroke::new(1.1_f32, BRAND),
            ));
            ui.painter().text(
                rect.right_center() - Vec2::new(8.0, 0.0),
                egui::Align2::RIGHT_CENTER,
                count.to_string(),
                FontId::proportional(11.0),
                MUTED,
            );
            34.0
        }
        RowKind::File { index } => {
            let file = &files[index];
            let origin = center + Vec2::new(12.0, -6.0);
            let outline = [
                (0.0, 0.0),
                (7.0, 0.0),
                (11.0, 4.0),
                (11.0, 13.0),
                (0.0, 13.0),
                (0.0, 0.0),
            ];
            ui.painter().add(egui::Shape::line(
                outline
                    .into_iter()
                    .map(|(x, y)| origin + Vec2::new(x, y))
                    .collect(),
                Stroke::new(1.0_f32, MUTED),
            ));
            ui.painter().add(egui::Shape::line(
                vec![
                    origin + Vec2::new(7.0, 0.0),
                    origin + Vec2::new(7.0, 4.0),
                    origin + Vec2::new(11.0, 4.0),
                ],
                Stroke::new(1.0_f32, MUTED),
            ));
            let (status, color) = match file.status.as_str() {
                "Added" => ("A", GREEN),
                "Deleted" => ("D", RED),
                _ => ("M", ACCENT),
            };
            let right = rect.right_center() - Vec2::new(8.0, 0.0);
            let font = FontId::monospace(11.0);
            if file.opaque.is_some() {
                ui.painter()
                    .text(right, egui::Align2::RIGHT_CENTER, "!", font, RED);
            } else if file.additions == 0 && file.deletions == 0 {
                ui.painter()
                    .text(right, egui::Align2::RIGHT_CENTER, "mode", font, MUTED);
            } else {
                if file.additions > 0 {
                    ui.painter().text(
                        right - Vec2::new(37.0, 0.0),
                        egui::Align2::RIGHT_CENTER,
                        format!("+{count}", count = compact_count(file.additions)),
                        font.clone(),
                        GREEN,
                    );
                }
                if file.deletions > 0 {
                    ui.painter().text(
                        right,
                        egui::Align2::RIGHT_CENTER,
                        format!("−{count}", count = compact_count(file.deletions)),
                        font,
                        RED,
                    );
                }
            }
            ui.painter().text(
                right - Vec2::new(82.0, 0.0),
                egui::Align2::RIGHT_CENTER,
                status,
                FontId::monospace(11.0),
                color,
            );
            108.0
        }
    };

    let mut job = egui::text::LayoutJob::simple(
        visible_path(&row.label),
        font,
        if is_selected { FOREGROUND } else { MUTED },
        (rect.right() - reserved - text_left).max(20.0),
    );
    job.wrap = egui::text::TextWrapping::truncate_at_width(
        (rect.right() - reserved - text_left).max(20.0),
    );
    let galley = ui.painter().layout_job(job);
    ui.painter().galley(
        egui::pos2(text_left, rect.center().y - galley.size().y / 2.0),
        galley,
        FOREGROUND,
    );

    let tooltip = match row.kind {
        RowKind::Folder { count, .. } => {
            format!(
                "{path}\n{count} changed files",
                path = visible_path(&row.path)
            )
        }
        RowKind::File { index } => {
            let file = &files[index];
            format!(
                "{path}\n{status} · +{additions} / −{deletions}{opaque}",
                path = visible_path(&row.path),
                status = file.status,
                additions = file.additions,
                deletions = file.deletions,
                opaque = file
                    .opaque
                    .as_ref()
                    .map(|reason| format!("\n{reason}"))
                    .unwrap_or_default()
            )
        }
    };
    response.context_menu(|ui| {
        if ui.button("Copy path").clicked() {
            ui.ctx().copy_text(row.path.clone());
            ui.close();
        }

        if let RowKind::File { index } = row.kind {
            if ui.button("Copy filename").clicked() {
                ui.ctx()
                    .copy_text(row.path.rsplit('/').next().unwrap_or(&row.path).to_owned());
                ui.close();
            }
            if files[index].opaque.is_none() {
                ui.separator();
                if ui.button("Copy baseline").clicked() {
                    ui.ctx().copy_text(files[index].before.clone());
                    ui.close();
                }
                if ui.button("Copy candidate").clicked() {
                    ui.ctx().copy_text(files[index].after.clone());
                    ui.close();
                }
            }
        }
    });
    response.on_hover_text(tooltip)
}

fn tree_id(path: &str) -> egui::Id {
    egui::Id::new("ctrl-file-tree-path").with(path)
}

fn compact_count(count: usize) -> String {
    if count >= 10_000 {
        format!("{count}k", count = count / 1000)
    } else if count >= 1000 {
        format!("{count:.1}k", count = count as f32 / 1000.0)
    } else {
        count.to_string()
    }
}
