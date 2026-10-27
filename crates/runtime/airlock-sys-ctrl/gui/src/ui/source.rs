//! Align source changes, navigate hunks and render selectable diff panes.

use super::*;

/// One syntax-highlighted source line with its original identity and diff status.
struct CodeLine {
    /// One-based source line number displayed in the gutter.
    number: usize,
    /// UTF-8 byte offset of this line in its original source.
    source_start: usize,
    /// Syntax-highlighted text layout prepared for the source line.
    job: egui::text::LayoutJob,
    /// Diff tag controlling added, removed or unchanged line styling.
    kind: ChangeTag,
}

/// Aligned baseline and candidate cells occupying one row in the source view.
pub(super) struct DiffRow {
    /// Baseline line, absent for an unpaired addition.
    left: Option<CodeLine>,
    /// Candidate line, absent for an unpaired deletion.
    right: Option<CodeLine>,
}

pub(super) fn operations(file: &FileChange) -> Vec<similar::DiffOp> {
    TextDiff::configure()
        .timeout(std::time::Duration::from_millis(250))
        .diff_lines(&file.before, &file.after)
        .ops()
        .to_vec()
}

pub(super) fn rows(file: &FileChange, ops: &[similar::DiffOp]) -> Vec<DiffRow> {
    let starts = |source: &str| {
        let mut offset = 0;
        source
            .split_inclusive('\n')
            .map(|line| {
                let start = offset;
                offset += line.len();
                start
            })
            .collect::<Vec<_>>()
    };

    let before_starts = starts(&file.before);
    let after_starts = starts(&file.after);
    let before_syntax = syntax::highlight(&file.path, &file.before);
    let after_syntax = syntax::highlight(&file.path, &file.after);
    let diff = TextDiff::configure()
        .timeout(std::time::Duration::from_millis(250))
        .diff_lines(&file.before, &file.after);

    let mut result = Vec::new();
    for op in ops {
        let mut deleted = Vec::new();
        let mut inserted = Vec::new();
        for change in diff.iter_inline_changes(op) {
            let segments = change
                .iter_strings_lossy()
                .map(|(emphasized, value)| {
                    (
                        emphasized,
                        value.trim_end_matches('\n').replace('\t', "    "),
                    )
                })
                .collect::<Vec<_>>();
            let highlighted = if let Some(index) = change.old_index() {
                &before_syntax[index]
            } else {
                &after_syntax[change.new_index().unwrap()]
            };
            let line = CodeLine {
                number: change.old_index().or(change.new_index()).unwrap_or(0) + 1,
                source_start: if let Some(index) = change.old_index() {
                    before_starts[index]
                } else {
                    after_starts[change.new_index().unwrap()]
                },
                job: syntax::diff_line(highlighted, &segments, change.tag()),
                kind: change.tag(),
            };
            match change.tag() {
                ChangeTag::Equal => {
                    let right = CodeLine {
                        number: change.new_index().unwrap_or(0) + 1,
                        source_start: after_starts[change.new_index().unwrap()],
                        job: after_syntax[change.new_index().unwrap()].clone(),
                        kind: ChangeTag::Equal,
                    };
                    result.push(DiffRow {
                        left: Some(line),
                        right: Some(right),
                    });
                }
                ChangeTag::Delete => deleted.push(line),
                ChangeTag::Insert => inserted.push(line),
            }
        }

        let count = deleted.len().max(inserted.len());
        let mut deleted = deleted.into_iter();
        let mut inserted = inserted.into_iter();
        for _ in 0..count {
            result.push(DiffRow {
                left: deleted.next(),
                right: inserted.next(),
            });
        }
    }

    result
}

impl Controller {
    pub(super) fn select_file(&mut self, index: usize) {
        if self.selected != index {
            self.selected = index;
            self.source_selection = SourceSelection::default();
            self.diff_rows = rows(&self.review.files[index], &self.diff_ops[index]);
        }

        self.active_section = self.sections.iter().position(|(file, _)| *file == index);
        self.scroll_to_section = None;
        self.tab = Tab::Source;
    }

    pub(super) fn navigate_section(&mut self, forward: bool) {
        let Some(index) =
            adjacent_section(&self.sections, self.active_section, self.selected, forward)
        else {
            return;
        };

        let (file, section) = self.sections[index];
        if file != self.selected {
            self.select_file(file);
            // Navigation covers the complete review, including filtered files.
            self.filter.clear();
            self.file_tree
                .reveal(&self.review.files, file, &mut self.collapsed_folders);
            self.scroll_to_selection = true;
        }

        self.active_section = Some(index);
        self.scroll_to_section = Some(section.first_change);
    }

    pub(super) fn section_toolbar(&mut self, ui: &mut egui::Ui) {
        icons::row(ui, |ui| {
            let previous =
                adjacent_section(&self.sections, self.active_section, self.selected, false)
                    .is_some();
            let next = adjacent_section(&self.sections, self.active_section, self.selected, true)
                .is_some();
            if icons::button(
                ui,
                Icon::Previous,
                "Previous diff section (Shift+F7)",
                previous,
            )
            .clicked()
            {
                self.navigate_section(false);
            }
            if icons::button(ui, Icon::Next, "Next diff section (F7)", next).clicked() {
                self.navigate_section(true);
            }

            let counter = self.active_section.map_or_else(
                || format!("{count} diff sections", count = self.sections.len()),
                |index| {
                    format!(
                        "Section {number} of {count}",
                        number = index + 1,
                        count = self.sections.len()
                    )
                },
            );
            ui.label(RichText::new(counter).size(12.0).color(MUTED));

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if icons::button(ui, Icon::CollapseAll, "Reset to 3 lines of context", true)
                    .clicked()
                {
                    self.context_views[self.selected].reset();
                    self.source_selection = SourceSelection::default();
                    self.scroll_to_section = self
                        .active_section
                        .map(|index| self.sections[index].1.first_change);
                }
                if icons::button(ui, Icon::ExpandAll, "Show entire file", true).clicked() {
                    self.context_views[self.selected].show_all();
                }
            });
        });
    }

    pub(super) fn source(&mut self, ui: &mut egui::Ui) {
        if !self.review.files.is_empty() {
            self.section_toolbar(ui);
        }

        let Some(file) = self.review.files.get(self.selected) else {
            ui.centered_and_justified(|ui| {
                ui.label("No source changes between these commits.");
            });
            return;
        };

        ui.horizontal(|ui| {
            copyable_label(
                ui,
                RichText::new(visible_path(&file.path)).strong().monospace(),
                &file.path,
            );
            ui.label(RichText::new(format!("+{count}", count = file.additions)).color(GREEN));
            ui.label(RichText::new(format!("−{count}", count = file.deletions)).color(RED));
        });
        if file.old_mode != file.new_mode {
            ui.label(
                RichText::new(format!(
                    "File mode: {before} -> {after}",
                    before = file.old_mode.as_deref().unwrap_or("absent"),
                    after = file.new_mode.as_deref().unwrap_or("absent")
                ))
                .color(ACCENT),
            );
        }

        if let Some(reason) = &file.opaque {
            ui.label(RichText::new(reason).color(RED));
            ui.monospace(format!(
                "Before object: {object}",
                object = file.old_oid.as_deref().unwrap_or("absent")
            ));
            ui.monospace(format!(
                "After object:  {object}",
                object = file.new_oid.as_deref().unwrap_or("absent")
            ));
            return;
        }

        ui.separator();
        for (label, content) in [("Baseline", &file.before), ("Candidate", &file.after)] {
            if !content.is_empty() && !content.ends_with('\n') {
                ui.label(
                    RichText::new(format!("{label} has no final newline"))
                        .color(MUTED)
                        .size(12.0),
                );
            }
        }

        ui.scope(|ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            ui.columns(2, |columns| {
                column_header(
                    &mut columns[0],
                    "Baseline",
                    MUTED,
                    file,
                    0,
                    &self.source_selection,
                );
                column_header(
                    &mut columns[1],
                    "Candidate",
                    ACCENT,
                    file,
                    1,
                    &self.source_selection,
                );
            });
        });

        let available = ui.available_width();
        let max_chars = self.context_views[self.selected]
            .entries
            .iter()
            .filter_map(|entry| match entry {
                DisplayRow::Source(index) => Some(&self.diff_rows[*index]),
                DisplayRow::Gap { .. } => None,
            })
            .flat_map(|row| [&row.left, &row.right])
            .filter_map(|line| line.as_ref())
            .map(|line| line.job.text.chars().count())
            .max()
            .unwrap_or(0);
        let character_width =
            ui.fonts_mut(|fonts| fonts.glyph_width(&FontId::monospace(syntax::FONT_SIZE), ' '));
        let column_width =
            (available / 2.0).max(max_chars as f32 * character_width + syntax::TEXT_LEFT + 16.0);

        // Keep selection focus alive when its starting row scrolls out of the virtual list.
        let focus_ids = [0, 1].map(|side| ui.id().with(("source-selection", self.selected, side)));
        for id in focus_ids {
            ui.interact(
                egui::Rect::NOTHING,
                id,
                egui::Sense::focusable_noninteractive(),
            );
        }
        self.source_selection
            .keyboard(ui, [&file.before, &file.after]);

        let entries = &self.context_views[self.selected].entries;
        let active_range = self.active_section.map(|index| {
            let section = self.sections[index].1;
            section.start..section.end
        });
        let target = self.scroll_to_section.take().and_then(|row| {
            entries
                .iter()
                .position(|entry| *entry == DisplayRow::Source(row))
        });

        let mut expansion = None;
        let scroll = ui
            .scope(|ui| {
                // show_rows includes item spacing in its row stride. Code has no gaps.
                ui.spacing_mut().item_spacing.y = 0.0;
                let mut area = egui::ScrollArea::both()
                    .id_salt(("source", self.selected))
                    .auto_shrink([false, false]);
                if let Some(index) = target {
                    area = area.vertical_scroll_offset(
                        (index as f32 * syntax::LINE_HEIGHT - ui.available_height() / 3.0).max(0.0),
                    );
                }
                area.show_rows(ui, syntax::LINE_HEIGHT, entries.len(), |ui, range| {
                    ui.set_min_width(column_width * 2.0);
                    for index in range {
                        let source_index = match entries[index] {
                            DisplayRow::Gap { start, end } => {
                                if let Some(all) = ui
                                    .push_id((self.selected, start, end), |ui| {
                                        context_gap(ui, start, end, column_width * 2.0)
                                    })
                                    .inner
                                {
                                    expansion = Some((start, end, all));
                                }
                                continue;
                            }
                            DisplayRow::Source(row) => row,
                        };
                        let row = &self.diff_rows[source_index];
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 0.0;
                            ui.push_id((self.selected, source_index, 0), |ui| {
                                code_cell(
                                    ui,
                                    row.left.as_ref(),
                                    column_width,
                                    0,
                                    (
                                        focus_ids[0],
                                        active_range
                                            .as_ref()
                                            .is_some_and(|range| range.contains(&source_index)),
                                    ),
                                    file,
                                    &mut self.source_selection,
                                );
                            });
                            ui.push_id((self.selected, source_index, 1), |ui| {
                                code_cell(
                                    ui,
                                    row.right.as_ref(),
                                    column_width,
                                    1,
                                    (
                                        focus_ids[1],
                                        active_range
                                            .as_ref()
                                            .is_some_and(|range| range.contains(&source_index)),
                                    ),
                                    file,
                                    &mut self.source_selection,
                                );
                            });
                        });
                    }
                })
            })
            .inner;

        if let Some((start, end, all)) = expansion {
            self.context_views[self.selected].expand(start, end, all);
            ui.ctx().request_repaint();
        }

        if self.source_selection.dragging
            && let Some(pointer) = ui.input(|input| input.pointer.interact_pos())
            && pointer.x >= scroll.inner_rect.left()
            && pointer.x <= scroll.inner_rect.right()
        {
            let edge = 18.0;
            let delta = if pointer.y < scroll.inner_rect.top() + edge {
                pointer.y - (scroll.inner_rect.top() + edge)
            } else if pointer.y > scroll.inner_rect.bottom() - edge {
                pointer.y - (scroll.inner_rect.bottom() - edge)
            } else {
                0.0
            };
            if delta != 0.0 {
                let mut state = scroll.state;
                let elapsed = ui.input(|input| input.stable_dt).min(0.05);
                state.offset.y = (state.offset.y + delta.clamp(-60.0, 60.0) * elapsed * 12.0)
                    .clamp(
                        0.0,
                        (scroll.content_size.y - scroll.inner_rect.height()).max(0.0),
                    );
                state.store(ui.ctx(), scroll.id);
                ui.ctx().request_repaint();
            }
        }

        if !ui.input(|input| input.pointer.primary_down()) {
            self.source_selection.dragging = false;
        }
    }
}

fn column_header(
    ui: &mut egui::Ui,
    label: &str,
    color: Color32,
    file: &FileChange,
    side: usize,
    selection: &SourceSelection,
) {
    let source = if side == 0 { &file.before } else { &file.after };
    icons::row(ui, |ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        ui.label(
            RichText::new(label.to_uppercase())
                .color(color)
                .size(11.0)
                .strong(),
        );
        let (response, _) =
            egui::containers::menu::MenuButton::from_button(icons::control()).ui(ui, |ui| {
                let selected = selection.text(source, side);
                if ui
                    .add_enabled(selected.is_some(), egui::Button::new("Copy selection"))
                    .clicked()
                {
                    ui.ctx().copy_text(selected.unwrap().to_owned());
                    ui.close();
                }
                if ui.button("Copy file contents").clicked() {
                    ui.ctx().copy_text(source.clone());
                    ui.close();
                }
                ui.separator();
                if ui.button("Copy file path").clicked() {
                    ui.ctx().copy_text(file.path.clone());
                    ui.close();
                }
            });
        icons::decorate(ui, response, Icon::More, &format!("{label} file actions"));
    });
}

fn context_gap(ui: &mut egui::Ui, start: usize, end: usize, width: f32) -> Option<bool> {
    let mut expand = None;
    let (rect, _) =
        ui.allocate_exact_size(Vec2::new(width, syntax::LINE_HEIGHT), egui::Sense::hover());
    ui.painter().rect_filled(rect, 0.0, PANEL);
    ui.painter()
        .hline(rect.x_range(), rect.top(), Stroke::new(1.0_f32, BORDER));
    ui.painter()
        .hline(rect.x_range(), rect.bottom(), Stroke::new(1.0_f32, BORDER));

    // Keep controls inside the visible viewport even when long code scrolls horizontally.
    let visible = rect.intersect(ui.clip_rect());
    ui.scope_builder(egui::UiBuilder::new().max_rect(visible), |ui| {
        ui.spacing_mut().interact_size.y = syntax::LINE_HEIGHT;
        ui.spacing_mut().button_padding.y = 0.0;
        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
            ui.add_space(8.0);
            if ui
                .add(
                    egui::Button::new(
                        RichText::new(format!(
                            "{count} unchanged {unit}",
                            count = end - start,
                            unit = if end - start == 1 { "line" } else { "lines" }
                        ))
                        .color(MUTED)
                        .size(12.0),
                    )
                    .frame(false),
                )
                .on_hover_text("Reveal up to 20 more lines next to each surrounding change")
                .clicked()
            {
                expand = Some(false);
            }
            let response = ui.add(icons::control().min_size(Vec2::splat(syntax::LINE_HEIGHT)));
            if icons::decorate(
                ui,
                response,
                Icon::ExpandAll,
                "Show this entire unchanged section",
            )
            .clicked()
            {
                expand = Some(true);
            }
        });
    });

    expand
}

fn code_cell(
    ui: &mut egui::Ui,
    line: Option<&CodeLine>,
    width: f32,
    side: usize,
    focus: (egui::Id, bool),
    file: &FileChange,
    selection: &mut SourceSelection,
) {
    let (focus_id, active) = focus;
    let (rect, response) = ui.allocate_exact_size(
        Vec2::new(width, syntax::LINE_HEIGHT),
        egui::Sense::click_and_drag(),
    );
    let background = match line.map(|line| line.kind) {
        Some(ChangeTag::Delete) => Color32::from_rgb(58, 31, 40),
        Some(ChangeTag::Insert) => Color32::from_rgb(23, 49, 40),
        _ => BACKGROUND,
    };
    ui.painter().rect_filled(rect, 0.0, background);
    if active {
        ui.painter().rect_filled(
            egui::Rect::from_min_size(rect.min, Vec2::new(2.0, rect.height())),
            0.0,
            ACCENT,
        );
    }
    if side == 1 {
        ui.painter().line_segment(
            [rect.left_top(), rect.left_bottom()],
            Stroke::new(1.0_f32, BORDER),
        );
    }
    ui.painter().line_segment(
        [rect.right_top(), rect.right_bottom()],
        Stroke::new(1.0_f32, BORDER),
    );

    let Some(line) = line else {
        return;
    };
    ui.painter().text(
        rect.left_center() + Vec2::new(34.0, 0.0),
        egui::Align2::RIGHT_CENTER,
        line.number.to_string(),
        FontId::monospace(12.0),
        MUTED,
    );
    let (marker, marker_color) = match line.kind {
        ChangeTag::Delete => ("−", RED),
        ChangeTag::Insert => ("+", GREEN),
        ChangeTag::Equal => ("", MUTED),
    };
    ui.painter().text(
        rect.left_center() + Vec2::new(46.0, 0.0),
        egui::Align2::CENTER_CENTER,
        marker,
        FontId::monospace(12.0),
        marker_color,
    );

    let mut galley = ui.painter().layout_job(line.job.clone());
    let origin = rect.left_top() + Vec2::new(syntax::TEXT_LEFT, 0.0);
    let source = if side == 0 { &file.before } else { &file.after };
    let raw_line = source[line.source_start..].split('\n').next().unwrap_or("");
    let pointer = ui.input(|input| input.pointer.interact_pos());
    let pointer_byte = pointer.map(|position| {
        line.source_start
            + selection::source_byte(raw_line, galley.cursor_from_pos(position - origin).index)
    });
    let at_vertical_edge = pointer.is_some_and(|position| {
        position.x >= rect.left()
            && position.x <= rect.right()
            && ((position.y < ui.clip_rect().top()
                && rect.contains(egui::pos2(position.x, ui.clip_rect().top())))
                || (position.y > ui.clip_rect().bottom()
                    && rect.contains(egui::pos2(position.x, ui.clip_rect().bottom()))))
    });

    if response.contains_pointer() || selection.dragging && at_vertical_edge {
        if response.contains_pointer() && ui.input(|input| input.pointer.primary_pressed()) {
            let byte = pointer_byte.unwrap_or(line.source_start);
            if !ui.input(|input| input.modifiers.shift) || selection.side != side {
                selection.anchor = byte;
            }
            selection.side = side;
            selection.cursor = byte;
            selection.dragging = true;
            selection.focus = Some(focus_id);
            ui.memory_mut(|memory| memory.request_focus(focus_id));
        }
        if selection.dragging && selection.side == side {
            selection.cursor = pointer_byte.unwrap_or(selection.cursor);
            ui.ctx().request_repaint();
        }
    }

    if response.triple_clicked() {
        selection.anchor = line.source_start;
        selection.cursor = (line.source_start + raw_line.len() + 1).min(source.len());
    } else if response.double_clicked() {
        let range = selection::word_range(source, pointer_byte.unwrap_or(line.source_start));
        selection.anchor = range.start;
        selection.cursor = range.end;
    }

    response.clone().on_hover_cursor(egui::CursorIcon::Text);
    response.context_menu(|ui| {
        let selected = selection.text(source, side);
        if ui
            .add_enabled(selected.is_some(), egui::Button::new("Copy selection"))
            .clicked()
        {
            ui.ctx().copy_text(selected.unwrap().to_owned());
            ui.close();
        }
        if ui.button("Copy line").clicked() {
            ui.ctx().copy_text(raw_line.to_owned());
            ui.close();
        }
        if ui
            .button(if side == 0 {
                "Copy baseline"
            } else {
                "Copy candidate"
            })
            .clicked()
        {
            ui.ctx().copy_text(source.clone());
            ui.close();
        }
        if ui.button("Select all").clicked() {
            selection.select_all(source, side, focus_id);
            ui.memory_mut(|memory| memory.request_focus(focus_id));
            ui.close();
        }
        ui.separator();
        if ui.button("Copy file path").clicked() {
            ui.ctx().copy_text(file.path.clone());
            ui.close();
        }
    });

    if selection.side == side {
        let range = selection.range();
        let start = range
            .start
            .saturating_sub(line.source_start)
            .min(raw_line.len());
        let end = range
            .end
            .saturating_sub(line.source_start)
            .min(raw_line.len());
        if start < end {
            egui::text_selection::visuals::paint_text_selection(
                &mut galley,
                ui.visuals(),
                &egui::text::CCursorRange::two(
                    egui::text::CCursor::new(selection::displayed_cursor(raw_line, start)),
                    egui::text::CCursor::new(selection::displayed_cursor(raw_line, end)),
                ),
                None,
            );
        }
        if range.start <= line.source_start + raw_line.len()
            && range.end > line.source_start + raw_line.len()
        {
            ui.painter().rect_filled(
                egui::Rect::from_min_size(
                    origin + Vec2::new(galley.size().x, 0.0),
                    Vec2::new(7.9, galley.size().y.max(13.0)),
                ),
                0.0,
                ui.visuals().selection.bg_fill,
            );
        }
    }

    ui.painter().galley(origin, galley, Color32::WHITE);
}
