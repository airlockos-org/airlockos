//! Source selections refer to original UTF-8 bytes, never diff gutters or alignment gaps.
use eframe::egui::{self, RichText};

/// Byte-offset selection shared by the source panes, excluding diff gutters and gaps.
#[derive(Default)]
pub struct SourceSelection {
    /// Source pane index: zero for baseline, one for candidate.
    pub side: usize,
    /// UTF-8 byte offset at which the selection began.
    pub anchor: usize,
    /// UTF-8 byte offset of the moving selection endpoint.
    pub cursor: usize,
    /// Whether pointer motion should continue extending this selection.
    pub dragging: bool,
    /// Widget identity allowed to handle selection keyboard shortcuts.
    pub focus: Option<egui::Id>,
}

impl SourceSelection {
    /// Return the ordered half-open UTF-8 byte range between anchor and cursor.
    pub fn range(&self) -> std::ops::Range<usize> {
        self.anchor.min(self.cursor)..self.anchor.max(self.cursor)
    }

    /// Borrow selected source text only for the active side and valid nonempty byte boundaries.
    pub fn text<'a>(&self, source: &'a str, side: usize) -> Option<&'a str> {
        (self.side == side && self.anchor != self.cursor)
            .then(|| source.get(self.range()))
            .flatten()
    }

    /// Select the complete supplied source and give its widget keyboard selection focus.
    pub fn select_all(&mut self, source: &str, side: usize, id: egui::Id) {
        self.side = side;
        self.anchor = 0;
        self.cursor = source.len();
        self.focus = Some(id);
    }

    /// Handle select-all and copy shortcuts only while the owning source widget has focus.
    pub fn keyboard(&mut self, ui: &mut egui::Ui, sources: [&str; 2]) {
        if self.focus.is_none() || ui.memory(|memory| memory.focused()) != self.focus {
            return;
        }

        if ui.input_mut(|input| input.consume_key(egui::Modifiers::COMMAND, egui::Key::A)) {
            self.anchor = 0;
            self.cursor = sources[self.side].len();
        }

        if let Some(text) = self.text(sources[self.side], self.side) {
            let copy = ui.input_mut(|input| {
                let mut copy = input.consume_key(egui::Modifiers::COMMAND, egui::Key::C);
                input.events.retain(|event| {
                    if matches!(event, egui::Event::Copy) {
                        copy = true;
                        false
                    } else {
                        true
                    }
                });
                copy
            });
            if copy {
                ui.ctx().copy_text(text.to_owned());
            }
        }
    }
}

/// Map egui's displayed character cursor through the four-space tab expansion.
pub fn source_byte(line: &str, displayed_character: usize) -> usize {
    let mut displayed = 0;
    for (byte, character) in line.char_indices() {
        let width = if character == '\t' { 4 } else { 1 };
        if displayed_character < displayed + width {
            return if width > 1 && displayed_character - displayed >= width / 2 {
                byte + character.len_utf8()
            } else {
                byte
            };
        }
        displayed += width;
    }

    line.len()
}

pub fn displayed_cursor(line: &str, byte: usize) -> usize {
    line[..byte]
        .chars()
        .map(|character| if character == '\t' { 4 } else { 1 })
        .sum()
}

pub fn word_range(source: &str, byte: usize) -> std::ops::Range<usize> {
    let word = |character: char| character.is_alphanumeric() || character == '_';
    let Some(character) = source[byte..].chars().next() else {
        return byte..byte;
    };

    let same = |other: char| {
        if word(character) {
            word(other)
        } else if character.is_whitespace() {
            other.is_whitespace() && other != '\n'
        } else {
            other == character
        }
    };

    let start = source[..byte]
        .char_indices()
        .rev()
        .take_while(|(_, character)| same(*character))
        .last()
        .map_or(byte, |(index, _)| index);
    let end = source[byte..]
        .char_indices()
        .take_while(|(_, character)| same(*character))
        .last()
        .map_or(byte, |(index, character)| {
            byte + index + character.len_utf8()
        });
    start..end
}

/// Native selection and copy shortcuts, with an immutable TextBuffer.
pub fn read_only_text(ui: &mut egui::Ui, id: impl std::hash::Hash, text: &str, multiline: bool) {
    let mut buffer = text;
    let edit = if multiline {
        egui::TextEdit::multiline(&mut buffer)
    } else {
        egui::TextEdit::singleline(&mut buffer)
    };

    // egui's TextEdit starts a new selection on any pointer button by default.
    // A secondary click should preserve the selection the context menu will copy.
    let secondary_pressed = ui.input(|input| input.pointer.secondary_pressed());
    let widget_id = ui.make_persistent_id(id);
    let previous_cursor =
        egui::TextEdit::load_state(ui.ctx(), widget_id).and_then(|state| state.cursor.char_range());
    let mut output = edit
        .id(widget_id)
        .font(egui::TextStyle::Monospace)
        .desired_width(f32::INFINITY)
        .frame(false)
        .show(ui);
    if secondary_pressed && output.response.contains_pointer() {
        output.state.cursor.set_char_range(previous_cursor);
        output.state.clone().store(ui.ctx(), output.response.id);
    }

    text_edit_menu(&mut output, text, false);
}

pub fn text_edit_menu(output: &mut egui::text_edit::TextEditOutput, text: &str, editable: bool) {
    output.response.context_menu(|ui| {
        let selected = output
            .state
            .cursor
            .char_range()
            .filter(|range| !range.is_empty())
            .map(|range| range.slice_str(text));
        if ui
            .add_enabled(selected.is_some(), egui::Button::new("Copy selection"))
            .clicked()
        {
            ui.ctx().copy_text(selected.unwrap().to_owned());
            ui.close();
        }

        if ui.button("Copy all").clicked() {
            ui.ctx().copy_text(text.to_owned());
            ui.close();
        }

        if editable {
            if ui
                .add_enabled(selected.is_some(), egui::Button::new("Cut selection"))
                .clicked()
            {
                output.response.request_focus();
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::RequestCut);
                ui.close();
            }
            if ui.button("Paste").clicked() {
                output.response.request_focus();
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::RequestPaste);
                ui.close();
            }
        }

        if ui.button("Select all").clicked() {
            output
                .state
                .cursor
                .set_char_range(Some(egui::text::CCursorRange::two(
                    egui::text::CCursor::new(0),
                    egui::text::CCursor::new(text.chars().count()),
                )));
            output.state.clone().store(ui.ctx(), output.response.id);
            output.response.request_focus();
            ui.close();
        }
    });
}

pub fn copyable_label(ui: &mut egui::Ui, label: RichText, text: &str) {
    ui.add(egui::Label::new(label).selectable(true))
        .context_menu(|ui| {
            if ui.button("Copy text").clicked() {
                ui.ctx().copy_text(text.to_owned());
                ui.close();
            }
        });
}
