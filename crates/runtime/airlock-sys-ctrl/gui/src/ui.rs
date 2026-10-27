//! Coordinate the review session while each view owns its rendering and interaction.

mod chrome;

mod sidebar;

mod source;

mod plan;

mod record;

use crate::{
    Decision,
    approval::{ApprovalDecision, Session},
    diff_context::{ContextView, DisplayRow, Section, adjacent_section},
    effects::{self, PlannedEffects, names_text},
    file_tree::{FileTree, RowKind, TreeRow},
    icons::{self, Icon},
    model::{FileChange, Review},
    selection::{self, SourceSelection, copyable_label, read_only_text},
    syntax,
    theme::{
        self, ACCENT, ACCENT_TINT, BACKGROUND, BORDER, BRAND, BUTTON_TEXT, FOREGROUND, GREEN,
        MUTED, PANEL, RED,
    },
};
use eframe::egui::{self, Color32, FontId, RichText, Stroke, Vec2};
use similar::{ChangeTag, TextDiff};
use std::collections::BTreeSet;
use std::path::PathBuf;

use plan::effects_summary;
use source::{DiffRow, operations, rows};

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Source,
    Plan,
    Record,
}

/// Review window state: immutable source material, hunk navigation and human decision UI.
pub struct Controller {
    /// Uploaded brand texture shared by the main and About windows.
    logo: egui::TextureHandle,
    /// Immutable source and deployment material currently under review.
    review: Review,
    /// Prepared complete review text, or an error preventing faithful copying.
    clipboard_review: Result<String, String>,
    /// User-facing VM and reboot summary derived from the supplied plan.
    effects: Option<PlannedEffects>,
    /// Index of the file currently displayed in the diff panes.
    selected: usize,
    /// Active main view, such as source changes or deployment effects.
    tab: Tab,
    /// Text used to filter the changed-file tree.
    filter: String,
    /// Whether file-search editing should consume keyboard navigation.
    filter_has_focus: bool,
    /// Hierarchy of the changed files, retaining their review indices.
    file_tree: FileTree,
    /// Directory paths currently folded in the file tree.
    collapsed_folders: BTreeSet<String>,
    /// One-shot request to reveal the selected tree entry.
    scroll_to_selection: bool,
    /// Aligned baseline and candidate rows for the selected file.
    diff_rows: Vec<DiffRow>,
    /// Per-file diff operations cached for building highlighted rows.
    diff_ops: Vec<Vec<similar::DiffOp>>,
    /// Per-file context folding state retained while switching files.
    context_views: Vec<ContextView>,
    /// Repository-wide hunk destinations paired with file indices.
    sections: Vec<(usize, Section)>,
    /// Current repository-wide hunk navigation position, if any.
    active_section: Option<usize>,
    /// Hunk row to reveal on the next source-panel frame.
    scroll_to_section: Option<usize>,
    /// Byte-accurate selection and focus state shared by the source panes.
    source_selection: SourceSelection,
    /// Local review decision awaiting confirmation, when applicable.
    confirm: Option<Decision>,
    /// Whether the About window is currently visible.
    about_open: bool,
    /// Controller launch session, absent in standalone local review mode.
    approval: Option<Session>,
    /// Most recent local decision record shown to the user.
    receipt: Option<serde_json::Value>,
    /// Copied-item label and expiry time for temporary clipboard feedback.
    copy_feedback: Option<(&'static str, f64)>,
    /// User-facing diagnostic from the most recent failed action.
    notice: Option<String>,
    /// Optional destination for local review decision records.
    decisions_dir: Option<PathBuf>,
    /// Optional screenshot output requested by inspection tooling.
    screenshot: Option<PathBuf>,
    /// Rendered frame count used to delay automated screenshot capture.
    frames: usize,
    /// Whether the capture request was already submitted to the renderer.
    screenshot_requested: bool,
}

impl Controller {
    /// Build review-window state and cache source layouts without submitting a deployment.
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        review: Review,
        decisions_dir: Option<PathBuf>,
        screenshot: Option<PathBuf>,
        approval: Option<Session>,
    ) -> Self {
        theme::apply(&cc.egui_ctx);
        let clipboard_review = review
            .clipboard_report()
            .map_err(|error| format!("{error:#}"));
        let effects = review.plan().map(PlannedEffects::from_plan);

        let diff_ops: Vec<_> = review.files.iter().map(operations).collect();
        let diff_rows = review
            .files
            .first()
            .map(|file| rows(file, &diff_ops[0]))
            .unwrap_or_default();
        let mut sections = Vec::new();
        let context_views = diff_ops
            .iter()
            .enumerate()
            .map(|(file, ops)| {
                let flags: Vec<_> = ops
                    .iter()
                    .flat_map(|op| {
                        std::iter::repeat_n(
                            op.tag() != similar::DiffTag::Equal,
                            op.old_range().len().max(op.new_range().len()),
                        )
                    })
                    .collect();
                let view = ContextView::new(flags);
                sections.extend(view.sections.iter().map(|section| (file, *section)));
                view
            })
            .collect();

        let active_section = sections.iter().position(|(file, _)| *file == 0);
        let file_tree = FileTree::new(&review.files);

        let icon = crate::branding::logo()
            .expect("the embedded logo was checked before opening the window");
        let logo = cc.egui_ctx.load_texture(
            "airlock-logo",
            egui::ColorImage::from_rgba_unmultiplied(
                [icon.width as usize, icon.height as usize],
                &icon.rgba,
            ),
            egui::TextureOptions::LINEAR,
        );

        Self {
            logo,
            review,
            clipboard_review,
            effects,
            selected: 0,
            tab: Tab::Source,
            filter: String::new(),
            filter_has_focus: false,
            file_tree,
            collapsed_folders: BTreeSet::new(),
            scroll_to_selection: false,
            diff_rows,
            diff_ops,
            context_views,
            sections,
            active_section,
            scroll_to_section: None,
            source_selection: SourceSelection::default(),
            confirm: None,
            about_open: false,
            approval,
            receipt: None,
            copy_feedback: None,
            notice: None,
            decisions_dir,
            screenshot,
            frames: 0,
            screenshot_requested: false,
        }
    }

    fn blocker(&self) -> Option<&str> {
        if let Some(session) = &self.approval {
            if session.scope().is_none() {
                return Some("Enter valid permitted VM names in Deployment plan.");
            }
            if self.review.files.iter().any(|file| file.opaque.is_some()) {
                return Some("Some changed files cannot be displayed. Approval is disabled.");
            }
            None
        } else {
            self.review.approval_blocker()
        }
    }
}

impl eframe::App for Controller {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.header(ctx);
        self.footer(ctx);
        self.sidebar(ctx);
        if self.tab == Tab::Source
            && self.confirm.is_none()
            && !self.about_open
            && !self.filter_has_focus
        {
            if ctx.input_mut(|input| input.consume_key(egui::Modifiers::SHIFT, egui::Key::F7)) {
                self.navigate_section(false);
                ctx.request_repaint();
            } else if ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::F7))
            {
                self.navigate_section(true);
                ctx.request_repaint();
            }
        }

        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(BACKGROUND).inner_margin(22.0))
            .show(ctx, |ui| {
                self.review_title(ui);
                ui.separator();
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.tab, Tab::Source, "Source changes");
                    ui.selectable_value(&mut self.tab, Tab::Plan, "Deployment plan");
                    ui.selectable_value(&mut self.tab, Tab::Record, "Review record");
                    let show_copy_label = ui.available_width() >= 130.0;
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let live_copy = self.approval.as_ref().map(|session| {
                            self.clipboard_review
                                .as_ref()
                                .map_err(Clone::clone)
                                .and_then(|base| {
                                    session.copy_text(base).map_err(|error| error.to_string())
                                })
                        });
                        let clipboard = live_copy.as_ref().unwrap_or(&self.clipboard_review);
                        let value = clipboard.as_ref().ok();
                        let response = copy_button(
                            ui,
                            "entire review",
                            value.map(String::as_str),
                            &mut self.copy_feedback,
                        );
                        if let Err(error) = clipboard {
                            response.on_disabled_hover_text(error);
                        }
                        if show_copy_label {
                            ui.label(RichText::new("Copy review").size(12.0).color(MUTED));
                        }
                    });
                });
                ui.add_space(12.0);
                match self.tab {
                    Tab::Source => self.source(ui),
                    Tab::Plan => self.plan(ui),
                    Tab::Record => self.record(ui),
                }
            });

        self.confirmation(ctx);
        self.about(ctx);

        self.frames += 1;
        if self.screenshot.is_some() && !self.screenshot_requested {
            if self.frames >= 4 {
                ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::default()));
                self.screenshot_requested = true;
            }
            ctx.request_repaint();
        }

        for event in ctx.input(|input| input.events.clone()) {
            if let egui::Event::Screenshot { image, .. } = event
                && let Some(path) = self.screenshot.take()
            {
                let bytes: Vec<u8> = image
                    .pixels
                    .iter()
                    .flat_map(|pixel| pixel.to_array())
                    .collect();
                if let Err(error) = image::save_buffer(
                    &path,
                    &bytes,
                    image.width() as u32,
                    image.height() as u32,
                    image::ColorType::Rgba8,
                ) {
                    eprintln!("airlock-sys-ctrl-gui: saving screenshot failed: {error}");
                }
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
    }
}

fn copy_button(
    ui: &mut egui::Ui,
    label: &'static str,
    value: Option<&str>,
    feedback: &mut Option<(&'static str, f64)>,
) -> egui::Response {
    let now = ui.input(|input| input.time);
    let remaining = feedback
        .filter(|(field, _)| *field == label)
        .map_or(0.0, |(_, time)| 1.6 - (now - time));
    let copied = remaining > 0.0;
    let tooltip = if copied {
        format!("{label} copied")
    } else {
        format!("Copy {label}")
    };

    let response = icons::button(
        ui,
        if copied { Icon::Check } else { Icon::Copy },
        &tooltip,
        value.is_some(),
    );
    if response.clicked() {
        ui.ctx().copy_text(value.unwrap().to_owned());
        *feedback = Some((label, now));
        ui.ctx().request_repaint();
    }
    if copied {
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_secs_f64(remaining));
    }

    response
}

fn visible_path(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| {
            if character.is_control() || character == '\\' {
                character.escape_default().collect::<Vec<_>>()
            } else {
                vec![character]
            }
        })
        .collect()
}
