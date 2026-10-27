//! Highlight complete source sides independently, then overlay inline diff emphasis.
use crate::theme::{FOREGROUND, GREEN, MUTED};
use eframe::egui::{self, Color32, FontId};
use similar::ChangeTag;
use std::sync::OnceLock;
use two_face::re_exports::syntect::{
    easy::HighlightLines,
    highlighting::{Color, StyleModifier, Theme, ThemeItem, ThemeSettings},
    parsing::SyntaxSet,
};

pub const FONT_SIZE: f32 = 13.0;

pub const LINE_HEIGHT: f32 = 22.0;

pub const TEXT_LEFT: f32 = 60.0;

fn color(value: Color32) -> Color {
    let [r, g, b, a] = value.to_array();
    Color { r, g, b, a }
}

fn theme() -> &'static Theme {
    static THEME: OnceLock<Theme> = OnceLock::new();
    THEME.get_or_init(|| Theme {
        settings: ThemeSettings {
            foreground: Some(color(FOREGROUND)),
            ..Default::default()
        },
        scopes: [
            ("comment", MUTED),
            ("string", GREEN),
            ("keyword, storage", Color32::from_rgb(197, 173, 240)),
            ("constant", Color32::from_rgb(245, 202, 142)),
            ("entity.name, support", Color32::from_rgb(140, 203, 239)),
            (
                "punctuation.section.interpolation",
                Color32::from_rgb(197, 173, 240),
            ),
        ]
        .into_iter()
        .map(|(scope, foreground)| ThemeItem {
            scope: scope.parse().expect("embedded syntax theme scope"),
            style: StyleModifier {
                foreground: Some(color(foreground)),
                ..Default::default()
            },
        })
        .collect(),
        ..Default::default()
    })
}

fn append(job: &mut egui::text::LayoutJob, text: &str, color: Color32) {
    job.append(
        &text.trim_end_matches('\n').replace('\t', "    "),
        0.0,
        egui::TextFormat {
            font_id: FontId::monospace(FONT_SIZE),
            line_height: Some(LINE_HEIGHT),
            valign: egui::Align::Center,
            color,
            ..Default::default()
        },
    );
}

/// Filename/extension and shebang detection never reads another file or runs code.
/// State follows the original source, including multiline strings and comments.
pub fn highlight(path: &str, source: &str) -> Vec<egui::text::LayoutJob> {
    static SYNTAXES: OnceLock<SyntaxSet> = OnceLock::new();
    let syntaxes = SYNTAXES.get_or_init(two_face::syntax::extra_newlines);
    let filename = path.rsplit('/').next().unwrap_or(path);
    let extension = if filename == "flake.lock" {
        "json"
    } else {
        filename.rsplit_once('.').map_or(filename, |(_, ext)| ext)
    };
    let syntax = syntaxes
        .find_syntax_by_extension(extension)
        .or_else(|| syntaxes.find_syntax_by_first_line(source.split('\n').next().unwrap_or("")))
        .unwrap_or_else(|| syntaxes.find_syntax_plain_text());

    let mut highlighter = HighlightLines::new(syntax, theme());
    source
        .split_inclusive('\n')
        .map(|line| {
            let mut job = egui::text::LayoutJob::default();
            match highlighter.highlight_line(line, syntaxes) {
                Ok(spans) => {
                    for (style, text) in spans {
                        let c = style.foreground;
                        append(&mut job, text, Color32::from_rgb(c.r, c.g, c.b));
                    }
                }
                Err(_) => append(&mut job, line, FOREGROUND),
            }
            job
        })
        .collect()
}

/// Split at both syntax and inline-change boundaries; syntax colour stays visible.
pub fn diff_line(
    highlighted: &egui::text::LayoutJob,
    segments: &[(bool, String)],
    kind: ChangeTag,
) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    let mut start = 0;
    for (emphasized, text) in segments {
        let end = start + text.len();
        for section in &highlighted.sections {
            let a = start.max(section.byte_range.start);
            let b = end.min(section.byte_range.end);
            if a >= b {
                continue;
            }

            let mut format = section.format.clone();
            if *emphasized {
                format.background = match kind {
                    ChangeTag::Delete => Color32::from_rgb(100, 43, 53),
                    ChangeTag::Insert => Color32::from_rgb(35, 87, 62),
                    ChangeTag::Equal => Color32::TRANSPARENT,
                };
            }
            job.append(&text[a - start..b - start], 0.0, format);
        }
        start = end;
    }

    job
}
