//! Check folding and navigation without a display or an external compiler driver.

use super::{ContextView, DisplayRow, Section, adjacent_section};

/// Mark changed rows while leaving the rest unchanged.
fn view(count: usize, changes: &[usize]) -> ContextView {
    ContextView::new((0..count).map(|index| changes.contains(&index)).collect())
}

/// Interleave visible ranges and folded gaps in readable expectations.
fn rows(parts: &[(usize, usize, bool)]) -> Vec<DisplayRow> {
    parts
        .iter()
        .flat_map(|&(start, end, gap)| {
            if gap {
                vec![DisplayRow::Gap { start, end }]
            } else {
                (start..end).map(DisplayRow::Source).collect()
            }
        })
        .collect()
}

/// Touching context belongs to one stable navigation destination.
#[test]
fn sections_merge_touching_context_and_handle_boundaries() {
    for (count, changes, expected) in [
        (60, vec![10, 11, 12, 30], vec![(7, 16, 10), (27, 34, 30)]),
        (30, vec![10, 17], vec![(7, 21, 10)]),
        (30, vec![10, 18], vec![(7, 14, 10), (15, 22, 18)]),
        (4, vec![0, 1, 2, 3], vec![(0, 4, 0)]),
        (4, vec![], vec![]),
        (0, vec![], vec![]),
    ] {
        let actual = view(count, &changes).sections;
        let expected: Vec<_> = expected
            .into_iter()
            .map(|(start, end, first_change)| Section {
                start,
                end,
                first_change,
            })
            .collect();
        assert_eq!(actual, expected, "changes: {changes:?}");
    }
}

/// Folding preserves source offsets for changes and metadata-only files.
#[test]
fn folded_rows_preserve_source_offsets() {
    assert_eq!(
        view(40, &[10, 15, 30]).entries,
        rows(&[
            (0, 7, true),
            (7, 19, false),
            (19, 27, true),
            (27, 34, false),
            (34, 40, true),
        ])
    );
    assert_eq!(view(4, &[0, 1, 2, 3]).entries, rows(&[(0, 4, false)]));
    assert_eq!(
        view(20, &[0, 19]).entries,
        rows(&[(0, 4, false), (4, 16, true), (16, 20, false)])
    );
    assert_eq!(view(4, &[]).entries, rows(&[(0, 4, true)]));
    assert!(view(0, &[]).entries.is_empty());
}

/// Expansion preserves navigation anchors and reset restores the folded rows.
#[test]
fn expansion_and_reset_preserve_sections() {
    let mut middle = view(160, &[10, 140]);
    let initial = middle.entries.clone();
    let sections = middle.sections.clone();
    middle.expand(14, 137, false);
    assert_eq!(
        middle.entries,
        rows(&[
            (0, 7, true),
            (7, 34, false),
            (34, 117, true),
            (117, 144, false),
            (144, 160, true),
        ])
    );
    assert_eq!(middle.sections, sections);

    middle.reset();
    assert_eq!(middle.entries, initial);
    middle.expand(14, 137, true);
    assert_eq!(
        middle.entries,
        rows(&[(0, 7, true), (7, 144, false), (144, 160, true)])
    );
    assert_eq!(middle.sections, sections);

    middle.show_all();
    assert_eq!(middle.entries, rows(&[(0, 160, false)]));
    assert_eq!(middle.sections, sections);

    let mut prefix = view(100, &[50]);
    prefix.expand(0, 47, false);
    assert_eq!(
        prefix.entries,
        rows(&[(0, 27, true), (27, 54, false), (54, 100, true)])
    );
    prefix.expand(0, 27, false);
    prefix.expand(0, 7, false);
    assert_eq!(prefix.entries, rows(&[(0, 54, false), (54, 100, true)]));

    let mut suffix = view(100, &[50]);
    suffix.expand(54, 100, false);
    assert_eq!(
        suffix.entries,
        rows(&[(0, 47, true), (47, 74, false), (74, 100, true)])
    );
}

/// Navigation crosses files and skips files without changed rows.
#[test]
fn navigation_respects_file_and_section_boundaries() {
    let sections = [(0, 7, 15, 10), (0, 27, 34, 30), (2, 0, 7, 3), (4, 5, 12, 8)].map(
        |(file, start, end, first_change)| {
            (
                file,
                Section {
                    start,
                    end,
                    first_change,
                },
            )
        },
    );
    for (current, file, forward, expected) in [
        (Some(0), 0, false, None),
        (Some(0), 0, true, Some(1)),
        (Some(1), 0, true, Some(2)),
        (Some(2), 2, false, Some(1)),
        (Some(3), 4, true, None),
        (None, 1, true, Some(2)),
        (None, 1, false, Some(1)),
        (None, 5, true, None),
        (None, 0, true, Some(0)),
    ] {
        assert_eq!(
            adjacent_section(&sections, current, file, forward),
            expected
        );
    }
}
