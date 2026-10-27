//! Presentation of changed paths; indices always refer to the original review.
use crate::model::FileChange;
use std::collections::{BTreeMap, BTreeSet};

/// Ordered hierarchy of changed paths used to filter and navigate the review.
#[derive(Default)]
pub struct FileTree {
    /// Child directories ordered by their visible path component.
    folders: BTreeMap<String, FileTree>,
    /// Leaf labels paired with indices in the review file list.
    files: Vec<(String, usize)>,
    /// Review file indices under this directory, used for filtering and counts.
    descendants: Vec<usize>,
}

/// Folder expansion state or file selection target represented by a tree row.
#[derive(Clone, Copy)]
pub enum RowKind {
    Folder {
        /// Whether this folder is expanded in the current tree view.
        open: bool,
        /// Number of matching descendant files displayed beside the folder.
        count: usize,
    },
    File {
        /// Index in the immutable review file list selected by this row.
        index: usize,
    },
}

/// Flattened tree entry carrying its path, nesting and interaction target.
pub struct TreeRow {
    /// Path component displayed for this file or folder.
    pub label: String,
    /// Full repository-relative path used as stable UI identity.
    pub path: String,
    /// Nesting level controlling indentation in the file tree.
    pub depth: usize,
    /// File selection or folder expansion state represented by this row.
    pub kind: RowKind,
}

impl FileTree {
    /// Build an ordered hierarchy retaining indices into the original review file list.
    pub fn new(files: &[FileChange]) -> Self {
        let mut root = Self::default();
        for (index, file) in files.iter().enumerate() {
            let mut parts = file.path.split('/').peekable();
            let mut node = &mut root;
            node.descendants.push(index);
            while let Some(part) = parts.next() {
                if parts.peek().is_none() {
                    node.files.push((part.to_owned(), index));
                } else {
                    node = node.folders.entry(part.to_owned()).or_default();
                    node.descendants.push(index);
                }
            }
        }

        root.sort();
        root
    }

    fn sort(&mut self) {
        self.files.sort_by(|left, right| left.0.cmp(&right.0));
        for folder in self.folders.values_mut() {
            folder.sort();
        }
    }

    /// Return visible rows after search filtering and folder expansion have been applied.
    pub fn rows(
        &self,
        files: &[FileChange],
        query: &str,
        collapsed: &BTreeSet<String>,
    ) -> Vec<TreeRow> {
        let terms: Vec<_> = query.split_whitespace().map(str::to_lowercase).collect();
        let matching: Vec<_> = files
            .iter()
            .map(|file| {
                let path = file.path.to_lowercase();
                terms.iter().all(|term| path.contains(term))
            })
            .collect();

        let mut rows = Vec::new();
        // Search opens matching ancestors without changing the saved expansion state.
        self.append("", 0, &matching, collapsed, !terms.is_empty(), &mut rows);
        rows
    }

    fn append(
        &self,
        prefix: &str,
        depth: usize,
        matching: &[bool],
        collapsed: &BTreeSet<String>,
        searching: bool,
        rows: &mut Vec<TreeRow>,
    ) {
        for (name, child) in &self.folders {
            let mut path = join(prefix, name);
            let mut label = name.clone();
            let mut folder = child;

            // Compact chains with no files/siblings, as in a source-code explorer.
            while folder.files.is_empty() && folder.folders.len() == 1 {
                let (name, child) = folder.folders.first_key_value().unwrap();
                path = join(&path, name);
                label = join(&label, name);
                folder = child;
            }

            let count = folder
                .descendants
                .iter()
                .filter(|index| matching[**index])
                .count();
            if count == 0 {
                continue;
            }

            let open = searching || !collapsed.contains(&path);
            rows.push(TreeRow {
                label,
                path: path.clone(),
                depth,
                kind: RowKind::Folder { open, count },
            });
            if open {
                folder.append(&path, depth + 1, matching, collapsed, searching, rows);
            }
        }

        for (name, index) in &self.files {
            if matching[*index] {
                rows.push(TreeRow {
                    label: name.clone(),
                    path: join(prefix, name),
                    depth,
                    kind: RowKind::File { index: *index },
                });
            }
        }
    }

    /// Expand ancestors of a selected file without changing other folder states.
    pub fn reveal(&self, files: &[FileChange], index: usize, collapsed: &mut BTreeSet<String>) {
        let path = &files[index].path;
        collapsed.retain(|folder| !path.starts_with(&format!("{folder}/")));
    }
}

fn join(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_owned()
    } else {
        format!("{prefix}/{name}")
    }
}
