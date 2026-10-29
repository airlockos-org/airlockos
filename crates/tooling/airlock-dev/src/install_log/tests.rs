//! UTC labels must remain sortable across date and year boundaries.

use super::*;

/// Calendar labels use UTC, including leap days, independently of the local timezone.
#[test]
fn utc_labels_cover_epoch_leap_day_and_year_boundary() {
    for (seconds, expected) in [
        (0, "1970-01-01T00:00:00Z"),
        (951_782_400, "2000-02-29T00:00:00Z"),
        (1_767_225_599, "2025-12-31T23:59:59Z"),
        (1_767_225_600, "2026-01-01T00:00:00Z"),
    ] {
        assert_eq!(
            timestamp(UNIX_EPOCH + Duration::from_secs(seconds)),
            expected
        );
    }
}
