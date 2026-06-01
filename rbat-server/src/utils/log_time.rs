//! # Local Time Formatting Utility
//!
//! Custom timer formatting implementation for the `tracing-subscriber` logger output.

/// A formatter that prints local time without milliseconds.
///
/// Output format template: `%Y-%m-%d %H:%M:%S`
pub struct LocalTimeWithoutMillis;

impl tracing_subscriber::fmt::time::FormatTime for LocalTimeWithoutMillis {
    /// Formats the current local time to the writer.
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> std::fmt::Result {
        let now = chrono::Local::now();
        write!(w, "{}", now.format("%Y-%m-%d %H:%M:%S"))
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    #[test]
    fn test_time_formatting_pattern() {
        // Create a fixed datetime to test formatting pattern
        let dt = chrono::Local
            .with_ymd_and_hms(2026, 5, 31, 18, 30, 0)
            .unwrap();
        let formatted = dt.format("%Y-%m-%d %H:%M:%S").to_string();
        assert_eq!(formatted, "2026-05-31 18:30:00");
        assert_eq!(formatted.len(), 19);
    }
}
