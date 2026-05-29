pub struct LocalTimeWithoutMillis;

impl tracing_subscriber::fmt::time::FormatTime for LocalTimeWithoutMillis {
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> std::fmt::Result {
        let now = chrono::Local::now();
        write!(w, "{}", now.format("%Y-%m-%d %H:%M:%S"))
    }
}
