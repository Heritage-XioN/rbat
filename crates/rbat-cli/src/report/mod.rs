#[cfg(feature = "report-csv")]
pub mod csv;
#[cfg(feature = "report-json")]
pub mod json;
#[cfg(feature = "report-pdf")]
pub mod pdf;
pub mod terminal;
#[cfg(feature = "report-pdf")]
pub mod viz;

#[cfg(feature = "report-csv")]
pub use csv::generate_csv_report;
#[cfg(feature = "report-json")]
pub use json::generate_json_report;
#[cfg(feature = "report-pdf")]
pub use pdf::generate_pdf_report;
pub use terminal::print_terminal_report;
