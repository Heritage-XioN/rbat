//! # Custom Error Types
//!
//! This module defines the [`RbatError`] enumeration which encapsulates all
//! classification, disassembling, scanning, template rendering, and file I/O error states
//! produced by the RBAT core library.

use serde::Serialize;
use thiserror::Error;

/// Represents all possible error conditions returned by the RBAT core library.
#[derive(Debug, Error, Serialize)]
pub enum RbatError {
    /// Standard input/output operations error.
    #[error("I/O error occurred")]
    Io(
        #[from]
        #[serde(serialize_with = "serialize_to_string")]
        std::io::Error,
    ),

    /// Executable binary header parsing failure.
    #[error("Error occurred while parsing binary")]
    ParseError(
        #[from]
        #[serde(serialize_with = "serialize_to_string")]
        goblin::error::Error,
    ),

    /// Capstone disassembly engine failure.
    #[error("Error occurred while disassembling binary bytes")]
    DisassemblerError(
        #[from]
        #[serde(serialize_with = "serialize_to_string")]
        capstone::Error,
    ),

    /// YARA rules compilation failure.
    #[error("Error occurred while compiling YARA rules")]
    YaraCompileError(
        #[from]
        #[serde(serialize_with = "serialize_to_string")]
        yara::errors::YaraError,
    ),

    /// Memory scan execution failure in YARA backend.
    #[error("Error occurred while performing I/O with YARA")]
    YaraIO(
        #[from]
        #[serde(serialize_with = "serialize_to_string")]
        yara::Error,
    ),

    /// Serialization/deserialization failure.
    #[error("Serialization error")]
    SerializationError(
        #[from]
        #[serde(serialize_with = "serialize_to_string")]
        serde_json::Error,
    ),

    /// CLI argument parser validation failure.
    #[error("CLI error")]
    CliError(
        #[from]
        #[serde(serialize_with = "serialize_to_string")]
        clap::error::Error,
    ),

    /// Non-supported formats or corrupted machine layouts.
    #[error("Unsupported binary format: {0}")]
    UnsupportedBinaryFormat(String),

    /// Invalid entry point offsets or overlapping section boundaries.
    #[error("Invalid binary layout: {0}")]
    InvalidBinaryLayout(String),

    /// Executable section missing in elf/pe/macho headers.
    #[error("Missing executable section in binary")]
    MissingExecutableSection,

    /// Missing embedded resource (e.g. YARA rules, mnemonic blacklists).
    #[error("Missing required embedded asset: {0}")]
    MissingAsset(String),

    /// Missing analyzed data needed during reporting or aggregation.
    #[error("Missing analysis data: {0}")]
    MissingAnalysisData(String),

    /// UTF8 decoding failure.
    #[error("Invalid UTF-8 in embedded asset")]
    Utf8Error(
        #[from]
        #[serde(serialize_with = "serialize_to_string")]
        std::string::FromUtf8Error,
    ),

    /// CSV formatter error.
    #[error("csv creation error")]
    ErrorCreatingCsv(
        #[from]
        #[serde(serialize_with = "serialize_to_string")]
        csv::Error,
    ),

    /// Pipeline cancellation indicator.
    #[error("an error occurred which resulted in the cancellation of the analysis process")]
    ErrorAnalysisCancelled,

    /// Askama HTML template compilation failure.
    #[error("HTML template rendering error: {0}")]
    TemplateError(String),

    /// Fullbleed PDF compilation failure.
    #[error("PDF rendering error: {0}")]
    PdfRenderError(String),

    /// JSON serialization failure.
    #[error("JSON error: {0}")]
    JsonError(String),

    /// CSV writer output failure.
    #[error("CSV error: {0}")]
    CsvError(String),
}

fn serialize_to_string<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: std::fmt::Display,
    S: serde::Serializer,
{
    serializer.serialize_str(&value.to_string())
}
