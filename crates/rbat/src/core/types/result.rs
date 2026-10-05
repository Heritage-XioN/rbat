//! # Custom Result and Error Types
//!
//! This module defines the [`RbatResult`] type and the [`RbatError`] enum which encapsulates all
//! classification, disassembling, scanning, and file I/O error states and result outputs
//! produced by the RBAT core library.

use serde::Serialize;
use thiserror::Error;

/// A specialized Result type for rbat core operations.
pub type RbatResult<T> = core::result::Result<T, RbatError>;

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
        object::Error,
    ),

    /// Capstone disassembly engine failure.
    #[cfg(feature = "backend-capstone")]
    #[error("Error occurred while disassembling binary bytes")]
    DisassemblerError(
        #[from]
        #[serde(serialize_with = "serialize_to_string")]
        capstone::Error,
    ),

    /// Generic disassembly engine failure or configuration error.
    #[error("Disassembly error: {0}")]
    GenericDisassemblerError(String),

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
    #[error("Invalid UTF-8 in embedded asset: {0}")]
    Utf8Error(
        #[from]
        #[serde(serialize_with = "serialize_to_string")]
        std::string::FromUtf8Error,
    ),

    /// UTF-8 slice decoding failure.
    #[error("Invalid UTF-8 sequence: {0}")]
    StrUtf8Error(
        #[from]
        #[serde(serialize_with = "serialize_to_string")]
        std::str::Utf8Error,
    ),

    /// Configuration or override table parse error.
    #[error("Configuration or override error: {0}")]
    ConfigError(String),

    /// Rule parsing or validation error.
    #[error("Rule error: {0}")]
    RuleError(String),

    /// Pipeline cancellation indicator.
    #[error("An error occurred which resulted in the cancellation of the analysis process")]
    AnalysisCancelled,

    /// Pipeline cancellation indicator.
    #[error("An error occurred which resulted in the cancellation of the analysis process")]
    FlirtMatcherError(
        #[from]
        #[serde(serialize_with = "serialize_to_string")]
        fast_flirt::Error,
    ),
}

fn serialize_to_string<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: std::fmt::Display,
    S: serde::Serializer,
{
    serializer.serialize_str(&value.to_string())
}
