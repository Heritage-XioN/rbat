//! # Core Result and Error System
//!
//! Error definitions, result aliases, and serialization adapters used across
//! all phases of the binary analysis pipeline.
//!
//! ## Core Types
//!
//! - [`RbatResult`]: A specialized type alias for `Result<T, RbatError>`.
//! - [`RbatError`]: Unified error enum covering binary parsing, disassembly, YARA rule scanning,
//!   FLIRT signature matching, configuration parsing, and pipeline orchestration.
//!
//! ## Error Naming Standard
//!
//! All [`RbatError`] variants adhere strictly to the **`verbObjectError`** naming convention:
//! - **Verb**: Operation attempted (e.g. `Execute`, `Parse`, `Disassemble`, `Compile`, `Scan`, `Serialize`, `Validate`, `Locate`, `Load`, `Query`, `Decode`, `Cancel`, `Match`).
//! - **Object**: Domain entity affected (e.g. `Io`, `Binary`, `Instruction`, `YaraRule`, `YaraPayload`, `Json`, `BinaryFormat`, `BinaryLayout`, `ExecutableSection`, `EmbeddedAsset`, `AnalysisData`, `Utf8`, `Configuration`, `Rule`, `Analysis`, `FlirtSignature`).
//! - **Error**: Required suffix.
//!
//! ## Error Variant Classification
//!
//! | Category | Variant | Cause |
//! | :--- | :--- | :--- |
//! | **I/O & Serialization** | [`ExecuteIoError`](RbatError::ExecuteIoError) | Low-level filesystem or stream I/O failure |
//! | | [`SerializeJsonError`](RbatError::SerializeJsonError) | Serialization or deserialization error during JSON formatting |
//! | **Format & Layout** | [`ParseBinaryError`](RbatError::ParseBinaryError) | Executable header/section parsing failure via `object` crate |
//! | | [`ValidateBinaryFormatError`](RbatError::ValidateBinaryFormatError) | Unrecognized or unsupported file format / architecture |
//! | | [`ValidateBinaryLayoutError`](RbatError::ValidateBinaryLayoutError) | Corrupted section offsets, overlapping boundaries, or invalid virtual addresses |
//! | | [`LocateExecutableSectionError`](RbatError::LocateExecutableSectionError) | Binary missing executable text section |
//! | **Disassembly** | [`DisassembleInstructionError`](RbatError::DisassembleInstructionError) | Machine code decode failure; gated per backend feature |
//! | **Rules & Signatures** | [`CompileYaraRuleError`](RbatError::CompileYaraRuleError) | Syntax or compilation error in YARA rule text |
//! | | [`ScanYaraPayloadError`](RbatError::ScanYaraPayloadError) | Runtime scanning engine failure during memory inspection |
//! | | [`MatchFlirtSignatureError`](RbatError::MatchFlirtSignatureError) | Malformed FLIRT pattern or signature evaluation failure |
//! | | [`ParseRuleError`](RbatError::ParseRuleError) | Syntax error in capa YAML or JSON behavioral rules |
//! | **Configuration & Assets** | [`LoadConfigurationError`](RbatError::LoadConfigurationError) | TOML parsing failure in severity override tables |
//! | | [`LoadEmbeddedAssetError`](RbatError::LoadEmbeddedAssetError) | Missing compiled-in rule, signature, or static asset |
//! | | [`QueryAnalysisDataError`](RbatError::QueryAnalysisDataError) | Required intermediate heuristic finding missing during aggregation |
//! | | [`DecodeUtf8Error`](RbatError::DecodeUtf8Error) | Invalid UTF-8 sequence encountered in strings or embedded files |
//! | **Pipeline Orchestration** | [`CancelAnalysisError`](RbatError::CancelAnalysisError) | Early termination signal emitted when a sibling task fails |
//!
//! ## Examples
//!
//! ```rust
//! use rbat::core::types::result::{RbatError, RbatResult};
//!
//! fn validate_file_size(size: usize) -> RbatResult<()> {
//!     if size == 0 {
//!         return Err(RbatError::ValidateBinaryLayoutError("binary file is empty".into()));
//!     }
//!     Ok(())
//! }
//!
//! assert!(validate_file_size(0).is_err());
//! assert!(validate_file_size(1024).is_ok());
//! ```

use serde::Serialize;
use thiserror::Error;

/// A specialized Result type for rbat core operations.
pub type RbatResult<T> = core::result::Result<T, RbatError>;

/// Represents all possible error conditions returned by the RBAT core library.
#[derive(Debug, Error, Serialize)]
pub enum RbatError {
    /// Standard input/output operations error.
    #[error("I/O error occurred: {0}")]
    ExecuteIoError(
        #[from]
        #[serde(serialize_with = "serialize_to_string")]
        std::io::Error,
    ),

    /// Recursive directory traversal error
    #[error("Error occurred while walking dir: {0}")]
    WalkDirError(
        #[from]
        #[serde(serialize_with = "serialize_to_string")]
        walkdir::Error,
    ),

    /// Executable binary header parsing failure.
    #[error("Error occurred while parsing binary: {0}")]
    ParseBinaryError(
        #[from]
        #[serde(serialize_with = "serialize_to_string")]
        object::Error,
    ),

    /// Disassembly engine failure or configuration error.
    #[error("Disassembly error: {0}")]
    DisassembleInstructionError(String),

    /// YARA rules compilation failure.
    #[error("Error occurred while compiling YARA rules: {0}")]
    CompileYaraRuleError(
        #[from]
        #[serde(serialize_with = "serialize_to_string")]
        yara::errors::YaraError,
    ),

    /// Memory scan execution failure in YARA backend.
    #[error("Error occurred while performing scan with YARA: {0}")]
    ScanYaraPayloadError(
        #[from]
        #[serde(serialize_with = "serialize_to_string")]
        yara::Error,
    ),

    /// Serialization/deserialization failure.
    #[error("Serialization error: {0}")]
    SerializeJsonError(
        #[from]
        #[serde(serialize_with = "serialize_to_string")]
        serde_json::Error,
    ),

    /// Non-supported formats or unrecognized machine architectures.
    #[error("Unsupported binary format: {0}")]
    ValidateBinaryFormatError(String),

    /// Invalid entry point offsets or overlapping section boundaries.
    #[error("Invalid binary layout: {0}")]
    ValidateBinaryLayoutError(String),

    /// Executable section missing in elf/pe/macho headers.
    #[error("Missing executable section in binary")]
    LocateExecutableSectionError,

    /// Missing embedded resource (e.g. YARA rules, mnemonic blacklists).
    #[error("Missing required embedded asset: {0}")]
    LoadEmbeddedAssetError(String),

    /// Missing analyzed data needed during reporting or aggregation.
    #[error("Missing analysis data: {0}")]
    QueryAnalysisDataError(String),

    /// UTF-8 string or slice decoding failure.
    #[error("Invalid UTF-8 sequence: {0}")]
    DecodeUtf8Error(String),

    /// Configuration or override table parse error.
    #[error("Configuration or override error: {0}")]
    LoadConfigurationError(String),

    /// Rule parsing or validation error.
    #[error("Rule error: {0}")]
    ParseRuleError(String),

    /// Pipeline cancellation indicator.
    #[error("An error occurred which resulted in the cancellation of the analysis process")]
    CancelAnalysisError,

    /// FLIRT signature parsing or matching error.
    #[error("FLIRT signature matching error: {0}")]
    MatchFlirtSignatureError(
        #[from]
        #[serde(serialize_with = "serialize_to_string")]
        fast_flirt::Error,
    ),
}

impl From<std::string::FromUtf8Error> for RbatError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        RbatError::DecodeUtf8Error(err.to_string())
    }
}

impl From<std::str::Utf8Error> for RbatError {
    fn from(err: std::str::Utf8Error) -> Self {
        RbatError::DecodeUtf8Error(err.to_string())
    }
}

#[cfg(feature = "backend-capstone")]
impl From<capstone::Error> for RbatError {
    fn from(err: capstone::Error) -> Self {
        RbatError::DisassembleInstructionError(err.to_string())
    }
}

fn serialize_to_string<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: std::fmt::Display,
    S: serde::Serializer,
{
    serializer.serialize_str(&value.to_string())
}
