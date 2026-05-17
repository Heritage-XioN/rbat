use thiserror::Error;

#[derive(Debug, Error)]
pub enum RbatError {
    #[error("I/O error occurred")]
    Io(#[from] std::io::Error),

    #[error("Error occurred while parsing binary")]
    ParseError(#[from] goblin::error::Error),

    #[error("Error occurred while disassembling binary bytes")]
    DisassemblerError(#[from] capstone::Error),

    #[error("Error occurred while compiling YARA rules")]
    YaraCompileError(#[from] yara::errors::YaraError),

    #[error("Error occurred while performing I/O with YARA")]
    YaraIO(#[from] yara::Error),

    #[error("Serialization error")]
    SerializationError(#[from] serde_json::Error),

    #[error("CLI error")]
    CliError(#[from] clap::error::Error),

    #[error("Unsupported binary format: {0}")]
    UnsupportedBinaryFormat(String),

    #[error("Invalid binary layout: {0}")]
    InvalidBinaryLayout(String),

    #[error("Missing executable section in binary")]
    MissingExecutableSection,

    #[error("Missing required embedded asset: {0}")]
    MissingAsset(String),

    #[error("Missing analysis data: {0}")]
    MissingAnalysisData(String),

    #[error("Invalid UTF-8 in embedded asset")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    #[error("csv creation error")]
    ErrorCreatingCsv(#[from] csv::Error),
}
