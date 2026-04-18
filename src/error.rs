use thiserror::Error;

#[derive(Debug, Error)]
pub enum RbatError {
    #[error("I/O error occurred")]
    Io(#[from] std::io::Error),

    #[error("Error occured while parsing binary")]
    ParseError(#[from] goblin::error::Error),

    #[error("error occured while disassembling binary bytes")]
    DisassemblerError(#[from] capstone::Error),

    #[error("error occured while compiling yara rules")]
    YaraCompileError(#[from] yara::errors::YaraError),

    #[error("error occured while performing I/O of yara rules")]
    YaraIO(#[from] yara::Error),

    #[error("serialization error")]
    SerializationError(#[from] serde_json::Error),

    #[error("CLI error")]
    CliError(#[from] clap::error::Error),
}
