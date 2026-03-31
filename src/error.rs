use thiserror::Error;

#[derive(Debug, Error)]
pub enum RbatError {
    #[error("I/O error occurred")]
    Io(#[from] std::io::Error),

    #[error("Error occured while parsing binary")]
    ParseError(#[from] goblin::error::Error),

    #[error("error occured while disassembling binary bytes")]
    DisassemblerError(#[from] capstone::Error),
}
