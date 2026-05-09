use crate::rbat::Result;
pub use capstone::prelude::*;

pub trait Disassembler {
    /// capstone disassembly function.
    /// returns a Capstone instance based on the binary's OS type.
    fn disassemble(&self) -> Result<Capstone>;
}
