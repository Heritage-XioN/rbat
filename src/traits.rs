use crate::prelude::*;

pub trait Disassembler {
    fn disassemble(&self) -> Result<Capstone>;
}
