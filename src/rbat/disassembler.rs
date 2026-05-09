use crate::rbat::{Result, traits::*};

/// windows disassembler struct
#[derive(Debug)]
pub struct WinDisasm;

/// linux disassembler struct
#[derive(Debug)]
pub struct LinuxDisasm;

/// mac disassembler struct
#[derive(Debug)]
pub struct MacDisasm;

/// capstone factory implementation.
/// returns the appropriate disassembler based on the binary's OS type.
#[derive(Debug)]
pub struct Factory;

pub enum DisasmType {
    WinDisasm,
    LinuxDisasm,
    MacDisasm,
}

impl Disassembler for WinDisasm {
    fn disassemble(&self) -> Result<Capstone> {
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()?;

        Ok(cs)
    }
}

impl Disassembler for LinuxDisasm {
    fn disassemble(&self) -> Result<Capstone> {
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Att)
            .detail(true)
            .build()?;

        Ok(cs)
    }
}

impl Disassembler for MacDisasm {
    fn disassemble(&self) -> Result<Capstone> {
        let cs = Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .detail(true)
            .build()?;

        Ok(cs)
    }
}

impl Factory {
    pub fn disasm(disasm_type: DisasmType) -> Box<dyn Disassembler> {
        match disasm_type {
            DisasmType::WinDisasm => Box::new(WinDisasm),
            DisasmType::LinuxDisasm => Box::new(LinuxDisasm),
            DisasmType::MacDisasm => Box::new(MacDisasm),
        }
    }
}
