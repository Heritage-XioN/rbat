use super::{Result, traits::*};

/// capstone factory implementation.
#[derive(Debug)]
pub struct Factory;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOS {
    Win,
    Linux,
    Mac,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryArch {
    X86,
    X64,
    Arm,
    Arm64,
}

/// A generic disassembler that adapts to both OS syntax preferences
/// and the binary's actual CPU architecture.
#[derive(Debug)]
pub struct GenericDisasm {
    os: BinaryOS,
    arch: BinaryArch,
}

impl GenericDisasm {
    pub fn new(os: BinaryOS, arch: BinaryArch) -> Self {
        Self { os, arch }
    }
}

impl Disassembler for GenericDisasm {
    fn disassemble(&self) -> Result<Capstone> {
        match self.arch {
            BinaryArch::X86 | BinaryArch::X64 => {
                let mut x86 = Capstone::new().x86();

                if self.arch == BinaryArch::X64 {
                    x86 = x86.mode(arch::x86::ArchMode::Mode64);
                } else {
                    x86 = x86.mode(arch::x86::ArchMode::Mode32);
                }

                x86 = match self.os {
                    BinaryOS::Linux => x86.syntax(arch::x86::ArchSyntax::Att),
                    _ => x86.syntax(arch::x86::ArchSyntax::Intel),
                };

                Ok(x86.detail(true).build()?)
            }
            BinaryArch::Arm => Ok(Capstone::new()
                .arm()
                .mode(arch::arm::ArchMode::Arm)
                .detail(true)
                .build()?),
            BinaryArch::Arm64 => Ok(Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .detail(true)
                .build()?),
        }
    }
}

impl Factory {
    pub fn disasm(os: BinaryOS, arch: BinaryArch) -> Box<dyn Disassembler> {
        Box::new(GenericDisasm::new(os, arch))
    }
}
