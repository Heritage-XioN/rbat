//! # Capstone Disassembler Factory
//!
//! This module configures and constructs the Capstone disassembly engine,
//! adapting to target operating systems (e.g., Linux AT&T assembly syntax versus Windows/Mac Intel syntax)
//! and multiple CPU architectures (X86, X64, ARM, ARM64).

use super::{Result, traits::*};

/// A factory for creating dynamic disassembler instances.
///
/// # Example
/// ```rust
/// use rbat::core::{Factory, BinaryOS, BinaryArch};
///
/// let disasm = Factory::disasm(BinaryOS::Linux, BinaryArch::X64);
/// let cs = disasm.disassemble().unwrap();
/// ```
#[derive(Debug)]
pub struct Factory;

/// Supported target operating systems for assembly syntax style selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOS {
    /// Windows (Intel syntax).
    Win,
    /// Linux (AT&T syntax).
    Linux,
    /// macOS (Intel syntax).
    Mac,
}

/// Supported CPU architectures for disassembly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryArch {
    /// 32-bit x86 Intel.
    X86,
    /// 64-bit AMD64/x64.
    X64,
    /// 32-bit ARM.
    Arm,
    /// 64-bit ARM64/AArch64.
    Arm64,
}

/// A generic Capstone-based disassembler configured for a specific OS and CPU architecture.
#[derive(Debug)]
pub struct GenericDisasm {
    os: BinaryOS,
    arch: BinaryArch,
}

impl GenericDisasm {
    /// Creates a new `GenericDisasm` instance.
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

                Ok(x86.build()?)
            }
            BinaryArch::Arm => Ok(Capstone::new()
                .arm()
                .mode(arch::arm::ArchMode::Arm)
                .build()?),
            BinaryArch::Arm64 => Ok(Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .build()?),
        }
    }
}

impl Factory {
    /// Returns a box containing a configured disassembler for the specified OS and CPU architecture.
    pub fn disasm(os: BinaryOS, arch: BinaryArch) -> Box<dyn Disassembler> {
        Box::new(GenericDisasm::new(os, arch))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disasm_factory_x64_intel() {
        let disasm = Factory::disasm(BinaryOS::Win, BinaryArch::X64);
        let cs = disasm.disassemble().unwrap();
        let insns = cs.disasm_all(&[0x90], 0x1000).unwrap();
        assert_eq!(insns.len(), 1);
        assert_eq!(insns.as_ref()[0].mnemonic().unwrap(), "nop");
    }

    #[test]
    fn test_disasm_factory_x86_att() {
        let disasm = Factory::disasm(BinaryOS::Linux, BinaryArch::X86);
        let cs = disasm.disassemble().unwrap();
        let insns = cs.disasm_all(&[0x90], 0x1000).unwrap();
        assert_eq!(insns.len(), 1);
        assert_eq!(insns.as_ref()[0].mnemonic().unwrap(), "nop");
    }

    #[test]
    fn test_disasm_factory_arm() {
        let disasm = Factory::disasm(BinaryOS::Linux, BinaryArch::Arm);
        let cs = disasm.disassemble().unwrap();
        let bytes = [0x00, 0xf0, 0x20, 0xe3];
        let insns = cs.disasm_all(&bytes, 0x1000).unwrap();
        assert!(!insns.is_empty());
    }

    #[test]
    fn test_disasm_factory_arm64() {
        let disasm = Factory::disasm(BinaryOS::Linux, BinaryArch::Arm64);
        let cs = disasm.disassemble().unwrap();
        let bytes = [0x1f, 0x20, 0x03, 0xd5];
        let insns = cs.disasm_all(&bytes, 0x1000).unwrap();
        assert!(!insns.is_empty());
    }
}
