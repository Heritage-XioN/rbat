use std::{fmt::Debug, sync::Arc};

use crate::core::{
    disassembler::InstructionInfo,
    parser::{BinaryArch, IatMap},
    types::result::RbatResult,
};

/// Interface for architecture-specific or custom disassembler engines.
pub trait Disassembler: Send + Sync + Debug {
    /// Disassembles machine code from `text_bytes` starting at `entry_addr` for the given architecture.
    fn disassemble(
        &self,
        text_bytes: &[u8],
        entry_addr: u64,
        arch: BinaryArch,
        iat_map: &IatMap,
    ) -> RbatResult<Arc<[InstructionInfo]>>;

    /// Returns whether this disassembler supports the given binary architecture.
    fn supports_arch(&self, _arch: BinaryArch) -> bool {
        true
    }

    /// Returns a human-readable identifier for this disassembler backend.
    fn name(&self) -> &'static str;
}

impl<D: Disassembler + ?Sized> Disassembler for Arc<D> {
    fn disassemble(
        &self,
        text_bytes: &[u8],
        entry_addr: u64,
        arch: BinaryArch,
        iat_map: &IatMap,
    ) -> RbatResult<Arc<[InstructionInfo]>> {
        (**self).disassemble(text_bytes, entry_addr, arch, iat_map)
    }

    fn supports_arch(&self, arch: BinaryArch) -> bool {
        (**self).supports_arch(arch)
    }

    fn name(&self) -> &'static str {
        (**self).name()
    }
}

impl<D: Disassembler + ?Sized> Disassembler for Box<D> {
    fn disassemble(
        &self,
        text_bytes: &[u8],
        entry_addr: u64,
        arch: BinaryArch,
        iat_map: &IatMap,
    ) -> RbatResult<Arc<[InstructionInfo]>> {
        (**self).disassemble(text_bytes, entry_addr, arch, iat_map)
    }

    fn supports_arch(&self, arch: BinaryArch) -> bool {
        (**self).supports_arch(arch)
    }

    fn name(&self) -> &'static str {
        (**self).name()
    }
}
