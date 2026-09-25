#![no_main]

use libfuzzer_sys::fuzz_target;
use rbat::core::disassembler::DisassemblerImpl;
use rbat::core::traits::Disassembler;
use rbat::core::{BinaryArch, ControlFlowGraph, IatMap};
use std::sync::Arc;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let arch = match data[0] % 4 {
        0 => BinaryArch::X64,
        1 => BinaryArch::X86,
        2 => BinaryArch::Arm,
        _ => BinaryArch::Arm64,
    };
    let code_bytes = &data[1..];
    let dis = DisassemblerImpl::new(arch);
    let iat_map = IatMap::default();
    if let Ok(insns) = dis.disassemble(code_bytes, 0x1000, &iat_map) {
        if !insns.is_empty() {
            let insns_arc: Arc<[_]> = insns.into();
            let cfg = ControlFlowGraph::new(insns_arc, &arch);
            for block in cfg.blocks.values() {
                let _ = cfg.block_instructions(block);
                let _ = block.instruction_count();
            }
        }
    }
});
