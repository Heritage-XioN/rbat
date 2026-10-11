#![no_main]

use libfuzzer_sys::fuzz_target;
use rbat::core::{
    cfg::ControlFlowGraph,
    disassembler::DisassemblerImpl,
    parser::{BinaryArch, IatMap},
};

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
            let cfg = ControlFlowGraph::new(insns, &arch);
            for block in cfg.blocks.values() {
                let _ = cfg.as_block_instr(block);
                let _ = block.instr_count();
            }
        }
    }
});
