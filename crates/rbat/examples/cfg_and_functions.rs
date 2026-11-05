//! # Control Flow Graph and Function Traversal Example
//!
//! Demonstrates reconstructing a Control Flow Graph (CFG) from instruction streams,
//! analyzing basic blocks, extracting intra-procedural functions, and exporting to Graphviz DOT.
//!
//! ## Usage
//!
//! ```bash
//! cargo run --example cfg_and_functions
//! ```

use std::sync::Arc;

use rbat::core::cfg::{ControlFlowGraph, EdgeType, InstructionClass};
use rbat::core::disassembler::InstructionInfo;
use rbat::core::parser::BinaryArch;

fn create_sample_instruction(
    addr: u64,
    mnemonic: &str,
    op_str: &str,
    class: InstructionClass,
) -> InstructionInfo {
    InstructionInfo::new(addr, mnemonic, op_str, class, None)
}

fn main() {
    println!("Constructing synthetic instruction sequence representing a branching function...");

    // Synthetic function:
    // 0x1000: cmp eax, 0
    // 0x1003: jz 0x100a      (conditional jump)
    // 0x1005: mov eax, 1     (fallthrough block)
    // 0x1009: ret
    // 0x100a: xor eax, eax   (jump target block)
    // 0x100c: ret
    let instructions: Arc<[InstructionInfo]> = Arc::new([
        create_sample_instruction(0x1000, "cmp", "eax, 0", InstructionClass::Normal),
        create_sample_instruction(0x1003, "jz", "0x100a", InstructionClass::ConditionalJump),
        create_sample_instruction(0x1005, "mov", "eax, 1", InstructionClass::Normal),
        create_sample_instruction(0x1009, "ret", "", InstructionClass::Return),
        create_sample_instruction(0x100a, "xor", "eax, eax", InstructionClass::Normal),
        create_sample_instruction(0x100c, "ret", "", InstructionClass::Return),
    ]);

    println!("Building ControlFlowGraph for x86_64...");
    let cfg = ControlFlowGraph::new(instructions.clone(), &BinaryArch::X64);

    println!();
    println!("============================================================");
    println!("              CONTROL FLOW GRAPH ANALYSIS                   ");
    println!("============================================================");
    println!("Total Instructions:  {}", instructions.len());
    println!("Total Basic Blocks:  {}", cfg.blocks.len());
    println!("Recovered Functions: {}", cfg.functions.len());
    println!("Total Edges:         {}", cfg.edges.len());
    println!("------------------------------------------------------------");

    println!("Basic Blocks:");
    for (&_start_addr, block) in &cfg.blocks {
        println!(
            "  Block 0x{:08x} - 0x{:08x} ({} instructions)",
            block.start_address,
            block.end_address,
            block.instr_count()
        );
        for insn in cfg.as_block_instr(block) {
            println!(
                "    0x{:08x}: {:<8} {}",
                insn.address, insn.mnemonic, insn.op_str
            );
        }
    }

    println!("------------------------------------------------------------");
    println!("Control Flow Edges:");
    for &(src, dst, edge_type) in &cfg.edges {
        let label = match edge_type {
            EdgeType::ConditionalTrue => "ConditionalTrue",
            EdgeType::ConditionalFalse => "ConditionalFalse",
            EdgeType::Unconditional => "Unconditional",
            EdgeType::Call => "Call",
            EdgeType::FallThrough => "FallThrough",
        };
        println!("  0x{:08x} -> 0x{:08x} [{}]", src, dst, label);
    }

    println!("------------------------------------------------------------");
    println!("Functions:");
    for (&entry_addr, function) in &cfg.functions {
        println!(
            "  Function at entry 0x{:08x} (ends 0x{:08x}):",
            entry_addr, function.end_address
        );
        println!("    Blocks count:       {}", function.block_count());
        println!("    Instructions count: {}", function.instr_count(&cfg));
        println!("    Contained block addresses: {:?}", function.basic_blocks);
    }

    println!("------------------------------------------------------------");
    println!("Exporting Graphviz DOT format representation:");
    let dot = cfg.to_dot();
    for line in dot.lines().take(15) {
        println!("  {}", line);
    }
    if dot.lines().count() > 15 {
        println!("  ... [truncated, {} lines total]", dot.lines().count());
    }
    println!("============================================================");
}
