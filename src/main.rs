#![allow(unused)] // dont forget to remove

use std::{collections::binary_heap, ops::Deref};

use capstone::Instructions;

use crate::prelude::*;

mod error;
mod prelude;
mod traits;
mod types;
mod utils;

fn main() -> Result<()> {
    let buffer = Parser::new("/bin/cat".to_string());

    println!("program starts here");

    let binary_data = match buffer.parse_buffer() {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error parsing: {}", e);
            return Ok(());
        }
    };

    let factory = Factory::disasm(crate::DisasmType::LinuxDisam);
    let cs_factory = factory.disassemble();
    let cs = cs_factory.unwrap();

    if let (Some(MapSize::Bytes(bytes)), Some(MapSize::Word(entry_addr))) =
        (binary_data.get("text_bytes"), binary_data.get("entry_addr"))
    {
        let instructions = cs.disasm_all(bytes, *entry_addr)?;

        println!("disassembled data: {:#?}", instructions.len());

        for i in instructions.as_ref() {
            println!(
                "0x{:x}:\t{}\t{}",
                i.address(),
                i.mnemonic().unwrap_or(""),
                i.op_str().unwrap_or("")
            );
        }
    }

    Ok(())
}
