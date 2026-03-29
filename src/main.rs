#![allow(unused)] // dont forget to remove

use crate::prelude::*;

mod error;
mod prelude;
mod types;
mod utils;

fn main() -> Result<()> {
    let buffer = Parser::new("/bin/cat".to_string());
    println!("program starts here");

    if let Err(e) = buffer.parse_buffer() {
        eprintln!("Error parsing binary: {:?}", e);
    }

    Ok(())
}
