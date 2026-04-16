#![allow(unused)] // dont forget to remove

use crate::prelude::Result;
use crate::utils::analyzer::analyzer;
mod error;
mod prelude;
mod traits;
mod types;
mod utils;

fn main() -> Result<()> {
    let file_path = "/bin/cat";
    analyzer(file_path.to_owned());
    Ok(())
}
