//! # Disassembler Factory
//!
//! This module configures and constructs disassembly engines (Capstone or Iced),
//! adapting to target operating systems and CPU architectures.

#[cfg(all(feature = "backend-capstone", feature = "backend-iced"))]
compile_error!(
    "Conflicting disassembly backends: `backend-capstone` and `backend-iced` are both enabled. \
     Pick exactly ONE — for the iced backend use \
     `cargo build --release --no-default-features --features backend-iced`."
);

#[cfg(not(any(feature = "backend-capstone", feature = "backend-iced")))]
compile_error!(
    "No disassembly backend selected: enable exactly one of \
     `backend-capstone` (default) or `backend-iced`."
);

#[cfg(feature = "backend-capstone")]
mod capstone_backend;
#[cfg(feature = "backend-capstone")]
pub use capstone_backend::*;

#[cfg(all(feature = "backend-iced", not(feature = "backend-capstone")))]
mod iced_backend;
#[cfg(all(feature = "backend-iced", not(feature = "backend-capstone")))]
pub use iced_backend::*;
