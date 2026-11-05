use object::File;
use rbat::core::parser::{ParsedBinaryContext, Parser};
use std::path::PathBuf;

/// Helper to load a test file from `crates/rbat/tests/capa-testfiles/`.
pub fn load_sample(filename: &str) -> Vec<u8> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../crates/rbat/tests/capa-testfiles");
    path.push(filename);
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("Failed to read benchmark sample at {:?}: {}", path, e))
}

/// Helper to parse a sample into normalized binary context (text bytes, arch, entry point, IAT map).
pub fn parse_sample_context(buffer: &[u8]) -> ParsedBinaryContext {
    let file = File::parse(buffer).expect("Failed to parse binary object with `object` crate");
    let parser = Parser::new(&file);
    parser
        .parse_buffer()
        .expect("Failed to extract executable text context")
}
