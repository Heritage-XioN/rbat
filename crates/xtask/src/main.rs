pub use clap::{Parser, Subcommand};
use color_eyre::Result;
use rbat::core::rule::Rule;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Parser, Debug, Clone)]
#[command(name = "xtask", version, about = "rbat automation tasks cli")]
struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

/// Subcommands supported by RBAT xtask cli.
#[derive(Subcommand, Debug, Clone)]
enum Commands {
    /// Compile capa-rules into embedded_rules.mp
    BundleRules,
}

fn main() -> Result<()> {
    color_eyre::install()?;

    let cli = Cli::parse();

    match cli.command {
        Commands::BundleRules => bundle_rules(),
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("Failed to locate workspace root")
        .to_path_buf()
}

fn collect_rule_files(dir: &Path, files: &mut Vec<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_rule_files(&path, files);
            } else if let Some(ext) = path.extension().and_then(|s| s.to_str())
                && (ext == "yaml" || ext == "yml" || ext == "json")
                && !path.to_string_lossy().contains("/.")
            {
                files.push(path);
            }
        }
    }
}

fn bundle_rules() -> Result<()> {
    let start = Instant::now();
    let root = workspace_root();
    let rules_dir = root.join("rbat/assets/capa-rules");
    let out_path = root.join("rbat/assets/embedded_rules.mp");

    if !rules_dir.exists() {
        eprintln!(
            "Error: rules directory does not exist: {}",
            rules_dir.display()
        );
        std::process::exit(1);
    }

    println!("Scanning capa-rules in {}...", rules_dir.display());

    let mut rule_files = Vec::new();
    collect_rule_files(&rules_dir, &mut rule_files);
    rule_files.sort();

    println!("Found {} rule files", rule_files.len());

    let mut rules = Vec::with_capacity(rule_files.len());
    let mut total_raw_bytes = 0usize;

    for path in &rule_files {
        let data = fs::read(path)?;
        total_raw_bytes += data.len();
        match Rule::from_slice(&data) {
            Ok(rule) => rules.push(rule),
            Err(e) => eprintln!("Warning: Failed to parse rule {}: {}", path.display(), e),
        }
    }

    // Deterministic sort by rule name
    rules.sort_by(|a, b| a.rule.meta.name.cmp(&b.rule.meta.name));

    println!(
        "Successfully parsed {} rules ({:.2} MB raw text)",
        rules.len(),
        total_raw_bytes as f64 / 1024.0 / 1024.0
    );

    let mp_bytes = rmp_serde::encode::to_vec_named(&rules)?;
    fs::write(&out_path, &mp_bytes)?;

    println!(
        "Compiled into {} ({} bytes, {:.2} MB) in {:?}",
        out_path.display(),
        mp_bytes.len(),
        mp_bytes.len() as f64 / 1024.0 / 1024.0,
        start.elapsed()
    );

    // Verify roundtrip fidelity
    let decoded: Vec<Rule> = rmp_serde::from_slice(&mp_bytes)?;
    assert_eq!(rules.len(), decoded.len());
    println!(
        "Verified roundtrip: {} rules successfully decoded from MessagePack!",
        decoded.len()
    );

    Ok(())
}
