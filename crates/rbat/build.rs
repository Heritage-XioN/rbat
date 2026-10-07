//! Collects IDA FLIRT `.sig` signature files from the
//! `assets/flirtdb/` Git submodule and copies them into `assets/signatures_embedded/`
//! for embedding into the library.

use std::fs;
use std::path::Path;

fn main() {
    // Re-run this build script if flirtdb folder changes
    println!("cargo:rerun-if-changed=assets/flirtdb");

    let out_dir_str = "assets/signatures_embedded";
    let out_dir = Path::new(out_dir_str);

    if !out_dir.exists() {
        fs::create_dir_all(out_dir).expect("failed to create signatures_embedded directory");
    }

    let source_dirs = [
        "assets/flirtdb/cmt/windows",
        "assets/flirtdb/cpmt/windows",
        "assets/flirtdb/vcruntime/windows",
        "assets/flirtdb/openssl/windows",
        "assets/flirtdb/libcurl/windows",
        "assets/flirtdb/boost/windows",
    ];

    let mut copied_count = 0;
    let mut discovered_count = 0;

    for dir_path in &source_dirs {
        let path = Path::new(dir_path);
        if path.exists()
            && path.is_dir()
            && let Ok(entries) = fs::read_dir(path)
        {
            for entry in entries.flatten() {
                let entry_path = entry.path();
                if entry_path.is_file()
                    && let Some(ext) = entry_path.extension()
                    && ext == "sig"
                    && let Some(file_name) = entry_path.file_name()
                {
                    discovered_count += 1;
                    let dest_path = out_dir.join(file_name);
                    if !dest_path.exists() {
                        if let Err(e) = fs::copy(&entry_path, &dest_path) {
                            println!(
                                "cargo:warning=Failed to copy signature {:?}: {}",
                                entry_path, e
                            );
                        } else {
                            copied_count += 1;
                        }
                    }
                }
            }
        }
    }

    if discovered_count == 0 {
        println!(
            "cargo:warning=No FLIRT signatures found in assets/flirtdb. Make sure git submodules are checked out."
        );
    } else if copied_count > 0 {
        println!(
            "cargo:warning=Successfully bundled {} new FLIRT signatures into assets/signatures_embedded",
            copied_count
        );
    }
}
