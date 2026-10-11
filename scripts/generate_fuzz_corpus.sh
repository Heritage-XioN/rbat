#!/usr/bin/env bash
# ==============================================================================
# scripts/generate_fuzz_corpus.sh
# Deterministic seed generator for RBAT fuzz targets:
# - fuzz_analyze (PE, ELF, Mach-O, raw binaries)
# - fuzz_cfg (multi-arch instruction streams & basic block graphs)
# - fuzz_flirt (FLIRT signatures, trie nodes, function candidate patterns)
# - fuzz_rules (CAPA YAML rules, AST expressions, complex boolean trees)
#
# Note: Implemented entirely in pure Bash/POSIX without external dependencies
# (no python, perl, etc.) to guarantee seamless execution on any runner image.
# ==============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FUZZ_DIR="$REPO_ROOT/fuzz"
CORPUS_DIR="$FUZZ_DIR/corpus"

echo "==> Initializing fuzz corpus directories..."
mkdir -p "$CORPUS_DIR/fuzz_analyze"
mkdir -p "$CORPUS_DIR/fuzz_cfg"
mkdir -p "$CORPUS_DIR/fuzz_flirt"
mkdir -p "$CORPUS_DIR/fuzz_rules"

# ------------------------------------------------------------------------------
# 1. fuzz_analyze: Binary analysis seeds
# ------------------------------------------------------------------------------
echo "==> Generating seeds for fuzz_analyze..."

# Seed: Small authentic PE DLL from fixtures (4.6 KB)
if [ -f "$REPO_ROOT/crates/rbat/tests/capa-testfiles/e842958188274d5ffee7fbeffb803b2e.dll_" ]; then
    cp "$REPO_ROOT/crates/rbat/tests/capa-testfiles/e842958188274d5ffee7fbeffb803b2e.dll_" \
       "$CORPUS_DIR/fuzz_analyze/seed_pe_small_dll.bin"
fi

# Seed: Authentic ELF testfile (truncated to first 16KB for fast throughput)
if [ -f "$REPO_ROOT/crates/rbat/tests/capa-testfiles/5e4263575796c6ea2445505a843e616111e0e540ec49441e3bb3fc99be7d3afb.elf_" ]; then
    head -c 16384 "$REPO_ROOT/crates/rbat/tests/capa-testfiles/5e4263575796c6ea2445505a843e616111e0e540ec49441e3bb3fc99be7d3afb.elf_" \
       > "$CORPUS_DIR/fuzz_analyze/seed_elf_truncated.bin"
fi

# Seed: Synthetic minimal valid ELF64 header (64 bytes)
# ELF header: 64-bit, little endian, SYSV ABI, EXEC, x86-64, entry point 0x401000
printf '\x7f\x45\x4c\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00\x01\x00\x00\x00\x00\x10\x40\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x38\x00\x01\x00\x00\x00\x00\x00\x00\x00' \
    > "$CORPUS_DIR/fuzz_analyze/seed_minimal_elf64.bin"

# Seed: Synthetic minimal valid PE DOS+NT header (88 bytes)
# DOS Header with e_lfanew at 0x3c -> 0x40, followed by PE signature + FileHeader (x86-64)
printf '\x4d\x5a\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x40\x00\x00\x00\x50\x45\x00\x00\x64\x86\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x22\x00' \
    > "$CORPUS_DIR/fuzz_analyze/seed_minimal_pe.bin"

# ------------------------------------------------------------------------------
# 2. fuzz_cfg: Control-flow graph & disassembler seeds
# Architecture byte: 0 = X64, 1 = X86, 2 = Arm, 3 = Arm64
# ------------------------------------------------------------------------------
echo "==> Generating seeds for fuzz_cfg..."

# Arch 0 (X64): Function prologue, cmp, conditional jump, call, ret
printf '\x00\x55\x48\x89\xe5\x48\x83\xec\x10\x83\xf8\x01\x74\x05\xe8\x0a\x00\x00\x00\x48\x83\xc4\x10\x5d\xc3' \
    > "$CORPUS_DIR/fuzz_cfg/seed_x64_branch.bin"

# Arch 1 (X86): Function prologue, loop with dec ecx / jnz, ret
printf '\x01\x55\x89\xe5\xb9\x0a\x00\x00\x00\x49\x75\xfd\x5d\xc3' \
    > "$CORPUS_DIR/fuzz_cfg/seed_x86_loop.bin"

# Arch 2 (ARM32): push {r4, lr}; cmp r0, #0; beq +8; bl +16; pop {r4, pc}
printf '\x02\x10\x40\x2d\xe9\x00\x00\x50\xe3\x02\x00\x00\x0a\x04\x00\x00\xeb\x10\x80\xbd\xe8' \
    > "$CORPUS_DIR/fuzz_cfg/seed_arm32_branch.bin"

# Arch 3 (ARM64 / AArch64): stp x29, x30, [sp, -16]!; cbz w0, +8; bl +16; ldp x29, x30, [sp], 16; ret
printf '\x03\xfd\x7b\xbf\xa9\x40\x00\x00\x34\x04\x00\x00\x94\xfd\x7b\xc1\xa8\xc0\x03\x5f\xd6' \
    > "$CORPUS_DIR/fuzz_cfg/seed_arm64_branch.bin"

# ------------------------------------------------------------------------------
# 3. fuzz_flirt: FLIRT matcher and signature parsing seeds
# ------------------------------------------------------------------------------
echo "==> Generating seeds for fuzz_flirt..."

# Seed: Authentic Boost exception signature file (first 8KB)
if [ -f "$REPO_ROOT/crates/rbat/assets/signatures_embedded/libboost_exception-vc142-mt-s-x64-1_72.sig" ]; then
    head -c 8192 "$REPO_ROOT/crates/rbat/assets/signatures_embedded/libboost_exception-vc142-mt-s-x64-1_72.sig" \
       > "$CORPUS_DIR/fuzz_flirt/seed_boost_exception_sig.bin"
fi

# Seed: Synthetic valid IDA FLIRT header + uncompressed trie node
# Magic "IDASGN" + Version 9 + Arch 0 (386) + Features 0 + LibName ("test") + Node
printf '\x49\x44\x41\x53\x47\x4e\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x74\x65\x73\x74\x04\x00\x55\x89\xe5\xc3\x00\x00' \
    > "$CORPUS_DIR/fuzz_flirt/seed_synthetic_flirt.bin"

# Seed: Regression test payload (malformed bitmask) to ensure target stability
printf '\x49\x44\x41\x53\x47\x4e\x09\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x26\x00\x00\x01\x00\x00\x00\x20\x00\x6c\x69\x62\x62\x6f\x6f\x73\x74\x2d\x65\x78\x63\x65\x70\x74\x69\x6f\x6e\x00\x00\x00\x00\x00\x00\x00\xba\x74\x2d\x73\x2d\x78\x36\x34\x2d\x31\x2e\x37\x32\x01\x06\x41\x53\x47\x4e\x09\x00\xc3\x00\x00\x00\x00\x06\x00\x3f\x63\x6c\x6f\x6e\x65\x5f\x1b\x00\x00\x00\x63\x75\x72\x72\x65\x74\x5f\x65\x78\x63\x65\x70\x74\x69\x49\x44\x41\x53\x47\x4e\x09\x00\x2d\x6f\x6e\x65' \
    > "$CORPUS_DIR/fuzz_flirt/seed_regression_overflow.bin"

# ------------------------------------------------------------------------------
# 4. fuzz_rules: CAPA YAML rule parsing seeds
# ------------------------------------------------------------------------------
echo "==> Generating seeds for fuzz_rules..."

# Seed 1: Authentic rule with subscope / basic block match
if [ -f "$REPO_ROOT/crates/rbat/assets/capa-rules/compiler/ps2exe/compiled-with-ps2exe.yml" ]; then
    cp "$REPO_ROOT/crates/rbat/assets/capa-rules/compiler/ps2exe/compiled-with-ps2exe.yml" \
       "$CORPUS_DIR/fuzz_rules/seed_ps2exe.yml"
fi

# Seed 2: Complex rule with boolean logic, counts, numbers, and strings
cat << 'EOF' > "$CORPUS_DIR/fuzz_rules/seed_complex_features.yml"
rule:
  meta:
    name: fuzz seed complex features
    namespace: test/fuzz
    scope: function
    att&ck:
      - Execution::Command and Scripting Interpreter [T1059]
  features:
    - and:
      - string: "cmd.exe"
      - api: CreateProcessA
      - number: 0x1000
      - count(basic block): 5 or more
      - optional:
        - mnemonic: xor
        - characteristic: loop
      - not:
        - string: "powershell"
EOF

# Seed 3: Minimal valid rule
cat << 'EOF' > "$CORPUS_DIR/fuzz_rules/seed_minimal.yml"
rule:
  meta:
    name: minimal rule
    scope: file
  features:
    - string: "RBAT"
EOF

echo "==> Corpus seeding complete!"
for d in "$CORPUS_DIR"/*; do
    if [ -d "$d" ]; then
        echo "    $(basename "$d"): $(ls -1 "$d" | wc -l) files"
    fi
done
