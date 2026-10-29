#!/usr/bin/env bash
# ==============================================================================
# scripts/validate-release.sh
# Comprehensive release validation suite for RBAT.
# Executes formatting, linting, multi-backend feature checks, fuzz manifests,
# rule compilation via xtask, and workspace test suites.
# ==============================================================================

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=====================================================${NC}"
echo -e "${BLUE}            RBAT Pre-Release Validation              ${NC}"
echo -e "${BLUE}=====================================================${NC}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# 1. Formatting check
echo -e "\n${YELLOW}🔍 1. Checking Code Formatting (cargo fmt)...${NC}"
cargo fmt --all -- --check
echo -e "${GREEN}✓ Formatting check passed.${NC}"

# 2. Strict Clippy check on all targets & features
echo -e "\n${YELLOW}🔍 2. Running Workspace Lints (cargo clippy)...${NC}"
cargo clippy --workspace --all-targets --all-features -- -D warnings
echo -e "${GREEN}✓ Clippy checks passed with 0 warnings.${NC}"

# 3. Disassembler Backend Feature Checks
echo -e "\n${YELLOW}🔍 3. Verifying Disassembler Feature Configurations...${NC}"
echo "   -> Checking rbat (backend-iced only)..."
cargo check -p rbat --no-default-features --features backend-iced --quiet
echo "   -> Checking rbat (backend-capstone only)..."
cargo check -p rbat --no-default-features --features backend-capstone --quiet
echo "   -> Checking rbat-cli (backend-iced only)..."
cargo check -p rbat-cli --no-default-features --features backend-iced --quiet
echo "   -> Checking rbat-cli (backend-capstone only)..."
cargo check -p rbat-cli --no-default-features --features backend-capstone --quiet
echo -e "${GREEN}✓ Feature compilation matrix passed.${NC}"

# 4. Fuzz Manifest Check
echo -e "\n${YELLOW}🔍 4. Verifying Fuzz Targets Manifest...${NC}"
cargo check --manifest-path fuzz/Cargo.toml --quiet
echo -e "${GREEN}✓ Fuzz manifest check passed.${NC}"

# 5. Capa Rules Precompilation via xtask
echo -e "\n${YELLOW}🔍 5. Verifying Rule Compilation (cargo xtask bundle-rules)...${NC}"
cargo xtask bundle-rules
echo -e "${GREEN}✓ Rule bundling passed successfully.${NC}"

# 6. Workspace Unit and Integration Tests
echo -e "\n${YELLOW}🧪 6. Running Workspace Test Suite...${NC}"
cargo test --workspace --all-targets
echo -e "${GREEN}✓ Workspace test suite passed.${NC}"

# 7. Optional SemVer Compatibility Check
echo -e "\n${YELLOW}🔍 7. Checking SemVer Compliance (cargo-semver-checks)...${NC}"
if ! command -v cargo-semver-checks &> /dev/null; then
  echo -e "${YELLOW}⚠️  cargo-semver-checks is not installed locally.${NC}"
  echo -e "   Install with: cargo install cargo-semver-checks --locked"
  echo -e "   Skipping local SemVer check..."
else
  echo "Running semver-checks for rbat..."
  if [ "${CI:-false}" = "true" ]; then
    cargo semver-checks --package rbat
  else
    cargo semver-checks --package rbat || {
      echo -e "${RED}❌ SemVer compatibility check failed!${NC}"
      echo -e "If this version includes breaking changes, ensure you bump the MAJOR version."
      exit 1
    }
  fi
  echo -e "${GREEN}✓ SemVer check passed successfully.${NC}"
fi

echo -e "\n${GREEN}=====================================================${NC}"
echo -e "${GREEN}🎉 SUCCESS: All release validation gates passed!     ${NC}"
echo -e "${GREEN}=====================================================${NC}"
exit 0
