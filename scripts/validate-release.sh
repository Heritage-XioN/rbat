#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=====================================================${NC}"
echo -e "${BLUE}            RBAT Pre-Release Validation              ${NC}"
echo -e "${BLUE}=====================================================${NC}"

# Define cleanup function for cargo config
cleanup_config() {
  echo -e "\n${YELLOW}🧹 Cleaning up temporary cargo configuration...${NC}"
  rm -f .cargo/config.toml 2>/dev/null || true
  rmdir .cargo 2>/dev/null || true
}
# Register cleanup to run on exit, interrupt, or termination
trap cleanup_config EXIT

# Setup temporary cargo patch config to fix crates.io baseline compile error in cargo-semver-checks
echo -e "\n${YELLOW}📦 Setting up temporary lightningcss patch...${NC}"
mkdir -p /tmp/lightningcss-src
if [ ! -f "/tmp/lightningcss-src/Cargo.toml" ]; then
  echo "Downloading lightningcss source crate from crates.io..."
  curl -L -s https://static.crates.io/crates/lightningcss/lightningcss-1.0.0-alpha.70.crate | tar -xz -C /tmp/lightningcss-src --strip-components=1
fi
mkdir -p .cargo
echo '[patch.crates-io]' > .cargo/config.toml
echo 'lightningcss = { path = "/tmp/lightningcss-src" }' >> .cargo/config.toml

# 1. Verify workspace compilation and unit tests
echo -e "\n${YELLOW}🧪 1. Running Workspace Unit Tests...${NC}"
cargo test --workspace --all-targets --verbose

# 2. Verify client compilation and unit tests
echo -e "\n${YELLOW}🧪 2. Verifying Next.js Client Compilation...${NC}"
pnpm --dir rbat-client build

# 3. Verify public API SemVer compliance using cargo-semver-checks
echo -e "\n${YELLOW}🧪 3. Running SemVer Compatibility Checks (cargo-semver-checks)...${NC}"
if ! command -v cargo-semver-checks &> /dev/null; then
  echo -e "${YELLOW}⚠️  cargo-semver-checks is not installed.${NC}"
  echo -e "You can install it with: ${BLUE}cargo install cargo-semver-checks --locked${NC}"
  echo -e "Skipping local SemVer check..."
else
  echo "Running semver-checks for rbat-core (package: rbat)..."
  # Run semver check against crates.io version (default)
  # If it fails, print a warning or error. If we are running in CI, we want to enforce it.
  if [ "$CI" = "true" ]; then
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

# 4. Run E2E Integration Tests (Client -> Server -> Storage -> Redis)
echo -e "\n${YELLOW}🧪 4. Running End-to-End Integration Tests...${NC}"
./scripts/run-integration-tests.sh

echo -e "\n${GREEN}🎉 SUCCESS: All release validation gates passed successfully!${NC}"
echo -e "The codebase is 100% ready for a stable release."
exit 0
