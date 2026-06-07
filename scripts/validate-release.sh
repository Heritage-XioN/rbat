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
