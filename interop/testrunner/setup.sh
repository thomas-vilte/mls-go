#!/bin/bash
# Builds the MLS interop test-runner from mls-implementations and places it here.
# Run once after cloning the repo.
#
# Usage: ./setup.sh [path-to-mls-implementations]
# Default mls-implementations path: ../../../mls-implementations (sibling of mls-go)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMPLS_DIR="${1:-$(cd "$SCRIPT_DIR/../../.." && pwd)/mls-implementations}"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${YELLOW}=== MLS Interop Test Runner Setup ===${NC}"

# Clone if needed
if [ ! -d "$IMPLS_DIR" ]; then
    echo -e "${YELLOW}Cloning mls-implementations into $IMPLS_DIR ...${NC}"
    git clone https://github.com/mlswg/mls-implementations.git "$IMPLS_DIR"
fi

RUNNER_SRC="$IMPLS_DIR/interop/test-runner"
if [ ! -d "$RUNNER_SRC" ]; then
    echo -e "${RED}test-runner source not found at $RUNNER_SRC${NC}"
    exit 1
fi

echo -e "${YELLOW}Building test-runner...${NC}"
(cd "$RUNNER_SRC" && go build -o test-runner .)
cp "$RUNNER_SRC/test-runner" "$SCRIPT_DIR/test-runner"
chmod +x "$SCRIPT_DIR/test-runner"

echo -e "${GREEN}test-runner built and installed at $SCRIPT_DIR/test-runner${NC}"
echo ""
echo "To run tests:"
echo "  cd $SCRIPT_DIR && ./run.sh [config]"
echo "  ./run.sh all               # run all 8 configs"
echo "  ./run.sh welcome_join      # single config"
