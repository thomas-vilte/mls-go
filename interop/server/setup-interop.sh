#!/bin/bash
# MLS interoperability framework setup
# Clones and configures everything needed to run interop tests
# See: https://github.com/mlswg/mls-implementations

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MLS_GO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
INTEROP_DIR="$MLS_GO_DIR/../mls-implementations"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== MLS-Go Interop Framework Setup ===${NC}"
echo ""

# 1. Check we're in the right repo
if [ ! -f "$MLS_GO_DIR/go.mod" ]; then
    echo -e "${RED}Error: go.mod not found at $MLS_GO_DIR${NC}"
    exit 1
fi

echo -e "${GREEN}mls-go repository found${NC}"

# 2. Clone mls-implementations if needed
if [ ! -d "$INTEROP_DIR" ]; then
    echo -e "${YELLOW}Cloning mls-implementations...${NC}"
    git clone https://github.com/mlswg/mls-implementations.git "$INTEROP_DIR"
else
    echo -e "${GREEN}mls-implementations already exists${NC}"
fi

# 3. Setup interop framework dependencies
echo -e "${YELLOW}Setting up framework dependencies...${NC}"
cd "$INTEROP_DIR/interop"

if [ ! -f "go.mod" ]; then
    go mod init github.com/mlswg/mls-implementations/interop
fi

go get google.golang.org/grpc@v1.64.0 \
   google.golang.org/protobuf@v1.33.0 \
   github.com/google/uuid@v1.6.0 2>&1 || true

echo -e "${GREEN}Dependencies configured${NC}"

# 4. Patch Makefile to use our server
echo -e "${YELLOW}Patching Makefile...${NC}"

MAKEFILE_BACKUP="Makefile.backup"
if [ ! -f "$MAKEFILE_BACKUP" ]; then
    cp Makefile "$MAKEFILE_BACKUP"
fi

# Replace go-mock-client paths
sed -i "s|go-mock-client/\*.go|$MLS_GO_DIR/interop/server/*.go|g" Makefile
sed -i "s|cd go-mock-client|cd $MLS_GO_DIR/interop/server|g" Makefile

echo -e "${GREEN}Makefile patched${NC}"

# 5. Build server
echo -e "${YELLOW}Building mls-go server...${NC}"
cd "$SCRIPT_DIR"
go build -o mls-mock-client .

echo -e "${GREEN}Server built${NC}"

# 6. Build test runner
echo -e "${YELLOW}Building test runner...${NC}"
cd "$INTEROP_DIR/interop"
make test-runner/test-runner 2>&1 || go build -C test-runner -o test-runner .

echo -e "${GREEN}Test runner built${NC}"

# 7. Verify setup
echo ""
echo -e "${BLUE}=== Verification ===${NC}"
echo ""

# Test server starts
cd "$SCRIPT_DIR"
./mls-mock-client -port 50001 &
SERVER_PID=$!
sleep 2

if lsof -i :50001 > /dev/null 2>&1; then
    echo -e "${GREEN}Server listening on port 50001${NC}"
    kill $SERVER_PID 2>/dev/null || true
else
    echo -e "${RED}Server not responding${NC}"
    exit 1
fi

# Check test runner exists
if [ -f "$INTEROP_DIR/interop/test-runner/test-runner" ]; then
    echo -e "${GREEN}Test runner ready${NC}"
else
    echo -e "${RED}Test runner not found${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}=== Setup complete ===${NC}"
echo ""
echo "To run tests:"
echo "  cd $SCRIPT_DIR"
echo "  ./run-interop-test.sh [config_name]"
echo ""
echo "Available configs:"
ls -1 "$INTEROP_DIR/interop/configs"/*.json 2>/dev/null | xargs -n1 basename | sed 's/^/  - /' || echo "  (none found)"
echo ""
echo "Example:"
echo "  ./run-interop-test.sh welcome_join"
