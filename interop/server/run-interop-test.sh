#!/bin/bash
# MLSWG interoperability test runner
# Usage: ./run-interop-test.sh [config_name]
# Example: ./run-interop-test.sh welcome_join

set -e

# Config
SERVER_PORT=${SERVER_PORT:-50001}
SERVER_BIN="./mls-mock-client"
TEST_RUNNER="../mls-implementations/interop/test-runner/test-runner"
CONFIGS_DIR="../mls-implementations/interop/configs"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}=== MLS-Go Interop Test Runner ===${NC}"

# Build server if needed
if [ ! -f "$SERVER_BIN" ]; then
    echo -e "${YELLOW}Building server...${NC}"
    go build -o "$SERVER_BIN" .
fi

# Kill any existing server
pkill -f "$SERVER_BIN" 2>/dev/null || true
sleep 1

# Start server
echo -e "${YELLOW}Starting server on port $SERVER_PORT...${NC}"
nohup "$SERVER_BIN" -port "$SERVER_PORT" > /tmp/mls-server.log 2>&1 &
SERVER_PID=$!
sleep 2

# Check server is running
if ! lsof -i :"$SERVER_PORT" > /dev/null 2>&1; then
    echo -e "${RED}Error: Failed to start server${NC}"
    cat /tmp/mls-server.log
    exit 1
fi

echo -e "${GREEN}Server running (PID: $SERVER_PID)${NC}"

# Pick config
CONFIG_NAME=${1:-welcome_join}
CONFIG_FILE="$CONFIGS_DIR/$CONFIG_NAME.json"

if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${RED}Error: Config not found: $CONFIG_FILE${NC}"
    echo "Available configs:"
    ls -1 "$CONFIGS_DIR"/*.json | xargs -n1 basename
    kill $SERVER_PID 2>/dev/null
    exit 1
fi

echo -e "${YELLOW}Running test: $CONFIG_NAME${NC}"

# Run test
cd ../mls-implementations/interop || exit 1

if ! ./test-runner/test-runner -client "localhost:$SERVER_PORT" -config "$CONFIG_FILE" 2>&1; then
    echo -e "${RED}Test failed${NC}"
    echo "Server log:"
    cat /tmp/mls-server.log | tail -50
    kill $SERVER_PID 2>/dev/null
    exit 1
fi

echo -e "${GREEN}Test passed${NC}"

# Cleanup
kill $SERVER_PID 2>/dev/null || true

echo -e "${GREEN}=== Test finished ===${NC}"
