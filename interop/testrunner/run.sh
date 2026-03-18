#!/bin/bash
# Runs MLS interop tests against the mls-go gRPC server.
#
# Usage:
#   ./run.sh                    # run all configs
#   ./run.sh all                # run all configs
#   ./run.sh welcome_join       # run single config (no .json extension needed)
#   ./run.sh deep_random        # random self-interop stress test (slow)
#
# Environment:
#   PORT=50051                  # server port (default 50051)
#   SUITE=2                     # cipher suite filter (default: all suites)
#   PRIVATE=1                   # set to enable -private flag (CS2-only mode)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="$SCRIPT_DIR/../server"
RUNNER="$SCRIPT_DIR/test-runner"
CONFIGS_DIR="$SCRIPT_DIR/configs"

PORT="${PORT:-50051}"
SUITE="${SUITE:-}"
PRIVATE="${PRIVATE:-}"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# All configs in recommended run order (simple → complex)
ALL_CONFIGS=(
    welcome_join
    application
    commit
    external_join
    external_proposals
    reinit
    branch
    deep_random
)

# Check test-runner exists
if [ ! -f "$RUNNER" ]; then
    echo -e "${RED}test-runner not found. Run ./setup.sh first.${NC}"
    exit 1
fi

# Build and start server
echo -e "${YELLOW}Building mls-go server...${NC}"
(cd "$SERVER_DIR" && go build -o mls-go-server .)

pkill -f "mls-go-server" 2>/dev/null || true
sleep 1

echo -e "${YELLOW}Starting server on :$PORT ...${NC}"
"$SERVER_DIR/mls-go-server" &
SERVER_PID=$!
sleep 2

cleanup() {
    kill "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

if ! ss -tlnp 2>/dev/null | grep -q ":$PORT" && ! lsof -i ":$PORT" > /dev/null 2>&1; then
    echo -e "${RED}Server failed to start on :$PORT${NC}"
    exit 1
fi
echo -e "${GREEN}Server running (PID $SERVER_PID)${NC}"

# Build runner flags
RUNNER_FLAGS=(-client "localhost:$PORT" -fail-fast)
[ -n "$SUITE" ] && RUNNER_FLAGS+=(-suite "$SUITE")
[ -n "$PRIVATE" ] && RUNNER_FLAGS+=(-private)

run_config() {
    local name="$1"
    local config="$CONFIGS_DIR/${name}.json"

    if [ ! -f "$config" ]; then
        echo -e "${RED}Config not found: $config${NC}"
        return 1
    fi

    echo -e "${BLUE}--- $name ---${NC}"
    if "$RUNNER" "${RUNNER_FLAGS[@]}" -config "$config" > /dev/null 2>&1; then
        echo -e "${GREEN}PASS: $name${NC}"
        return 0
    else
        echo -e "${RED}FAIL: $name${NC}"
        # Re-run without output suppression to show error
        "$RUNNER" "${RUNNER_FLAGS[@]}" -config "$config" 2>&1 | grep -E '"error"|error' | head -5 || true
        return 1
    fi
}

# Determine which configs to run
CONFIG_ARG="${1:-all}"
FAILED=0
PASSED=0

if [ "$CONFIG_ARG" = "all" ] || [ -z "$CONFIG_ARG" ]; then
    echo -e "${YELLOW}Running all ${#ALL_CONFIGS[@]} configs...${NC}"
    echo ""
    for cfg in "${ALL_CONFIGS[@]}"; do
        if run_config "$cfg"; then
            PASSED=$((PASSED + 1))
        else
            FAILED=$((FAILED + 1))
        fi
    done
    echo ""
    echo -e "${BLUE}Results: ${GREEN}$PASSED passed${NC}, ${RED}$FAILED failed${NC} / ${#ALL_CONFIGS[@]} total"
    [ "$FAILED" -gt 0 ] && exit 1
else
    name="${CONFIG_ARG%.json}"
    run_config "$name" || exit 1
fi
