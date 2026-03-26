#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"

MODE="${1:-all}"
CONFIG_ARG="${2:-all}"
SUITES="${SUITES:-1 2 3}"
RUN_STRESS="${RUN_STRESS:-}"
WAIT_SECS="${WAIT_SECS:-8}"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SELF_CONFIGS=(welcome_join application commit external_join external_proposals reinit branch deep_random)
CROSS_CONFIGS=(welcome_join application commit external_join external_proposals reinit branch)

if [ -n "$RUN_STRESS" ]; then
    CROSS_CONFIGS+=(deep_random)
fi

cleanup() {
    docker compose -f "$COMPOSE_FILE" down >/dev/null 2>&1 || true
}

trap cleanup EXIT

case "$MODE" in
    all|self|cross)
        ;;
    *)
        echo "Usage: $0 [all|self|cross] [config_name|all]"
        exit 1
        ;;
esac

select_configs() {
    local kind="$1"
    local -n out_ref="$2"

    if [ "$kind" = "self" ]; then
        out_ref=("${SELF_CONFIGS[@]}")
    else
        out_ref=("${CROSS_CONFIGS[@]}")
    fi

    if [ "$CONFIG_ARG" != "all" ]; then
        out_ref=("${CONFIG_ARG%.json}")
    fi
}

run_mode() {
    local kind="$1"
    local client_a="$2"
    local client_b="$3"
    shift 3
    local configs=("$@")

    local configs_str="${configs[*]}"

    echo -e "${BLUE}Running Docker ${kind} interop${NC}"
    echo -e "${YELLOW}Suites:${NC} $SUITES"
    echo -e "${YELLOW}Configs:${NC} $configs_str"

    docker compose -f "$COMPOSE_FILE" run --rm \
        -e SUITES="$SUITES" \
        -e CONFIGS="$configs_str" \
        -e CLIENT_A="$client_a" \
        -e CLIENT_B="$client_b" \
        -e KIND="$kind" \
        --entrypoint /bin/sh test-runner -c '
set -eu
passed=0
total=0
for suite in $SUITES; do
  for cfg in $CONFIGS; do
    total=$((total + 1))
    printf "--- [%s] suite=%s config=%s ---\n" "$KIND" "$suite" "$cfg"
    log_file="/tmp/${KIND}-${suite}-${cfg}.log"
    if /test-runner -client "$CLIENT_A" -client "$CLIENT_B" -suite "$suite" -fail-fast -config "/configs/${cfg}.json" >"$log_file" 2>&1; then
      passed=$((passed + 1))
      printf "PASS: [%s] suite=%s config=%s\n" "$KIND" "$suite" "$cfg"
    else
      printf "FAIL: [%s] suite=%s config=%s\n" "$KIND" "$suite" "$cfg"
      sed -n "1,120p" "$log_file"
      exit 1
    fi
  done
done
printf "Summary: [%s] %s/%s passed\n" "$KIND" "$passed" "$total"
'
}

echo -e "${YELLOW}Starting Docker services...${NC}"
if [ "$MODE" = "self" ]; then
    docker compose -f "$COMPOSE_FILE" up -d mls-go >/dev/null
else
    docker compose -f "$COMPOSE_FILE" up -d mls-go mlspp >/dev/null
fi

sleep "$WAIT_SECS"

if [ "$MODE" = "all" ] || [ "$MODE" = "self" ]; then
    declare -a selected_self
    select_configs self selected_self
    run_mode self "mls-go:50051" "mls-go:50051" "${selected_self[@]}"
fi

if [ "$MODE" = "all" ] || [ "$MODE" = "cross" ]; then
    declare -a selected_cross
    select_configs cross selected_cross
    run_mode cross "mls-go:50051" "mlspp:50051" "${selected_cross[@]}"
fi

echo -e "${GREEN}Docker interop OK${NC}"
