#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"

MODE="${1:-all}"
CONFIG_ARG="${2:-all}"
SUITES="${SUITES:-1 2 3}"
RUN_STRESS="${RUN_STRESS:-}"
WAIT_SECS="${WAIT_SECS:-8}"
CROSS_TARGET="${CROSS_TARGET:-mlspp}"
# SEQUENTIAL=1 runs one cipher suite at a time instead of all in parallel.
# Required for targets that don't handle concurrent gRPC connections well (e.g. OpenMLS).
# Automatically enabled when CROSS_TARGET=openmls.
SEQUENTIAL="${SEQUENTIAL:-}"
if [ "$CROSS_TARGET" = "openmls" ]; then
    SEQUENTIAL=1
fi

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# deep_random is opt-in via RUN_STRESS for both self and cross interop.
# Without it the full suite runs in a few minutes instead of several hours.
SELF_CONFIGS=(welcome_join application commit external_join external_proposals reinit branch)
MLSPP_CROSS_CONFIGS=(welcome_join application commit external_join external_proposals reinit branch)
OPENMLS_CROSS_CONFIGS=(welcome_join application external_join deep_random)

if [ -n "$RUN_STRESS" ]; then
    SELF_CONFIGS+=(deep_random)
    MLSPP_CROSS_CONFIGS+=(deep_random)
fi

if [ "$CROSS_TARGET" = "openmls" ]; then
    CROSS_CONFIGS=("${OPENMLS_CROSS_CONFIGS[@]}")
else
    CROSS_CONFIGS=("${MLSPP_CROSS_CONFIGS[@]}")
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
    if [ "$kind" = "cross" ]; then
        echo -e "${YELLOW}Target:${NC} $CROSS_TARGET"
    fi
    echo -e "${YELLOW}Suites:${NC} $SUITES"
    echo -e "${YELLOW}Configs:${NC} $configs_str"

    # Run one background subshell per suite; each subshell runs its configs
    # sequentially. This gives an N-suites speedup (typically 3x) without
    # flooding the gRPC server with simultaneous connections.
    #
    # The inner shell is /bin/sh (ash on alpine) — only POSIX constructs used.
    docker compose -f "$COMPOSE_FILE" run --rm \
        -e SUITES="$SUITES" \
        -e CONFIGS="$configs_str" \
        -e CLIENT_A="$client_a" \
        -e CLIENT_B="$client_b" \
        -e KIND="$kind" \
        -e SEQUENTIAL="$SEQUENTIAL" \
        --entrypoint /bin/sh test-runner -c '
set -eu

run_suite() {
  suite="$1"
  for cfg in $CONFIGS; do
    log="/tmp/${KIND}-s${suite}-${cfg}.log"
    res="/tmp/${KIND}-s${suite}-${cfg}.result"
    if /test-runner \
        -client "$CLIENT_A" \
        -client "$CLIENT_B" \
        -suite  "$suite" \
        -fail-fast \
        -config "/configs/${cfg}.json" \
        >"$log" 2>&1
    then
      printf PASS > "$res"
    else
      printf FAIL > "$res"
    fi
  done
}

if [ -n "$SEQUENTIAL" ]; then
  # Sequential mode: one suite at a time. Required for targets that do not
  # handle concurrent gRPC connections well (e.g. OpenMLS).
  for suite in $SUITES; do
    run_suite "$suite"
  done
else
  # Parallel mode: one background worker per suite. ~3x faster for targets
  # that support concurrent connections (e.g. mlspp, mls-go self).
  for suite in $SUITES; do
    run_suite "$suite" &
  done
  wait
fi

# Print results in deterministic order and tally.
passed=0
total=0
failed=0
for suite in $SUITES; do
  for cfg in $CONFIGS; do
    total=$((total + 1))
    log="/tmp/${KIND}-s${suite}-${cfg}.log"
    res="/tmp/${KIND}-s${suite}-${cfg}.result"
    result=$(cat "$res" 2>/dev/null || printf FAIL)
    printf "--- [%s] suite=%s config=%s ---\n" "$KIND" "$suite" "$cfg"
    if [ "$result" = "PASS" ]; then
      passed=$((passed + 1))
      printf "PASS: [%s] suite=%s config=%s\n" "$KIND" "$suite" "$cfg"
    else
      failed=$((failed + 1))
      printf "FAIL: [%s] suite=%s config=%s\n" "$KIND" "$suite" "$cfg"
      tail -80 "$log"
    fi
  done
done

printf "Summary: [%s] %s/%s passed\n" "$KIND" "$passed" "$total"
[ "$failed" -eq 0 ]
'
}

echo -e "${YELLOW}Starting Docker services...${NC}"
if [ "$MODE" = "self" ]; then
    docker compose -f "$COMPOSE_FILE" up -d mls-go >/dev/null
else
    docker compose -f "$COMPOSE_FILE" up -d mls-go "$CROSS_TARGET" >/dev/null
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
    run_mode cross "mls-go:50051" "$CROSS_TARGET:50051" "${selected_cross[@]}"
fi

echo -e "${GREEN}Docker interop OK${NC}"
