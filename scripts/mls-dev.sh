#!/usr/bin/env bash
# Dev mode wrapper for mls-go interop (hot-reload)
#
# Usage:
#   ./scripts/mls-dev.sh up              # start services in dev mode
#   ./scripts/mls-dev.sh rebuild         # restart mls-go (picks up code changes)
#   ./scripts/mls-dev.sh logs [service]  # tail logs
#   ./scripts/mls-dev.sh test [config]   # run a single test
#   ./scripts/mls-dev.sh down            # stop everything

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$SCRIPT_DIR/../docker"

COMPOSE="docker compose -f $DOCKER_DIR/docker-compose.yml -f $DOCKER_DIR/docker-compose.dev.yml"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

cmd="${1:-help}"
shift || true

case "$cmd" in
  up)
    echo -e "${YELLOW}Starting dev environment (mls-go hot-reload + mlspp)...${NC}"
    $COMPOSE up --build -d mls-go mlspp
    $COMPOSE up --wait mls-go mlspp
    echo -e "${GREEN}Ready. Run './scripts/mls-dev.sh test welcome_join' to test.${NC}"
    ;;

  rebuild)
    echo -e "${YELLOW}Restarting mls-go (rebuilds from source)...${NC}"
    $COMPOSE restart mls-go
    $COMPOSE up --wait mls-go
    echo -e "${GREEN}Done.${NC}"
    ;;

  logs)
    $COMPOSE logs -f "${1:-}"
    ;;

  test)
    config="${1:-welcome_join}"
    echo -e "${BLUE}Running: $config${NC}"
    $COMPOSE run --rm test-runner \
      -client mls-go:50051 -client mlspp:50051 \
      -config "/configs/${config}.json"
    ;;

  down)
    $COMPOSE down
    ;;

  *)
    echo "Usage: $0 {up|rebuild|logs [svc]|test [config]|down}"
    ;;
esac
