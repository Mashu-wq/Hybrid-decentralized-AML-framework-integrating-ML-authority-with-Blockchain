#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

docker compose -f "${ROOT_DIR}/docker-compose.yaml" down -v --remove-orphans || true
rm -rf "${ROOT_DIR}/crypto-config" "${ROOT_DIR}/channel-artifacts" "${ROOT_DIR}/system-genesis-block"
echo "Fabric network removed"
