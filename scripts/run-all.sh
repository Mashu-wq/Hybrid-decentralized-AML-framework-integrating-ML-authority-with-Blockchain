#!/usr/bin/env bash
# =============================================================================
# FRAUD DETECTION SYSTEM — Start All Services
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log_info()    { echo -e "${BLUE}[RUN]${NC}  $1"; }
log_success() { echo -e "${GREEN}[OK]${NC}   $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }

if [ -f ".env" ]; then source .env; fi

# --- Check infra is up ---
if ! docker exec fds-postgres pg_isready -U "${POSTGRES_USER:-fraud_user}" &>/dev/null; then
    log_warn "Infrastructure not running. Starting..."
    make infra-up
    sleep 10
fi

# --- Run services in background ---
PIDS=()
start_service() {
    local name=$1
    local dir="services/$2"
    log_info "Starting $name..."
    cd "$REPO_ROOT/$dir" && go run ./cmd/server/ > "$REPO_ROOT/logs/${name}.log" 2>&1 &
    PIDS+=($!)
    log_success "$name started (PID ${PIDS[-1]})"
}

mkdir -p logs

start_service "encryption-service" "encryption-service"
sleep 2  # encryption-service must start first (other services depend on it)

start_service "iam-service"         "iam-service"
start_service "kyc-service"         "kyc-service"
start_service "transaction-service" "transaction-service"
start_service "blockchain-service"  "blockchain-service"
start_service "alert-service"       "alert-service"
start_service "case-service"        "case-service"
# analytics-service has no implementation yet (Phase 12)

# Start ML service (Python)
log_info "Starting ml-service..."
cd "$REPO_ROOT/services/ml-service"
poetry run uvicorn main:app --host 0.0.0.0 --port 8000 \
    > "$REPO_ROOT/logs/ml-service.log" 2>&1 &
PIDS+=($!)
log_success "ml-service started (PID ${PIDS[-1]})"
cd "$REPO_ROOT"

# Wait for all services then start gateway
sleep 5
start_service "api-gateway" "api-gateway"

echo ""
log_success "All services started!"
echo "  API Gateway: http://localhost:${API_GATEWAY_PORT:-8080}"
echo "  Logs: ./logs/<service>.log"
echo "  Press Ctrl+C to stop all services"
echo ""

# Trap to kill all child processes on exit
cleanup() {
    log_info "Stopping all services..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    log_success "All services stopped"
}
trap cleanup EXIT INT TERM

# Wait for all background processes
wait
