#!/usr/bin/env bash
# Hyperledger Fabric Performance Benchmark
#
# Runs the blockchain-service benchmark tool and saves all output for thesis.
#
# Prerequisites:
#   1. Fabric network running  (bash blockchain/network/start.sh)
#   2. Chaincodes deployed     (bash blockchain/network/deploy-chaincode.sh ...)
#   3. blockchain-service running on :8095
#
# Usage:
#   bash blockchain/benchmark/run_benchmark.sh
#   bash blockchain/benchmark/run_benchmark.sh --requests 500 --tps-requests 1000

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BENCHMARK_BIN="${ROOT}/services/blockchain-service/cmd/benchmark"
RESULTS_DIR="${ROOT}/blockchain/benchmark/results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
CSV_FILE="${RESULTS_DIR}/benchmark_${TIMESTAMP}.csv"
LOG_FILE="${RESULTS_DIR}/benchmark_${TIMESTAMP}.log"

mkdir -p "${RESULTS_DIR}"

# Default args — override via CLI
REQUESTS="${REQUESTS:-200}"
TPS_REQUESTS="${TPS_REQUESTS:-500}"
URL="${BLOCKCHAIN_URL:-http://localhost:8095}"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║          AML Fraud Detection — Blockchain Benchmark          ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Results dir : ${RESULTS_DIR}"
echo "CSV output  : ${CSV_FILE}"
echo "Log output  : ${LOG_FILE}"
echo ""

# Build fresh binary
echo "Building benchmark tool..."
cd "${ROOT}/services/blockchain-service"
go build -o /tmp/fabric-benchmark ./cmd/benchmark/
echo "Build OK"
echo ""

# Check if blockchain-service is reachable
echo -n "Checking blockchain-service at ${URL}... "
if curl -sf "${URL}/health" > /dev/null 2>&1; then
    echo "OK"
else
    echo "UNREACHABLE"
    echo ""
    echo "ERROR: blockchain-service is not running at ${URL}"
    echo ""
    echo "Start it with:"
    echo "  cd ${ROOT}/services/blockchain-service"
    echo "  INTERNAL_JWT_SECRET=dev-secret go run ./cmd/server/"
    echo ""
    exit 1
fi

echo ""
echo "Starting benchmark (this will take a few minutes)..."
echo ""

# Run benchmark — capture both stdout and log file
/tmp/fabric-benchmark \
    --url "${URL}" \
    --requests "${REQUESTS}" \
    --tps-requests "${TPS_REQUESTS}" \
    --csv "${CSV_FILE}" \
    "$@" \
    | tee "${LOG_FILE}"

echo ""
echo "══════════════════════════════════════════════════════════════"
echo "Benchmark complete. Files saved:"
echo "  CSV (for thesis tables) : ${CSV_FILE}"
echo "  Full log                : ${LOG_FILE}"
echo ""
echo "To import into your thesis LaTeX table:"
echo "  Open ${CSV_FILE} in Excel/Google Sheets"
echo "  Copy the Latency section into Table X (Chaincode Invocation Latency)"
echo "  Copy the TPS section into Table Y (System Throughput)"
echo "══════════════════════════════════════════════════════════════"
