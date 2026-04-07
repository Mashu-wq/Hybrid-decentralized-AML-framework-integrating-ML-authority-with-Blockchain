#!/usr/bin/env bash
# =============================================================================
# FRAUD DETECTION SYSTEM — One-Command Local Bootstrap
# =============================================================================
# Usage: bash scripts/setup.sh
# Idempotent: safe to run multiple times
# =============================================================================

set -euo pipefail

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC}   $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1" >&2; }

# --- Banner ---
echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║       Fraud Detection System — Development Bootstrap       ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# =============================================================================
# STEP 1: Check Prerequisites
# =============================================================================
log_info "Checking prerequisites..."

check_tool() {
    local tool=$1
    local install_hint=$2
    if ! command -v "$tool" &>/dev/null; then
        log_error "$tool is required but not installed. $install_hint"
        return 1
    fi
    log_success "$tool: $(${tool} --version 2>&1 | head -1)"
}

MISSING=0
check_tool "docker"         "Install: https://docs.docker.com/get-docker/"        || MISSING=1
check_tool "docker"         ""  # compose is bundled with Docker Desktop
# Check docker compose (v2)
if ! docker compose version &>/dev/null; then
    log_error "docker compose (v2) not found. Update Docker Desktop or install the plugin."
    MISSING=1
fi
check_tool "go"             "Install: https://go.dev/dl/"                          || MISSING=1
check_tool "python3"        "Install: https://www.python.org/downloads/"           || MISSING=1
check_tool "git"            "Install: https://git-scm.com/"                        || MISSING=1
check_tool "make"           "Install: sudo apt install build-essential (Linux) or Xcode tools (Mac)" || MISSING=1

# Check versions
GO_VERSION=$(go version | grep -oP '\d+\.\d+' | head -1)
REQUIRED_GO="1.22"
if ! awk "BEGIN{exit !($GO_VERSION >= $REQUIRED_GO)}"; then
    log_error "Go $REQUIRED_GO+ required (found $GO_VERSION)"
    MISSING=1
fi

PYTHON_VERSION=$(python3 --version | grep -oP '\d+\.\d+' | head -1)
REQUIRED_PY="3.11"
if ! awk "BEGIN{exit !($PYTHON_VERSION >= $REQUIRED_PY)}"; then
    log_error "Python $REQUIRED_PY+ required (found $PYTHON_VERSION)"
    MISSING=1
fi

if [ "$MISSING" -eq 1 ]; then
    log_error "Fix missing prerequisites above and re-run setup.sh"
    exit 1
fi

# Check optional tools
log_info "Checking optional tools..."
check_tool "protoc"         "Install: https://grpc.io/docs/protoc-installation/"  || log_warn "protoc not found — needed for 'make proto'"
check_tool "golangci-lint"  "Install: https://golangci-lint.run/usage/install/"   || log_warn "golangci-lint not found — needed for 'make lint-go'"
check_tool "kubectl"        "Install: https://kubernetes.io/docs/tasks/tools/"     || log_warn "kubectl not found — needed for Kubernetes deployment"
check_tool "helm"           "Install: https://helm.sh/docs/intro/install/"         || log_warn "helm not found — needed for Kubernetes deployment"

# =============================================================================
# STEP 2: Environment Configuration
# =============================================================================
log_info "Configuring environment..."

if [ ! -f ".env" ]; then
    cp .env.example .env
    log_success "Created .env from .env.example"
    log_warn "Review .env and update secrets before running in production!"
else
    log_success ".env already exists, skipping"
fi

# =============================================================================
# STEP 3: Go Workspace & Dependencies
# =============================================================================
log_info "Setting up Go workspace..."

# Ensure go.work exists
if [ ! -f "go.work" ]; then
    log_error "go.work not found — repository may be corrupted"
    exit 1
fi

# Initialize Go modules for each service
for svc_dir in services/*/; do
    svc=$(basename "$svc_dir")
    if [ -f "$svc_dir/go.mod" ]; then
        log_info "  Tidying Go module: $svc"
        (cd "$svc_dir" && go mod tidy) || log_warn "  go mod tidy failed for $svc"
    fi
done

# Shared Go module
if [ -f "shared/go/go.mod" ]; then
    log_info "  Tidying shared Go module"
    (cd "shared/go" && go mod tidy) || log_warn "  go mod tidy failed for shared/go"
fi

# Chaincode modules
for cc_dir in blockchain/chaincode/*/; do
    if [ -f "$cc_dir/go.mod" ]; then
        log_info "  Tidying chaincode module: $(basename $cc_dir)"
        (cd "$cc_dir" && go mod tidy) || log_warn "  go mod tidy failed for $(basename $cc_dir)"
    fi
done

log_success "Go workspace configured"

# =============================================================================
# STEP 4: Python / Poetry Setup
# =============================================================================
log_info "Setting up Python environment..."

if ! command -v poetry &>/dev/null; then
    log_info "  Installing Poetry..."
    curl -sSL https://install.python-poetry.org | python3 -
    export PATH="$HOME/.local/bin:$PATH"
fi
log_success "Poetry: $(poetry --version)"

# Install ML service dependencies
if [ -f "pyproject.toml" ]; then
    log_info "  Installing Python dependencies (may take a few minutes)..."
    poetry install --no-interaction --no-ansi
    log_success "Python dependencies installed"
fi

# Services/ml-service Python env
if [ -f "services/ml-service/pyproject.toml" ]; then
    log_info "  Installing ml-service dependencies..."
    (cd services/ml-service && poetry install --no-interaction --no-ansi)
    log_success "ml-service Python dependencies installed"
fi

# =============================================================================
# STEP 5: Create Required Directories
# =============================================================================
log_info "Creating project directory structure..."

dirs=(
    "bin"
    "coverage"
    "ml/data/raw"
    "ml/data/processed"
    "ml/artifacts"
    "ml/mlruns"
    "ml/evaluation/results"
    "proto/gen/go"
    "proto/gen/python"
    "scripts/output"
    "logs"
    "blockchain/wallet"
    "infrastructure/monitoring/prometheus/rules"
    "infrastructure/monitoring/grafana/provisioning/datasources"
    "infrastructure/monitoring/grafana/provisioning/dashboards"
    "infrastructure/monitoring/grafana/dashboards"
    "tests/unit"
    "tests/integration"
    "tests/e2e"
    "tests/performance/results"
    "docs/thesis-diagrams"
)

for dir in "${dirs[@]}"; do
    mkdir -p "$dir"
done
log_success "Directory structure created"

# =============================================================================
# STEP 6: Install protoc plugins (if protoc available)
# =============================================================================
if command -v protoc &>/dev/null; then
    log_info "Installing protoc plugins for Go..."
    go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
    log_success "protoc plugins installed"
fi

# =============================================================================
# STEP 7: Start Infrastructure
# =============================================================================
log_info "Starting infrastructure containers..."
log_warn "This will download Docker images on first run (~2GB). Please wait..."

docker compose pull --ignore-pull-failures 2>/dev/null || true
docker compose up -d postgres mongodb redis zookeeper kafka vault jaeger prometheus grafana mlflow

log_info "Waiting for services to be healthy..."
sleep 10

# Wait for PostgreSQL
log_info "  Waiting for PostgreSQL..."
for i in {1..30}; do
    if docker exec fds-postgres pg_isready -U fraud_user -d fraud_detection &>/dev/null; then
        log_success "  PostgreSQL ready"
        break
    fi
    sleep 2
done

# Wait for Kafka
log_info "  Waiting for Kafka..."
for i in {1..30}; do
    if docker exec fds-kafka kafka-broker-api-versions --bootstrap-server localhost:9092 &>/dev/null; then
        log_success "  Kafka ready"
        break
    fi
    sleep 3
done

# Initialize Kafka topics
log_info "  Creating Kafka topics..."
docker compose up -d kafka-init

# Initialize Vault
log_info "  Configuring Vault..."
docker compose up -d vault-init
sleep 5

# =============================================================================
# STEP 8: Run Database Migrations
# =============================================================================
log_info "Running database migrations..."
# Only run if binaries exist (after first build)
if [ -f "bin/iam-service" ]; then
    make migrate || log_warn "Migration failed — run 'make migrate' manually after building services"
else
    log_warn "Services not built yet — run 'make build && make migrate' to apply migrations"
fi

# =============================================================================
# STEP 9: Generate Proto Stubs
# =============================================================================
if command -v protoc &>/dev/null; then
    log_info "Generating protobuf stubs..."
    make proto
    log_success "Proto stubs generated"
else
    log_warn "Skipping proto generation (protoc not installed)"
fi

# =============================================================================
# DONE
# =============================================================================
echo ""
echo -e "${GREEN}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                  Setup Complete!                           ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""
echo "  Next steps:"
echo "    make build        → Build all Go services"
echo "    make migrate      → Run database migrations"
echo "    make seed         → Seed development data"
echo "    make seed-ml      → Download Elliptic dataset for ML"
echo "    make ml-train     → Train ML models"
echo "    make run          → Start all services"
echo "    make test         → Run unit tests"
echo ""
echo "  Service UIs:"
echo "    Grafana:    http://localhost:3000  (admin / \$GRAFANA_ADMIN_PASSWORD)"
echo "    Jaeger:     http://localhost:16686"
echo "    Prometheus: http://localhost:9090"
echo "    MLflow:     http://localhost:5000"
echo "    Vault UI:   http://localhost:8200  (token: \$VAULT_TOKEN)"
echo "    Kafka UI:   docker compose --profile dev-tools up -d kafka-ui"
echo ""
echo "  Run 'make help' to see all available commands."
echo ""
