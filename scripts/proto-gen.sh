#!/usr/bin/env bash
# =============================================================================
# FRAUD DETECTION SYSTEM — Protobuf Code Generation
# =============================================================================
# Generates Go and Python stubs from all .proto files in /proto/.
# Run: bash scripts/proto-gen.sh
# Or:  make proto
# =============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

GREEN='\033[0;32m'; BLUE='\033[0;34m'; RED='\033[0;31m'; NC='\033[0m'
log_info()    { echo -e "${BLUE}[PROTO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC}   $1"; }
log_error()   { echo -e "${RED}[ERR]${NC}  $1" >&2; }

# --- Check tools ---
check_tool() {
    command -v "$1" &>/dev/null || {
        log_error "$1 not found. Install: $2"
        exit 1
    }
}

check_tool protoc             "https://grpc.io/docs/protoc-installation/"
check_tool protoc-gen-go      "go install google.golang.org/protobuf/cmd/protoc-gen-go@latest"
check_tool protoc-gen-go-grpc "go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest"
check_tool python3            "https://python.org"

# Check Python grpc tools
python3 -c "import grpc_tools" 2>/dev/null || {
    log_info "Installing grpcio-tools..."
    pip install grpcio-tools
}

# --- Setup output directories ---
GO_OUT="$REPO_ROOT/proto/gen/go"
PY_OUT="$REPO_ROOT/proto/gen/python"
PROTO_DIR="$REPO_ROOT/proto"

mkdir -p "$GO_OUT" "$PY_OUT"

# --- Well-known types include path ---
# Find google protobuf includes
GOOGLE_PROTO_PATH=""
for candidate in \
    "$(python3 -c 'import grpc_tools; import os; print(os.path.dirname(grpc_tools.__file__))' 2>/dev/null)/_proto" \
    "/usr/local/include" \
    "/usr/include"; do
    if [ -d "$candidate/google/protobuf" ]; then
        GOOGLE_PROTO_PATH="$candidate"
        break
    fi
done

if [ -z "$GOOGLE_PROTO_PATH" ]; then
    log_error "Cannot find google/protobuf includes. Install: pip install grpcio-tools"
    exit 1
fi

log_info "Using protobuf includes: $GOOGLE_PROTO_PATH"

# --- Proto files to compile (order matters: common.proto first) ---
PROTO_FILES=(
    "common.proto"
    "iam.proto"
    "encryption.proto"
    "kyc.proto"
    "fraud.proto"
    "transaction.proto"
    "alert.proto"
    "audit.proto"
)

# --- Generate ---
FAILED=0

for proto_file in "${PROTO_FILES[@]}"; do
    full_path="$PROTO_DIR/$proto_file"
    if [ ! -f "$full_path" ]; then
        log_error "Proto file not found: $full_path"
        FAILED=1
        continue
    fi

    log_info "Compiling $proto_file..."

    # Go stubs
    protoc \
        --proto_path="$PROTO_DIR" \
        --proto_path="$GOOGLE_PROTO_PATH" \
        --go_out="$GO_OUT" \
        --go_opt=paths=source_relative \
        --go-grpc_out="$GO_OUT" \
        --go-grpc_opt=paths=source_relative \
        "$full_path" \
        && log_success "  Go: $proto_file" \
        || { log_error "  Go generation failed for $proto_file"; FAILED=1; }

    # Python stubs
    python3 -m grpc_tools.protoc \
        --proto_path="$PROTO_DIR" \
        --proto_path="$GOOGLE_PROTO_PATH" \
        --python_out="$PY_OUT" \
        --pyi_out="$PY_OUT" \
        --grpc_python_out="$PY_OUT" \
        "$full_path" \
        && log_success "  Python: $proto_file" \
        || { log_error "  Python generation failed for $proto_file"; FAILED=1; }
done

# --- Fix Python import paths (grpc_tools generates relative imports) ---
log_info "Fixing Python relative imports..."
find "$PY_OUT" -name "*_pb2_grpc.py" | while read -r f; do
    # Replace: import foo_pb2 as foo__pb2
    # With:    from . import foo_pb2 as foo__pb2
    if command -v gsed &>/dev/null; then
        gsed -i 's/^import \(.*_pb2\) as /from . import \1 as /g' "$f"
    else
        sed -i 's/^import \(.*_pb2\) as /from . import \1 as /g' "$f"
    fi
done

# Create __init__.py for Python packages
find "$PY_OUT" -type d | while read -r d; do
    touch "$d/__init__.py"
done

# --- Show summary ---
if [ "$FAILED" -eq 0 ]; then
    echo ""
    log_success "All proto files compiled successfully!"
    echo ""
    echo "  Go stubs:     $GO_OUT"
    echo "  Python stubs: $PY_OUT"
    echo ""
    echo "  Generated files:"
    find "$GO_OUT" -name "*.go" | head -20
    find "$PY_OUT" -name "*.py" | head -20
else
    log_error "Some proto files failed to compile — check errors above"
    exit 1
fi
