# =============================================================================
# FRAUD DETECTION SYSTEM — Makefile
# =============================================================================
# Usage: make <target>
# Run `make help` to see all available targets.

SHELL := /bin/bash
.DEFAULT_GOAL := help

# --- Project Config ---
PROJECT_NAME   := fraud-detection-system
GO_VERSION     := 1.22
PYTHON_VERSION := 3.11
DOCKER_REGISTRY := ghcr.io/fraud-detection
IMAGE_TAG      := $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")

# --- Colors ---
RED    := \033[31m
GREEN  := \033[32m
YELLOW := \033[33m
BLUE   := \033[34m
RESET  := \033[0m

# --- Go Services ---
GO_SERVICES := api-gateway iam-service kyc-service transaction-service \
               blockchain-service alert-service case-service \
               analytics-service encryption-service

# --- Proto ---
PROTO_DIR := proto
PROTO_GEN_GO := proto/gen/go
PROTO_GEN_PY := proto/gen/python

.PHONY: help
help: ## Show this help message
	@echo ""
	@echo "$(BLUE)╔══════════════════════════════════════════════════════╗$(RESET)"
	@echo "$(BLUE)║   Fraud Detection System — Developer Commands        ║$(RESET)"
	@echo "$(BLUE)╚══════════════════════════════════════════════════════╝$(RESET)"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf "  %-30s %s\n", "Target", "Description\n  %-30s %s\n", "──────────────────────────────", "───────────────────────────────"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  $(GREEN)%-30s$(RESET) %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@echo ""

# =============================================================================
# SETUP & BOOTSTRAP
# =============================================================================

.PHONY: setup
setup: ## Bootstrap full local dev environment (first-time setup)
	@echo "$(BLUE)► Setting up local development environment...$(RESET)"
	@bash scripts/setup.sh

.PHONY: env
env: ## Copy .env.example to .env if it doesn't exist
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "$(GREEN)✓ Created .env from .env.example — please fill in secrets$(RESET)"; \
	else \
		echo "$(YELLOW)⚠ .env already exists, skipping$(RESET)"; \
	fi

# =============================================================================
# INFRASTRUCTURE (Docker Compose)
# =============================================================================

.PHONY: infra-up
infra-up: env ## Start all infrastructure containers (postgres, mongo, redis, kafka, vault, etc.)
	@echo "$(BLUE)► Starting infrastructure...$(RESET)"
	@docker compose up -d postgres mongodb redis zookeeper kafka vault jaeger prometheus grafana mlflow kafka-init vault-init
	@echo "$(GREEN)✓ Infrastructure started$(RESET)"
	@make infra-status

.PHONY: infra-up-full
infra-up-full: env ## Start ALL containers including dev tools (kafka-ui, pgadmin)
	@docker compose --profile dev-tools up -d
	@echo "$(GREEN)✓ Full infrastructure (with dev tools) started$(RESET)"

.PHONY: infra-down
infra-down: ## Stop all infrastructure containers (keeps volumes)
	@docker compose down
	@echo "$(GREEN)✓ Infrastructure stopped$(RESET)"

.PHONY: infra-clean
infra-clean: ## Stop and REMOVE all containers and volumes (destructive!)
	@echo "$(RED)⚠ This will delete all data volumes. Press Ctrl+C to cancel.$(RESET)"
	@sleep 3
	@docker compose down -v --remove-orphans
	@echo "$(GREEN)✓ Infrastructure cleaned$(RESET)"

.PHONY: infra-status
infra-status: ## Show running container status
	@docker compose ps

.PHONY: infra-logs
infra-logs: ## Tail logs from all infrastructure containers
	@docker compose logs -f

.PHONY: infra-restart
infra-restart: ## Restart all infrastructure containers
	@docker compose restart

# =============================================================================
# PROTOBUF CODE GENERATION
# =============================================================================

.PHONY: proto
proto: ## Generate Go and Python gRPC stubs from all .proto files
	@echo "$(BLUE)► Generating protobuf stubs...$(RESET)"
	@mkdir -p $(PROTO_GEN_GO) $(PROTO_GEN_PY)
	@for proto_file in $(PROTO_DIR)/*.proto; do \
		echo "  Processing $$proto_file..."; \
		protoc \
			--proto_path=$(PROTO_DIR) \
			--go_out=$(PROTO_GEN_GO) \
			--go_opt=paths=source_relative \
			--go-grpc_out=$(PROTO_GEN_GO) \
			--go-grpc_opt=paths=source_relative \
			--python_out=$(PROTO_GEN_PY) \
			--grpc_python_out=$(PROTO_GEN_PY) \
			$$proto_file; \
	done
	@echo "$(GREEN)✓ Proto stubs generated$(RESET)"

.PHONY: proto-check
proto-check: ## Verify all required proto tools are installed
	@which protoc      || (echo "$(RED)✗ protoc not found$(RESET)" && exit 1)
	@which protoc-gen-go      || (echo "$(RED)✗ protoc-gen-go not found$(RESET)" && exit 1)
	@which protoc-gen-go-grpc || (echo "$(RED)✗ protoc-gen-go-grpc not found$(RESET)" && exit 1)
	@echo "$(GREEN)✓ All proto tools available$(RESET)"

# =============================================================================
# BUILD
# =============================================================================

.PHONY: build
build: ## Build all Go services
	@echo "$(BLUE)► Building all Go services...$(RESET)"
	@for svc in $(GO_SERVICES); do \
		echo "  Building $$svc..."; \
		(cd services/$$svc && go build -ldflags="-X main.version=$(IMAGE_TAG)" -o ../../bin/$$svc ./cmd/...) \
			&& echo "  $(GREEN)✓ $$svc$(RESET)" \
			|| echo "  $(RED)✗ $$svc failed$(RESET)"; \
	done

.PHONY: build-svc
build-svc: ## Build a specific service: make build-svc SVC=iam-service
	@if [ -z "$(SVC)" ]; then echo "$(RED)Usage: make build-svc SVC=<service-name>$(RESET)"; exit 1; fi
	@echo "$(BLUE)► Building $(SVC)...$(RESET)"
	@cd services/$(SVC) && go build -ldflags="-X main.version=$(IMAGE_TAG)" -o ../../bin/$(SVC) ./cmd/...
	@echo "$(GREEN)✓ $(SVC) built$(RESET)"

.PHONY: build-ml
build-ml: ## Install Python dependencies for ML service
	@echo "$(BLUE)► Installing ML Python dependencies...$(RESET)"
	@cd services/ml-service && poetry install
	@echo "$(GREEN)✓ ML dependencies installed$(RESET)"

# =============================================================================
# DOCKER IMAGE BUILDS
# =============================================================================

.PHONY: docker-build
docker-build: ## Build Docker images for all services
	@echo "$(BLUE)► Building Docker images...$(RESET)"
	@echo "  Building image: $(DOCKER_REGISTRY)/api-gateway:$(IMAGE_TAG)"; \
	docker build -f services/api-gateway/Dockerfile \
		-t $(DOCKER_REGISTRY)/api-gateway:$(IMAGE_TAG) \
		-t $(DOCKER_REGISTRY)/api-gateway:latest \
		.
	@for svc in iam-service kyc-service transaction-service blockchain-service \
	             alert-service case-service analytics-service encryption-service; do \
		echo "  Building image: $(DOCKER_REGISTRY)/$$svc:$(IMAGE_TAG)"; \
		docker build -f infrastructure/docker/$$svc.Dockerfile \
			-t $(DOCKER_REGISTRY)/$$svc:$(IMAGE_TAG) \
			-t $(DOCKER_REGISTRY)/$$svc:latest \
			. ; \
	done
	@docker build -f infrastructure/docker/ml-service.Dockerfile \
		-t $(DOCKER_REGISTRY)/ml-service:$(IMAGE_TAG) \
		-t $(DOCKER_REGISTRY)/ml-service:latest .
	@echo "$(GREEN)✓ All images built$(RESET)"

.PHONY: docker-push
docker-push: ## Push Docker images to registry
	@echo "$(BLUE)► Pushing images to $(DOCKER_REGISTRY)...$(RESET)"
	@for svc in $(GO_SERVICES) ml-service; do \
		docker push $(DOCKER_REGISTRY)/$$svc:$(IMAGE_TAG); \
		docker push $(DOCKER_REGISTRY)/$$svc:latest; \
	done

# =============================================================================
# DATABASE MIGRATIONS
# =============================================================================

.PHONY: migrate
migrate: ## Run all database migrations (PostgreSQL)
	@echo "$(BLUE)► Running database migrations...$(RESET)"
	@for svc in $(GO_SERVICES); do \
		if [ -d "services/$$svc/migrations" ]; then \
			echo "  Migrating $$svc..."; \
			cd services/$$svc && go run cmd/migrate/main.go up; \
			cd ../..; \
		fi \
	done
	@echo "$(GREEN)✓ Migrations complete$(RESET)"

.PHONY: migrate-down
migrate-down: ## Roll back last migration for all services
	@for svc in $(GO_SERVICES); do \
		if [ -d "services/$$svc/migrations" ]; then \
			cd services/$$svc && go run cmd/migrate/main.go down 1; \
			cd ../..; \
		fi \
	done

.PHONY: migrate-status
migrate-status: ## Show migration status for all services
	@for svc in $(GO_SERVICES); do \
		if [ -d "services/$$svc/migrations" ]; then \
			echo "  $$svc:"; \
			cd services/$$svc && go run cmd/migrate/main.go status; \
			cd ../..; \
		fi \
	done

# =============================================================================
# SEED DATA
# =============================================================================

.PHONY: seed
seed: ## Seed all databases with development data
	@echo "$(BLUE)► Seeding development data...$(RESET)"
	@bash scripts/seed-data.sh
	@echo "$(GREEN)✓ Data seeded$(RESET)"

.PHONY: seed-ml
seed-ml: ## Download and prepare Elliptic dataset for ML training
	@echo "$(BLUE)► Preparing Elliptic dataset...$(RESET)"
	@cd ml && poetry run python data/download_elliptic.py
	@cd ml && poetry run python data/preprocess.py
	@echo "$(GREEN)✓ ML data prepared$(RESET)"

# =============================================================================
# LINT
# =============================================================================

.PHONY: lint
lint: lint-go lint-python ## Run all linters

.PHONY: lint-go
lint-go: ## Lint all Go code with golangci-lint
	@echo "$(BLUE)► Linting Go code...$(RESET)"
	@which golangci-lint || (echo "$(RED)golangci-lint not found — install: brew install golangci-lint$(RESET)" && exit 1)
	@golangci-lint run ./...
	@echo "$(GREEN)✓ Go lint passed$(RESET)"

.PHONY: lint-python
lint-python: ## Lint Python code (flake8 + black + mypy)
	@echo "$(BLUE)► Linting Python code...$(RESET)"
	@cd services/ml-service && poetry run flake8 . --max-line-length=100 --exclude=proto/gen
	@cd services/ml-service && poetry run black --check . --line-length=100
	@cd services/ml-service && poetry run mypy . --ignore-missing-imports
	@echo "$(GREEN)✓ Python lint passed$(RESET)"

.PHONY: fmt
fmt: ## Format all code (gofmt + black)
	@echo "$(BLUE)► Formatting code...$(RESET)"
	@gofmt -w ./services ./shared
	@cd services/ml-service && poetry run black . --line-length=100
	@cd services/ml-service && poetry run isort .
	@echo "$(GREEN)✓ Code formatted$(RESET)"

# =============================================================================
# TESTS
# =============================================================================

.PHONY: test
test: test-unit ## Run unit tests (fast, no external dependencies)

.PHONY: test-unit
test-unit: test-unit-go test-unit-python test-unit-chaincode ## Run all unit tests

.PHONY: test-unit-go
test-unit-go: ## Run Go unit tests with coverage
	@echo "$(BLUE)► Running Go unit tests...$(RESET)"
	@go test -v -race -coverprofile=coverage/go-coverage.out ./services/...
	@go tool cover -html=coverage/go-coverage.out -o coverage/go-coverage.html
	@echo "$(GREEN)✓ Go unit tests passed$(RESET)"

.PHONY: test-unit-python
test-unit-python: ## Run Python unit tests with coverage
	@echo "$(BLUE)► Running Python unit tests...$(RESET)"
	@cd services/ml-service && poetry run pytest tests/unit/ -v --tb=short
	@echo "$(GREEN)✓ Python unit tests passed$(RESET)"

.PHONY: test-unit-chaincode
test-unit-chaincode: ## Run chaincode unit tests with mock shim
	@echo "$(BLUE)► Running chaincode unit tests...$(RESET)"
	@for contract in kyc-contract alert-contract audit-contract; do \
		cd blockchain/chaincode/$$contract && go test -v -race ./... ; \
		cd ../../..; \
	done
	@echo "$(GREEN)✓ Chaincode unit tests passed$(RESET)"

.PHONY: test-integration
test-integration: ## Run integration tests (requires Docker containers)
	@echo "$(BLUE)► Running integration tests...$(RESET)"
	@go test -v -tags=integration -timeout=300s ./tests/integration/...
	@echo "$(GREEN)✓ Integration tests passed$(RESET)"

.PHONY: test-integration-docker
test-integration-docker: ## Run integration tests in Docker (full isolation)
	@docker compose -f docker-compose.test.yml up --abort-on-container-exit
	@docker compose -f docker-compose.test.yml down -v

.PHONY: test-e2e
test-e2e: ## Run end-to-end tests (requires full stack running)
	@echo "$(BLUE)► Running E2E tests...$(RESET)"
	@newman run tests/e2e/postman-collection.json \
		--environment tests/e2e/postman-environment.json \
		--reporters cli,json \
		--reporter-json-export tests/e2e/results.json
	@echo "$(GREEN)✓ E2E tests passed$(RESET)"

.PHONY: test-perf
test-perf: ## Run performance tests with Locust
	@echo "$(BLUE)► Running performance tests...$(RESET)"
	@cd tests/performance && poetry run locust \
		-f locustfile.py \
		--host=http://localhost:8080 \
		--users=1000 \
		--spawn-rate=50 \
		--run-time=60s \
		--headless \
		--csv=results/perf
	@echo "$(GREEN)✓ Performance tests complete$(RESET)"

.PHONY: test-security
test-security: ## Run security tests (gosec + bandit)
	@echo "$(BLUE)► Running security tests...$(RESET)"
	@which gosec || go install github.com/securecorp/gosec/v2/cmd/gosec@latest
	@gosec -severity medium ./services/...
	@cd services/ml-service && poetry run bandit -r . -x tests/ -ll
	@echo "$(GREEN)✓ Security tests passed$(RESET)"

.PHONY: test-coverage
test-coverage: ## Show test coverage report
	@go tool cover -func=coverage/go-coverage.out | grep -E "^total|services/"
	@echo ""
	@cat coverage/python-coverage.txt 2>/dev/null || echo "Run 'make test-unit-python' first"

# =============================================================================
# ML TRAINING
# =============================================================================

.PHONY: ml-train
ml-train: ## Train all ML models
	@echo "$(BLUE)► Training ML models...$(RESET)"
	@cd ml && poetry run python -m models.train_all
	@echo "$(GREEN)✓ ML training complete$(RESET)"

.PHONY: ml-train-model
ml-train-model: ## Train a specific model: make ml-train-model MODEL=xgboost
	@if [ -z "$(MODEL)" ]; then echo "$(RED)Usage: make ml-train-model MODEL=<name>$(RESET)"; exit 1; fi
	@cd ml && poetry run python -m models.$(MODEL)_model --train

.PHONY: ml-evaluate
ml-evaluate: ## Evaluate all models and generate comparison table
	@echo "$(BLUE)► Evaluating ML models...$(RESET)"
	@cd ml && poetry run python -m evaluation.evaluate_all
	@echo "$(GREEN)✓ Evaluation complete — see ml/evaluation/results/$(RESET)"

.PHONY: ml-serve
ml-serve: ## Start ML service locally (FastAPI + gRPC)
	@cd services/ml-service && poetry run python -m app.main

# =============================================================================
# RUN SERVICES
# =============================================================================

.PHONY: run
run: ## Start all services with docker-compose
	@bash scripts/run-all.sh

.PHONY: run-svc
run-svc: ## Run a specific Go service locally: make run-svc SVC=iam-service
	@if [ -z "$(SVC)" ]; then echo "$(RED)Usage: make run-svc SVC=<service-name>$(RESET)"; exit 1; fi
	@echo "$(BLUE)► Starting $(SVC)...$(RESET)"
	@cd services/$(SVC) && go run ./cmd/main.go

# =============================================================================
# BLOCKCHAIN
# =============================================================================

.PHONY: fabric-up
fabric-up: ## Start Hyperledger Fabric network
	@echo "$(BLUE)► Starting Fabric network...$(RESET)"
	@cd blockchain/network && bash start.sh

.PHONY: fabric-down
fabric-down: ## Stop and clean Fabric network
	@cd blockchain/network && bash teardown.sh

.PHONY: chaincode-deploy
chaincode-deploy: ## Deploy all chaincodes to running Fabric network
	@echo "$(BLUE)► Deploying chaincodes...$(RESET)"
	@cd blockchain/network && bash deploy-chaincode.sh kyc-contract kyc-channel
	@cd blockchain/network && bash deploy-chaincode.sh alert-contract alert-channel
	@cd blockchain/network && bash deploy-chaincode.sh audit-contract audit-channel
	@echo "$(GREEN)✓ Chaincodes deployed$(RESET)"

# =============================================================================
# INFRASTRUCTURE (Kubernetes + Terraform)
# =============================================================================

.PHONY: k8s-apply
k8s-apply: ## Apply all Kubernetes manifests to current context
	@echo "$(BLUE)► Applying Kubernetes manifests...$(RESET)"
	@kubectl apply -f infrastructure/kubernetes/namespaces.yaml
	@for svc in $(GO_SERVICES) ml-service; do \
		helm upgrade --install $$svc infrastructure/kubernetes/charts/$$svc \
			--namespace fraud-detection \
			--values infrastructure/kubernetes/charts/$$svc/values.yaml; \
	done

.PHONY: tf-init
tf-init: ## Initialize Terraform
	@cd infrastructure/terraform && terraform init

.PHONY: tf-plan
tf-plan: ## Terraform plan (dry run)
	@cd infrastructure/terraform && terraform plan -var-file=environments/staging.tfvars

.PHONY: tf-apply
tf-apply: ## Apply Terraform changes (requires confirmation)
	@cd infrastructure/terraform && terraform apply -var-file=environments/staging.tfvars

# =============================================================================
# DOCS
# =============================================================================

.PHONY: docs
docs: ## Generate API docs from OpenAPI spec
	@echo "$(BLUE)► Generating documentation...$(RESET)"
	@npx @redocly/cli build-docs docs/api-spec.yaml -o docs/api.html
	@echo "$(GREEN)✓ API docs generated at docs/api.html$(RESET)"

.PHONY: docs-serve
docs-serve: ## Serve API docs locally
	@npx @redocly/cli preview-docs docs/api-spec.yaml

# =============================================================================
# CLEANUP
# =============================================================================

.PHONY: clean
clean: ## Remove build artifacts and generated files
	@echo "$(BLUE)► Cleaning build artifacts...$(RESET)"
	@rm -rf bin/ coverage/ dist/
	@find . -name "*.out" -delete
	@find . -name "*.test" -delete
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	@echo "$(GREEN)✓ Clean complete$(RESET)"

.PHONY: clean-proto
clean-proto: ## Remove generated protobuf stubs
	@rm -rf $(PROTO_GEN_GO) $(PROTO_GEN_PY)
	@echo "$(GREEN)✓ Proto stubs removed$(RESET)"

# =============================================================================
# HEALTH CHECKS
# =============================================================================

.PHONY: health
health: ## Check health of all running services
	@echo "$(BLUE)► Checking service health...$(RESET)"
	@echo "PostgreSQL:  $$(docker exec fds-postgres pg_isready -U fraud_user 2>/dev/null && echo '$(GREEN)OK$(RESET)' || echo '$(RED)DOWN$(RESET)')"
	@echo "MongoDB:     $$(docker exec fds-mongodb mongosh --quiet --eval 'db.adminCommand(\"ping\").ok' 2>/dev/null | grep -q 1 && echo '$(GREEN)OK$(RESET)' || echo '$(RED)DOWN$(RESET)')"
	@echo "Redis:       $$(docker exec fds-redis redis-cli -a changeme_redis_password ping 2>/dev/null | grep -q PONG && echo '$(GREEN)OK$(RESET)' || echo '$(RED)DOWN$(RESET)')"
	@echo "Kafka:       $$(docker exec fds-kafka kafka-broker-api-versions --bootstrap-server localhost:9092 2>/dev/null | grep -q 'ApiKey' && echo '$(GREEN)OK$(RESET)' || echo '$(RED)DOWN$(RESET)')"
	@echo "Vault:       $$(curl -sf http://localhost:8200/v1/sys/health 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin); print(\"$(GREEN)OK$(RESET)\")' 2>/dev/null || echo '$(RED)DOWN$(RESET)')"
	@echo "Jaeger:      $$(curl -sf http://localhost:16686/ >/dev/null 2>&1 && echo '$(GREEN)OK$(RESET)' || echo '$(RED)DOWN$(RESET)')"
	@echo "Prometheus:  $$(curl -sf http://localhost:9090/-/healthy >/dev/null 2>&1 && echo '$(GREEN)OK$(RESET)' || echo '$(RED)DOWN$(RESET)')"
	@echo "Grafana:     $$(curl -sf http://localhost:3000/api/health >/dev/null 2>&1 && echo '$(GREEN)OK$(RESET)' || echo '$(RED)DOWN$(RESET)')"
	@echo "MLflow:      $$(curl -sf http://localhost:5000/health >/dev/null 2>&1 && echo '$(GREEN)OK$(RESET)' || echo '$(RED)DOWN$(RESET)')"
	@echo "API Gateway: $$(curl -sf http://localhost:8080/health >/dev/null 2>&1 && echo '$(GREEN)OK$(RESET)' || echo '$(RED)DOWN$(RESET)')"

# Create coverage directory if it doesn't exist
$(shell mkdir -p coverage bin)
