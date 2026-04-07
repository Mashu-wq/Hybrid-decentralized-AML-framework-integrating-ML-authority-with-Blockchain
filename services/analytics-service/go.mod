module github.com/fraud-detection/analytics-service

go 1.22

require (
	github.com/fraud-detection/shared v0.0.0
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.6.0
	github.com/rs/zerolog v1.33.0
	github.com/stretchr/testify v1.9.0
	google.golang.org/grpc v1.64.0
	google.golang.org/protobuf v1.34.1
	go.opentelemetry.io/otel v1.27.0
)

replace github.com/fraud-detection/shared => ../../shared/go
