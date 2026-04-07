// Package grpc (handler.go) implements the TransactionServiceServer interface.
// It translates between proto/domain types and delegates all business logic
// to the TransactionService.
package grpc

import (
	"context"
	"errors"
	"time"

	commonv1 "github.com/fraud-detection/proto/gen/go/common/v1"
	mlv1 "github.com/fraud-detection/proto/gen/go/ml/v1"
	transactionv1 "github.com/fraud-detection/proto/gen/go/transaction/v1"
	"github.com/fraud-detection/transaction-service/internal/domain"
	"github.com/fraud-detection/transaction-service/internal/service"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

// Handler implements transactionv1.TransactionServiceServer.
type Handler struct {
	transactionv1.UnimplementedTransactionServiceServer
	svc service.TransactionServiceInterface
	log zerolog.Logger
}

// TransactionServiceInterface is a narrow interface for the handler so it can be
// tested without constructing the full service.
type TransactionServiceInterface interface {
	ProcessTransaction(ctx context.Context, raw *domain.RawTransaction) (*domain.EnrichedTransaction, error)
	GetTransaction(ctx context.Context, txHash string) (*domain.EnrichedTransaction, error)
	GetCustomerHistory(ctx context.Context, customerID string, startTime, endTime time.Time, minFraudProb float64, pageSize int, pageToken string) ([]*domain.EnrichedTransaction, string, error)
	GetRiskScore(ctx context.Context, customerID string) (*domain.CachedRiskScore, error)
	GetVelocityStats(ctx context.Context, customerID string) (*domain.VelocityStats, error)
	HealthCheck(ctx context.Context) error
}

// Compile-time interface assertion.
var _ TransactionServiceInterface = (*service.TransactionService)(nil)

// NewHandler constructs a Handler backed by the given service.
func NewHandler(svc *service.TransactionService, log zerolog.Logger) *Handler {
	return &Handler{
		svc: svc,
		log: log.With().Str("component", "grpc_handler").Logger(),
	}
}

// ---------------------------------------------------------------------------
// IngestTransaction — synchronous ingestion with optional wait-for-score
// ---------------------------------------------------------------------------

// IngestTransaction ingests a single transaction and optionally waits for ML prediction.
func (h *Handler) IngestTransaction(ctx context.Context, req *transactionv1.IngestTransactionRequest) (*transactionv1.IngestTransactionResponse, error) {
	if req.Transaction == nil {
		return nil, grpcstatus.Error(codes.InvalidArgument, "transaction is required")
	}

	raw := protoToRaw(req.Transaction)

	if !req.Sync {
		// Async path: queue and return immediately.
		// TODO: push to an internal channel or Kafka for processing; for now we process inline.
		go func() {
			bgCtx := context.Background()
			if _, err := h.svc.ProcessTransaction(bgCtx, raw); err != nil {
				h.log.Error().Err(err).Str("tx_hash", raw.TxHash).Msg("async ProcessTransaction failed")
			}
		}()
		return &transactionv1.IngestTransactionResponse{
			TxHash: raw.TxHash,
			Status: "QUEUED",
		}, nil
	}

	// Sync path: wait for full pipeline completion.
	enriched, err := h.svc.ProcessTransaction(ctx, raw)
	if err != nil {
		return nil, mapDomainError(err)
	}

	return &transactionv1.IngestTransactionResponse{
		TxHash:           enriched.TxHash,
		Status:           "SCORED",
		FraudProbability: enriched.FraudProbability,
		RiskLevel:        commonv1.RiskLevel(enriched.RiskLevel),
		AlertCreated:     enriched.AlertCreated,
		AlertID:          enriched.AlertID,
	}, nil
}

// ---------------------------------------------------------------------------
// IngestBatch
// ---------------------------------------------------------------------------

// IngestBatch ingests up to 500 transactions asynchronously.
func (h *Handler) IngestBatch(ctx context.Context, req *transactionv1.IngestBatchRequest) (*transactionv1.IngestBatchResponse, error) {
	if len(req.Transactions) == 0 {
		return nil, grpcstatus.Error(codes.InvalidArgument, "transactions list is empty")
	}
	if len(req.Transactions) > 500 {
		return nil, grpcstatus.Errorf(codes.InvalidArgument, "batch size %d exceeds maximum of 500", len(req.Transactions))
	}

	resp := &transactionv1.IngestBatchResponse{}
	for _, proto := range req.Transactions {
		raw := protoToRaw(proto)
		if err := raw.Validate(); err != nil {
			resp.Rejected++
			resp.RejectedTxHashes = append(resp.RejectedTxHashes, raw.TxHash)
			resp.ErrorMessages = append(resp.ErrorMessages, err.Error())
			continue
		}
		// Queue for async processing
		txCopy := raw
		go func() {
			if _, err := h.svc.ProcessTransaction(context.Background(), txCopy); err != nil {
				h.log.Error().Err(err).Str("tx_hash", txCopy.TxHash).Msg("batch ProcessTransaction failed")
			}
		}()
		resp.Accepted++
	}

	return resp, nil
}

// ---------------------------------------------------------------------------
// GetTransaction
// ---------------------------------------------------------------------------

// GetTransaction retrieves a single enriched transaction by tx_hash.
func (h *Handler) GetTransaction(ctx context.Context, req *transactionv1.GetTransactionRequest) (*transactionv1.GetTransactionResponse, error) {
	if req.TxHash == "" {
		return nil, grpcstatus.Error(codes.InvalidArgument, "tx_hash is required")
	}

	enriched, err := h.svc.GetTransaction(ctx, req.TxHash)
	if err != nil {
		return nil, mapDomainError(err)
	}

	return &transactionv1.GetTransactionResponse{
		Transaction: enrichedToProto(enriched),
	}, nil
}

// ---------------------------------------------------------------------------
// GetCustomerHistory
// ---------------------------------------------------------------------------

// GetCustomerHistory returns paginated enriched transactions for a customer.
func (h *Handler) GetCustomerHistory(ctx context.Context, req *transactionv1.GetCustomerHistoryRequest) (*transactionv1.GetCustomerHistoryResponse, error) {
	if req.CustomerID == "" {
		return nil, grpcstatus.Error(codes.InvalidArgument, "customer_id is required")
	}

	pageSize := 20
	var pageToken string
	if req.Page != nil {
		if req.Page.PageSize > 0 {
			pageSize = int(req.Page.PageSize)
		}
		pageToken = req.Page.PageToken
	}

	txs, nextToken, err := h.svc.GetCustomerHistory(
		ctx, req.CustomerID,
		req.StartTime, req.EndTime,
		req.MinFraudProb,
		pageSize, pageToken,
	)
	if err != nil {
		return nil, mapDomainError(err)
	}

	protoTxs := make([]*transactionv1.EnrichedTransaction, 0, len(txs))
	for _, tx := range txs {
		protoTxs = append(protoTxs, enrichedToProto(tx))
	}

	return &transactionv1.GetCustomerHistoryResponse{
		Transactions: protoTxs,
		Page: &commonv1.PageResponse{
			NextPageToken: nextToken,
			TotalCount:    int32(len(protoTxs)),
		},
	}, nil
}

// ---------------------------------------------------------------------------
// GetRiskScore
// ---------------------------------------------------------------------------

// GetRiskScore returns the current risk score for a customer (cached 5 min).
func (h *Handler) GetRiskScore(ctx context.Context, req *transactionv1.GetRiskScoreRequest) (*transactionv1.GetRiskScoreResponse, error) {
	if req.CustomerID == "" {
		return nil, grpcstatus.Error(codes.InvalidArgument, "customer_id is required")
	}

	score, err := h.svc.GetRiskScore(ctx, req.CustomerID)
	if err != nil {
		return nil, mapDomainError(err)
	}

	return &transactionv1.GetRiskScoreResponse{
		CustomerID:        score.CustomerID,
		CurrentRiskScore:  score.RiskScore,
		RiskLevel:         commonv1.RiskLevel(score.RiskLevel),
		FraudRate30D:      score.FraudRate30D,
		AlertCount30D:     int32(score.AlertCount30D),
		ComputedAt:        score.ComputedAt,
	}, nil
}

// ---------------------------------------------------------------------------
// GetFeatures
// ---------------------------------------------------------------------------

// GetFeatures returns the stored feature vector for a transaction.
func (h *Handler) GetFeatures(ctx context.Context, req *transactionv1.GetFeaturesRequest) (*transactionv1.GetFeaturesResponse, error) {
	if req.TxHash == "" {
		return nil, grpcstatus.Error(codes.InvalidArgument, "tx_hash is required")
	}

	enriched, err := h.svc.GetTransaction(ctx, req.TxHash)
	if err != nil {
		return nil, mapDomainError(err)
	}

	var protoFeatures *mlv1.TransactionFeatures
	if enriched.Features != nil {
		protoFeatures = domainFeaturesToProto(enriched.Features)
	}

	return &transactionv1.GetFeaturesResponse{
		Features:        protoFeatures,
		ComputedAt:      enriched.ProcessedAt,
		PipelineVersion: "1.0.0", // TODO: store pipeline_version in enriched tx
	}, nil
}

// ---------------------------------------------------------------------------
// GetVelocityStats
// ---------------------------------------------------------------------------

// GetVelocityStats returns real-time velocity statistics for a customer.
func (h *Handler) GetVelocityStats(ctx context.Context, req *transactionv1.GetVelocityStatsRequest) (*transactionv1.GetVelocityStatsResponse, error) {
	if req.CustomerID == "" {
		return nil, grpcstatus.Error(codes.InvalidArgument, "customer_id is required")
	}

	stats, err := h.svc.GetVelocityStats(ctx, req.CustomerID)
	if err != nil {
		return nil, mapDomainError(err)
	}

	return &transactionv1.GetVelocityStatsResponse{
		CustomerID:           stats.CustomerID,
		TxCount1H:            int32(stats.TxCount1H),
		TxCount24H:           int32(stats.TxCount24H),
		TxCount7D:            int32(stats.TxCount7D),
		TotalAmount1H:        stats.TotalAmount1H,
		TotalAmount24H:       stats.TotalAmount24H,
		TotalAmount7D:        stats.TotalAmount7D,
		DistinctCountries24H: int32(stats.DistinctCountries24H),
		DistinctMerchants24H: int32(stats.DistinctMerchants24H),
		VelocityAlert1H:      stats.VelocityAlert1H,
		VelocityAlert24H:     stats.VelocityAlert24H,
	}, nil
}

// ---------------------------------------------------------------------------
// HealthCheck
// ---------------------------------------------------------------------------

// HealthCheck verifies that the service and all dependencies are reachable.
func (h *Handler) HealthCheck(ctx context.Context, _ *commonv1.HealthCheckRequest) (*commonv1.HealthCheckResponse, error) {
	if err := h.svc.HealthCheck(ctx); err != nil {
		return &commonv1.HealthCheckResponse{
			Status:  commonv1.HealthStatus_HEALTH_STATUS_NOT_SERVING,
			Details: err.Error(),
		}, nil
	}
	return &commonv1.HealthCheckResponse{
		Status:  commonv1.HealthStatus_HEALTH_STATUS_SERVING,
		Details: "transaction-service operational",
	}, nil
}

// ---------------------------------------------------------------------------
// Proto ↔ domain mapping helpers
// ---------------------------------------------------------------------------

func protoToRaw(p *transactionv1.RawTransaction) *domain.RawTransaction {
	if p == nil {
		return nil
	}
	return &domain.RawTransaction{
		TxHash:              p.TxHash,
		CustomerID:          p.CustomerID,
		Amount:              p.Amount,
		CurrencyCode:        p.CurrencyCode,
		MerchantID:          p.MerchantID,
		MerchantName:        p.MerchantName,
		MerchantCategory:    p.MerchantCategory,
		CountryCode:         p.CountryCode,
		Channel:             p.Channel,
		CounterpartyID:      p.CounterpartyID,
		CounterpartyCountry: p.CounterpartyCountry,
		Latitude:            p.Latitude,
		Longitude:           p.Longitude,
		TransactionAt:       p.TransactionAt,
		Metadata:            p.Metadata,
	}
}

func enrichedToProto(e *domain.EnrichedTransaction) *transactionv1.EnrichedTransaction {
	if e == nil {
		return nil
	}
	raw := &transactionv1.RawTransaction{}
	if e.Raw != nil {
		raw.TxHash = e.Raw.TxHash
		raw.CustomerID = e.Raw.CustomerID
		raw.Amount = e.Raw.Amount
		raw.CurrencyCode = e.Raw.CurrencyCode
		raw.MerchantID = e.Raw.MerchantID
		raw.MerchantName = e.Raw.MerchantName
		raw.MerchantCategory = e.Raw.MerchantCategory
		raw.CountryCode = e.Raw.CountryCode
		raw.Channel = e.Raw.Channel
		raw.CounterpartyID = e.Raw.CounterpartyID
		raw.CounterpartyCountry = e.Raw.CounterpartyCountry
		raw.Latitude = e.Raw.Latitude
		raw.Longitude = e.Raw.Longitude
		raw.TransactionAt = e.Raw.TransactionAt
		raw.Metadata = e.Raw.Metadata
	}

	var protoFeatures *mlv1.TransactionFeatures
	if e.Features != nil {
		protoFeatures = domainFeaturesToProto(e.Features)
	}

	shap := make([]commonv1.SHAPContribution, 0, len(e.SHAPValues))
	for _, s := range e.SHAPValues {
		shap = append(shap, commonv1.SHAPContribution{
			FeatureName:   s.FeatureName,
			FeatureValue:  s.FeatureValue,
			ShapValue:     s.SHAPValue,
			AbsImportance: s.AbsImportance,
		})
	}

	return &transactionv1.EnrichedTransaction{
		Raw:              raw,
		Features:         protoFeatures,
		FraudProbability: e.FraudProbability,
		RiskLevel:        commonv1.RiskLevel(e.RiskLevel),
		ModelVersion:     e.ModelVersion,
		ShapValues:       shap,
		AlertCreated:     e.AlertCreated,
		AlertID:          e.AlertID,
		ProcessedAt:      e.ProcessedAt,
	}
}

func domainFeaturesToProto(f *domain.TransactionFeatures) *mlv1.TransactionFeatures {
	if f == nil {
		return nil
	}
	return &mlv1.TransactionFeatures{
		TxHash:               f.TxHash,
		CustomerID:           f.CustomerID,
		TxHour:               int32(f.TxHour),
		DayOfWeek:            int32(f.DayOfWeek),
		IsWeekend:            f.IsWeekend,
		TimeSinceLastTxS:     f.TimeSinceLastTxS,
		TxFrequency1H:        f.TxFrequency1H,
		TxFrequency24H:       f.TxFrequency24H,
		Amount:               f.Amount,
		CurrencyCode:         f.CurrencyCode,
		AmountUSDEquiv:       f.AmountUSDEquiv,
		AvgAmount7D:          f.AvgAmount7D,
		AvgAmount30D:         f.AvgAmount30D,
		StdAmount30D:         f.StdAmount30D,
		AmountDeviationScore: f.AmountDeviationScore,
		Velocity1H:           f.Velocity1H,
		Velocity24H:          f.Velocity24H,
		CountryCode:          f.CountryCode,
		GeographicRiskScore:  f.GeographicRiskScore,
		CrossBorderFlag:      f.CrossBorderFlag,
		CountryChange2H:      f.CountryChange2H,
		DistanceKmFromLast:   f.DistanceKmFromLast,
		MerchantCategory:     f.MerchantCategory,
		MerchantRiskScore:    f.MerchantRiskScore,
		IsHighRiskMerchant:   f.IsHighRiskMerchant,
		CustomerRiskScore:    f.CustomerRiskScore,
		KYCRiskLevel:         int32(f.KYCRiskLevel),
		DaysSinceKYC:         int32(f.DaysSinceKYC),
		TotalTxCount30D:      int32(f.TotalTxCount30D),
		Pagerank:             f.Pagerank,
		ClusteringCoefficient: f.ClusteringCoefficient,
		BetweennessCentrality: f.BetweennessCentrality,
		LouvainCommunityID:   int32(f.LouvainCommunityID),
		HopsToKnownFraudster: int32(f.HopsToKnownFraudster),
		DirectFraudNeighbors: int32(f.DirectFraudNeighbors),
		EllipticFeatures:     f.EllipticFeatures,
	}
}

// mapDomainError converts domain errors to gRPC status errors.
func mapDomainError(err error) error {
	if err == nil {
		return nil
	}

	var txErr *domain.TransactionError
	if errors.As(err, &txErr) {
		switch txErr.Code {
		case "TRANSACTION_NOT_FOUND", "CUSTOMER_NOT_FOUND":
			return grpcstatus.Error(codes.NotFound, txErr.Message)
		case "DUPLICATE_TRANSACTION":
			return grpcstatus.Error(codes.AlreadyExists, txErr.Message)
		case "INVALID_TRANSACTION":
			return grpcstatus.Error(codes.InvalidArgument, txErr.Message)
		case "ML_SERVICE_UNAVAILABLE":
			return grpcstatus.Error(codes.Unavailable, txErr.Message)
		}
	}

	return grpcstatus.Error(codes.Internal, err.Error())
}
