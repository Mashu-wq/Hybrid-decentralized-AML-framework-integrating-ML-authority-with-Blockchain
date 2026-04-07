// Package clients provides gRPC client wrappers for downstream services.
package clients

import (
	"context"
	"fmt"
	"time"

	commonv1 "github.com/fraud-detection/proto/gen/go/common/v1"
	mlv1 "github.com/fraud-detection/proto/gen/go/ml/v1"
	"github.com/fraud-detection/transaction-service/internal/domain"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
)

// MLClient wraps the FraudMLServiceClient gRPC stub with domain-level types.
// It handles proto ↔ domain mapping and timeout enforcement.
// When conn is nil (ML service unavailable at startup), PredictFraud returns a
// heuristic-based fallback prediction rather than panicking.
type MLClient struct {
	stub    mlv1.FraudMLServiceClient
	timeout time.Duration
	log     zerolog.Logger
}

// NewMLClient creates a new MLClient using the given gRPC connection.
// conn may be nil — in that case PredictFraud falls back to the heuristic predictor.
func NewMLClient(conn *grpc.ClientConn, timeoutSec int, log zerolog.Logger) *MLClient {
	var stub mlv1.FraudMLServiceClient
	if conn != nil {
		stub = mlv1.NewFraudMLServiceClient(conn)
	}
	return &MLClient{
		stub:    stub,
		timeout: time.Duration(timeoutSec) * time.Second,
		log:     log.With().Str("component", "ml_client").Logger(),
	}
}

// PredictFraud calls the ML service PredictFraud RPC and returns a domain FraudPrediction.
// On ML service unavailability (or nil connection), it returns a safe default prediction
// rather than failing so that transaction recording always proceeds (fail-open).
func (c *MLClient) PredictFraud(ctx context.Context, f *domain.TransactionFeatures) (*domain.FraudPrediction, error) {
	if c.stub == nil {
		c.log.Warn().Str("tx_hash", f.TxHash).Msg("ML stub nil (service not connected); using heuristic fallback")
		return defaultPrediction(f), nil
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req := &mlv1.PredictFraudRequest{
		Meta:     &commonv1.RequestMetadata{CallerSvc: "transaction-service"},
		Features: domainFeaturesToProto(f),
	}

	resp, err := c.stub.PredictFraud(ctx, req)
	if err != nil {
		c.log.Error().
			Err(err).
			Str("tx_hash", f.TxHash).
			Str("customer_id", f.CustomerID).
			Msg("ML PredictFraud RPC failed; returning safe default prediction")
		return defaultPrediction(f), nil
	}

	prediction := protoToDomainPrediction(resp)

	c.log.Debug().
		Str("tx_hash", f.TxHash).
		Float64("fraud_prob", prediction.FraudProbability).
		Str("risk_level", prediction.RiskLevel.String()).
		Str("model_version", prediction.ModelVersion).
		Float64("latency_ms", prediction.LatencyMS).
		Msg("ML prediction received")

	return prediction, nil
}

// HealthCheck verifies ML service reachability.
func (c *MLClient) HealthCheck(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resp, err := c.stub.HealthCheck(ctx, &commonv1.HealthCheckRequest{Service: "FraudMLService"})
	if err != nil {
		return fmt.Errorf("ML service health check failed: %w", err)
	}
	if resp.Status != commonv1.HealthStatus_HEALTH_STATUS_SERVING {
		return fmt.Errorf("ML service not serving: %s", resp.Details)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Proto ↔ domain mapping
// ---------------------------------------------------------------------------

// domainFeaturesToProto converts domain.TransactionFeatures to the mlv1 proto type.
func domainFeaturesToProto(f *domain.TransactionFeatures) *mlv1.TransactionFeatures {
	return &mlv1.TransactionFeatures{
		TxHash:     f.TxHash,
		CustomerID: f.CustomerID,

		TxHour:           int32(f.TxHour),
		DayOfWeek:        int32(f.DayOfWeek),
		IsWeekend:        f.IsWeekend,
		TimeSinceLastTxS: f.TimeSinceLastTxS,
		TxFrequency1H:    f.TxFrequency1H,
		TxFrequency24H:   f.TxFrequency24H,

		Amount:               f.Amount,
		CurrencyCode:         f.CurrencyCode,
		AmountUSDEquiv:       f.AmountUSDEquiv,
		AvgAmount7D:          f.AvgAmount7D,
		AvgAmount30D:         f.AvgAmount30D,
		StdAmount30D:         f.StdAmount30D,
		AmountDeviationScore: f.AmountDeviationScore,
		Velocity1H:           f.Velocity1H,
		Velocity24H:          f.Velocity24H,

		CountryCode:         f.CountryCode,
		GeographicRiskScore: f.GeographicRiskScore,
		CrossBorderFlag:     f.CrossBorderFlag,
		CountryChange2H:     f.CountryChange2H,
		DistanceKmFromLast:  f.DistanceKmFromLast,

		MerchantCategory:   f.MerchantCategory,
		MerchantRiskScore:  f.MerchantRiskScore,
		IsHighRiskMerchant: f.IsHighRiskMerchant,

		CustomerRiskScore: f.CustomerRiskScore,
		KYCRiskLevel:      int32(f.KYCRiskLevel),
		DaysSinceKYC:      int32(f.DaysSinceKYC),
		TotalTxCount30D:   int32(f.TotalTxCount30D),

		Pagerank:              f.Pagerank,
		ClusteringCoefficient: f.ClusteringCoefficient,
		BetweennessCentrality: f.BetweennessCentrality,
		LouvainCommunityID:    int32(f.LouvainCommunityID),
		HopsToKnownFraudster:  int32(f.HopsToKnownFraudster),
		DirectFraudNeighbors:  int32(f.DirectFraudNeighbors),

		EllipticFeatures: f.EllipticFeatures,
	}
}

// protoToDomainPrediction converts the ML service response to a domain FraudPrediction.
func protoToDomainPrediction(r *mlv1.PredictFraudResponse) *domain.FraudPrediction {
	shap := make([]domain.SHAPContribution, 0, len(r.ShapValues))
	for _, s := range r.ShapValues {
		shap = append(shap, domain.SHAPContribution{
			FeatureName:   s.FeatureName,
			FeatureValue:  s.FeatureValue,
			SHAPValue:     s.ShapValue,
			AbsImportance: s.AbsImportance,
		})
	}

	predictedAt := r.PredictedAt
	if predictedAt.IsZero() {
		predictedAt = time.Now().UTC()
	}

	return &domain.FraudPrediction{
		FraudProbability:   r.FraudProbability,
		IsFraud:            r.IsFraud,
		RiskLevel:          domain.RiskLevel(r.RiskLevel),
		ModelVersion:       r.ModelVersion,
		PredictionID:       r.PredictionID,
		SHAPValues:         shap,
		ModelProbabilities: r.ModelProbabilities,
		BaseValue:          r.BaseValue,
		LatencyMS:          r.LatencyMs,
		PredictedAt:        predictedAt,
	}
}

// defaultPrediction returns a safe-default medium-risk prediction when the
// ML service is unreachable. This keeps the pipeline running with reduced
// accuracy rather than dropping transactions entirely (fail-open).
func defaultPrediction(f *domain.TransactionFeatures) *domain.FraudPrediction {
	// Use a heuristic: high geographic risk + high-risk merchant = medium flag
	prob := 0.3
	if f.GeographicRiskScore > 70 || f.IsHighRiskMerchant {
		prob = 0.5
	}
	if f.CountryChange2H && f.IsHighRiskMerchant {
		prob = 0.65
	}
	return &domain.FraudPrediction{
		FraudProbability: prob,
		IsFraud:          false,
		RiskLevel:        domain.FraudProbToRiskLevel(prob),
		ModelVersion:     "heuristic-fallback-v1",
		PredictionID:     "",
		PredictedAt:      time.Now().UTC(),
	}
}
