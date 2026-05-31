// Package grpc wires the gRPC handler for the Analytics Service.
package grpc

import (
	"context"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	analyticsv1 "github.com/fraud-detection/proto/gen/go/analytics/v1"
	commonv1 "github.com/fraud-detection/proto/gen/go/common/v1"

	"github.com/fraud-detection/analytics-service/internal/domain"
	"github.com/fraud-detection/analytics-service/internal/service"
)

// Handler implements analyticsv1.AnalyticsServiceServer.
type Handler struct {
	analyticsv1.UnimplementedAnalyticsServiceServer
	svc *service.AnalyticsService
	log zerolog.Logger
}

// NewHandler constructs the gRPC handler.
func NewHandler(svc *service.AnalyticsService, log zerolog.Logger) *Handler {
	return &Handler{svc: svc, log: log}
}

// ---------------------------------------------------------------------------
// GetFraudTrends
// ---------------------------------------------------------------------------

func (h *Handler) GetFraudTrends(ctx context.Context, req *analyticsv1.GetFraudTrendsRequest) (*analyticsv1.GetFraudTrendsResponse, error) {
	var from, to time.Time
	if req.StartTime != nil {
		from = req.StartTime.AsTime()
	}
	if req.EndTime != nil {
		to = req.EndTime.AsTime()
	}

	gran := protoGranularityToDomain(req.Granularity)
	result, err := h.svc.GetFraudTrends(ctx, from, to, gran)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get fraud trends: %v", err)
	}

	points := make([]*analyticsv1.TrendPoint, len(result.Points))
	for i, p := range result.Points {
		points[i] = &analyticsv1.TrendPoint{
			Date:         timestamppb.New(p.Date),
			AlertCount:   int32(p.AlertCount),
			FraudCount:   int32(p.FraudCount),
			TotalTxCount: int32(p.TotalTxCount),
			FraudRate:    p.FraudRate,
			AvgFraudProb: p.AvgFraudProb,
		}
	}
	return &analyticsv1.GetFraudTrendsResponse{
		Points:      points,
		Period:      result.Period,
		Granularity: req.Granularity,
	}, nil
}

// ---------------------------------------------------------------------------
// GetRiskDistribution
// ---------------------------------------------------------------------------

func (h *Handler) GetRiskDistribution(ctx context.Context, req *analyticsv1.GetRiskDistributionRequest) (*analyticsv1.GetRiskDistributionResponse, error) {
	buckets, err := h.svc.GetRiskDistribution(ctx, req.Period)
	if err != nil {
		if isInvalidInput(err) {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "get risk distribution: %v", err)
	}

	var total int32
	protoB := make([]*analyticsv1.RiskBucket, len(buckets))
	for i, b := range buckets {
		protoB[i] = &analyticsv1.RiskBucket{
			RiskLevel:    b.RiskLevel,
			Count:        int32(b.Count),
			Percentage:   b.Percentage,
			AvgFraudProb: b.AvgFraudProb,
		}
		total += int32(b.Count)
	}
	return &analyticsv1.GetRiskDistributionResponse{
		Buckets: protoB,
		Total:   total,
		Period:  req.Period,
	}, nil
}

// ---------------------------------------------------------------------------
// GetTopRiskyCustomers
// ---------------------------------------------------------------------------

func (h *Handler) GetTopRiskyCustomers(ctx context.Context, req *analyticsv1.GetTopRiskyCustomersRequest) (*analyticsv1.GetTopRiskyCustomersResponse, error) {
	customers, err := h.svc.GetTopRiskyCustomers(ctx, req.Period, int(req.Limit))
	if err != nil {
		if isInvalidInput(err) {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "get top risky customers: %v", err)
	}

	protoC := make([]*analyticsv1.RiskyCustomer, len(customers))
	for i, c := range customers {
		rc := &analyticsv1.RiskyCustomer{
			CustomerId:   c.CustomerID,
			AlertCount:   int32(c.AlertCount),
			FraudRate:    c.FraudRate,
			TotalAmount:  c.TotalAmount,
			AvgRiskScore: c.AvgRiskScore,
		}
		if !c.LastAlertAt.IsZero() {
			rc.LastAlertAt = timestamppb.New(c.LastAlertAt)
		}
		protoC[i] = rc
	}
	return &analyticsv1.GetTopRiskyCustomersResponse{
		Customers: protoC,
		Period:    req.Period,
	}, nil
}

// ---------------------------------------------------------------------------
// GetModelPerformance
// ---------------------------------------------------------------------------

func (h *Handler) GetModelPerformance(ctx context.Context, req *analyticsv1.GetModelPerformanceRequest) (*analyticsv1.GetModelPerformanceResponse, error) {
	perf, err := h.svc.GetModelPerformance(ctx, req.ModelVersion, req.Period)
	if err != nil {
		if isInvalidInput(err) {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "get model performance: %v", err)
	}
	return &analyticsv1.GetModelPerformanceResponse{
		Performance: &analyticsv1.ModelPerformance{
			ModelVersion:     perf.ModelVersion,
			Period:           perf.Period,
			TotalPredictions: perf.TotalPredictions,
			TruePositives:    perf.TruePositives,
			FalsePositives:   perf.FalsePositives,
			TrueNegatives:    perf.TrueNegatives,
			FalseNegatives:   perf.FalseNegatives,
			Precision:        perf.Precision,
			Recall:           perf.Recall,
			F1Score:          perf.F1Score,
			AucRoc:           perf.AUCROC,
		},
	}, nil
}

// ---------------------------------------------------------------------------
// GetTransactionVolume
// ---------------------------------------------------------------------------

func (h *Handler) GetTransactionVolume(ctx context.Context, req *analyticsv1.GetTransactionVolumeRequest) (*analyticsv1.GetTransactionVolumeResponse, error) {
	var from, to time.Time
	if req.StartTime != nil {
		from = req.StartTime.AsTime()
	}
	if req.EndTime != nil {
		to = req.EndTime.AsTime()
	}

	gran := protoGranularityToDomain(req.Granularity)
	points, err := h.svc.GetTransactionVolume(ctx, from, to, gran)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get transaction volume: %v", err)
	}

	protoP := make([]*analyticsv1.VolumePoint, len(points))
	for i, p := range points {
		protoP[i] = &analyticsv1.VolumePoint{
			Date:        timestamppb.New(p.Date),
			TxCount:     int32(p.TxCount),
			TotalAmount: p.TotalAmount,
			AvgAmount:   p.AvgAmount,
			FraudCount:  int32(p.FraudCount),
		}
	}
	return &analyticsv1.GetTransactionVolumeResponse{Points: protoP}, nil
}

// ---------------------------------------------------------------------------
// GetAlertMetrics
// ---------------------------------------------------------------------------

func (h *Handler) GetAlertMetrics(ctx context.Context, req *analyticsv1.GetAlertMetricsRequest) (*analyticsv1.GetAlertMetricsResponse, error) {
	metrics, err := h.svc.GetAlertMetrics(ctx, req.Period)
	if err != nil {
		if isInvalidInput(err) {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "get alert metrics: %v", err)
	}

	byPriority := make(map[string]int32, len(metrics.ByPriority))
	for k, v := range metrics.ByPriority {
		byPriority[k] = int32(v)
	}

	return &analyticsv1.GetAlertMetricsResponse{
		Metrics: &analyticsv1.AlertMetrics{
			Period:             metrics.Period,
			TotalAlerts:        int32(metrics.TotalAlerts),
			OpenAlerts:         int32(metrics.OpenAlerts),
			ResolvedAlerts:     int32(metrics.ResolvedAlerts),
			FalsePositives:     int32(metrics.FalsePositives),
			EscalatedAlerts:    int32(metrics.EscalatedAlerts),
			AvgResolutionMin:   metrics.AvgResolutionMin,
			EscalationRate:     metrics.EscalationRate,
			FalsePositiveRate:  metrics.FalsePositiveRate,
			ByPriority:         byPriority,
		},
	}, nil
}

// ---------------------------------------------------------------------------
// GetGeographicDistribution
// ---------------------------------------------------------------------------

func (h *Handler) GetGeographicDistribution(ctx context.Context, req *analyticsv1.GetGeographicDistributionRequest) (*analyticsv1.GetGeographicDistributionResponse, error) {
	points, err := h.svc.GetGeographicDistribution(ctx, req.Period)
	if err != nil {
		if isInvalidInput(err) {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "get geographic distribution: %v", err)
	}

	protoP := make([]*analyticsv1.GeoFraudPoint, len(points))
	for i, p := range points {
		protoP[i] = &analyticsv1.GeoFraudPoint{
			CountryCode: p.CountryCode,
			AlertCount:  int32(p.AlertCount),
			TxCount:     int32(p.TxCount),
			FraudRate:   p.FraudRate,
			TotalAmount: p.TotalAmount,
		}
	}
	return &analyticsv1.GetGeographicDistributionResponse{
		Points: protoP,
		Period: req.Period,
	}, nil
}

// ---------------------------------------------------------------------------
// GenerateReport
// ---------------------------------------------------------------------------

func (h *Handler) GenerateReport(ctx context.Context, req *analyticsv1.GenerateReportRequest) (*analyticsv1.GenerateReportResponse, error) {
	rType := protoReportTypeToDomain(req.ReportType)
	report, err := h.svc.GenerateReport(ctx, rType, req.Period)
	if err != nil {
		if isInvalidInput(err) {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "generate report: %v", err)
	}
	return &analyticsv1.GenerateReportResponse{
		ReportId:    report.ReportID,
		ReportType:  req.ReportType,
		Period:      report.Period,
		GeneratedAt: timestamppb.New(report.GeneratedAt),
		ContentJson: report.ContentJSON,
	}, nil
}

// ---------------------------------------------------------------------------
// HealthCheck
// ---------------------------------------------------------------------------

func (h *Handler) HealthCheck(ctx context.Context, _ *commonv1.HealthCheckRequest) (*commonv1.HealthCheckResponse, error) {
	pgOK, mongoOK, pgErr, mongoErr := h.svc.HealthCheck(ctx)

	if pgOK && mongoOK {
		return &commonv1.HealthCheckResponse{
			Status:  commonv1.HealthStatus_HEALTH_STATUS_SERVING,
			Details: "postgres: ok, mongo: ok",
		}, nil
	}

	var details string
	if !pgOK {
		details += "postgres: " + pgErr.Error() + "; "
	}
	if !mongoOK {
		details += "mongo: " + mongoErr.Error()
	}
	return &commonv1.HealthCheckResponse{
		Status:  commonv1.HealthStatus_HEALTH_STATUS_NOT_SERVING,
		Details: details,
	}, nil
}

// ---------------------------------------------------------------------------
// Converters
// ---------------------------------------------------------------------------

func protoGranularityToDomain(g analyticsv1.Granularity) domain.Granularity {
	switch g {
	case analyticsv1.Granularity_GRANULARITY_HOUR:
		return domain.GranularityHour
	case analyticsv1.Granularity_GRANULARITY_WEEK:
		return domain.GranularityWeek
	case analyticsv1.Granularity_GRANULARITY_MONTH:
		return domain.GranularityMonth
	default:
		return domain.GranularityDay
	}
}

func protoReportTypeToDomain(t analyticsv1.ReportType) domain.ReportType {
	switch t {
	case analyticsv1.ReportType_REPORT_TYPE_COMPLIANCE:
		return domain.ReportTypeCompliance
	case analyticsv1.ReportType_REPORT_TYPE_SAR:
		return domain.ReportTypeSAR
	case analyticsv1.ReportType_REPORT_TYPE_MODEL_AUDIT:
		return domain.ReportTypeModelAudit
	default:
		return domain.ReportTypeSummary
	}
}

func isInvalidInput(err error) bool {
	return err == domain.ErrInvalidPeriod || err == domain.ErrInvalidGranularity
}
