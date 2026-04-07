// Package grpc (handler.go) implements the AlertServiceServer interface.
package grpc

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	alertv1 "github.com/fraud-detection/proto/gen/go/alert/v1"
	commonv1 "github.com/fraud-detection/proto/gen/go/common/v1"
	"github.com/fraud-detection/alert-service/internal/domain"
	"github.com/fraud-detection/alert-service/internal/service"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

// Handler implements alertv1.AlertServiceServer.
type Handler struct {
	alertv1.UnimplementedAlertServiceServer
	svc *service.AlertService
	log zerolog.Logger
}

// NewHandler constructs a Handler.
func NewHandler(svc *service.AlertService, log zerolog.Logger) *Handler {
	return &Handler{
		svc: svc,
		log: log.With().Str("component", "alert_grpc_handler").Logger(),
	}
}

// ---------------------------------------------------------------------------
// CreateAlert — called by Transaction Service
// ---------------------------------------------------------------------------

func (h *Handler) CreateAlert(ctx context.Context, req *alertv1.CreateAlertRequest) (*alertv1.CreateAlertResponse, error) {
	if req.CustomerID == "" || req.TxHash == "" {
		return nil, grpcstatus.Error(codes.InvalidArgument, "customer_id and tx_hash are required")
	}

	event := &domain.AlertIngestEvent{
		AlertID:              generateAlertID(req.CustomerID, req.TxHash),
		CustomerID:           req.CustomerID,
		TxHash:               req.TxHash,
		FraudProbability:     req.FraudProbability,
		RiskScore:            req.RiskScore,
		ModelVersion:         req.ModelVersion,
		SHAPExplanationJSON:  req.SHAPExplanationJSON,
		FeaturesSnapshotJSON: req.FeaturesSnapshotJSON,
		CreatedAt:            time.Now().UTC(),
	}

	if err := h.svc.IngestAlert(ctx, event); err != nil {
		if errors.Is(err, domain.ErrDuplicateAlert) {
			return &alertv1.CreateAlertResponse{Duplicate: true, CreatedAt: time.Now().UTC()}, nil
		}
		return nil, mapDomainError(err)
	}

	alert, err := h.svc.GetAlert(ctx, event.AlertID)
	if err != nil {
		// Created but couldn't read back — return minimal response
		return &alertv1.CreateAlertResponse{
			AlertID:   event.AlertID,
			Priority:  alertv1.AlertPriority(domain.PriorityFromFraudProb(req.FraudProbability)),
			CreatedAt: time.Now().UTC(),
		}, nil
	}

	return &alertv1.CreateAlertResponse{
		AlertID:   alert.AlertID,
		Priority:  alertv1.AlertPriority(alert.Priority),
		CreatedAt: alert.CreatedAt,
	}, nil
}

// ---------------------------------------------------------------------------
// GetAlert
// ---------------------------------------------------------------------------

func (h *Handler) GetAlert(ctx context.Context, req *alertv1.GetAlertRequest) (*alertv1.GetAlertResponse, error) {
	if req.AlertID == "" {
		return nil, grpcstatus.Error(codes.InvalidArgument, "alert_id is required")
	}
	a, err := h.svc.GetAlert(ctx, req.AlertID)
	if err != nil {
		return nil, mapDomainError(err)
	}
	return &alertv1.GetAlertResponse{Alert: domainToProto(a)}, nil
}

// ---------------------------------------------------------------------------
// ListAlerts
// ---------------------------------------------------------------------------

func (h *Handler) ListAlerts(ctx context.Context, req *alertv1.ListAlertsRequest) (*alertv1.ListAlertsResponse, error) {
	pageSize := 50
	offset := 0
	if req.Page != nil {
		if req.Page.PageSize > 0 {
			pageSize = int(req.Page.PageSize)
		}
	}

	f := domain.AlertFilters{
		Status:       protoStatusToDomain(req.StatusFilter),
		Priority:     domain.AlertPriority(req.PriorityFilter),
		AssigneeID:   req.AssigneeID,
		MinFraudProb: req.MinFraudProb,
		StartTime:    req.StartTime,
		EndTime:      req.EndTime,
		SortBy:       req.SortBy,
		Ascending:    req.Ascending,
		PageSize:     pageSize,
		Offset:       offset,
	}

	alerts, total, err := h.svc.ListAlerts(ctx, f)
	if err != nil {
		return nil, mapDomainError(err)
	}

	records := make([]*alertv1.AlertRecord, 0, len(alerts))
	for _, a := range alerts {
		records = append(records, domainToProto(a))
	}

	return &alertv1.ListAlertsResponse{
		Alerts: records,
		Page:   &commonv1.PageResponse{TotalCount: int32(total)},
	}, nil
}

// ---------------------------------------------------------------------------
// GetAlertsByCustomer
// ---------------------------------------------------------------------------

func (h *Handler) GetAlertsByCustomer(ctx context.Context, req *alertv1.GetAlertsByCustomerRequest) (*alertv1.GetAlertsByCustomerResponse, error) {
	if req.CustomerID == "" {
		return nil, grpcstatus.Error(codes.InvalidArgument, "customer_id is required")
	}
	limit := 50
	if req.Page != nil && req.Page.PageSize > 0 {
		limit = int(req.Page.PageSize)
	}
	alerts, err := h.svc.GetAlertsByCustomer(ctx, req.CustomerID, limit, 0)
	if err != nil {
		return nil, mapDomainError(err)
	}
	records := make([]*alertv1.AlertRecord, 0, len(alerts))
	for _, a := range alerts {
		records = append(records, domainToProto(a))
	}
	return &alertv1.GetAlertsByCustomerResponse{Alerts: records}, nil
}

// ---------------------------------------------------------------------------
// UpdateAlertStatus
// ---------------------------------------------------------------------------

func (h *Handler) UpdateAlertStatus(ctx context.Context, req *alertv1.UpdateAlertStatusRequest) (*alertv1.UpdateAlertStatusResponse, error) {
	if req.AlertID == "" {
		return nil, grpcstatus.Error(codes.InvalidArgument, "alert_id is required")
	}
	newStatus := protoStatusToDomain(req.NewStatus)
	if newStatus == "" {
		return nil, grpcstatus.Error(codes.InvalidArgument, "new_status is required")
	}
	updated, err := h.svc.UpdateStatus(ctx, req.AlertID, req.UpdatedBy, req.Notes, newStatus)
	if err != nil {
		return nil, mapDomainError(err)
	}
	return &alertv1.UpdateAlertStatusResponse{UpdatedAlert: domainToProto(updated)}, nil
}

// ---------------------------------------------------------------------------
// AssignAlert
// ---------------------------------------------------------------------------

func (h *Handler) AssignAlert(ctx context.Context, req *alertv1.AssignAlertRequest) (*alertv1.AssignAlertResponse, error) {
	if req.AlertID == "" || req.AssigneeID == "" {
		return nil, grpcstatus.Error(codes.InvalidArgument, "alert_id and assignee_id are required")
	}
	updated, err := h.svc.AssignAlert(ctx, req.AlertID, req.AssigneeID)
	if err != nil {
		return nil, mapDomainError(err)
	}
	return &alertv1.AssignAlertResponse{UpdatedAlert: domainToProto(updated)}, nil
}

// ---------------------------------------------------------------------------
// EscalateAlert
// ---------------------------------------------------------------------------

func (h *Handler) EscalateAlert(ctx context.Context, req *alertv1.EscalateAlertRequest) (*alertv1.EscalateAlertResponse, error) {
	if req.AlertID == "" {
		return nil, grpcstatus.Error(codes.InvalidArgument, "alert_id is required")
	}
	updated, err := h.svc.EscalateAlert(ctx, req.AlertID, req.EscalatedBy, req.Reason)
	if err != nil {
		return nil, mapDomainError(err)
	}
	return &alertv1.EscalateAlertResponse{UpdatedAlert: domainToProto(updated)}, nil
}

// ---------------------------------------------------------------------------
// SendNotification — triggers ad-hoc notification for an alert
// ---------------------------------------------------------------------------

func (h *Handler) SendNotification(ctx context.Context, req *alertv1.SendNotificationRequest) (*alertv1.SendNotificationResponse, error) {
	if req.AlertID == "" {
		return nil, grpcstatus.Error(codes.InvalidArgument, "alert_id is required")
	}
	a, err := h.svc.GetAlert(ctx, req.AlertID)
	if err != nil {
		return nil, mapDomainError(err)
	}
	_ = a // notification dispatch via Dispatcher.Dispatch is triggered by IngestAlert; this RPC is a manual trigger hook
	return &alertv1.SendNotificationResponse{Success: true}, nil
}

// ---------------------------------------------------------------------------
// GetAlertStats
// ---------------------------------------------------------------------------

func (h *Handler) GetAlertStats(ctx context.Context, req *alertv1.GetAlertStatsRequest) (*alertv1.GetAlertStatsResponse, error) {
	stats, err := h.svc.GetStats(ctx, req.Period)
	if err != nil {
		return nil, mapDomainError(err)
	}
	return &alertv1.GetAlertStatsResponse{
		Stats: &alertv1.AlertStatistics{
			TotalAlerts:          int32(stats.TotalAlerts),
			OpenAlerts:           int32(stats.OpenAlerts),
			CriticalAlerts:       int32(stats.CriticalAlerts),
			HighAlerts:           int32(stats.HighAlerts),
			MediumAlerts:         int32(stats.MediumAlerts),
			LowAlerts:            int32(stats.LowAlerts),
			ResolvedAlerts:       int32(stats.ResolvedAlerts),
			FalsePositives:       int32(stats.FalsePositives),
			EscalatedAlerts:      int32(stats.EscalatedAlerts),
			AvgFraudProbability:  stats.AvgFraudProbability,
			FalsePositiveRate:    stats.FalsePositiveRate,
			AvgResolutionTimeMin: stats.AvgResolutionTimeMin,
			EscalationRate:       stats.EscalationRate,
			Period:               stats.Period,
		},
	}, nil
}

// ---------------------------------------------------------------------------
// HealthCheck
// ---------------------------------------------------------------------------

func (h *Handler) HealthCheck(ctx context.Context, _ *commonv1.HealthCheckRequest) (*commonv1.HealthCheckResponse, error) {
	checks := h.svc.HealthCheck(ctx)
	allOK := true
	for _, v := range checks {
		if v != "ok" {
			allOK = false
			break
		}
	}
	status := commonv1.HealthStatus_HEALTH_STATUS_SERVING
	if !allOK {
		status = commonv1.HealthStatus_HEALTH_STATUS_NOT_SERVING
	}
	return &commonv1.HealthCheckResponse{Status: status}, nil
}

// ---------------------------------------------------------------------------
// Type conversions
// ---------------------------------------------------------------------------

func domainToProto(a *domain.Alert) *alertv1.AlertRecord {
	return &alertv1.AlertRecord{
		AlertID:             a.AlertID,
		CustomerID:          a.CustomerID,
		TxHash:              a.TxHash,
		FraudProbability:    a.FraudProbability,
		RiskScore:           a.RiskScore,
		Status:              domainStatusToProto(a.Status),
		Priority:            alertv1.AlertPriority(a.Priority),
		ModelVersion:        a.ModelVersion,
		SHAPExplanationJSON: a.SHAPExplanationJSON,
		AssigneeID:          a.AssigneeID,
		AssignedAt:          a.AssignedAt,
		ResolvedAt:          a.ResolvedAt,
		ResolutionNotes:     a.ResolutionNotes,
		BlockchainTxID:      a.BlockchainTxID,
		CreatedAt:           a.CreatedAt,
		UpdatedAt:           a.UpdatedAt,
	}
}

func domainStatusToProto(s domain.AlertStatus) commonv1.AlertStatus {
	switch s {
	case domain.StatusOpen:
		return commonv1.AlertStatus_ALERT_STATUS_OPEN
	case domain.StatusInvestigating:
		return commonv1.AlertStatus_ALERT_STATUS_INVESTIGATING
	case domain.StatusResolved:
		return commonv1.AlertStatus_ALERT_STATUS_RESOLVED
	case domain.StatusFalsePositive:
		return commonv1.AlertStatus_ALERT_STATUS_FALSE_POSITIVE
	case domain.StatusEscalated:
		return commonv1.AlertStatus_ALERT_STATUS_ESCALATED
	default:
		return commonv1.AlertStatus_ALERT_STATUS_UNSPECIFIED
	}
}

func protoStatusToDomain(s commonv1.AlertStatus) domain.AlertStatus {
	switch s {
	case commonv1.AlertStatus_ALERT_STATUS_OPEN:
		return domain.StatusOpen
	case commonv1.AlertStatus_ALERT_STATUS_INVESTIGATING:
		return domain.StatusInvestigating
	case commonv1.AlertStatus_ALERT_STATUS_RESOLVED:
		return domain.StatusResolved
	case commonv1.AlertStatus_ALERT_STATUS_FALSE_POSITIVE:
		return domain.StatusFalsePositive
	case commonv1.AlertStatus_ALERT_STATUS_ESCALATED:
		return domain.StatusEscalated
	default:
		return ""
	}
}

func mapDomainError(err error) error {
	var ae *domain.AlertError
	if !errors.As(err, &ae) {
		return grpcstatus.Error(codes.Internal, err.Error())
	}
	switch ae.Code {
	case "ALERT_NOT_FOUND":
		return grpcstatus.Error(codes.NotFound, ae.Message)
	case "DUPLICATE_ALERT":
		return grpcstatus.Error(codes.AlreadyExists, ae.Message)
	case "INVALID_TRANSITION":
		return grpcstatus.Error(codes.FailedPrecondition, ae.Message)
	case "INVALID_ALERT":
		return grpcstatus.Error(codes.InvalidArgument, ae.Message)
	default:
		return grpcstatus.Error(codes.Internal, ae.Message)
	}
}

// generateAlertID builds a deterministic alert ID from customerID + txHash.
// Used when the caller (Transaction Service gRPC) does not supply an alert_id.
func generateAlertID(customerID, txHash string) string {
	h := sha256.Sum256([]byte(customerID + ":" + txHash))
	return fmt.Sprintf("alert-%x", h[:8])
}
