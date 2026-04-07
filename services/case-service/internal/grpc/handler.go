// Package grpc (handler.go) implements the CaseServiceServer interface.
package grpc

import (
	"context"
	"errors"
	"time"

	casev1 "github.com/fraud-detection/proto/gen/go/case/v1"
	commonv1 "github.com/fraud-detection/proto/gen/go/common/v1"
	"github.com/fraud-detection/case-service/internal/domain"
	"github.com/fraud-detection/case-service/internal/service"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

// Handler implements casev1.CaseServiceServer.
type Handler struct {
	casev1.UnimplementedCaseServiceServer
	svc *service.CaseService
	log zerolog.Logger
}

// NewHandler creates a Handler.
func NewHandler(svc *service.CaseService, log zerolog.Logger) *Handler {
	return &Handler{svc: svc, log: log.With().Str("component", "case_grpc_handler").Logger()}
}

func (h *Handler) CreateCase(ctx context.Context, req *casev1.CreateCaseRequest) (*casev1.CreateCaseResponse, error) {
	if req.AlertID == "" || req.CustomerID == "" {
		return nil, grpcstatus.Error(codes.InvalidArgument, "alert_id and customer_id are required")
	}
	c, err := h.svc.CreateCase(ctx, &service.CreateCaseInput{
		AlertID:          req.AlertID,
		CustomerID:       req.CustomerID,
		TxHash:           req.TxHash,
		Title:            req.Title,
		Description:      req.Description,
		Priority:         domain.CasePriority(req.Priority),
		FraudProbability: req.FraudProbability,
		RiskScore:        req.RiskScore,
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return &casev1.CreateCaseResponse{Case: domainToProto(c)}, nil
}

func (h *Handler) GetCase(ctx context.Context, req *casev1.GetCaseRequest) (*casev1.GetCaseResponse, error) {
	if req.CaseID == "" {
		return nil, grpcstatus.Error(codes.InvalidArgument, "case_id is required")
	}
	c, actions, err := h.svc.GetCase(ctx, req.CaseID)
	if err != nil {
		return nil, mapErr(err)
	}
	protoActions := make([]*casev1.CaseActionRecord, 0, len(actions))
	for _, a := range actions {
		protoActions = append(protoActions, actionToProto(a))
	}
	return &casev1.GetCaseResponse{Case: domainToProto(c), Actions: protoActions}, nil
}

func (h *Handler) ListCases(ctx context.Context, req *casev1.ListCasesRequest) (*casev1.ListCasesResponse, error) {
	pageSize := 50
	if req.Page != nil && req.Page.PageSize > 0 {
		pageSize = int(req.Page.PageSize)
	}
	f := domain.CaseFilters{
		Status:     protoStatusToDomain(req.StatusFilter),
		Priority:   domain.CasePriority(req.PriorityFilter),
		AssigneeID: req.AssigneeID,
		CustomerID: req.CustomerID,
		SortBy:     req.SortBy,
		Ascending:  req.Ascending,
		PageSize:   pageSize,
	}
	cases, total, err := h.svc.ListCases(ctx, f)
	if err != nil {
		return nil, mapErr(err)
	}
	records := make([]*casev1.CaseRecord, 0, len(cases))
	for _, c := range cases {
		records = append(records, domainToProto(c))
	}
	return &casev1.ListCasesResponse{
		Cases: records,
		Page:  &commonv1.PageResponse{TotalCount: int32(total)},
	}, nil
}

func (h *Handler) UpdateCaseStatus(ctx context.Context, req *casev1.UpdateCaseStatusRequest) (*casev1.UpdateCaseStatusResponse, error) {
	if req.CaseID == "" {
		return nil, grpcstatus.Error(codes.InvalidArgument, "case_id is required")
	}
	newStatus := protoStatusToDomain(req.NewStatus)
	if newStatus == "" {
		return nil, grpcstatus.Error(codes.InvalidArgument, "new_status is required")
	}
	updated, err := h.svc.UpdateCaseStatus(ctx, req.CaseID, req.UpdatedBy, req.Notes, newStatus, req.ResolutionSummary)
	if err != nil {
		return nil, mapErr(err)
	}
	return &casev1.UpdateCaseStatusResponse{Case: domainToProto(updated)}, nil
}

func (h *Handler) AssignCase(ctx context.Context, req *casev1.AssignCaseRequest) (*casev1.AssignCaseResponse, error) {
	if req.CaseID == "" || req.AssigneeID == "" {
		return nil, grpcstatus.Error(codes.InvalidArgument, "case_id and assignee_id are required")
	}
	updated, err := h.svc.AssignCase(ctx, req.CaseID, req.AssigneeID, req.AssignedBy)
	if err != nil {
		return nil, mapErr(err)
	}
	return &casev1.AssignCaseResponse{Case: domainToProto(updated)}, nil
}

func (h *Handler) AddEvidence(ctx context.Context, req *casev1.AddEvidenceRequest) (*casev1.AddEvidenceResponse, error) {
	if req.CaseID == "" || req.FileName == "" {
		return nil, grpcstatus.Error(codes.InvalidArgument, "case_id and file_name are required")
	}
	e, putURL, getURL, err := h.svc.AddEvidence(ctx, &service.AddEvidenceInput{
		CaseID:       req.CaseID,
		UploadedBy:   req.UploadedBy,
		FileName:     req.FileName,
		FileSize:     req.FileSize,
		ContentType:  req.ContentType,
		EvidenceType: domain.EvidenceType(req.EvidenceType.String()),
		Notes:        req.Notes,
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return &casev1.AddEvidenceResponse{
		Evidence:     evidenceToProto(e),
		UploadURL:    putURL,
		PresignedURL: getURL,
	}, nil
}

func (h *Handler) GetEvidence(ctx context.Context, req *casev1.GetEvidenceRequest) (*casev1.GetEvidenceResponse, error) {
	if req.CaseID == "" {
		return nil, grpcstatus.Error(codes.InvalidArgument, "case_id is required")
	}
	evs, urls, err := h.svc.GetEvidence(ctx, req.CaseID, req.EvidenceID)
	if err != nil {
		return nil, mapErr(err)
	}
	records := make([]*casev1.EvidenceRecord, 0, len(evs))
	for i, e := range evs {
		p := evidenceToProto(e)
		if i < len(urls) {
			p.PresignedURL = urls[i]
		}
		records = append(records, p)
	}
	return &casev1.GetEvidenceResponse{Evidence: records}, nil
}

func (h *Handler) DeleteEvidence(ctx context.Context, req *casev1.DeleteEvidenceRequest) (*casev1.DeleteEvidenceResponse, error) {
	if req.CaseID == "" || req.EvidenceID == "" {
		return nil, grpcstatus.Error(codes.InvalidArgument, "case_id and evidence_id are required")
	}
	if err := h.svc.DeleteEvidence(ctx, req.CaseID, req.EvidenceID, req.DeletedBy); err != nil {
		return nil, mapErr(err)
	}
	return &casev1.DeleteEvidenceResponse{Success: true}, nil
}

func (h *Handler) GenerateSAR(ctx context.Context, req *casev1.GenerateSARRequest) (*casev1.GenerateSARResponse, error) {
	if req.CaseID == "" {
		return nil, grpcstatus.Error(codes.InvalidArgument, "case_id is required")
	}
	s3Key, downloadURL, err := h.svc.GenerateSAR(ctx, req.CaseID, req.GeneratedBy, req.Notes)
	if err != nil {
		return nil, mapErr(err)
	}
	return &casev1.GenerateSARResponse{
		CaseID:      req.CaseID,
		S3Key:       s3Key,
		DownloadURL: downloadURL,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func (h *Handler) GetCaseStats(ctx context.Context, req *casev1.GetCaseStatsRequest) (*casev1.GetCaseStatsResponse, error) {
	stats, err := h.svc.GetCaseStats(ctx, req.Period)
	if err != nil {
		return nil, mapErr(err)
	}
	return &casev1.GetCaseStatsResponse{
		Stats: &casev1.CaseStats{
			TotalCases:         int32(stats.TotalCases),
			OpenCases:          int32(stats.OpenCases),
			InReviewCases:      int32(stats.InReviewCases),
			PendingSARCases:    int32(stats.PendingSARCases),
			ClosedCases:        int32(stats.ClosedCases),
			CriticalCases:      int32(stats.CriticalCases),
			SARGenerated:       int32(stats.SARGenerated),
			AvgResolutionHours: stats.AvgResolutionHours,
			Period:             stats.Period,
		},
	}, nil
}

func (h *Handler) GetInvestigatorWorkload(ctx context.Context, req *casev1.GetInvestigatorWorkloadRequest) (*casev1.GetInvestigatorWorkloadResponse, error) {
	workloads, err := h.svc.GetInvestigatorWorkload(ctx, req.InvestigatorIDs)
	if err != nil {
		return nil, mapErr(err)
	}
	records := make([]*casev1.InvestigatorRecord, 0, len(workloads))
	for _, w := range workloads {
		records = append(records, &casev1.InvestigatorRecord{
			InvestigatorID: w.InvestigatorID,
			ActiveCases:    int32(w.ActiveCases),
		})
	}
	return &casev1.GetInvestigatorWorkloadResponse{Workloads: records}, nil
}

func (h *Handler) HealthCheck(ctx context.Context, _ *commonv1.HealthCheckRequest) (*commonv1.HealthCheckResponse, error) {
	checks := h.svc.HealthCheck(ctx)
	allOK := true
	for _, v := range checks {
		if v != "ok" {
			allOK = false
			break
		}
	}
	st := commonv1.HealthStatus_HEALTH_STATUS_SERVING
	if !allOK {
		st = commonv1.HealthStatus_HEALTH_STATUS_NOT_SERVING
	}
	return &commonv1.HealthCheckResponse{Status: st}, nil
}

// ---------------------------------------------------------------------------
// Type conversions
// ---------------------------------------------------------------------------

func domainToProto(c *domain.Case) *casev1.CaseRecord {
	return &casev1.CaseRecord{
		CaseID:            c.CaseID,
		AlertID:           c.AlertID,
		CustomerID:        c.CustomerID,
		TxHash:            c.TxHash,
		Title:             c.Title,
		Description:       c.Description,
		Status:            domainStatusToProto(c.Status),
		Priority:          casev1.CasePriority(c.Priority),
		AssigneeID:        c.AssigneeID,
		AssignedAt:        c.AssignedAt,
		FraudProbability:  c.FraudProbability,
		RiskScore:         c.RiskScore,
		SARRequired:       c.SARRequired,
		SARS3Key:          c.SARS3Key,
		SARGeneratedAt:    c.SARGeneratedAt,
		BlockchainTxID:    c.BlockchainTxID,
		ResolutionSummary: c.ResolutionSummary,
		ClosedAt:          c.ClosedAt,
		CreatedAt:         c.CreatedAt,
		UpdatedAt:         c.UpdatedAt,
	}
}

func evidenceToProto(e *domain.Evidence) *casev1.EvidenceRecord {
	return &casev1.EvidenceRecord{
		EvidenceID:  e.EvidenceID,
		CaseID:      e.CaseID,
		UploadedBy:  e.UploadedBy,
		FileName:    e.FileName,
		FileSize:    e.FileSize,
		ContentType: e.ContentType,
		S3Key:       e.S3Key,
		Notes:       e.Notes,
		CreatedAt:   e.CreatedAt,
	}
}

func actionToProto(a *domain.CaseAction) *casev1.CaseActionRecord {
	return &casev1.CaseActionRecord{
		ActionID:       a.ActionID,
		CaseID:         a.CaseID,
		InvestigatorID: a.InvestigatorID,
		Action:         a.Action,
		Notes:          a.Notes,
		BlockchainTxID: a.BlockchainTxID,
		PerformedAt:    a.PerformedAt,
	}
}

func domainStatusToProto(s domain.CaseStatus) casev1.CaseStatus {
	switch s {
	case domain.CaseStatusOpen:
		return casev1.CaseStatus_CASE_STATUS_OPEN
	case domain.CaseStatusInReview:
		return casev1.CaseStatus_CASE_STATUS_IN_REVIEW
	case domain.CaseStatusPendingSAR:
		return casev1.CaseStatus_CASE_STATUS_PENDING_SAR
	case domain.CaseStatusClosed:
		return casev1.CaseStatus_CASE_STATUS_CLOSED
	case domain.CaseStatusEscalated:
		return casev1.CaseStatus_CASE_STATUS_ESCALATED
	default:
		return casev1.CaseStatus_CASE_STATUS_UNSPECIFIED
	}
}

func protoStatusToDomain(s casev1.CaseStatus) domain.CaseStatus {
	switch s {
	case casev1.CaseStatus_CASE_STATUS_OPEN:
		return domain.CaseStatusOpen
	case casev1.CaseStatus_CASE_STATUS_IN_REVIEW:
		return domain.CaseStatusInReview
	case casev1.CaseStatus_CASE_STATUS_PENDING_SAR:
		return domain.CaseStatusPendingSAR
	case casev1.CaseStatus_CASE_STATUS_CLOSED:
		return domain.CaseStatusClosed
	case casev1.CaseStatus_CASE_STATUS_ESCALATED:
		return domain.CaseStatusEscalated
	default:
		return ""
	}
}

func mapErr(err error) error {
	var ce *domain.CaseError
	if !errors.As(err, &ce) {
		return grpcstatus.Error(codes.Internal, err.Error())
	}
	switch ce.Code {
	case "CASE_NOT_FOUND", "EVIDENCE_NOT_FOUND":
		return grpcstatus.Error(codes.NotFound, ce.Message)
	case "DUPLICATE_CASE":
		return grpcstatus.Error(codes.AlreadyExists, ce.Message)
	case "INVALID_TRANSITION", "SAR_EXISTS":
		return grpcstatus.Error(codes.FailedPrecondition, ce.Message)
	case "INVALID_CASE", "NO_INVESTIGATORS":
		return grpcstatus.Error(codes.InvalidArgument, ce.Message)
	default:
		return grpcstatus.Error(codes.Internal, ce.Message)
	}
}
