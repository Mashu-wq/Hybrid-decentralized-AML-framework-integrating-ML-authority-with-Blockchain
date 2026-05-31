// Package grpc — KYCService gRPC handler.
// Translates between proto request/response types and the service layer.
package grpc

import (
	"context"

	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/fraud-detection/kyc-service/internal/domain"
	"github.com/fraud-detection/kyc-service/internal/service"
	commonv1 "github.com/fraud-detection/proto/gen/go/common/v1"
	kycv1 "github.com/fraud-detection/proto/gen/go/kyc/v1"
)

// KYCHandler implements kycv1.KYCServiceServer by delegating to KYCService.
type KYCHandler struct {
	kycv1.UnimplementedKYCServiceServer
	kycSvc *service.KYCService
	log    zerolog.Logger
}

// NewKYCHandler constructs a KYCHandler.
func NewKYCHandler(kycSvc *service.KYCService, log zerolog.Logger) *KYCHandler {
	return &KYCHandler{kycSvc: kycSvc, log: log}
}

// Compile-time assertion that KYCHandler satisfies the server interface.
var _ kycv1.KYCServiceServer = (*KYCHandler)(nil)

// ---------------------------------------------------------------------------
// RPC implementations
// ---------------------------------------------------------------------------

// RegisterCustomer creates a new customer KYC record.
func (h *KYCHandler) RegisterCustomer(ctx context.Context, req *kycv1.RegisterCustomerRequest) (*kycv1.RegisterCustomerResponse, error) {
	if req.FullName == "" || req.Email == "" || req.DocumentType == "" || req.CountryCode == "" {
		return nil, status.Error(codes.InvalidArgument, "full_name, email, document_type, and country_code are required")
	}

	in := &service.RegisterCustomerInput{
		FullName:              req.FullName,
		DateOfBirth:           req.DateOfBirth,
		AddressLine1:          req.AddressLine1,
		AddressLine2:          req.AddressLine2,
		Email:                 req.Email,
		PhoneNumber:           req.PhoneNumber,
		DocumentNumber:        req.DocumentNumber,
		ExpiryDate:            req.ExpiryDate,
		DocumentType:          req.DocumentType,
		CountryOfIssue:        req.CountryOfIssue,
		Nationality:           req.Nationality,
		City:                  req.City,
		CountryCode:           req.CountryCode,
		PostalCode:            req.PostalCode,
		Occupation:            req.Occupation,
		Employer:              req.Employer,
		SourceOfFunds:         req.SourceOfFunds,
		ExpectedMonthlyVolume: req.ExpectedMonthlyVolume,
	}

	customer, err := h.kycSvc.RegisterCustomer(ctx, in)
	if err != nil {
		return nil, mapKYCError(err)
	}

	return &kycv1.RegisterCustomerResponse{
		CustomerId:   customer.ID,
		IdentityHash: customer.IdentityHash,
		KycStatus:    domainKYCStatusToProto(customer.KYCStatus),
		CreatedAt:    timestamppb.New(customer.CreatedAt),
	}, nil
}

// SubmitDocument processes a document image via OCR.
func (h *KYCHandler) SubmitDocument(ctx context.Context, req *kycv1.SubmitDocumentRequest) (*kycv1.SubmitDocumentResponse, error) {
	if req.CustomerId == "" || req.S3Key == "" || req.DocumentType == "" {
		return nil, status.Error(codes.InvalidArgument, "customer_id, s3_key, and document_type are required")
	}

	in := &service.SubmitDocumentInput{
		CustomerID:   req.CustomerId,
		DocumentType: req.DocumentType,
		S3Key:        req.S3Key,
		ContentType:  req.ContentType,
		IsFront:      req.IsFront,
	}

	doc, err := h.kycSvc.SubmitDocument(ctx, in)
	if err != nil {
		return nil, mapKYCError(err)
	}

	resp := &kycv1.SubmitDocumentResponse{
		DocumentId:   doc.ID,
		Status:       doc.Status,
		OcrCompleted: doc.OCRCompleted,
	}

	if doc.OCRResult != nil {
		resp.OcrResult = domainOCRToProto(doc.OCRResult)
	}

	return resp, nil
}

// VerifyFace performs biometric liveness and face-match checks.
func (h *KYCHandler) VerifyFace(ctx context.Context, req *kycv1.VerifyFaceRequest) (*kycv1.VerifyFaceResponse, error) {
	if req.CustomerId == "" || req.SelfieS3Key == "" || req.DocumentS3Key == "" {
		return nil, status.Error(codes.InvalidArgument, "customer_id, selfie_s3_key, and document_s3_key are required")
	}

	in := &service.VerifyFaceInput{
		CustomerID:    req.CustomerId,
		SelfieS3Key:   req.SelfieS3Key,
		DocumentS3Key: req.DocumentS3Key,
		CheckLiveness: req.CheckLiveness,
	}

	result, err := h.kycSvc.VerifyFace(ctx, in)
	if err != nil {
		return nil, mapKYCError(err)
	}

	return &kycv1.VerifyFaceResponse{
		FaceMatch:      result.FaceMatch,
		MatchScore:     result.MatchScore,
		LivenessPassed: result.LivenessPassed,
		LivenessScore:  result.LivenessScore,
		ModelVersion:   result.ModelVersion,
		FailureReason:  result.FailureReason,
	}, nil
}

// UpdateKYCStatus changes the KYC status of a customer.
func (h *KYCHandler) UpdateKYCStatus(ctx context.Context, req *kycv1.UpdateKYCStatusRequest) (*kycv1.UpdateKYCStatusResponse, error) {
	if req.CustomerId == "" || req.NewStatus == commonv1.KYCStatus_KYC_STATUS_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "customer_id and new_status are required")
	}

	in := &service.UpdateKYCStatusInput{
		CustomerID: req.CustomerId,
		Status:     protoKYCStatusToDomain(req.NewStatus),
		RiskLevel:  protoRiskLevelToDomain(req.RiskLevel),
		VerifierID: req.VerifierId,
		Reason:     req.Reason,
	}

	customer, err := h.kycSvc.UpdateKYCStatus(ctx, in)
	if err != nil {
		return nil, mapKYCError(err)
	}

	return &kycv1.UpdateKYCStatusResponse{
		UpdatedRecord:  domainCustomerToProto(customer),
		BlockchainTxId: customer.BlockchainTxID,
	}, nil
}

// GetKYCRecord retrieves the non-PII KYC record for a customer.
func (h *KYCHandler) GetKYCRecord(ctx context.Context, req *kycv1.GetKYCRecordRequest) (*kycv1.GetKYCRecordResponse, error) {
	if req.CustomerId == "" {
		return nil, status.Error(codes.InvalidArgument, "customer_id is required")
	}

	customer, err := h.kycSvc.GetKYCRecord(ctx, req.CustomerId)
	if err != nil {
		return nil, mapKYCError(err)
	}

	return &kycv1.GetKYCRecordResponse{
		Record: domainCustomerToProto(customer),
	}, nil
}

// ListByStatus returns a paginated list of customers filtered by KYC status.
func (h *KYCHandler) ListByStatus(ctx context.Context, req *kycv1.ListByStatusRequest) (*kycv1.ListByStatusResponse, error) {
	if req.Status == commonv1.KYCStatus_KYC_STATUS_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "status is required")
	}

	limit, offset := 20, 0
	if req.Page != nil {
		if req.Page.PageSize > 0 {
			limit = int(req.Page.PageSize)
		}
	}

	customers, total, err := h.kycSvc.ListByStatus(
		ctx,
		protoKYCStatusToDomain(req.Status),
		req.CountryCode,
		limit, offset,
	)
	if err != nil {
		return nil, mapKYCError(err)
	}

	records := make([]*kycv1.KYCRecord, len(customers))
	for i, c := range customers {
		records[i] = domainCustomerToProto(c)
	}

	return &kycv1.ListByStatusResponse{
		Records: records,
		Page: &commonv1.PageResponse{
			TotalCount: int32(total),
		},
	}, nil
}

// GetDecryptedPII retrieves and decrypts PII for a customer (privileged access only).
func (h *KYCHandler) GetDecryptedPII(ctx context.Context, req *kycv1.GetDecryptedPIIRequest) (*kycv1.GetDecryptedPIIResponse, error) {
	if req.CustomerId == "" {
		return nil, status.Error(codes.InvalidArgument, "customer_id is required")
	}
	if req.Reason == "" {
		return nil, status.Error(codes.InvalidArgument, "reason is required for PII access audit")
	}

	actorID := ""
	if req.Meta != nil {
		actorID = req.Meta.UserId
	}

	// IMPORTANT: Do not log the result. The service layer handles audit logging.
	result, err := h.kycSvc.GetDecryptedPII(ctx, req.CustomerId, actorID, req.Reason)
	if err != nil {
		return nil, mapKYCError(err)
	}

	// DO NOT LOG any fields from result — all contain raw PII.
	return &kycv1.GetDecryptedPIIResponse{
		Pii: &kycv1.CustomerPII{
			FullName:       result.FullName,
			DateOfBirth:    result.DateOfBirth,
			AddressLine1:   result.AddressLine1,
			AddressLine2:   result.AddressLine2,
			Email:          result.Email,
			PhoneNumber:    result.PhoneNumber,
			DocumentNumber: result.DocumentNumber,
			ExpiryDate:     result.ExpiryDate,
		},
	}, nil
}

// GetCustomerRiskLevel returns the risk level and KYC status for a customer.
func (h *KYCHandler) GetCustomerRiskLevel(ctx context.Context, req *kycv1.GetCustomerRiskLevelRequest) (*kycv1.GetCustomerRiskLevelResponse, error) {
	if req.CustomerId == "" {
		return nil, status.Error(codes.InvalidArgument, "customer_id is required")
	}

	customer, err := h.kycSvc.GetCustomerRiskLevel(ctx, req.CustomerId)
	if err != nil {
		return nil, mapKYCError(err)
	}

	return &kycv1.GetCustomerRiskLevelResponse{
		RiskLevel:   domainRiskLevelToProto(customer.RiskLevel),
		KycStatus:   domainKYCStatusToProto(customer.KYCStatus),
		CountryCode: customer.CountryCode,
	}, nil
}

// HealthCheck reports service liveness.
func (h *KYCHandler) HealthCheck(ctx context.Context, _ *commonv1.HealthCheckRequest) (*commonv1.HealthCheckResponse, error) {
	return &commonv1.HealthCheckResponse{
		Status:  commonv1.HealthStatus_HEALTH_STATUS_SERVING,
		Details: "kyc-service healthy",
	}, nil
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

// domainCustomerToProto converts a domain.Customer to its proto representation.
func domainCustomerToProto(c *domain.Customer) *kycv1.KYCRecord {
	rec := &kycv1.KYCRecord{
		CustomerId:      c.ID,
		IdentityHash:    c.IdentityHash,
		KycStatus:       domainKYCStatusToProto(c.KYCStatus),
		RiskLevel:       domainRiskLevelToProto(c.RiskLevel),
		DocumentType:    c.DocumentType,
		CountryOfIssue:  c.CountryOfIssue,
		LivenessPassed:  c.LivenessPassed,
		FaceMatchScore:  c.FaceMatchScore,
		OcrConfidence:   c.OCRConfidence,
		VerifierId:      c.VerifierID,
		RejectionReason: c.RejectionReason,
		BlockchainTxId:  c.BlockchainTxID,
		CreatedAt:       timestamppb.New(c.CreatedAt),
		UpdatedAt:       timestamppb.New(c.UpdatedAt),
	}
	if c.ReviewedAt != nil {
		rec.ReviewedAt = timestamppb.New(*c.ReviewedAt)
	}
	return rec
}

func domainRiskLevelToProto(r domain.RiskLevel) commonv1.RiskLevel {
	switch r {
	case domain.RiskLevelLow:
		return commonv1.RiskLevel_RISK_LEVEL_LOW
	case domain.RiskLevelMedium:
		return commonv1.RiskLevel_RISK_LEVEL_MEDIUM
	case domain.RiskLevelHigh:
		return commonv1.RiskLevel_RISK_LEVEL_HIGH
	case domain.RiskLevelCritical:
		return commonv1.RiskLevel_RISK_LEVEL_CRITICAL
	default:
		return commonv1.RiskLevel_RISK_LEVEL_UNSPECIFIED
	}
}

func domainKYCStatusToProto(s domain.KYCStatus) commonv1.KYCStatus {
	switch s {
	case domain.KYCStatusPending:
		return commonv1.KYCStatus_KYC_STATUS_PENDING
	case domain.KYCStatusApproved:
		return commonv1.KYCStatus_KYC_STATUS_APPROVED
	case domain.KYCStatusRejected:
		return commonv1.KYCStatus_KYC_STATUS_REJECTED
	case domain.KYCStatusSuspended:
		return commonv1.KYCStatus_KYC_STATUS_SUSPENDED
	default:
		return commonv1.KYCStatus_KYC_STATUS_UNSPECIFIED
	}
}

func protoKYCStatusToDomain(s commonv1.KYCStatus) domain.KYCStatus {
	switch s {
	case commonv1.KYCStatus_KYC_STATUS_PENDING:
		return domain.KYCStatusPending
	case commonv1.KYCStatus_KYC_STATUS_APPROVED:
		return domain.KYCStatusApproved
	case commonv1.KYCStatus_KYC_STATUS_REJECTED:
		return domain.KYCStatusRejected
	case commonv1.KYCStatus_KYC_STATUS_SUSPENDED:
		return domain.KYCStatusSuspended
	default:
		return domain.KYCStatusPending
	}
}

func protoRiskLevelToDomain(r commonv1.RiskLevel) domain.RiskLevel {
	switch r {
	case commonv1.RiskLevel_RISK_LEVEL_LOW:
		return domain.RiskLevelLow
	case commonv1.RiskLevel_RISK_LEVEL_MEDIUM:
		return domain.RiskLevelMedium
	case commonv1.RiskLevel_RISK_LEVEL_HIGH:
		return domain.RiskLevelHigh
	case commonv1.RiskLevel_RISK_LEVEL_CRITICAL:
		return domain.RiskLevelCritical
	default:
		return domain.RiskLevelUnspecified
	}
}

// domainOCRToProto converts a domain.OCRResult to its proto representation.
func domainOCRToProto(o *domain.OCRResult) *kycv1.OCRResult {
	return &kycv1.OCRResult{
		Success:         o.Success,
		Confidence:      o.Confidence,
		ExpiryValid:     o.ExpiryValid,
		NameMatch:       o.NameMatch,
		Warnings:        o.Warnings,
		ExtractedName:   o.ExtractedName,  // client responsibility not to log
		ExtractedDob:    o.ExtractedDOB,   // client responsibility not to log
		ExtractedDocNo:  o.ExtractedDocNo, // client responsibility not to log
		ExtractedExpiry: o.ExtractedExpiry,
	}
}

// mapKYCError converts domain KYCErrors to gRPC status codes.
func mapKYCError(err error) error {
	if err == nil {
		return nil
	}

	kycErr, ok := err.(*domain.KYCError)
	if !ok {
		return status.Errorf(codes.Internal, "internal error: %v", err)
	}

	switch kycErr.Code {
	case domain.ErrCustomerNotFound, domain.ErrDocumentNotFound:
		return status.Error(codes.NotFound, kycErr.Message)
	case domain.ErrCustomerAlreadyExists:
		return status.Error(codes.AlreadyExists, kycErr.Message)
	case domain.ErrInvalidStatus:
		return status.Error(codes.FailedPrecondition, kycErr.Message)
	case domain.ErrPermissionDenied:
		return status.Error(codes.PermissionDenied, kycErr.Message)
	case domain.ErrInternal:
		return status.Error(codes.Internal, kycErr.Message)
	default:
		return status.Errorf(codes.Internal, "internal error: %s", kycErr.Message)
	}
}
