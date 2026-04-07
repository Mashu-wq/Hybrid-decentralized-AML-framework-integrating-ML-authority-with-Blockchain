// Package clients — mock face match client.
// Phase 7 will replace this with a real gRPC client to the ML service.
package clients

import (
	"context"
	"fmt"
	"time"

	"github.com/fraud-detection/kyc-service/internal/domain"
	mlv1 "github.com/fraud-detection/proto/gen/go/ml/v1"
	"github.com/fraud-detection/shared/grpcclient"
	"github.com/rs/zerolog"
)

// FaceMatchClient is the interface for biometric face verification.
// The real implementation (Phase 7) will call the ML service gRPC API.
type FaceMatchClient interface {
	// MatchFaces compares a selfie against a document photo.
	// checkLiveness triggers active liveness detection when true.
	MatchFaces(
		ctx context.Context,
		selfieS3Key, documentS3Key string,
		checkLiveness bool,
	) (*domain.FaceVerifyResult, error)
}

// mlFaceMatchClient calls the ML service gRPC endpoint for face verification.
type mlFaceMatchClient struct {
	client mlv1.FraudMLServiceClient
	log    zerolog.Logger
}

// NewMLFaceMatchClient dials the ML service and returns a gRPC-backed client.
func NewMLFaceMatchClient(addr string, log zerolog.Logger) (FaceMatchClient, error) {
	conn, err := grpcclient.New(context.Background(), grpcclient.Config{
		Target:        addr,
		CallerService: "kyc-service",
		TLS:           false,
		Log:           log,
	})
	if err != nil {
		return nil, fmt.Errorf("dial ML service at %s: %w", addr, err)
	}

	return &mlFaceMatchClient{
		client: mlv1.NewFraudMLServiceClient(conn),
		log:    log.With().Str("component", "face_match_client").Logger(),
	}, nil
}

// MatchFaces delegates biometric verification to the ML service over gRPC.
func (m *mlFaceMatchClient) MatchFaces(
	ctx context.Context,
	selfieS3Key, documentS3Key string,
	checkLiveness bool,
) (*domain.FaceVerifyResult, error) {
	resp, err := m.client.VerifyFace(ctx, &mlv1.VerifyFaceRequest{
		SelfieS3Key:   selfieS3Key,
		DocumentS3Key: documentS3Key,
		CheckLiveness: checkLiveness,
	})
	if err != nil {
		return nil, fmt.Errorf("verify face via ML service: %w", err)
	}

	result := &domain.FaceVerifyResult{
		FaceMatch:      resp.FaceMatch,
		MatchScore:     resp.MatchScore,
		LivenessPassed: resp.LivenessPassed,
		LivenessScore:  resp.LivenessScore,
		FailureReason:  resp.FailureReason,
		ModelVersion:   resp.ModelVersion,
	}

	m.log.Debug().
		Str("selfie_key", selfieS3Key).
		Str("document_key", documentS3Key).
		Bool("face_match", result.FaceMatch).
		Bool("liveness_passed", result.LivenessPassed).
		Msg("face verification completed via ML service")

	return result, nil
}

// mockFaceMatchClient returns realistic mock face match results for development.
type mockFaceMatchClient struct {
	threshold float64
	log       zerolog.Logger
}

// NewMockFaceMatchClient returns a FaceMatchClient that returns positive mock
// results without calling any ML service. Replace with a real client in Phase 7.
func NewMockFaceMatchClient(threshold float64, log zerolog.Logger) FaceMatchClient {
	return &mockFaceMatchClient{
		threshold: threshold,
		log:       log.With().Str("component", "face_match_client_mock").Logger(),
	}
}

// MatchFaces returns a realistic positive match result.
// score=0.92 is above the default threshold of 0.85, so verification passes.
func (m *mockFaceMatchClient) MatchFaces(
	ctx context.Context,
	selfieS3Key, documentS3Key string,
	checkLiveness bool,
) (*domain.FaceVerifyResult, error) {
	// Simulate processing delay.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(100 * time.Millisecond):
	}

	const mockScore = 0.92
	const mockLivenessScore = 0.97

	result := &domain.FaceVerifyResult{
		FaceMatch:    mockScore >= m.threshold,
		MatchScore:   mockScore,
		ModelVersion: "mock-v1.0",
	}

	if checkLiveness {
		result.LivenessPassed = true
		result.LivenessScore = mockLivenessScore
	}

	m.log.Debug().
		Str("selfie_key", selfieS3Key).
		Float64("match_score", result.MatchScore).
		Bool("face_match", result.FaceMatch).
		Bool("liveness_passed", result.LivenessPassed).
		Msg("[MOCK] face match result — Phase 7 will use real ML service")

	return result, nil
}
