// Package s3 manages evidence file storage using Amazon S3.
package s3

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/rs/zerolog/log"
)

// EvidenceStore manages pre-signed S3 URLs for case evidence and SAR PDFs.
type EvidenceStore struct {
	client     *s3.Client
	presigner  *s3.PresignClient
	bucket     string
	presignTTL time.Duration
}

// New creates an EvidenceStore using explicit credentials.
// If accessKeyID is empty, the default credential chain is used (IAM role / env).
func New(ctx context.Context, region, bucket, accessKeyID, secretKey string, presignTTL time.Duration) (*EvidenceStore, error) {
	var opts []func(*awsconfig.LoadOptions) error
	opts = append(opts, awsconfig.WithRegion(region))

	if accessKeyID != "" && secretKey != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(accessKeyID, secretKey, ""),
		))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}

	client := s3.NewFromConfig(cfg)
	presigner := s3.NewPresignClient(client)

	return &EvidenceStore{
		client:     client,
		presigner:  presigner,
		bucket:     bucket,
		presignTTL: presignTTL,
	}, nil
}

// EvidenceKey constructs the S3 object key for a piece of case evidence.
//
//	evidence/cases/<caseID>/<evidenceID>/<fileName>
func EvidenceKey(caseID, evidenceID, fileName string) string {
	return fmt.Sprintf("evidence/cases/%s/%s/%s", caseID, evidenceID, fileName)
}

// SARKey constructs the S3 object key for a SAR PDF.
//
//	sar/<caseID>/SAR_<caseID>_<timestamp>.pdf
func SARKey(caseID string) string {
	ts := time.Now().UTC().Format("20060102T150405")
	return fmt.Sprintf("sar/%s/SAR_%s_%s.pdf", caseID, caseID, ts)
}

// PresignPutURL generates a pre-signed S3 PUT URL for evidence upload.
// The caller uploads the file directly to S3 — the Case Service never handles raw bytes.
func (s *EvidenceStore) PresignPutURL(ctx context.Context, s3Key, contentType string) (string, error) {
	req, err := s.presigner.PresignPutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(s3Key),
		ContentType: aws.String(contentType),
	}, s3.WithPresignExpires(s.presignTTL))
	if err != nil {
		return "", fmt.Errorf("presign PUT %s: %w", s3Key, err)
	}
	log.Debug().Str("key", s3Key).Dur("ttl", s.presignTTL).Msg("generated S3 PUT URL")
	return req.URL, nil
}

// PresignGetURL generates a pre-signed S3 GET URL for evidence download.
func (s *EvidenceStore) PresignGetURL(ctx context.Context, s3Key string) (string, error) {
	req, err := s.presigner.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s3Key),
	}, s3.WithPresignExpires(s.presignTTL))
	if err != nil {
		return "", fmt.Errorf("presign GET %s: %w", s3Key, err)
	}
	return req.URL, nil
}

// PutObject uploads raw bytes to S3. Used for SAR PDFs generated in-process.
func (s *EvidenceStore) PutObject(ctx context.Context, s3Key, contentType string, data []byte) error {
	if _, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(s3Key),
		Body:          bytesReader(data),
		ContentType:   aws.String(contentType),
		ContentLength: aws.Int64(int64(len(data))),
	}); err != nil {
		return fmt.Errorf("put object %s: %w", s3Key, err)
	}
	log.Info().Str("key", s3Key).Int("bytes", len(data)).Msg("SAR PDF uploaded to S3")
	return nil
}

// DeleteObject removes an object from S3 (called on evidence deletion).
func (s *EvidenceStore) DeleteObject(ctx context.Context, s3Key string) error {
	if _, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s3Key),
	}); err != nil {
		return fmt.Errorf("delete object %s: %w", s3Key, err)
	}
	return nil
}

// bytesReader wraps a []byte as an io.Reader for the AWS SDK.
type bytesReaderImpl struct {
	data   []byte
	offset int
}

func (r *bytesReaderImpl) Read(p []byte) (int, error) {
	if r.offset >= len(r.data) {
		return 0, fmt.Errorf("EOF")
	}
	n := copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}

func bytesReader(data []byte) *bytesReaderImpl {
	return &bytesReaderImpl{data: data}
}
