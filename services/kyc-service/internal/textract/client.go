// Package textract wraps AWS Textract for document OCR in the KYC pipeline.
// The OCRClient interface is satisfied by both the real TextractClient and the
// MockOCRClient, allowing tests and local development to run without AWS.
package textract

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/textract"
	"github.com/aws/aws-sdk-go-v2/service/textract/types"
	"github.com/fraud-detection/kyc-service/internal/domain"
)

// OCRClient is the interface implemented by both the real Textract client and
// the mock client used in local development and tests.
type OCRClient interface {
	// ExtractDocument runs OCR on the given S3 object and returns structured
	// field extractions. documentType hints which fields to look for.
	ExtractDocument(ctx context.Context, s3Key, s3Bucket, documentType string) (*domain.OCRResult, error)
}

// TextractClient wraps the AWS Textract SDK to extract text from identity documents.
type TextractClient struct {
	client *textract.Client
	bucket string
}

// NewTextractClient creates a new TextractClient using the provided AWS configuration.
func NewTextractClient(cfg aws.Config, bucket string) *TextractClient {
	return &TextractClient{
		client: textract.NewFromConfig(cfg),
		bucket: bucket,
	}
}

// ExtractDocument starts a Textract async analysis job, polls for completion,
// and parses the resulting key-value pairs into a domain.OCRResult.
// A 30-second timeout is recommended via the context passed by the caller.
func (c *TextractClient) ExtractDocument(ctx context.Context, s3Key, s3Bucket, documentType string) (*domain.OCRResult, error) {
	bucket := c.bucket
	if s3Bucket != "" {
		bucket = s3Bucket
	}

	// Start asynchronous document analysis with FORMS and TABLES feature types.
	startInput := &textract.StartDocumentAnalysisInput{
		DocumentLocation: &types.DocumentLocation{
			S3Object: &types.S3Object{
				Bucket: aws.String(bucket),
				Name:   aws.String(s3Key),
			},
		},
		FeatureTypes: []types.FeatureType{
			types.FeatureTypeForms,
			types.FeatureTypeTables,
		},
	}

	startOut, err := c.client.StartDocumentAnalysis(ctx, startInput)
	if err != nil {
		return nil, fmt.Errorf("start textract analysis: %w", err)
	}

	jobID := aws.ToString(startOut.JobId)

	// Poll for job completion.
	result, err := c.pollForCompletion(ctx, jobID)
	if err != nil {
		return nil, err
	}

	return c.parseResult(result, documentType), nil
}

// pollForCompletion polls the Textract GetDocumentAnalysis API until the job
// reaches a terminal state (SUCCEEDED or FAILED).
func (c *TextractClient) pollForCompletion(ctx context.Context, jobID string) ([]types.Block, error) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var allBlocks []types.Block
	var nextToken *string

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("textract poll cancelled: %w", ctx.Err())
		case <-ticker.C:
			input := &textract.GetDocumentAnalysisInput{
				JobId:     aws.String(jobID),
				NextToken: nextToken,
			}
			out, err := c.client.GetDocumentAnalysis(ctx, input)
			if err != nil {
				return nil, fmt.Errorf("get document analysis: %w", err)
			}

			switch out.JobStatus {
			case types.JobStatusSucceeded:
				allBlocks = append(allBlocks, out.Blocks...)
				for out.NextToken != nil {
					// Fetch remaining pages.
					nextInput := &textract.GetDocumentAnalysisInput{
						JobId:     aws.String(jobID),
						NextToken: out.NextToken,
					}
					nextOut, err := c.client.GetDocumentAnalysis(ctx, nextInput)
					if err != nil {
						return nil, fmt.Errorf("get document analysis page: %w", err)
					}
					allBlocks = append(allBlocks, nextOut.Blocks...)
					out = nextOut
				}
				return allBlocks, nil

			case types.JobStatusFailed:
				statusMsg := ""
				if out.StatusMessage != nil {
					statusMsg = *out.StatusMessage
				}
				return nil, fmt.Errorf("textract job failed: %s", statusMsg)

			default:
				// IN_PROGRESS or PARTIAL_SUCCESS — continue polling.
				continue
			}
		}
	}
}

// parseResult extracts key-value pairs from Textract blocks and maps them to
// the document fields relevant for KYC (name, DOB, document number, expiry).
// Confidence is computed as the average of all KEY_VALUE_SET block confidences.
func (c *TextractClient) parseResult(blocks []types.Block, documentType string) *domain.OCRResult {
	result := &domain.OCRResult{
		Success: true,
	}

	// Build a map of block IDs to blocks for relationship traversal.
	blockMap := make(map[string]types.Block, len(blocks))
	for _, b := range blocks {
		if b.Id != nil {
			blockMap[*b.Id] = b
		}
	}

	// Extract key-value pairs.
	kvPairs := extractKeyValuePairs(blocks, blockMap)

	// Map extracted pairs to known field names.
	var totalConf float64
	var confCount int

	for _, kv := range kvPairs {
		key := normalizeKey(kv.key)
		val := kv.value
		conf := kv.confidence

		if conf > 0 {
			totalConf += float64(conf)
			confCount++
		}

		switch {
		case containsAny(key, "name", "full name", "surname"):
			if result.ExtractedName == "" {
				result.ExtractedName = val
			}
		case containsAny(key, "date of birth", "dob", "birth date", "born"):
			if result.ExtractedDOB == "" {
				result.ExtractedDOB = val
			}
		case containsAny(key, "document number", "passport number", "id number", "licence number", "license number"):
			if result.ExtractedDocNo == "" {
				result.ExtractedDocNo = val
			}
		case containsAny(key, "expiry", "expiration", "valid until", "expires"):
			if result.ExtractedExpiry == "" {
				result.ExtractedExpiry = val
			}
		}
	}

	if confCount > 0 {
		result.Confidence = totalConf / float64(confCount) / 100.0 // normalize to [0,1]
	}

	// Validate expiry date if extracted.
	if result.ExtractedExpiry != "" {
		result.ExpiryValid = isExpiryValid(result.ExtractedExpiry)
		if !result.ExpiryValid {
			result.Warnings = append(result.Warnings, "document may be expired")
		}
	}

	// Flag missing critical fields as warnings.
	if result.ExtractedName == "" {
		result.Warnings = append(result.Warnings, "could not extract name from document")
	}
	if result.ExtractedDocNo == "" {
		result.Warnings = append(result.Warnings, "could not extract document number")
	}

	return result
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

type kvPair struct {
	key        string
	value      string
	confidence float32
}

func extractKeyValuePairs(blocks []types.Block, blockMap map[string]types.Block) []kvPair {
	var pairs []kvPair

	for _, block := range blocks {
		if block.BlockType != types.BlockTypeKeyValueSet {
			continue
		}
		// Only process KEY blocks (not VALUE blocks).
		isKey := false
		for _, et := range block.EntityTypes {
			if et == types.EntityTypeKey {
				isKey = true
				break
			}
		}
		if !isKey {
			continue
		}

		keyText := extractTextFromBlock(block, blockMap)
		conf := float32(0)
		if block.Confidence != nil {
			conf = *block.Confidence
		}

		// Find the VALUE block via the VALUE relationship.
		var valueText string
		for _, rel := range block.Relationships {
			if rel.Type != types.RelationshipTypeValue {
				continue
			}
			for _, id := range rel.Ids {
				if valBlock, ok := blockMap[id]; ok {
					valueText = extractTextFromBlock(valBlock, blockMap)
				}
			}
		}

		if keyText != "" {
			pairs = append(pairs, kvPair{key: keyText, value: valueText, confidence: conf})
		}
	}
	return pairs
}

func extractTextFromBlock(block types.Block, blockMap map[string]types.Block) string {
	var sb strings.Builder
	for _, rel := range block.Relationships {
		if rel.Type != types.RelationshipTypeChild {
			continue
		}
		for _, id := range rel.Ids {
			if child, ok := blockMap[id]; ok {
				if child.BlockType == types.BlockTypeWord && child.Text != nil {
					if sb.Len() > 0 {
						sb.WriteByte(' ')
					}
					sb.WriteString(*child.Text)
				}
			}
		}
	}
	return sb.String()
}

func normalizeKey(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func containsAny(s string, substrings ...string) bool {
	for _, sub := range substrings {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func isExpiryValid(expiry string) bool {
	layouts := []string{"02/01/2006", "01/02/2006", "2006-01-02", "02-01-2006", "Jan 2006", "2 Jan 2006"}
	now := time.Now()
	for _, layout := range layouts {
		if t, err := time.Parse(layout, expiry); err == nil {
			return t.After(now)
		}
	}
	return true // unknown format — assume valid to avoid false positives
}
