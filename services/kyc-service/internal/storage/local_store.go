package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

// DocumentStore persists uploaded KYC documents and returns a retrievable key.
type DocumentStore interface {
	SaveUploadedDocument(ctx context.Context, customerID, originalFilename string, body io.Reader) (string, error)
}

// LocalDocumentStore saves uploaded files under a local directory for
// development and test workflows where S3 is not available.
type LocalDocumentStore struct {
	baseDir string
}

// NewLocalDocumentStore creates a local document store rooted at baseDir.
func NewLocalDocumentStore(baseDir string) *LocalDocumentStore {
	return &LocalDocumentStore{baseDir: baseDir}
}

// SaveUploadedDocument writes the uploaded file to disk and returns its key.
func (s *LocalDocumentStore) SaveUploadedDocument(ctx context.Context, customerID, originalFilename string, body io.Reader) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	if customerID == "" {
		customerID = "anonymous"
	}

	cleanName := sanitizeFilename(originalFilename)
	if cleanName == "" {
		cleanName = "document.bin"
	}

	dir := filepath.Join(s.baseDir, customerID, time.Now().UTC().Format("20060102"))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create upload directory: %w", err)
	}

	filename := uuid.NewString() + "_" + cleanName
	fullPath := filepath.Join(dir, filename)

	file, err := os.Create(fullPath)
	if err != nil {
		return "", fmt.Errorf("create upload file: %w", err)
	}
	defer file.Close()

	if _, err := io.Copy(file, body); err != nil {
		return "", fmt.Errorf("write upload file: %w", err)
	}

	return filepath.ToSlash(fullPath), nil
}

func sanitizeFilename(name string) string {
	name = filepath.Base(strings.TrimSpace(name))
	if name == "." || name == "/" || name == `\` {
		return ""
	}

	replacer := strings.NewReplacer("..", "", "/", "_", `\`, "_", ":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_")
	return replacer.Replace(name)
}
