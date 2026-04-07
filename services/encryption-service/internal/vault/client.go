// Package vault wraps the HashiCorp Vault Transit secrets engine.
// All encryption/decryption of PII is performed exclusively through this package;
// no other package in the encryption service ever touches raw plaintext key material.
package vault

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	vault "github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"

	"github.com/fraud-detection/encryption-service/internal/config"
)

// KeyMetadata holds Transit key rotation and policy information.
type KeyMetadata struct {
	Name              string
	CurrentVersion    int32
	MinDecryptVersion int32
	RotationPeriod    string
	DeletionAllowed   bool
}

// VaultClient is a thin wrapper around the Vault Transit secrets engine.
type VaultClient struct {
	client         *vault.Client
	defaultKeyName string
}

// New creates an authenticated VaultClient using the provided configuration.
// It verifies connectivity by calling Ping before returning.
func New(cfg *config.Config) (*VaultClient, error) {
	client, err := vault.New(
		vault.WithAddress(cfg.VaultAddr),
	)
	if err != nil {
		return nil, fmt.Errorf("create vault client: %w", err)
	}

	vc := &VaultClient{
		client:         client,
		defaultKeyName: cfg.DefaultKeyName,
	}

	if cfg.VaultAuthMethod == "approle" {
		// AppRole authentication — exchange RoleID + SecretID for a Vault token.
		resp, err := client.Auth.AppRoleLogin(
			context.Background(),
			schema.AppRoleLoginRequest{
				RoleId:   cfg.VaultAppRoleID,
				SecretId: cfg.VaultSecretID,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("vault approle login: %w", err)
		}
		if err := client.SetToken(resp.Auth.ClientToken); err != nil {
			return nil, fmt.Errorf("set vault token from approle: %w", err)
		}
	} else {
		// Token authentication — use the supplied static token.
		if err := client.SetToken(cfg.VaultToken); err != nil {
			return nil, fmt.Errorf("set vault token: %w", err)
		}
	}

	// Verify connectivity and seal status.
	pingCtx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()
	if err := vc.Ping(pingCtx); err != nil {
		return nil, fmt.Errorf("vault ping: %w", err)
	}

	return vc, nil
}

// pingTimeout is the default deadline for the startup connectivity check.
const pingTimeout = 10 * time.Second

// Encrypt encrypts plaintext using the Vault Transit engine under keyName.
// The returned ciphertext has the form "vault:vN:..." where N is the key version.
// Pass an empty string for contextStr to omit convergent encryption context.
//
// IMPORTANT: Never log the plaintext parameter — it contains raw PII.
func (c *VaultClient) Encrypt(ctx context.Context, keyName string, plaintext []byte, contextStr string) (ciphertext string, keyVersion int32, err error) {
	req := schema.TransitEncryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
	}
	if contextStr != "" {
		req.Context = base64.StdEncoding.EncodeToString([]byte(contextStr))
	}

	resp, err := c.client.Secrets.TransitEncrypt(ctx, keyName, req)
	if err != nil {
		return "", 0, fmt.Errorf("transit encrypt: %w", err)
	}

	ct, ok := resp.Data["ciphertext"].(string)
	if !ok || ct == "" {
		return "", 0, fmt.Errorf("transit encrypt: missing ciphertext in response")
	}

	return ct, parseKeyVersion(ct), nil
}

// Decrypt decrypts a Vault Transit ciphertext and returns the raw plaintext bytes.
// The ciphertext must have the form "vault:vN:...".
//
// IMPORTANT: The returned []byte contains raw PII — NEVER log it.
func (c *VaultClient) Decrypt(ctx context.Context, keyName string, ciphertext string, contextStr string) ([]byte, error) {
	req := schema.TransitDecryptRequest{
		Ciphertext: ciphertext,
	}
	if contextStr != "" {
		req.Context = base64.StdEncoding.EncodeToString([]byte(contextStr))
	}

	resp, err := c.client.Secrets.TransitDecrypt(ctx, keyName, req)
	if err != nil {
		return nil, fmt.Errorf("transit decrypt: %w", err)
	}

	plaintextB64, ok := resp.Data["plaintext"].(string)
	if !ok {
		return nil, fmt.Errorf("transit decrypt: missing plaintext in response")
	}

	// Vault returns base64-encoded plaintext; decode to raw bytes.
	// Result contains PII — do not log.
	raw, err := base64.StdEncoding.DecodeString(plaintextB64)
	if err != nil {
		return nil, fmt.Errorf("transit decrypt: base64 decode: %w", err)
	}
	return raw, nil
}

// Rewrap re-encrypts existing ciphertexts under the latest key version without
// exposing the underlying plaintext to the caller.
func (c *VaultClient) Rewrap(ctx context.Context, keyName string, ciphertexts []string, contextStr string) ([]string, int32, error) {
	ctx64 := ""
	if contextStr != "" {
		ctx64 = base64.StdEncoding.EncodeToString([]byte(contextStr))
	}

	newCiphertexts := make([]string, 0, len(ciphertexts))
	var latestVersion int32

	for _, ct := range ciphertexts {
		req := schema.TransitRewrapRequest{
			Ciphertext: ct,
		}
		if ctx64 != "" {
			req.Context = ctx64
		}

		resp, err := c.client.Secrets.TransitRewrap(ctx, keyName, req)
		if err != nil {
			return nil, 0, fmt.Errorf("transit rewrap: %w", err)
		}

		newCt, ok := resp.Data["ciphertext"].(string)
		if !ok || newCt == "" {
			return nil, 0, fmt.Errorf("transit rewrap: missing ciphertext in response")
		}
		newCiphertexts = append(newCiphertexts, newCt)

		if kv := parseKeyVersion(newCt); kv > latestVersion {
			latestVersion = kv
		}
	}

	return newCiphertexts, latestVersion, nil
}

// GetKeyMetadata returns rotation and policy metadata for the named Transit key.
func (c *VaultClient) GetKeyMetadata(ctx context.Context, keyName string) (*KeyMetadata, error) {
	resp, err := c.client.Secrets.TransitReadKey(ctx, keyName)
	if err != nil {
		return nil, fmt.Errorf("transit read key %q: %w", keyName, err)
	}

	data := resp.Data
	meta := &KeyMetadata{Name: keyName}

	if v, ok := data["latest_version"]; ok {
		meta.CurrentVersion = toInt32(v)
	}
	if v, ok := data["min_decryption_version"]; ok {
		meta.MinDecryptVersion = toInt32(v)
	}
	if v, ok := data["auto_rotate_period"]; ok {
		meta.RotationPeriod = fmt.Sprintf("%v", v)
	}
	if v, ok := data["deletion_allowed"]; ok {
		if b, ok2 := v.(bool); ok2 {
			meta.DeletionAllowed = b
		}
	}

	return meta, nil
}

// EnsureKeyExists creates the Transit key if it does not already exist.
// If the key already exists this is a no-op.
func (c *VaultClient) EnsureKeyExists(ctx context.Context, keyName string, rotationPeriod string) error {
	// Attempt to read first — if the key exists we are done.
	_, err := c.client.Secrets.TransitReadKey(ctx, keyName)
	if err == nil {
		return nil // key already exists
	}

	// Create the key; Vault returns an error if it already exists (TOCTOU
	// race), which we treat as success.
	_, createErr := c.client.Secrets.TransitCreateKey(ctx, keyName, schema.TransitCreateKeyRequest{
		Type:             "aes256-gcm96",
		AutoRotatePeriod: rotationPeriod,
	})
	if createErr != nil {
		if strings.Contains(createErr.Error(), "already exists") {
			return nil
		}
		return fmt.Errorf("transit create key %q: %w", keyName, createErr)
	}

	return nil
}

// Ping verifies that Vault is reachable and unsealed by reading sys/health.
func (c *VaultClient) Ping(ctx context.Context) error {
	resp, err := c.client.System.ReadHealthStatus(ctx)
	if err != nil {
		return fmt.Errorf("vault health check: %w", err)
	}

	sealed, _ := resp.Data["sealed"].(bool)
	if sealed {
		return fmt.Errorf("vault is sealed")
	}
	return nil
}

// parseKeyVersion extracts the integer version N from a "vault:vN:..." ciphertext.
// Returns 0 if parsing fails.
func parseKeyVersion(ciphertext string) int32 {
	// Format: vault:v{N}:{base64-data}
	parts := strings.SplitN(ciphertext, ":", 3)
	if len(parts) < 2 {
		return 0
	}
	versionStr := strings.TrimPrefix(parts[1], "v")
	n, err := strconv.ParseInt(versionStr, 10, 32)
	if err != nil {
		return 0
	}
	return int32(n)
}

// toInt32 converts a JSON-decoded numeric value to int32.
func toInt32(v interface{}) int32 {
	switch t := v.(type) {
	case float64:
		return int32(t)
	case json.Number:
		n, _ := t.Int64()
		return int32(n)
	case int:
		return int32(t)
	case int32:
		return t
	case int64:
		return int32(t)
	}
	return 0
}
