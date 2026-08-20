package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ServiceName string
	Environment string
	LogLevel    string

	HTTPPort          int
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	ShutdownTimeout   time.Duration
	ConnectionProfile string
	OrgName           string
	Username          string
	PoolSize          int

	// fabric-gateway connection settings (Fabric 2.4+ Gateway service)
	MSPID                   string
	PeerEndpoint            string
	GatewayHostnameOverride string
	TLSCertPath             string
	SignCertPath            string
	KeystoreDir             string

	KYCChannel     string
	AlertChannel   string
	AuditChannel   string
	KYCChaincode   string
	AlertChaincode string
	AuditChaincode string

	// CustomerHMACKey keys the HMAC-SHA256 pseudonymization applied to customer
	// identifiers before they leave the bank's trust domain for the shared
	// ledger (alert-channel and audit-channel writes/reads). The mapping from
	// pseudonym back to customer is held only by the bank and disclosed to the
	// regulator on lawful request.
	CustomerHMACKey string

	// AuditPrivateOrgs are the MSP IDs allowed to endorse (and therefore see the
	// transient data of) private receipt-detail writes. Must match the policy in
	// blockchain/chaincode/audit-contract/collections_config.json.
	AuditPrivateOrgs []string

	KafkaBrokers []string
	KafkaTopic   string
}

func Load() (Config, error) {
	cfg := Config{
		ServiceName:       getenv("BLOCKCHAIN_SERVICE_NAME", "blockchain-service"),
		Environment:       getenv("BLOCKCHAIN_ENV", "development"),
		LogLevel:          getenv("BLOCKCHAIN_LOG_LEVEL", "info"),
		HTTPPort:          getenvInt("BLOCKCHAIN_HTTP_PORT", 8095),
		ReadTimeout:       getenvDuration("BLOCKCHAIN_HTTP_READ_TIMEOUT", 15*time.Second),
		WriteTimeout:      getenvDuration("BLOCKCHAIN_HTTP_WRITE_TIMEOUT", 15*time.Second),
		ShutdownTimeout:   getenvDuration("BLOCKCHAIN_SHUTDOWN_TIMEOUT", 10*time.Second),
		ConnectionProfile: getenv("BLOCKCHAIN_CONNECTION_PROFILE", "../../blockchain/network/connection-profiles/org1.yaml"),
		OrgName:           getenv("BLOCKCHAIN_ORG_NAME", "Org1"),
		Username:          getenv("BLOCKCHAIN_USERNAME", "Admin"),
		PoolSize:          getenvInt("BLOCKCHAIN_POOL_SIZE", 4),
		KYCChannel:        getenv("BLOCKCHAIN_KYC_CHANNEL", "kyc-channel"),
		AlertChannel:      getenv("BLOCKCHAIN_ALERT_CHANNEL", "alert-channel"),
		AuditChannel:      getenv("BLOCKCHAIN_AUDIT_CHANNEL", "audit-channel"),
		KYCChaincode:      getenv("BLOCKCHAIN_KYC_CHAINCODE", "kyc-contract"),
		AlertChaincode:    getenv("BLOCKCHAIN_ALERT_CHAINCODE", "alert-contract"),
		AuditChaincode:    getenv("BLOCKCHAIN_AUDIT_CHAINCODE", "audit-contract"),
		KafkaTopic:        getenv("BLOCKCHAIN_EVENT_TOPIC", "blockchain.events"),
		CustomerHMACKey:   getenv("BLOCKCHAIN_CUSTOMER_HMAC_KEY", "dev-insecure-customer-pseudonym-key"),
		AuditPrivateOrgs:  splitAndTrim(getenv("BLOCKCHAIN_AUDIT_PRIVATE_ORGS", "Org1MSP,Org2MSP")),
	}

	if raw := strings.TrimSpace(os.Getenv("KAFKA_BROKERS")); raw != "" {
		cfg.KafkaBrokers = splitAndTrim(raw)
	}
	if cfg.ConnectionProfile == "" {
		return Config{}, fmt.Errorf("BLOCKCHAIN_CONNECTION_PROFILE is required")
	}
	if cfg.PoolSize < 1 {
		return Config{}, fmt.Errorf("BLOCKCHAIN_POOL_SIZE must be >= 1")
	}

	// Derive fabric-gateway settings. Defaults assume the cryptogen layout under
	// blockchain/network/crypto-config, located relative to the connection profile.
	orgDomain := getenv("BLOCKCHAIN_ORG_DOMAIN", "org1.fraud-detection.example.com")
	peerHost := getenv("BLOCKCHAIN_PEER_HOST", "peer0."+orgDomain)
	peerPort := getenv("BLOCKCHAIN_PEER_PORT", "7051")
	cryptoBase := getenv("BLOCKCHAIN_CRYPTO_CONFIG", filepath.Join(filepath.Dir(cfg.ConnectionProfile), "..", "crypto-config"))
	adminUser := "Admin@" + orgDomain
	userMSP := filepath.Join(cryptoBase, "peerOrganizations", orgDomain, "users", adminUser, "msp")

	cfg.MSPID = getenv("BLOCKCHAIN_MSP_ID", "Org1MSP")
	cfg.PeerEndpoint = getenv("BLOCKCHAIN_PEER_ENDPOINT", peerHost+":"+peerPort)
	cfg.GatewayHostnameOverride = getenv("BLOCKCHAIN_GATEWAY_HOSTNAME_OVERRIDE", peerHost)
	cfg.TLSCertPath = getenv("BLOCKCHAIN_TLS_CERT_PATH",
		filepath.Join(cryptoBase, "peerOrganizations", orgDomain, "peers", peerHost, "tls", "ca.crt"))
	cfg.SignCertPath = getenv("BLOCKCHAIN_MSP_SIGNCERT",
		filepath.Join(userMSP, "signcerts", adminUser+"-cert.pem"))
	cfg.KeystoreDir = getenv("BLOCKCHAIN_MSP_KEYSTORE", filepath.Join(userMSP, "keystore"))

	return cfg, nil
}

func getenv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	if raw := strings.TrimSpace(os.Getenv(key)); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil {
			return value
		}
	}
	return fallback
}

func getenvDuration(key string, fallback time.Duration) time.Duration {
	if raw := strings.TrimSpace(os.Getenv(key)); raw != "" {
		if value, err := time.ParseDuration(raw); err == nil {
			return value
		}
	}
	return fallback
}

func splitAndTrim(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
