package fabric

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	appconfig "github.com/fraud-detection/blockchain-service/internal/config"
	"github.com/fraud-detection/blockchain-service/internal/kafka"
	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
)

// Gateway is the contract exposed to the service layer. The implementation uses
// the Hyperledger fabric-gateway client (Fabric 2.4+), which connects to a single
// peer's Gateway service; that peer performs cross-org endorsement server-side.
type Gateway interface {
	Invoke(ctx context.Context, channelName, chaincodeName, function string, args [][]byte) (string, []byte, error)
	Query(ctx context.Context, channelName, chaincodeName, function string, args [][]byte) ([]byte, error)
	StartEventListeners(ctx context.Context) error
	Health(ctx context.Context) map[string]string
	Close()
}

type gateway struct {
	cfg       appconfig.Config
	log       zerolog.Logger
	conn      *grpc.ClientConn
	gw        *client.Gateway
	publisher kafka.Publisher

	channelChaincodes map[string]string
}

type eventEnvelope struct {
	ChannelName string `json:"channel_name"`
	Chaincode   string `json:"chaincode"`
	EventName   string `json:"event_name"`
	TxID        string `json:"tx_id"`
	BlockNumber uint64 `json:"block_number"`
	Payload     string `json:"payload"`
	Timestamp   string `json:"timestamp"`
}

// New connects to the Fabric Gateway peer and returns a ready Gateway.
func New(cfg appconfig.Config, publisher kafka.Publisher, log zerolog.Logger) (Gateway, error) {
	conn, err := newGRPCConnection(cfg)
	if err != nil {
		return nil, fmt.Errorf("create grpc connection: %w", err)
	}

	id, err := newIdentity(cfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("create identity: %w", err)
	}

	sign, err := newSign(cfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("create signer: %w", err)
	}

	gw, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithClientConnection(conn),
		client.WithEvaluateTimeout(15*time.Second),
		client.WithEndorseTimeout(30*time.Second),
		client.WithSubmitTimeout(30*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("connect gateway: %w", err)
	}

	return &gateway{
		cfg:       cfg,
		log:       log.With().Str("component", "fabric_gateway").Logger(),
		conn:      conn,
		gw:        gw,
		publisher: publisher,
		channelChaincodes: map[string]string{
			cfg.KYCChannel:   cfg.KYCChaincode,
			cfg.AlertChannel: cfg.AlertChaincode,
			cfg.AuditChannel: cfg.AuditChaincode,
		},
	}, nil
}

// newGRPCConnection dials the Gateway peer over TLS, validating the peer
// certificate against the configured hostname override.
func newGRPCConnection(cfg appconfig.Config) (*grpc.ClientConn, error) {
	pem, err := os.ReadFile(cfg.TLSCertPath)
	if err != nil {
		return nil, fmt.Errorf("read tls cert %s: %w", cfg.TLSCertPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("failed to add tls cert from %s", cfg.TLSCertPath)
	}
	creds := credentials.NewClientTLSFromCert(pool, cfg.GatewayHostnameOverride)
	conn, err := grpc.NewClient(cfg.PeerEndpoint, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", cfg.PeerEndpoint, err)
	}
	return conn, nil
}

func newIdentity(cfg appconfig.Config) (*identity.X509Identity, error) {
	certPEM, err := os.ReadFile(cfg.SignCertPath)
	if err != nil {
		return nil, fmt.Errorf("read signcert %s: %w", cfg.SignCertPath, err)
	}
	cert, err := identity.CertificateFromPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("parse signcert: %w", err)
	}
	return identity.NewX509Identity(cfg.MSPID, cert)
}

func newSign(cfg appconfig.Config) (identity.Sign, error) {
	entries, err := os.ReadDir(cfg.KeystoreDir)
	if err != nil {
		return nil, fmt.Errorf("read keystore %s: %w", cfg.KeystoreDir, err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no private key found in keystore %s", cfg.KeystoreDir)
	}
	keyPEM, err := os.ReadFile(filepath.Join(cfg.KeystoreDir, entries[0].Name()))
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	key, err := identity.PrivateKeyFromPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return identity.NewPrivateKeySign(key)
}

func (g *gateway) Invoke(ctx context.Context, channelName, chaincodeName, function string, args [][]byte) (string, []byte, error) {
	contract := g.gw.GetNetwork(channelName).GetContract(chaincodeName)

	proposal, err := contract.NewProposal(function, client.WithBytesArguments(args...))
	if err != nil {
		return "", nil, fmt.Errorf("create proposal %s on %s/%s: %w", function, channelName, chaincodeName, err)
	}

	txn, err := proposal.EndorseWithContext(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("endorse %s on %s/%s: %w", function, channelName, chaincodeName, err)
	}

	commit, err := txn.SubmitWithContext(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("submit %s on %s/%s: %w", function, channelName, chaincodeName, err)
	}

	status, err := commit.StatusWithContext(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("commit status %s on %s/%s: %w", function, channelName, chaincodeName, err)
	}
	if !status.Successful {
		return "", nil, fmt.Errorf("transaction %s committed with code %d", status.TransactionID, status.Code)
	}

	return proposal.TransactionID(), txn.Result(), nil
}

func (g *gateway) Query(ctx context.Context, channelName, chaincodeName, function string, args [][]byte) ([]byte, error) {
	contract := g.gw.GetNetwork(channelName).GetContract(chaincodeName)
	result, err := contract.EvaluateWithContext(ctx, function, client.WithBytesArguments(args...))
	if err != nil {
		return nil, fmt.Errorf("query %s on %s/%s: %w", function, channelName, chaincodeName, err)
	}
	return result, nil
}

// StartEventListeners subscribes to chaincode events on every channel and
// forwards them to Kafka. Each listener runs until ctx is cancelled.
func (g *gateway) StartEventListeners(ctx context.Context) error {
	for channelName, chaincodeName := range g.channelChaincodes {
		network := g.gw.GetNetwork(channelName)
		events, err := network.ChaincodeEvents(ctx, chaincodeName)
		if err != nil {
			return fmt.Errorf("register chaincode events for %s/%s: %w", channelName, chaincodeName, err)
		}
		go g.consumeEvents(ctx, channelName, chaincodeName, events)
	}
	return nil
}

func (g *gateway) consumeEvents(ctx context.Context, channelName, chaincodeName string, events <-chan *client.ChaincodeEvent) {
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-events:
			if !ok {
				return
			}

			envelope := eventEnvelope{
				ChannelName: channelName,
				Chaincode:   chaincodeName,
				EventName:   evt.EventName,
				TxID:        evt.TransactionID,
				BlockNumber: evt.BlockNumber,
				Payload:     string(evt.Payload),
				Timestamp:   time.Now().UTC().Format(time.RFC3339),
			}
			payload, _ := json.Marshal(envelope)

			if err := g.publisher.Publish(ctx, evt.TransactionID, payload); err != nil {
				g.log.Error().Err(err).Str("channel", channelName).Str("chaincode", chaincodeName).Msg("publish chaincode event")
				continue
			}

			g.log.Info().
				Str("channel", channelName).
				Str("chaincode", chaincodeName).
				Str("event_name", evt.EventName).
				Str("tx_id", evt.TransactionID).
				Uint64("block_number", evt.BlockNumber).
				Msg("forwarded chaincode event to kafka")
		}
	}
}

// Health queries the ledger height of each channel via the qscc system chaincode.
func (g *gateway) Health(ctx context.Context) map[string]string {
	results := make(map[string]string, len(g.channelChaincodes))

	for channelName := range g.channelChaincodes {
		qscc := g.gw.GetNetwork(channelName).GetContract("qscc")
		raw, err := qscc.EvaluateWithContext(ctx, "GetChainInfo", client.WithArguments(channelName))
		if err != nil {
			results[channelName] = "error: " + err.Error()
			continue
		}

		info := &common.BlockchainInfo{}
		if err := proto.Unmarshal(raw, info); err != nil {
			results[channelName] = "error: decode chain info: " + err.Error()
			continue
		}
		results[channelName] = fmt.Sprintf("connected:block_height=%d", info.GetHeight())
	}

	return results
}

func (g *gateway) Close() {
	if g.gw != nil {
		_ = g.gw.Close()
	}
	if g.conn != nil {
		_ = g.conn.Close()
	}
}
