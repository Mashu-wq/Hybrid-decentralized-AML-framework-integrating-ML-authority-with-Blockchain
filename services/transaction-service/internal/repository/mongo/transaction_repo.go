// Package mongo implements the transaction storage repository using MongoDB.
// Enriched transactions are stored in a time-series collection keyed on
// processed_at (timeField) and customer_id (metaField).
//
// Collection setup (run once at startup via EnsureCollection):
//
//	db.createCollection("enriched_transactions", {
//	  timeseries: {
//	    timeField:   "processed_at",
//	    metaField:   "customer_id",
//	    granularity: "seconds",
//	  },
//	  expireAfterSeconds: 7776000,  // 90-day TTL
//	})
package mongo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/fraud-detection/transaction-service/internal/domain"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"github.com/rs/zerolog"
)

const (
	// collectionTTLSeconds = 90 days — auto-expire old transactions
	collectionTTLSeconds = 60 * 60 * 24 * 90
)

// TransactionRepository provides persistence for EnrichedTransaction records.
type TransactionRepository struct {
	coll *mongo.Collection
	log  zerolog.Logger
}

// NewTransactionRepository creates a repository and ensures the time-series
// collection and supporting indexes exist.
func NewTransactionRepository(ctx context.Context, db *mongo.Database, collectionName string, log zerolog.Logger) (*TransactionRepository, error) {
	repo := &TransactionRepository{
		coll: db.Collection(collectionName),
		log:  log.With().Str("component", "mongo_tx_repo").Str("collection", collectionName).Logger(),
	}

	if err := repo.ensureCollection(ctx, db, collectionName); err != nil {
		// Non-fatal — collection may already exist with correct schema.
		repo.log.Warn().Err(err).Msg("collection setup warning (may already exist)")
	}

	if err := repo.ensureIndexes(ctx); err != nil {
		return nil, fmt.Errorf("ensure indexes: %w", err)
	}

	return repo, nil
}

// ensureCollection creates the time-series collection if it does not exist.
func (r *TransactionRepository) ensureCollection(ctx context.Context, db *mongo.Database, name string) error {
	// Check if already exists
	names, err := db.ListCollectionNames(ctx, bson.M{"name": name})
	if err != nil {
		return fmt.Errorf("list collections: %w", err)
	}
	if len(names) > 0 {
		return nil // already exists
	}

	tsOpts := &options.TimeSeriesOptions{}
	tsOpts.SetTimeField("processed_at")
	tsOpts.SetMetaField("customer_id")
	tsOpts.SetGranularity("seconds")

	createOpts := options.CreateCollection().
		SetTimeSeriesOptions(tsOpts).
		SetExpireAfterSeconds(collectionTTLSeconds)

	if err := db.CreateCollection(ctx, name, createOpts); err != nil {
		return fmt.Errorf("create time-series collection %s: %w", name, err)
	}

	r.log.Info().Str("collection", name).Msg("time-series collection created")
	return nil
}

// ensureIndexes creates secondary indexes for efficient query patterns.
func (r *TransactionRepository) ensureIndexes(ctx context.Context) error {
	indexes := []mongo.IndexModel{
		// Primary query pattern: lookup by tx_hash (also serves as _id in regular collections).
		{
			Keys:    bson.D{{Key: "raw.tx_hash", Value: 1}},
			Options: options.Index().SetUnique(false).SetName("idx_tx_hash"),
		},
		// Customer transaction history queries.
		{
			Keys:    bson.D{{Key: "customer_id", Value: 1}, {Key: "processed_at", Value: -1}},
			Options: options.Index().SetName("idx_customer_time"),
		},
		// Fraud probability filter for analytics dashboards.
		{
			Keys:    bson.D{{Key: "fraud_probability", Value: -1}},
			Options: options.Index().SetName("idx_fraud_prob"),
		},
	}

	_, err := r.coll.Indexes().CreateMany(ctx, indexes)
	if err != nil {
		return fmt.Errorf("create indexes: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Write operations
// ---------------------------------------------------------------------------

// Save persists an EnrichedTransaction.
// For time-series collections, MongoDB does not support upsert by _id —
// we use InsertOne and tolerate duplicate-key errors as idempotent.
func (r *TransactionRepository) Save(ctx context.Context, tx *domain.EnrichedTransaction) error {
	_, err := r.coll.InsertOne(ctx, tx)
	if err != nil {
		// Duplicate key = already processed. Treat as success (idempotent).
		var writeErr mongo.WriteException
		if errors.As(err, &writeErr) {
			for _, we := range writeErr.WriteErrors {
				if we.Code == 11000 {
					r.log.Debug().
						Str("tx_hash", tx.TxHash).
						Msg("duplicate transaction — skipping (idempotent)")
					return nil
				}
			}
		}
		return fmt.Errorf("insert enriched transaction %s: %w", tx.TxHash, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Read operations
// ---------------------------------------------------------------------------

// GetByTxHash retrieves a single enriched transaction by its tx_hash.
func (r *TransactionRepository) GetByTxHash(ctx context.Context, txHash string) (*domain.EnrichedTransaction, error) {
	filter := bson.M{"raw.tx_hash": txHash}
	result := r.coll.FindOne(ctx, filter)
	if result.Err() == mongo.ErrNoDocuments {
		return nil, domain.ErrTransactionNotFound
	}
	if result.Err() != nil {
		return nil, fmt.Errorf("find by tx_hash %s: %w", txHash, result.Err())
	}

	var tx domain.EnrichedTransaction
	if err := result.Decode(&tx); err != nil {
		return nil, fmt.Errorf("decode enriched transaction: %w", err)
	}
	return &tx, nil
}

// GetCustomerHistory retrieves a paginated list of enriched transactions for a customer.
func (r *TransactionRepository) GetCustomerHistory(
	ctx context.Context,
	customerID string,
	startTime, endTime time.Time,
	minFraudProb float64,
	pageSize int,
	pageToken string,
) ([]*domain.EnrichedTransaction, string, error) {
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}

	filter := bson.M{"customer_id": customerID}

	// Time range filter
	timeFilter := bson.M{}
	if !startTime.IsZero() {
		timeFilter["$gte"] = startTime
	}
	if !endTime.IsZero() {
		timeFilter["$lte"] = endTime
	}
	if len(timeFilter) > 0 {
		filter["processed_at"] = timeFilter
	}

	// Minimum fraud probability filter
	if minFraudProb > 0 {
		filter["fraud_probability"] = bson.M{"$gte": minFraudProb}
	}

	// Cursor-based pagination: pageToken is the last processed_at as RFC3339
	if pageToken != "" {
		cursor, err := time.Parse(time.RFC3339Nano, pageToken)
		if err == nil {
			if filter["processed_at"] == nil {
				filter["processed_at"] = bson.M{"$lt": cursor}
			} else {
				existing := filter["processed_at"].(bson.M)
				existing["$lt"] = cursor
			}
		}
	}

	opts := options.Find().
		SetSort(bson.D{{Key: "processed_at", Value: -1}}).
		SetLimit(int64(pageSize + 1)) // fetch +1 to detect next page

	cursor, err := r.coll.Find(ctx, filter, opts)
	if err != nil {
		return nil, "", fmt.Errorf("find customer history %s: %w", customerID, err)
	}
	defer cursor.Close(ctx)

	var results []*domain.EnrichedTransaction
	if err := cursor.All(ctx, &results); err != nil {
		return nil, "", fmt.Errorf("decode customer history: %w", err)
	}

	// Build next page token from last item's processed_at
	var nextToken string
	if len(results) > pageSize {
		results = results[:pageSize]
		if len(results) > 0 {
			nextToken = results[len(results)-1].ProcessedAt.UTC().Format(time.RFC3339Nano)
		}
	}

	return results, nextToken, nil
}

// ComputeFraudRate30D returns the fraction of fraud-flagged transactions for a customer
// in the last 30 days. Returns 0 if no transactions found.
func (r *TransactionRepository) ComputeFraudRate30D(ctx context.Context, customerID string) (float64, int, error) {
	cutoff := time.Now().UTC().Add(-30 * 24 * time.Hour)

	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.M{
			"customer_id": customerID,
			"processed_at": bson.M{"$gte": cutoff},
		}}},
		{{Key: "$group", Value: bson.M{
			"_id":        nil,
			"total":      bson.M{"$sum": 1},
			"fraudCount": bson.M{"$sum": bson.M{"$cond": bson.A{bson.M{"$gt": bson.A{"$fraud_probability", 0.7}}, 1, 0}}},
			"alertCount": bson.M{"$sum": bson.M{"$cond": bson.A{"$alert_created", 1, 0}}},
		}}},
	}

	cursor, err := r.coll.Aggregate(ctx, pipeline)
	if err != nil {
		return 0, 0, fmt.Errorf("aggregate fraud rate: %w", err)
	}
	defer cursor.Close(ctx)

	var res struct {
		Total      int `bson:"total"`
		FraudCount int `bson:"fraudCount"`
		AlertCount int `bson:"alertCount"`
	}
	if cursor.Next(ctx) {
		if err := cursor.Decode(&res); err != nil {
			return 0, 0, fmt.Errorf("decode fraud rate aggregate: %w", err)
		}
	}

	if res.Total == 0 {
		return 0, 0, nil
	}
	return float64(res.FraudCount) / float64(res.Total), res.AlertCount, nil
}

// Ping verifies MongoDB connectivity.
func (r *TransactionRepository) Ping(ctx context.Context) error {
	return r.coll.Database().Client().Ping(ctx, nil)
}
