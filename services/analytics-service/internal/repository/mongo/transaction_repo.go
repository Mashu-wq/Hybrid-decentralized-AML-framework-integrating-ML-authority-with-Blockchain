// Package mongo implements analytics queries against the enriched_transactions
// MongoDB time-series collection.
package mongo

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/fraud-detection/analytics-service/internal/domain"
)

// TransactionRepository queries the enriched_transactions collection.
type TransactionRepository struct {
	col *mongo.Collection
}

// New returns a TransactionRepository for the given collection.
func New(col *mongo.Collection) *TransactionRepository {
	return &TransactionRepository{col: col}
}

// Connect opens a MongoDB connection and returns the target collection.
func Connect(ctx context.Context, uri, dbName, collection string) (*mongo.Collection, *mongo.Client, error) {
	opts := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(ctx, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("connect mongo: %w", err)
	}
	if err := client.Ping(ctx, nil); err != nil {
		return nil, nil, fmt.Errorf("ping mongo: %w", err)
	}
	col := client.Database(dbName).Collection(collection)
	return col, client, nil
}

// ---------------------------------------------------------------------------
// GetTransactionVolume — time-series transaction counts and amounts
// ---------------------------------------------------------------------------

// volumeDoc maps to one bucket returned by the MongoDB aggregation.
type volumeDoc struct {
	ID          string  `bson:"_id"`
	TxCount     int     `bson:"tx_count"`
	TotalAmount float64 `bson:"total_amount"`
	FraudCount  int     `bson:"fraud_count"`
}

// GetTransactionVolume returns per-bucket transaction volume from MongoDB.
func (r *TransactionRepository) GetTransactionVolume(ctx context.Context, from, to time.Time, gran domain.Granularity) ([]*domain.VolumePoint, error) {
	dateFmt, err := gran.MongoDateFmt()
	if err != nil {
		return nil, err
	}

	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.M{
			"processed_at": bson.M{"$gte": from, "$lte": to},
		}}},
		{{Key: "$group", Value: bson.M{
			"_id": bson.M{
				"$dateToString": bson.M{
					"format": dateFmt,
					"date":   "$processed_at",
				},
			},
			"tx_count":     bson.M{"$sum": 1},
			"total_amount": bson.M{"$sum": "$raw.amount"},
			"fraud_count": bson.M{"$sum": bson.M{
				"$cond": []interface{}{"$alert_created", 1, 0},
			}},
		}}},
		{{Key: "$sort", Value: bson.M{"_id": 1}}},
	}

	cursor, err := r.col.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, fmt.Errorf("transaction volume aggregate: %w", err)
	}
	defer cursor.Close(ctx)

	var points []*domain.VolumePoint
	for cursor.Next(ctx) {
		var doc volumeDoc
		if err := cursor.Decode(&doc); err != nil {
			return nil, fmt.Errorf("decode volume doc: %w", err)
		}
		p := &domain.VolumePoint{
			TxCount:     doc.TxCount,
			TotalAmount: doc.TotalAmount,
			FraudCount:  doc.FraudCount,
		}
		if doc.TxCount > 0 {
			p.AvgAmount = doc.TotalAmount / float64(doc.TxCount)
		}
		// Parse the string date back to time.Time for the bucket label
		p.Date = parseBucketDate(doc.ID, gran)
		points = append(points, p)
	}
	return points, cursor.Err()
}

// ---------------------------------------------------------------------------
// GetGeographicDistribution — fraud counts by country
// ---------------------------------------------------------------------------

// geoDoc maps to one country bucket.
type geoDoc struct {
	CountryCode string  `bson:"_id"`
	TxCount     int     `bson:"tx_count"`
	TotalAmount float64 `bson:"total_amount"`
	FraudCount  int     `bson:"fraud_count"`
}

// GetGeographicDistribution returns fraud distribution by country for the period.
func (r *TransactionRepository) GetGeographicDistribution(ctx context.Context, from, to time.Time) ([]*domain.GeoFraudPoint, error) {
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.M{
			"processed_at": bson.M{"$gte": from, "$lte": to},
		}}},
		{{Key: "$group", Value: bson.M{
			"_id":          "$raw.country_code",
			"tx_count":     bson.M{"$sum": 1},
			"total_amount": bson.M{"$sum": "$raw.amount"},
			"fraud_count": bson.M{"$sum": bson.M{
				"$cond": []interface{}{"$alert_created", 1, 0},
			}},
		}}},
		{{Key: "$match", Value: bson.M{"_id": bson.M{"$ne": ""}}}},
		{{Key: "$sort", Value: bson.M{"fraud_count": -1}}},
	}

	cursor, err := r.col.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, fmt.Errorf("geographic distribution aggregate: %w", err)
	}
	defer cursor.Close(ctx)

	var points []*domain.GeoFraudPoint
	for cursor.Next(ctx) {
		var doc geoDoc
		if err := cursor.Decode(&doc); err != nil {
			return nil, fmt.Errorf("decode geo doc: %w", err)
		}
		p := &domain.GeoFraudPoint{
			CountryCode: doc.CountryCode,
			TxCount:     doc.TxCount,
			TotalAmount: doc.TotalAmount,
			AlertCount:  doc.FraudCount,
		}
		if doc.TxCount > 0 {
			p.FraudRate = float64(doc.FraudCount) / float64(doc.TxCount)
		}
		points = append(points, p)
	}
	return points, cursor.Err()
}

// GetCustomerAmounts returns the total transaction amount per customer for
// a list of customer IDs — used by the service layer to enrich RiskyCustomer.
func (r *TransactionRepository) GetCustomerAmounts(ctx context.Context, customerIDs []string, from, to time.Time) (map[string]float64, error) {
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.M{
			"processed_at":     bson.M{"$gte": from, "$lte": to},
			"raw.customer_id":  bson.M{"$in": customerIDs},
		}}},
		{{Key: "$group", Value: bson.M{
			"_id":          "$raw.customer_id",
			"total_amount": bson.M{"$sum": "$raw.amount"},
		}}},
	}

	cursor, err := r.col.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, fmt.Errorf("customer amounts aggregate: %w", err)
	}
	defer cursor.Close(ctx)

	result := make(map[string]float64)
	for cursor.Next(ctx) {
		var doc struct {
			ID          string  `bson:"_id"`
			TotalAmount float64 `bson:"total_amount"`
		}
		if err := cursor.Decode(&doc); err != nil {
			return nil, fmt.Errorf("decode customer amount doc: %w", err)
		}
		result[doc.ID] = doc.TotalAmount
	}
	return result, cursor.Err()
}

// Ping checks the MongoDB connection.
func (r *TransactionRepository) Ping(ctx context.Context) error {
	return r.col.Database().Client().Ping(ctx, nil)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// parseBucketDate converts a MongoDB $dateToString bucket label back to time.Time.
func parseBucketDate(s string, gran domain.Granularity) time.Time {
	formats := map[domain.Granularity]string{
		domain.GranularityHour:  "2006-01-02T15:04:05",
		domain.GranularityDay:   "2006-01-02",
		domain.GranularityMonth: "2006-01",
	}
	layout, ok := formats[gran]
	if !ok {
		layout = "2006-01-02"
	}
	t, _ := time.Parse(layout, s)
	return t
}
