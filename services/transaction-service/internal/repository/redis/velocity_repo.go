// Package redis implements the velocity tracking repository using Redis sorted sets.
//
// Data model:
//   vel:{customerID}:records  — sorted set; score=unix_ms, member=JSON(VelocityRecord)
//     Stores all transactions for the last 30 days. Expired entries removed on write.
//
//   last_tx:{customerID}      — hash; fields: tx_hash, amount, country, lat, lon, ts
//     Most recent transaction metadata — updated on every ProcessTransaction call.
//
//   customer:profile:{customerID} — hash; fields: risk_score, kyc_risk_level, kyc_date
//     Written by the KYC service event consumer (or defaulted here if absent).
//
//   countries:{customerID}:2h  — sorted set; score=unix_ms, member=country_code
//     Country codes seen in the last 2 hours; used for CountryChange2H feature.
//
//   risk:{customerID}           — JSON string with 5-minute TTL
//     Cached CachedRiskScore — avoids recomputing on every request.
package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/fraud-detection/transaction-service/internal/domain"
	"github.com/fraud-detection/transaction-service/internal/features"
	goredis "github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
)

const (
	window30D = 30 * 24 * time.Hour
	window7D  = 7 * 24 * time.Hour
	window24H = 24 * time.Hour
	window1H  = time.Hour
	window2H  = 2 * time.Hour

	riskScoreTTL = 5 * time.Minute
	lastTxTTL    = 48 * time.Hour
	profileTTL   = 24 * time.Hour
)

// VelocityRepository implements features.VelocityReader and provides write methods
// for recording new transactions and caching risk scores.
type VelocityRepository struct {
	client goredis.UniversalClient
	log    zerolog.Logger
}

// NewVelocityRepository creates a new VelocityRepository backed by the given Redis client.
func NewVelocityRepository(client goredis.UniversalClient, log zerolog.Logger) *VelocityRepository {
	return &VelocityRepository{
		client: client,
		log:    log.With().Str("component", "velocity_repo").Logger(),
	}
}

// Compile-time interface assertion.
var _ features.VelocityReader = (*VelocityRepository)(nil)

// ---------------------------------------------------------------------------
// Write operations
// ---------------------------------------------------------------------------

// RecordTransaction adds a transaction to the customer's sorted-set velocity window
// and updates the last-transaction hash and country history.
// Old entries (> 30 days) are removed on every write to keep the set bounded.
func (r *VelocityRepository) RecordTransaction(ctx context.Context, raw *domain.RawTransaction, amountUSD float64) error {
	now := raw.TransactionAt
	scoreMS := float64(now.UnixMilli())
	cutoff30D := float64(now.Add(-window30D).UnixMilli())
	cutoff2H := float64(now.Add(-window2H).UnixMilli())

	rec := domain.VelocityRecord{
		TxHash:           raw.TxHash,
		Amount:           raw.Amount,
		AmountUSDEquiv:   amountUSD,
		CountryCode:      raw.CountryCode,
		MerchantCategory: raw.MerchantCategory,
	}
	recJSON, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal velocity record: %w", err)
	}

	velocityKey := velocityKey(raw.CustomerID)
	countriesKey := countriesKey(raw.CustomerID)

	pipe := r.client.Pipeline()

	// Add transaction record
	pipe.ZAdd(ctx, velocityKey, goredis.Z{Score: scoreMS, Member: string(recJSON)})
	// Expire entries older than 30 days
	pipe.ZRemRangeByScore(ctx, velocityKey, "-inf", fmt.Sprintf("%f", cutoff30D))
	// Refresh TTL on velocity set (add 1 day buffer beyond 30d window)
	pipe.Expire(ctx, velocityKey, window30D+24*time.Hour)

	// Add country to 2h history
	pipe.ZAdd(ctx, countriesKey, goredis.Z{Score: scoreMS, Member: raw.CountryCode})
	pipe.ZRemRangeByScore(ctx, countriesKey, "-inf", fmt.Sprintf("%f", cutoff2H))
	pipe.Expire(ctx, countriesKey, window2H+time.Hour)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("record transaction pipeline: %w", err)
	}

	// Update last transaction hash (separate command — ok to fail non-fatally)
	if err := r.setLastTransaction(ctx, raw, amountUSD); err != nil {
		r.log.Warn().Err(err).Str("tx_hash", raw.TxHash).Msg("failed to update last_tx cache")
	}

	return nil
}

// setLastTransaction stores the last transaction metadata for a customer.
func (r *VelocityRepository) setLastTransaction(ctx context.Context, raw *domain.RawTransaction, amountUSD float64) error {
	lastTx := domain.LastTxRecord{
		TxHash:      raw.TxHash,
		Amount:      amountUSD,
		CountryCode: raw.CountryCode,
		Latitude:    raw.Latitude,
		Longitude:   raw.Longitude,
		Timestamp:   raw.TransactionAt,
	}
	data, err := json.Marshal(lastTx)
	if err != nil {
		return fmt.Errorf("marshal last_tx: %w", err)
	}
	return r.client.Set(ctx, lastTxKey(raw.CustomerID), data, lastTxTTL).Err()
}

// CacheRiskScore stores a customer's computed risk score with a TTL.
func (r *VelocityRepository) CacheRiskScore(ctx context.Context, score *domain.CachedRiskScore) error {
	data, err := json.Marshal(score)
	if err != nil {
		return fmt.Errorf("marshal risk score: %w", err)
	}
	return r.client.Set(ctx, riskKey(score.CustomerID), data, riskScoreTTL).Err()
}

// SetCustomerProfile caches a KYC customer profile so the feature extractor can
// read it without calling the KYC service on the hot path.
func (r *VelocityRepository) SetCustomerProfile(ctx context.Context, profile *domain.CustomerProfile) error {
	pipe := r.client.Pipeline()
	k := profileKey(profile.CustomerID)
	pipe.HSet(ctx, k,
		"risk_score", fmt.Sprintf("%f", profile.RiskScore),
		"kyc_risk_level", profile.KYCRiskLevel,
		"kyc_date", profile.KYCDate.Format(time.RFC3339),
	)
	pipe.Expire(ctx, k, profileTTL)
	_, err := pipe.Exec(ctx)
	return err
}

// ---------------------------------------------------------------------------
// features.VelocityReader implementation
// ---------------------------------------------------------------------------

// GetVelocityAggregates computes aggregated velocity statistics for a customer
// by scanning the Redis sorted set for each time window.
func (r *VelocityRepository) GetVelocityAggregates(ctx context.Context, customerID string) (*features.VelocityAggregates, error) {
	now := time.Now().UnixMilli()
	key := velocityKey(customerID)

	// Fetch all records within the 30-day window (the widest window we need).
	members, err := r.client.ZRangeByScoreWithScores(ctx, key, &goredis.ZRangeBy{
		Min: fmt.Sprintf("%d", time.Now().Add(-window30D).UnixMilli()),
		Max: fmt.Sprintf("%d", now),
	}).Result()
	if err != nil {
		return nil, fmt.Errorf("ZRangeByScore velocity: %w", err)
	}

	agg := &features.VelocityAggregates{}

	var amounts7D, amounts30D []float64
	distinctCountries24H := map[string]struct{}{}
	distinctMerchants24H := map[string]struct{}{}

	cutoff1H := float64(time.Now().Add(-window1H).UnixMilli())
	cutoff24H := float64(time.Now().Add(-window24H).UnixMilli())
	cutoff7D := float64(time.Now().Add(-window7D).UnixMilli())

	for _, m := range members {
		var rec domain.VelocityRecord
		if err := json.Unmarshal([]byte(m.Member.(string)), &rec); err != nil {
			continue // skip malformed entries
		}
		scoreF := m.Score

		// 30-day window (all fetched)
		agg.TxCount30D++
		agg.TotalUSD30D += rec.AmountUSDEquiv
		amounts30D = append(amounts30D, rec.AmountUSDEquiv)

		if scoreF >= cutoff7D {
			agg.TxCount7D++
			agg.TotalUSD7D += rec.AmountUSDEquiv
			amounts7D = append(amounts7D, rec.AmountUSDEquiv)
		}
		if scoreF >= cutoff24H {
			agg.TxCount24H++
			agg.TotalUSD24H += rec.AmountUSDEquiv
			distinctCountries24H[rec.CountryCode] = struct{}{}
			distinctMerchants24H[rec.MerchantCategory] = struct{}{}
		}
		if scoreF >= cutoff1H {
			agg.TxCount1H++
			agg.TotalUSD1H += rec.AmountUSDEquiv
		}
	}

	// Averages and standard deviation
	if len(amounts7D) > 0 {
		agg.AvgAmount7D = agg.TotalUSD7D / float64(len(amounts7D))
	}
	if len(amounts30D) > 0 {
		agg.AvgAmount30D = agg.TotalUSD30D / float64(len(amounts30D))
		// population std dev
		var sumSq float64
		for _, a := range amounts30D {
			diff := a - agg.AvgAmount30D
			sumSq += diff * diff
		}
		agg.StdAmount30D = math.Sqrt(sumSq / float64(len(amounts30D)))
	}

	agg.DistinctCountries24H = len(distinctCountries24H)
	agg.DistinctMerchants24H = len(distinctMerchants24H)

	return agg, nil
}

// GetLastTransaction retrieves the most recent transaction metadata for a customer.
func (r *VelocityRepository) GetLastTransaction(ctx context.Context, customerID string) (*domain.LastTxRecord, error) {
	data, err := r.client.Get(ctx, lastTxKey(customerID)).Bytes()
	if err == goredis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get last_tx %s: %w", customerID, err)
	}
	var rec domain.LastTxRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("unmarshal last_tx: %w", err)
	}
	return &rec, nil
}

// GetCustomerProfile retrieves the cached KYC profile for a customer.
func (r *VelocityRepository) GetCustomerProfile(ctx context.Context, customerID string) (*domain.CustomerProfile, error) {
	vals, err := r.client.HGetAll(ctx, profileKey(customerID)).Result()
	if err != nil {
		return nil, fmt.Errorf("hgetall customer profile %s: %w", customerID, err)
	}
	if len(vals) == 0 {
		return nil, nil // not cached yet — caller uses defaults
	}

	profile := &domain.CustomerProfile{CustomerID: customerID}

	if v, ok := vals["risk_score"]; ok {
		profile.RiskScore, _ = strconv.ParseFloat(v, 64)
	}
	if v, ok := vals["kyc_risk_level"]; ok {
		level, _ := strconv.Atoi(v)
		profile.KYCRiskLevel = level
	}
	if v, ok := vals["kyc_date"]; ok {
		profile.KYCDate, _ = time.Parse(time.RFC3339, v)
	}

	return profile, nil
}

// GetCountryHistory returns the distinct country codes seen for a customer in the last 2 hours.
func (r *VelocityRepository) GetCountryHistory(ctx context.Context, customerID string) ([]string, error) {
	cutoff := float64(time.Now().Add(-window2H).UnixMilli())
	members, err := r.client.ZRangeByScore(ctx, countriesKey(customerID), &goredis.ZRangeBy{
		Min: fmt.Sprintf("%f", cutoff),
		Max: "+inf",
	}).Result()
	if err == goredis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ZRangeByScore countries: %w", err)
	}
	// Deduplicate
	seen := map[string]struct{}{}
	out := make([]string, 0, len(members))
	for _, m := range members {
		if _, dup := seen[m]; !dup {
			seen[m] = struct{}{}
			out = append(out, m)
		}
	}
	return out, nil
}

// GetCachedRiskScore retrieves the cached risk score for a customer (if still valid).
func (r *VelocityRepository) GetCachedRiskScore(ctx context.Context, customerID string) (*domain.CachedRiskScore, error) {
	data, err := r.client.Get(ctx, riskKey(customerID)).Bytes()
	if err == goredis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get risk score %s: %w", customerID, err)
	}
	var score domain.CachedRiskScore
	if err := json.Unmarshal(data, &score); err != nil {
		return nil, fmt.Errorf("unmarshal risk score: %w", err)
	}
	return &score, nil
}

// GetVelocityStats returns velocity stats formatted for the GetVelocityStats gRPC call.
func (r *VelocityRepository) GetVelocityStats(ctx context.Context, customerID string, alert1HLimit, alert24HLimit int) (*domain.VelocityStats, error) {
	agg, err := r.GetVelocityAggregates(ctx, customerID)
	if err != nil {
		return nil, err
	}
	return &domain.VelocityStats{
		CustomerID:           customerID,
		TxCount1H:            agg.TxCount1H,
		TxCount24H:           agg.TxCount24H,
		TxCount7D:            agg.TxCount7D,
		TotalAmount1H:        agg.TotalUSD1H,
		TotalAmount24H:       agg.TotalUSD24H,
		TotalAmount7D:        agg.TotalUSD7D,
		DistinctCountries24H: agg.DistinctCountries24H,
		DistinctMerchants24H: agg.DistinctMerchants24H,
		VelocityAlert1H:      agg.TxCount1H > alert1HLimit,
		VelocityAlert24H:     agg.TxCount24H > alert24HLimit,
	}, nil
}

// Ping checks Redis connectivity.
func (r *VelocityRepository) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

func velocityKey(customerID string) string  { return "vel:" + customerID + ":records" }
func lastTxKey(customerID string) string    { return "last_tx:" + customerID }
func profileKey(customerID string) string   { return "customer:profile:" + customerID }
func countriesKey(customerID string) string { return "countries:" + customerID + ":2h" }
func riskKey(customerID string) string      { return "risk:" + customerID }
