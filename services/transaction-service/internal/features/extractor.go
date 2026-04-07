// Package features implements the real-time feature extraction pipeline for the
// Transaction Monitoring Service. It transforms a RawTransaction into the complete
// TransactionFeatures vector consumed by the ML service.
//
// Feature categories:
//   - Temporal: hour, day-of-week, time-since-last-tx, rolling frequencies
//   - Behavioral: velocity (USD/hr, USD/24h), amount deviation from 30-day avg
//   - Geographic: country risk score, cross-border flag, country-change-in-2h
//   - Merchant: category risk score, high-risk flag
//   - KYC: customer risk level from Redis profile cache
//   - Graph: zeros (populated asynchronously by GNN — Phase 7)
package features

import (
	"context"
	"math"
	"strings"
	"time"

	"github.com/fraud-detection/transaction-service/internal/domain"
	"github.com/rs/zerolog"
)

// ---------------------------------------------------------------------------
// Country & merchant risk tables
// ---------------------------------------------------------------------------

// countryRiskScores maps ISO 3166-1 alpha-2 codes to a risk score (0–100).
// Higher = more associated with financial crime / FATF high-risk jurisdictions.
var countryRiskScores = map[string]float64{
	// FATF blacklist / heavily sanctioned
	"KP": 100, "IR": 95, "SY": 90, "MM": 85, "CU": 80,
	// FATF grey-list / enhanced monitoring
	"RU": 72, "BY": 68, "VE": 65, "PK": 60, "AF": 80,
	"YE": 75, "IQ": 70, "LY": 72, "ML": 60, "BF": 65,
	"NI": 55, "PA": 50, "TR": 45, "JM": 48, "HT": 62,
	// Tax havens / secrecy jurisdictions
	"KY": 50, "VG": 50, "BZ": 45, "AG": 42, "SC": 42,
	// Low-risk standard jurisdictions
	"US": 10, "GB": 10, "DE": 10, "FR": 12, "CA": 10,
	"AU": 10, "JP": 10, "SG": 12, "CH": 15, "NL": 12,
	"IN": 25, "BR": 30, "MX": 35, "ZA": 30, "NG": 55,
	"GH": 40, "EG": 35, "SA": 30, "AE": 25, "CN": 30,
}

const defaultCountryRisk = 20.0

// highRiskMerchantCategories contains MCC descriptions associated with elevated
// financial-crime risk (money services, gambling, crypto exchanges, etc.).
var highRiskMerchantCategories = map[string]bool{
	"gambling":            true,
	"casino":              true,
	"cryptocurrency":      true,
	"crypto exchange":     true,
	"money services":      true,
	"money transfer":      true,
	"wire transfer":       true,
	"forex":               true,
	"pawn shop":           true,
	"check cashing":       true,
	"prepaid cards":       true,
	"adult entertainment": true,
	"firearms":            true,
	"arms dealer":         true,
}

var merchantRiskScores = map[string]float64{
	"gambling":            90, "casino": 88,
	"cryptocurrency":      75, "crypto exchange": 78,
	"money services":      70, "money transfer": 68,
	"wire transfer":       65, "forex": 60,
	"pawn shop":           55, "check cashing": 52,
	"prepaid cards":       50, "adult entertainment": 60,
	"firearms":            55, "arms dealer": 80,
}

const defaultMerchantRisk = 15.0

// ---------------------------------------------------------------------------
// Currency USD conversion rates (static approximation — replace with live feed).
// ---------------------------------------------------------------------------

var usdConversionRates = map[string]float64{
	"USD": 1.00, "EUR": 1.08, "GBP": 1.25, "JPY": 0.0067,
	"CAD": 0.74, "AUD": 0.66, "CHF": 1.10, "CNY": 0.14,
	"INR": 0.012, "BRL": 0.20, "MXN": 0.058, "SGD": 0.74,
	"HKD": 0.13, "NOK": 0.094, "SEK": 0.095, "DKK": 0.14,
	"NZD": 0.61, "ZAR": 0.055, "TRY": 0.031, "AED": 0.27,
	"BTC": 65000, "ETH": 3500, "USDT": 1.0, "USDC": 1.0,
}

func toUSD(amount float64, currency string) float64 {
	rate, ok := usdConversionRates[strings.ToUpper(currency)]
	if !ok {
		return amount
	}
	return amount * rate
}

// ---------------------------------------------------------------------------
// Velocity repository interface (injected — breaks import cycle with redis pkg)
// ---------------------------------------------------------------------------

// VelocityReader reads pre-computed velocity aggregates from Redis.
type VelocityReader interface {
	// GetVelocityAggregates returns counts and USD totals for 1h/24h/7d/30d windows.
	GetVelocityAggregates(ctx context.Context, customerID string) (*VelocityAggregates, error)
	// GetLastTransaction returns the most recent processed transaction for a customer.
	GetLastTransaction(ctx context.Context, customerID string) (*domain.LastTxRecord, error)
	// GetCustomerProfile returns the cached KYC profile for a customer.
	GetCustomerProfile(ctx context.Context, customerID string) (*domain.CustomerProfile, error)
	// GetCountryHistory returns distinct country codes seen for a customer in last 2 hours.
	GetCountryHistory(ctx context.Context, customerID string) ([]string, error)
}

// VelocityAggregates holds pre-computed per-customer velocity statistics.
type VelocityAggregates struct {
	TxCount1H  int
	TxCount24H int
	TxCount7D  int
	TxCount30D int

	TotalUSD1H  float64
	TotalUSD24H float64
	TotalUSD7D  float64
	TotalUSD30D float64

	AvgAmount7D  float64
	AvgAmount30D float64
	StdAmount30D float64

	DistinctCountries24H int
	DistinctMerchants24H int
}

// ---------------------------------------------------------------------------
// Extractor
// ---------------------------------------------------------------------------

// Extractor transforms a RawTransaction into a complete TransactionFeatures vector.
type Extractor struct {
	velocity              VelocityReader
	log                   zerolog.Logger
	pipelineVersion       string
	velocityAlert1HLimit  int
	velocityAlert24HLimit int
}

// NewExtractor creates a new Extractor with the given dependencies.
func NewExtractor(
	velocity VelocityReader,
	log zerolog.Logger,
	pipelineVersion string,
	alert1HLimit, alert24HLimit int,
) *Extractor {
	return &Extractor{
		velocity:              velocity,
		log:                   log.With().Str("component", "feature_extractor").Logger(),
		pipelineVersion:       pipelineVersion,
		velocityAlert1HLimit:  alert1HLimit,
		velocityAlert24HLimit: alert24HLimit,
	}
}

// PipelineVersion returns the active pipeline version string.
func (e *Extractor) PipelineVersion() string { return e.pipelineVersion }

// Extract computes the full feature vector for a RawTransaction.
// Individual Redis lookup failures are logged and replaced with safe defaults
// so that ML prediction always has a feature vector to score.
func (e *Extractor) Extract(ctx context.Context, raw *domain.RawTransaction) (*domain.TransactionFeatures, error) {
	log := e.log.With().
		Str("tx_hash", raw.TxHash).
		Str("customer_id", raw.CustomerID).
		Logger()

	amountUSD := toUSD(raw.Amount, raw.CurrencyCode)

	f := &domain.TransactionFeatures{
		TxHash:               raw.TxHash,
		CustomerID:           raw.CustomerID,
		Amount:               raw.Amount,
		CurrencyCode:         raw.CurrencyCode,
		AmountUSDEquiv:       amountUSD,
		CountryCode:          raw.CountryCode,
		MerchantCategory:     raw.MerchantCategory,
		HopsToKnownFraudster: -1, // default: not reachable within 5 hops
	}

	// --- Temporal features ---
	txTime := raw.TransactionAt.UTC()
	f.TxHour = txTime.Hour()
	f.DayOfWeek = int(txTime.Weekday()) // 0=Sunday, 1=Monday … 6=Saturday
	f.IsWeekend = txTime.Weekday() == time.Saturday || txTime.Weekday() == time.Sunday

	// --- Velocity & behavioral features (from Redis) ---
	agg, err := e.velocity.GetVelocityAggregates(ctx, raw.CustomerID)
	if err != nil {
		log.Warn().Err(err).Msg("velocity aggregates unavailable; using zeros")
		agg = &VelocityAggregates{}
	}

	f.TxFrequency1H   = float64(agg.TxCount1H)
	f.TxFrequency24H  = float64(agg.TxCount24H)
	f.Velocity1H      = agg.TotalUSD1H
	f.Velocity24H     = agg.TotalUSD24H
	f.AvgAmount7D     = agg.AvgAmount7D
	f.AvgAmount30D    = agg.AvgAmount30D
	f.StdAmount30D    = agg.StdAmount30D
	f.TotalTxCount30D = agg.TxCount30D

	// Amount deviation: (current - avg_30d) / max(std_30d, 1)
	divisor := agg.StdAmount30D
	if divisor < 1.0 {
		if agg.AvgAmount30D > 0 {
			divisor = agg.AvgAmount30D
		} else {
			divisor = 1.0
		}
	}
	f.AmountDeviationScore = (amountUSD - agg.AvgAmount30D) / divisor

	// --- Last transaction (temporal gap + geographic continuity) ---
	lastTx, err := e.velocity.GetLastTransaction(ctx, raw.CustomerID)
	if err != nil {
		log.Debug().Err(err).Msg("no last transaction found; setting temporal defaults")
	}
	if lastTx != nil {
		gap := txTime.Sub(lastTx.Timestamp).Seconds()
		if gap > 0 {
			f.TimeSinceLastTxS = gap
		}
		f.DistanceKmFromLast = haversineKm(lastTx.Latitude, lastTx.Longitude, raw.Latitude, raw.Longitude)
	}

	// --- Country-change-in-2h ---
	recentCountries, err := e.velocity.GetCountryHistory(ctx, raw.CustomerID)
	if err != nil {
		log.Debug().Err(err).Msg("country history unavailable")
	}
	for _, cc := range recentCountries {
		if cc != raw.CountryCode {
			f.CountryChange2H = true
			break
		}
	}

	// --- Geographic risk ---
	f.GeographicRiskScore = countryRisk(raw.CountryCode)
	f.CrossBorderFlag = raw.CounterpartyCountry != "" &&
		raw.CounterpartyCountry != raw.CountryCode

	// --- Merchant / category risk ---
	f.MerchantRiskScore, f.IsHighRiskMerchant = merchantRisk(raw.MerchantCategory)

	// --- KYC / customer profile ---
	profile, err := e.velocity.GetCustomerProfile(ctx, raw.CustomerID)
	if err != nil {
		log.Debug().Err(err).Msg("customer profile unavailable; using safe defaults")
	}
	if profile != nil {
		f.CustomerRiskScore = profile.RiskScore
		f.KYCRiskLevel = profile.KYCRiskLevel
		if !profile.KYCDate.IsZero() {
			f.DaysSinceKYC = int(time.Since(profile.KYCDate).Hours() / 24)
		}
	} else {
		// Unknown customer → treat as medium risk until KYC profile is cached.
		f.CustomerRiskScore = 50.0
		f.KYCRiskLevel = 2
	}

	// --- Graph features: zeros — populated asynchronously by GNN (Phase 7) ---
	// The ensemble blends tree models (which don't need graph features) and the
	// GNN (which receives these zeros and fills them during offline enrichment).

	log.Debug().
		Float64("amount_usd", f.AmountUSDEquiv).
		Float64("velocity_1h_usd", f.Velocity1H).
		Float64("deviation_score", f.AmountDeviationScore).
		Float64("geo_risk", f.GeographicRiskScore).
		Bool("cross_border", f.CrossBorderFlag).
		Bool("country_change_2h", f.CountryChange2H).
		Bool("high_risk_merchant", f.IsHighRiskMerchant).
		Msg("features extracted")

	return f, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func countryRisk(code string) float64 {
	if score, ok := countryRiskScores[strings.ToUpper(code)]; ok {
		return score
	}
	return defaultCountryRisk
}

func merchantRisk(category string) (score float64, isHigh bool) {
	lower := strings.ToLower(category)
	for pattern, s := range merchantRiskScores {
		if strings.Contains(lower, pattern) {
			return s, highRiskMerchantCategories[pattern]
		}
	}
	return defaultMerchantRisk, false
}

// haversineKm computes the great-circle distance in kilometres between two
// WGS-84 coordinate pairs. Returns 0 if either point is exactly (0, 0).
func haversineKm(lat1, lon1, lat2, lon2 float64) float64 {
	if (lat1 == 0 && lon1 == 0) || (lat2 == 0 && lon2 == 0) {
		return 0
	}
	const r = 6371.0
	φ1 := lat1 * math.Pi / 180
	φ2 := lat2 * math.Pi / 180
	dφ := (lat2 - lat1) * math.Pi / 180
	dλ := (lon2 - lon1) * math.Pi / 180
	a := math.Sin(dφ/2)*math.Sin(dφ/2) + math.Cos(φ1)*math.Cos(φ2)*math.Sin(dλ/2)*math.Sin(dλ/2)
	return r * 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
}
