// Package domain contains core analytics types with no external dependencies.
package domain

import (
	"errors"
	"time"
)

// Sentinel errors.
var (
	ErrInvalidPeriod      = errors.New("invalid period: use 24h, 7d, or 30d")
	ErrInvalidGranularity = errors.New("invalid granularity")
	ErrNoData             = errors.New("no data for the requested range")
)

// Granularity controls time-bucket size for trend queries.
type Granularity string

const (
	GranularityHour  Granularity = "hour"
	GranularityDay   Granularity = "day"
	GranularityWeek  Granularity = "week"
	GranularityMonth Granularity = "month"
)

// PGTrunc returns the PostgreSQL date_trunc string for this granularity.
func (g Granularity) PGTrunc() (string, error) {
	switch g {
	case GranularityHour:
		return "hour", nil
	case GranularityDay:
		return "day", nil
	case GranularityWeek:
		return "week", nil
	case GranularityMonth:
		return "month", nil
	default:
		return "", ErrInvalidGranularity
	}
}

// MongoDateFmt returns the $dateToString format string for this granularity.
func (g Granularity) MongoDateFmt() (string, error) {
	switch g {
	case GranularityHour:
		return "%Y-%m-%dT%H:00:00", nil
	case GranularityDay:
		return "%Y-%m-%d", nil
	case GranularityWeek:
		return "%Y-W%V", nil
	case GranularityMonth:
		return "%Y-%m", nil
	default:
		return "", ErrInvalidGranularity
	}
}

// PeriodRange converts a named period string to a from/to time range.
func PeriodRange(period string) (from, to time.Time, err error) {
	to = time.Now().UTC()
	switch period {
	case "24h":
		from = to.Add(-24 * time.Hour)
	case "7d":
		from = to.Add(-7 * 24 * time.Hour)
	case "30d":
		from = to.Add(-30 * 24 * time.Hour)
	default:
		err = ErrInvalidPeriod
	}
	return
}

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

// TrendPoint is one time-bucket's aggregated fraud signal.
type TrendPoint struct {
	Date         time.Time
	AlertCount   int
	FraudCount   int // HIGH + CRITICAL alerts
	TotalTxCount int // from MongoDB; 0 if unavailable
	FraudRate    float64
	AvgFraudProb float64
}

// RiskBucket is the count of alerts in one risk level for a period.
type RiskBucket struct {
	RiskLevel    string // "LOW", "MEDIUM", "HIGH", "CRITICAL"
	Count        int
	Percentage   float64
	AvgFraudProb float64
}

// RiskyCustomer summarises fraud exposure for a single customer.
type RiskyCustomer struct {
	CustomerID   string
	AlertCount   int
	FraudRate    float64 // fraction of HIGH+CRITICAL alerts
	TotalAmount  float64
	AvgRiskScore float64
	LastAlertAt  time.Time
}

// ModelPerformance captures prediction quality metrics for a model version.
// TP/FP are derived from alert status transitions; TN/FN are not directly
// observable without full transaction data.
type ModelPerformance struct {
	ModelVersion     string
	Period           string
	TotalPredictions int64
	TruePositives    int64   // status = RESOLVED (confirmed fraud)
	FalsePositives   int64   // status = FALSE_POSITIVE
	TrueNegatives    int64   // not directly observable (0)
	FalseNegatives   int64   // not directly observable (0)
	Precision        float64 // TP / (TP + FP)
	Recall           float64 // approximate
	F1Score          float64
	AUCROC           float64 // approximation from fraud probability distribution
}

// VolumePoint is one time-bucket's transaction volume from MongoDB.
type VolumePoint struct {
	Date        time.Time
	TxCount     int
	TotalAmount float64
	AvgAmount   float64
	FraudCount  int // alert_created = true
}

// AlertMetrics contains detailed alert lifecycle statistics.
type AlertMetrics struct {
	Period             string
	TotalAlerts        int
	OpenAlerts         int
	ResolvedAlerts     int
	FalsePositives     int
	EscalatedAlerts    int
	AvgResolutionMin   float64
	EscalationRate     float64
	FalsePositiveRate  float64
	ByPriority         map[string]int
}

// GeoFraudPoint captures fraud activity for one country.
type GeoFraudPoint struct {
	CountryCode string
	AlertCount  int
	TxCount     int
	FraudRate   float64
	TotalAmount float64
}

// ReportType classifies the kind of generated report.
type ReportType string

const (
	ReportTypeSummary    ReportType = "SUMMARY"
	ReportTypeCompliance ReportType = "COMPLIANCE"
	ReportTypeSAR        ReportType = "SAR"
	ReportTypeModelAudit ReportType = "MODEL_AUDIT"
)

// Report is the result of GenerateReport.
type Report struct {
	ReportID    string
	ReportType  ReportType
	Period      string
	GeneratedAt time.Time
	ContentJSON string
}

// FraudTrendsResult groups the trend points with metadata.
type FraudTrendsResult struct {
	Points      []*TrendPoint
	Period      string
	Granularity Granularity
}
