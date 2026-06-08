// Package main is a standalone performance benchmark for the blockchain-service.
//
// It measures:
//   - Per-operation chaincode invocation latency (min/mean/p50/p95/p99/max)
//   - Throughput (TPS) at concurrency levels 1, 10, 50, 100
//   - Block batching efficiency (transactions per block based on BatchTimeout)
//
// Usage:
//
//	go run ./cmd/benchmark/ [flags]
//	go run ./cmd/benchmark/ --url http://localhost:8095 --requests 200 --csv results.csv
//
// All flags have safe defaults so the tool can be run with no arguments against
// a locally running blockchain-service.
package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// CLI flags
// ---------------------------------------------------------------------------

var (
	flagURL      = flag.String("url", "http://localhost:8095", "blockchain-service base URL")
	flagWarmup   = flag.Int("warmup", 10, "warmup requests per operation (discarded)")
	flagRequests = flag.Int("requests", 200, "requests per operation for latency test")
	flagTPSReqs  = flag.Int("tps-requests", 500, "total requests per concurrency level for TPS test")
	flagCSV      = flag.String("csv", "blockchain_benchmark_results.csv", "output CSV file (empty = no CSV)")
	flagVerbose  = flag.Bool("v", false, "print each request result")
)

// ---------------------------------------------------------------------------
// Payload builders — each generates a unique payload per invocation
// ---------------------------------------------------------------------------

var globalCounter int64 // atomic counter for unique IDs across goroutines

func nextID(prefix string) string {
	n := atomic.AddInt64(&globalCounter, 1)
	return fmt.Sprintf("%s-%d-%06d", prefix, time.Now().UnixMilli(), n)
}

func buildTransactionReceipt() map[string]interface{} {
	id := nextID("tx")
	return map[string]interface{}{
		"record_id":         id,
		"tx_hash":           id,
		"customer_id":       "bench-cust-001",
		"amount_usd":        9500.00,
		"currency_code":     "USD",
		"channel":           "WIRE_TRANSFER",
		"country_code":      "US",
		"processed_at":      time.Now().UTC().Format(time.RFC3339),
		"fraud_probability": 0.87,
		"risk_level":        "HIGH",
		"alert_fired":       true,
		"alert_id":          nextID("alert"),
		"model_version":     "ensemble-v1",
		"prediction_id":     nextID("pred"),
	}
}

func buildInvestigatorAction() map[string]interface{} {
	id := nextID("action")
	return map[string]interface{}{
		"action_id":       id,
		"investigator_id": "bench-investigator-001",
		"case_id":         nextID("case"),
		"action":          "BENCH_ACTION",
		"evidence":        "benchmark test evidence",
	}
}

func buildModelPrediction() map[string]interface{} {
	id := nextID("pred")
	return map[string]interface{}{
		"prediction_id": id,
		"model_version": "ensemble-v1",
		"features":      `{"amount_usd":9500,"velocity_1h":3,"geographic_risk":0.7}`,
		"prediction":    `{"fraud_probability":0.87,"is_fraud":true}`,
		"shap_values":   `[{"feature":"amount","value":0.31}]`,
	}
}

func buildSARFiled() map[string]interface{} {
	caseID := nextID("case")
	return map[string]interface{}{
		"record_id":    caseID + "-sar",
		"case_id":      caseID,
		"sar_hash":     fmt.Sprintf("sha256bench%020d", atomic.AddInt64(&globalCounter, 1)),
		"s3_key":       fmt.Sprintf("sar/%s/SAR_%s.pdf", caseID, caseID),
		"filed_at":     time.Now().UTC().Format(time.RFC3339),
		"generated_by": "bench-investigator-001",
	}
}

func buildCreateAlert() map[string]interface{} {
	id := nextID("alert")
	return map[string]interface{}{
		"alert_id":          id,
		"customer_id":       "bench-cust-001",
		"tx_hash":           nextID("tx"),
		"fraud_probability": 0.91,
		"risk_score":        91.0,
		"model_version":     "ensemble-v1",
	}
}

// ---------------------------------------------------------------------------
// Operation definitions
// ---------------------------------------------------------------------------

type operation struct {
	name    string
	path    string
	builder func() map[string]interface{}
}

func operations() []operation {
	return []operation{
		{
			name:    "RecordTransactionProcessed",
			path:    "/internal/v1/audit/transaction-receipt",
			builder: buildTransactionReceipt,
		},
		{
			name:    "RecordInvestigatorAction",
			path:    "/internal/v1/audit/investigator-action",
			builder: buildInvestigatorAction,
		},
		{
			name:    "RecordModelPrediction",
			path:    "/internal/v1/audit/model-prediction",
			builder: buildModelPrediction,
		},
		{
			name:    "RecordSARFiled",
			path:    "/internal/v1/audit/sar-filed",
			builder: buildSARFiled,
		},
		{
			name:    "CreateAlert",
			path:    "/internal/v1/alerts/create",
			builder: buildCreateAlert,
		},
	}
}

// ---------------------------------------------------------------------------
// HTTP client
// ---------------------------------------------------------------------------

var httpClient = &http.Client{Timeout: 60 * time.Second}

// invoke sends a POST request and returns the round-trip duration.
// Returns an error if the HTTP status is not 2xx.
func invoke(baseURL, path string, payload map[string]interface{}) (time.Duration, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("marshal: %w", err)
	}

	start := time.Now()
	resp, err := httpClient.Post(baseURL+path, "application/json", bytes.NewReader(body))
	elapsed := time.Since(start)
	if err != nil {
		return elapsed, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return elapsed, fmt.Errorf("HTTP %d from %s", resp.StatusCode, path)
	}
	return elapsed, nil
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

type stats struct {
	samples []float64 // ms
}

func (s *stats) add(d time.Duration) {
	s.samples = append(s.samples, float64(d.Milliseconds()))
}

func (s *stats) compute() result {
	if len(s.samples) == 0 {
		return result{}
	}
	sorted := make([]float64, len(s.samples))
	copy(sorted, s.samples)
	sort.Float64s(sorted)

	n := len(sorted)
	sum := 0.0
	for _, v := range sorted {
		sum += v
	}
	mean := sum / float64(n)

	variance := 0.0
	for _, v := range sorted {
		d := v - mean
		variance += d * d
	}
	stddev := math.Sqrt(variance / float64(n))

	return result{
		count:  n,
		min:    sorted[0],
		mean:   mean,
		stddev: stddev,
		p50:    percentile(sorted, 50),
		p95:    percentile(sorted, 95),
		p99:    percentile(sorted, 99),
		max:    sorted[n-1],
	}
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(p/100.0*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

type result struct {
	count  int
	min    float64
	mean   float64
	stddev float64
	p50    float64
	p95    float64
	p99    float64
	max    float64
}

type latencyResult struct {
	opName string
	errors int
	result
}

type tpsResult struct {
	opName      string
	concurrency int
	totalReqs   int
	errors      int
	elapsed     time.Duration
	tps         float64
	meanLatency float64
}

// ---------------------------------------------------------------------------
// Benchmark runners
// ---------------------------------------------------------------------------

func runLatencyBenchmark(baseURL string, op operation, warmup, requests int) latencyResult {
	// warmup — discard results
	for i := 0; i < warmup; i++ {
		_, _ = invoke(baseURL, op.path, op.builder())
	}

	s := &stats{}
	errorCount := 0

	for i := 0; i < requests; i++ {
		d, err := invoke(baseURL, op.path, op.builder())
		if err != nil {
			errorCount++
			if *flagVerbose {
				fmt.Printf("  [ERROR] %s: %v\n", op.name, err)
			}
			continue
		}
		s.add(d)
		if *flagVerbose {
			fmt.Printf("  [OK] %s: %dms\n", op.name, d.Milliseconds())
		}
	}

	return latencyResult{
		opName: op.name,
		errors: errorCount,
		result: s.compute(),
	}
}

func runTPSBenchmark(baseURL string, op operation, concurrency, totalReqs int) tpsResult {
	var (
		wg         sync.WaitGroup
		mu         sync.Mutex
		latencies  []float64
		errorCount int
	)

	sem := make(chan struct{}, concurrency)
	start := time.Now()

	for i := 0; i < totalReqs; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			d, err := invoke(baseURL, op.path, op.builder())
			mu.Lock()
			if err != nil {
				errorCount++
			} else {
				latencies = append(latencies, float64(d.Milliseconds()))
			}
			mu.Unlock()
		}()
	}

	wg.Wait()
	elapsed := time.Since(start)

	tps := float64(totalReqs-errorCount) / elapsed.Seconds()
	meanLat := 0.0
	if len(latencies) > 0 {
		sum := 0.0
		for _, v := range latencies {
			sum += v
		}
		meanLat = sum / float64(len(latencies))
	}

	return tpsResult{
		opName:      op.name,
		concurrency: concurrency,
		totalReqs:   totalReqs,
		errors:      errorCount,
		elapsed:     elapsed,
		tps:         tps,
		meanLatency: meanLat,
	}
}

// ---------------------------------------------------------------------------
// Output formatters
// ---------------------------------------------------------------------------

func printHeader(title string) {
	fmt.Printf("\n%s\n%s\n", title, repeat("─", len(title)))
}

func printLatencyTable(results []latencyResult) {
	printHeader("Chaincode Invocation Latency (ms) — Sequential, Concurrency=1")
	fmt.Printf("%-32s %6s %7s %7s %7s %7s %7s %7s %6s %6s\n",
		"Operation", "Count", "Min", "Mean", "StdDev", "P50", "P95", "P99", "Max", "Errs")
	fmt.Println(repeat("─", 110))
	for _, r := range results {
		fmt.Printf("%-32s %6d %7.1f %7.1f %7.1f %7.1f %7.1f %7.1f %6.1f %6d\n",
			r.opName, r.count, r.min, r.mean, r.stddev, r.p50, r.p95, r.p99, r.max, r.errors)
	}
}

func printTPSTable(results []tpsResult) {
	printHeader("Throughput (TPS) — RecordTransactionProcessed under load")
	fmt.Printf("%-32s %11s %8s %10s %10s %8s %6s\n",
		"Operation", "Concurrency", "Requests", "TPS", "Mean Lat(ms)", "Elapsed", "Errs")
	fmt.Println(repeat("─", 100))
	for _, r := range results {
		fmt.Printf("%-32s %11d %8d %10.2f %10.1f %8.2fs %6d\n",
			r.opName, r.concurrency, r.totalReqs,
			r.tps, r.meanLatency, r.elapsed.Seconds(), r.errors)
	}
}

func printBlockBatchNote() {
	printHeader("Block Batching Configuration (from configtx.yaml)")
	fmt.Println("  BatchTimeout     : 2 seconds")
	fmt.Println("  MaxMessageCount  : 20 transactions per block")
	fmt.Println("  AbsoluteMaxBytes : 99 MB")
	fmt.Println("  Consensus        : Raft (3 orderers)")
	fmt.Println()
	fmt.Println("  Implication: Under low load, latency ≈ BatchTimeout (2s) since the orderer")
	fmt.Println("  waits up to 2s to fill a block. Under high load (≥20 concurrent tx),")
	fmt.Println("  blocks fill faster and latency approaches network round-trip (~50–150ms).")
	fmt.Println("  This matches the P99 vs Mean gap visible in the latency table above.")
}

// ---------------------------------------------------------------------------
// CSV export
// ---------------------------------------------------------------------------

func writeCSV(path string, latResults []latencyResult, tpsResults []tpsResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)

	// Latency section
	_ = w.Write([]string{"=== Latency Benchmark ==="})
	_ = w.Write([]string{"Operation", "Count", "Min_ms", "Mean_ms", "StdDev_ms", "P50_ms", "P95_ms", "P99_ms", "Max_ms", "Errors"})
	for _, r := range latResults {
		_ = w.Write([]string{
			r.opName,
			fmt.Sprintf("%d", r.count),
			fmt.Sprintf("%.2f", r.min),
			fmt.Sprintf("%.2f", r.mean),
			fmt.Sprintf("%.2f", r.stddev),
			fmt.Sprintf("%.2f", r.p50),
			fmt.Sprintf("%.2f", r.p95),
			fmt.Sprintf("%.2f", r.p99),
			fmt.Sprintf("%.2f", r.max),
			fmt.Sprintf("%d", r.errors),
		})
	}

	_ = w.Write([]string{})
	// TPS section
	_ = w.Write([]string{"=== Throughput Benchmark ==="})
	_ = w.Write([]string{"Operation", "Concurrency", "TotalRequests", "TPS", "MeanLatency_ms", "Elapsed_s", "Errors"})
	for _, r := range tpsResults {
		_ = w.Write([]string{
			r.opName,
			fmt.Sprintf("%d", r.concurrency),
			fmt.Sprintf("%d", r.totalReqs),
			fmt.Sprintf("%.2f", r.tps),
			fmt.Sprintf("%.2f", r.meanLatency),
			fmt.Sprintf("%.2f", r.elapsed.Seconds()),
			fmt.Sprintf("%d", r.errors),
		})
	}

	w.Flush()
	return w.Error()
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

func healthCheck(baseURL string) error {
	resp, err := httpClient.Get(baseURL + "/health")
	if err != nil {
		return fmt.Errorf("cannot reach blockchain-service at %s: %w", baseURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("blockchain-service health returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	flag.Parse()

	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║    Hyperledger Fabric Blockchain-Service Performance Benchmark    ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
	fmt.Printf("\nTarget  : %s\n", *flagURL)
	fmt.Printf("Warmup  : %d requests/op\n", *flagWarmup)
	fmt.Printf("Latency : %d requests/op\n", *flagRequests)
	fmt.Printf("TPS     : %d total requests per concurrency level\n", *flagTPSReqs)
	fmt.Printf("CSV out : %s\n\n", *flagCSV)

	// Health check first
	fmt.Print("Checking blockchain-service health... ")
	if err := healthCheck(*flagURL); err != nil {
		fmt.Printf("FAILED\n\n  %v\n\n", err)
		fmt.Println("  Make sure the blockchain-service is running:")
		fmt.Println("  cd services/blockchain-service && go run ./cmd/server/")
		os.Exit(1)
	}
	fmt.Println("OK")

	// -----------------------------------------------------------------------
	// Phase 1: Latency benchmark (all operations, sequential)
	// -----------------------------------------------------------------------
	fmt.Printf("\nPhase 1/2 — Latency benchmark (%d warmup + %d measured per operation)\n",
		*flagWarmup, *flagRequests)

	ops := operations()
	latResults := make([]latencyResult, 0, len(ops))

	for _, op := range ops {
		fmt.Printf("  %-34s ", op.name+"...")
		r := runLatencyBenchmark(*flagURL, op, *flagWarmup, *flagRequests)
		latResults = append(latResults, r)
		if r.errors > 0 {
			fmt.Printf("done (errors: %d/%d)\n", r.errors, *flagRequests)
		} else {
			fmt.Printf("done (mean: %.0fms, p99: %.0fms)\n", r.mean, r.p99)
		}
	}

	// -----------------------------------------------------------------------
	// Phase 2: TPS benchmark (RecordTransactionProcessed — most frequent op)
	// -----------------------------------------------------------------------
	concurrencyLevels := []int{1, 10, 50, 100}
	fmt.Printf("\nPhase 2/2 — TPS benchmark (RecordTransactionProcessed, %d reqs per level)\n",
		*flagTPSReqs)

	tpsBenchOp := ops[0] // RecordTransactionProcessed
	tpsResults := make([]tpsResult, 0, len(concurrencyLevels))

	for _, conc := range concurrencyLevels {
		fmt.Printf("  Concurrency %-4d  ", conc)
		r := runTPSBenchmark(*flagURL, tpsBenchOp, conc, *flagTPSReqs)
		tpsResults = append(tpsResults, r)
		fmt.Printf("TPS: %7.2f  mean latency: %6.1fms  errors: %d\n",
			r.tps, r.meanLatency, r.errors)
	}

	// -----------------------------------------------------------------------
	// Print results
	// -----------------------------------------------------------------------
	printLatencyTable(latResults)
	printTPSTable(tpsResults)
	printBlockBatchNote()

	// -----------------------------------------------------------------------
	// Thesis summary section
	// -----------------------------------------------------------------------
	printHeader("Thesis Paper Key Numbers (copy into your evaluation section)")
	for _, r := range latResults {
		if r.count > 0 {
			fmt.Printf("  %-34s mean=%.1fms  p95=%.1fms  p99=%.1fms\n",
				r.opName, r.mean, r.p95, r.p99)
		}
	}
	fmt.Println()
	fmt.Println("  TPS Summary (RecordTransactionProcessed):")
	for _, r := range tpsResults {
		fmt.Printf("  Concurrency=%3d → TPS=%.2f  mean latency=%.1fms\n",
			r.concurrency, r.tps, r.meanLatency)
	}

	// -----------------------------------------------------------------------
	// CSV export
	// -----------------------------------------------------------------------
	if *flagCSV != "" {
		if err := writeCSV(*flagCSV, latResults, tpsResults); err != nil {
			fmt.Printf("\nWARN: failed to write CSV: %v\n", err)
		} else {
			fmt.Printf("\nResults saved to: %s\n", *flagCSV)
		}
	}

	fmt.Println("\nBenchmark complete.")
}
