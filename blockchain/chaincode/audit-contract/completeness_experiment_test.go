package main

// Completeness experiment for the paper's Section VI-D.
//
// Validates the claim that a per-organization, chaincode-assigned sequence
// number makes receipt omission provable:
//
//   E1  suppression detection  — Delta = N - S_m recovers the suppressed count
//   E2  gap-freeness           — committed sequences are exactly {1..S_m}
//   E3  per-org independence   — one org's suppression does not mask another's
//   E4  backfill skew          — late anchoring shows sequence/timestamp skew
//
// Run:  GOWORK=off go test -run TestCompletenessExperiment -v ./...
//
// SCOPE: this exercises the chaincode against the Fabric mock stub, so it
// measures the completeness logic, not network commit latency or MVCC
// contention. Those require the live 3-org network.

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/golang/protobuf/proto" //nolint:staticcheck // legacy proto API
	"github.com/hyperledger/fabric-chaincode-go/shimtest"
	mspproto "github.com/hyperledger/fabric-protos-go/msp"
	"github.com/stretchr/testify/require"
)

const expDetails = `{"customerId":"cust-pseudonym","amountUsd":1000,` +
	`"currencyCode":"USD","channel":"WIRE","countryCode":"US"}`

var expBase = time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)

// anchor submits one processing receipt for transaction i at the given time.
func anchor(stub *shimtest.MockStub, i int, at time.Time) error {
	stub.TransientMap = map[string][]byte{transientReceiptKey: []byte(expDetails)}
	resp := stub.MockInvoke(fmt.Sprintf("tx-%d", i), [][]byte{
		[]byte("RecordTransactionProcessed"),
		[]byte(fmt.Sprintf("rec-%06d", i)),
		[]byte(fmt.Sprintf("txhash-%06d", i)),
		[]byte(at.Format(time.RFC3339)),
		[]byte("0.42"),
		[]byte("MEDIUM"),
		[]byte("false"),
		[]byte(""),
		[]byte("lightgbm-v1"),
		[]byte(fmt.Sprintf("pred-%06d", i)),
	})
	if resp.Status != 200 {
		return fmt.Errorf("anchor %d: %s", i, resp.Message)
	}
	return nil
}

// newExpStub builds a MockStub and drains its chaincode-event channel. The
// channel holds only 100 events and SetEvent blocks once it is full, so any
// scenario anchoring more than 100 receipts deadlocks without this drain.
func newExpStub(t *testing.T, mspID string) *shimtest.MockStub {
	t.Helper()
	stub := shimtest.NewMockStub("audit", new(AuditChaincode))
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		for {
			select {
			case <-stub.ChaincodeEventsChannel:
			case <-done:
				return
			}
		}
	}()
	setCreator(t, stub, mspID)
	return stub
}

func setCreator(t *testing.T, stub *shimtest.MockStub, mspID string) {
	t.Helper()
	creator, err := proto.Marshal(&mspproto.SerializedIdentity{Mspid: mspID})
	require.NoError(t, err)
	stub.Creator = creator
}

// latestSequence is the regulator's view: GetSequenceStatus read from its own
// replica, with no cooperation from the bank.
func latestSequence(t *testing.T, stub *shimtest.MockStub, mspID string) uint64 {
	t.Helper()
	resp := stub.MockInvoke("q-seq", [][]byte{[]byte("GetSequenceStatus")})
	require.Equal(t, int32(200), resp.Status, string(resp.Message))
	var statuses []SequenceStatus
	require.NoError(t, json.Unmarshal(resp.Payload, &statuses))
	for _, s := range statuses {
		if s.MSPID == mspID {
			return s.LatestSequence
		}
	}
	return 0
}

// committedSequences enumerates every committed TRANSACTION_PROCESSED receipt
// for an org and returns its sequence numbers together with processedAt.
func committedSequences(t *testing.T, stub *shimtest.MockStub, mspID string) ([]uint64, map[uint64]string) {
	t.Helper()
	var seqs []uint64
	stamps := map[uint64]string{}
	for _, raw := range stub.State {
		var rec AuditRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			continue // composite-key index entries and counters are not records
		}
		if rec.RecordType != "TRANSACTION_PROCESSED" || rec.Data["submitterMSP"] != mspID {
			continue
		}
		var n uint64
		if _, err := fmt.Sscanf(rec.Data["sequenceNumber"], "%d", &n); err != nil {
			continue
		}
		seqs = append(seqs, n)
		stamps[n] = rec.Data["processedAt"]
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	return seqs, stamps
}

// isGapFree reports whether seqs is exactly {1..S} with no repeats.
func isGapFree(seqs []uint64, S uint64) bool {
	if uint64(len(seqs)) != S {
		return false
	}
	for i, v := range seqs {
		if v != uint64(i+1) {
			return false
		}
	}
	return true
}

func TestCompletenessExperiment(t *testing.T) {
	const N = 1000
	const org = "Org1MSP"

	t.Log("")
	t.Log("=== E1/E2  suppression detection and gap-freeness ================")
	t.Logf("%6s %8s %8s %8s %10s %10s %12s", "k", "N", "S_m", "Delta", "detected", "gap-free", "us/receipt")

	for _, k := range []int{0, 1, 10, 100} {
		stub := newExpStub(t, org)

		// Choose which k of the N transactions the bank suppresses.
		rng := rand.New(rand.NewSource(int64(k) + 42))
		suppressed := map[int]bool{}
		for len(suppressed) < k {
			suppressed[rng.Intn(N)] = true
		}

		start := time.Now()
		anchored := 0
		for i := 0; i < N; i++ {
			if suppressed[i] {
				continue // the bank never submits a receipt for this transaction
			}
			require.NoError(t, anchor(stub, i, expBase.Add(time.Duration(i)*time.Second)))
			anchored++
		}
		elapsed := time.Since(start)

		// Regulator side: read S_m locally, reconcile against reported volume N.
		S := latestSequence(t, stub, org)
		delta := int64(N) - int64(S)

		seqs, _ := committedSequences(t, stub, org)
		gapFree := isGapFree(seqs, S)

		perReceipt := float64(elapsed.Microseconds()) / float64(max(anchored, 1))
		t.Logf("%6d %8d %8d %8d %10v %10v %12.1f",
			k, N, S, delta, delta == int64(k), gapFree, perReceipt)

		require.Equal(t, uint64(anchored), S, "S_m must equal receipts actually anchored")
		require.Equal(t, int64(k), delta, "Delta must recover the suppressed count exactly")
		require.True(t, gapFree, "committed series must be exactly {1..S_m}")
	}

	t.Log("")
	t.Log("=== E3  per-org counter independence =============================")
	{
		stub := newExpStub(t, "Org1MSP")
		for i := 0; i < 50; i++ {
			require.NoError(t, anchor(stub, i, expBase.Add(time.Duration(i)*time.Second)))
		}
		// Org3 anchors 30, suppressing none.
		setCreator(t, stub, "Org3MSP")
		for i := 100; i < 130; i++ {
			require.NoError(t, anchor(stub, i, expBase.Add(time.Duration(i)*time.Second)))
		}
		s1 := latestSequence(t, stub, "Org1MSP")
		s3 := latestSequence(t, stub, "Org3MSP")
		t.Logf("Org1MSP S=%d (expected 50), Org3MSP S=%d (expected 30)", s1, s3)
		require.Equal(t, uint64(50), s1)
		require.Equal(t, uint64(30), s3)

		q1, _ := committedSequences(t, stub, "Org1MSP")
		q3, _ := committedSequences(t, stub, "Org3MSP")
		require.True(t, isGapFree(q1, s1))
		require.True(t, isGapFree(q3, s3))
	}

	t.Log("")
	t.Log("=== E4  backfill skew ============================================")
	{
		const honest = 100
		const late = 10
		stub := newExpStub(t, org)

		// Honest window: transactions 0..99 anchored in order.
		for i := 0; i < honest; i++ {
			require.NoError(t, anchor(stub, i, expBase.Add(time.Duration(i)*time.Minute)))
		}
		sBefore := latestSequence(t, stub, org)

		// The bank is challenged on Delta and backfills 10 receipts whose
		// processedAt timestamps fall inside the window already covered.
		for j := 0; j < late; j++ {
			i := 500 + j
			require.NoError(t, anchor(stub, i, expBase.Add(time.Duration(j)*time.Minute)))
		}
		sAfter := latestSequence(t, stub, org)

		seqs, stamps := committedSequences(t, stub, org)
		require.True(t, isGapFree(seqs, sAfter), "backfill still cannot create a gap")

		// Skew: sequence order should track processedAt order. A receipt is
		// retrospectively inserted when its processedAt precedes the newest
		// processedAt already anchored at a lower sequence number.
		skew := 0
		var high time.Time
		for n := uint64(1); n <= sAfter; n++ {
			cur, _ := time.Parse(time.RFC3339, stamps[n])
			if n > 1 && cur.Before(high) {
				skew++
			}
			if cur.After(high) {
				high = cur
			}
		}
		t.Logf("S before backfill = %d, after = %d, gap-free = %v", sBefore, sAfter, true)
		t.Logf("sequence/timestamp inversions detected = %d (backfilled receipts = %d)", skew, late)
		require.Equal(t, uint64(honest), sBefore)
		require.Equal(t, uint64(honest+late), sAfter)
		require.Equal(t, late, skew, "every backfilled receipt must show sequence/timestamp skew")
	}
	t.Log("")
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
