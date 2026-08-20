package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/golang/protobuf/proto" //nolint:staticcheck // fabric-protos-go v0.3.x messages only implement the legacy proto API
	"github.com/hyperledger/fabric-chaincode-go/shimtest"
	mspproto "github.com/hyperledger/fabric-protos-go/msp"
	"github.com/stretchr/testify/require"
)

// newReceiptStub returns a MockStub whose creator identity carries the given MSP
// ID, as RecordTransactionProcessed derives the per-org sequence key from it.
func newReceiptStub(t *testing.T, mspID string) *shimtest.MockStub {
	t.Helper()
	stub := shimtest.NewMockStub("audit", new(AuditChaincode))
	creator, err := proto.Marshal(&mspproto.SerializedIdentity{Mspid: mspID})
	require.NoError(t, err)
	stub.Creator = creator
	return stub
}

func invokeReceipt(stub *shimtest.MockStub, recordID string, details []byte) [][]byte {
	stub.TransientMap = map[string][]byte{transientReceiptKey: details}
	return [][]byte{
		[]byte("RecordTransactionProcessed"),
		[]byte(recordID),
		[]byte(recordID), // txHash
		[]byte("2026-06-08T10:00:00Z"),
		[]byte("0.87"),
		[]byte("CRITICAL"),
		[]byte("true"),
		[]byte("alert-001"),
		[]byte("ensemble-v1"),
		[]byte("pred-001"),
	}
}

func TestAuditChaincodeLifecycle(t *testing.T) {
	stub := shimtest.NewMockStub("audit", new(AuditChaincode))

	resp := stub.MockInvoke("tx-action", [][]byte{
		[]byte("RecordInvestigatorAction"),
		[]byte("action-1"),
		[]byte("investigator-1"),
		[]byte("case-22"),
		[]byte("CASE_REVIEWED"),
		[]byte("s3://evidence/file.pdf"),
	})
	require.Equal(t, int32(200), resp.Status, string(resp.Message))

	var actionRecord AuditRecord
	require.NoError(t, json.Unmarshal(resp.Payload, &actionRecord))
	require.Equal(t, "INVESTIGATOR_ACTION", actionRecord.RecordType)
	require.Equal(t, "CASE", actionRecord.EntityType)
	require.NotEmpty(t, actionRecord.Hash)

	resp = stub.MockInvoke("tx-pred", [][]byte{
		[]byte("RecordModelPrediction"),
		[]byte("prediction-1"),
		[]byte("gnn-v4"),
		[]byte("{\"velocity_1h\":4.2}"),
		[]byte("fraud"),
		[]byte("{\"velocity_1h\":0.17}"),
	})
	require.Equal(t, int32(200), resp.Status, string(resp.Message))

	resp = stub.MockInvoke("tx-trail-case", [][]byte{
		[]byte("GetAuditTrail"),
		[]byte("case-22"),
		[]byte("CASE"),
	})
	require.Equal(t, int32(200), resp.Status, string(resp.Message))

	var caseTrail []AuditRecord
	require.NoError(t, json.Unmarshal(resp.Payload, &caseTrail))
	require.Len(t, caseTrail, 1)
	require.Equal(t, "action-1", caseTrail[0].RecordID)

	resp = stub.MockInvoke("tx-trail-model", [][]byte{
		[]byte("GetAuditTrail"),
		[]byte("prediction-1"),
		[]byte("MODEL"),
	})
	require.Equal(t, int32(200), resp.Status, string(resp.Message))

	var modelTrail []AuditRecord
	require.NoError(t, json.Unmarshal(resp.Payload, &modelTrail))
	require.Len(t, modelTrail, 1)

	// MockStub stamps records with the wall-clock time, so query a wide window
	// rather than a fixed day (a fixed day rots as the calendar advances).
	resp = stub.MockInvoke("tx-report", [][]byte{
		[]byte("GetComplianceReport"),
		[]byte("2020-01-01T00:00:00Z"),
		[]byte("2099-01-01T00:00:00Z"),
	})
	require.Equal(t, int32(200), resp.Status, string(resp.Message))

	var report ComplianceReport
	require.NoError(t, json.Unmarshal(resp.Payload, &report))
	require.Equal(t, 2, report.TotalEvents)
	require.Equal(t, 1, report.InvestigatorActions)
	require.Equal(t, 1, report.ModelPredictions)
	require.Equal(t, 1, report.ByEntityType["CASE"])
	require.Equal(t, 1, report.ByEntityType["MODEL"])
}

func TestAuditChaincodeValidation(t *testing.T) {
	stub := shimtest.NewMockStub("audit", new(AuditChaincode))

	resp := stub.MockInvoke("tx-bad", [][]byte{
		[]byte("GetComplianceReport"),
		[]byte("2026-04-02T00:00:00Z"),
		[]byte("2026-04-01T00:00:00Z"),
	})
	require.Equal(t, int32(500), resp.Status)
	require.Contains(t, resp.Message, "endDate must not be before startDate")
}

func TestTransactionReceiptSequenceAndPrivateDetails(t *testing.T) {
	stub := newReceiptStub(t, "Org1MSP")

	details := []byte(`{"customerId":"a1b2c3-pseudonym","amountUsd":15000,"currencyCode":"USD","channel":"WIRE","countryCode":"US"}`)

	// First receipt gets sequence 1.
	resp := stub.MockInvoke("tx-r1", invokeReceipt(stub, "txhash-001", details))
	require.Equal(t, int32(200), resp.Status, string(resp.Message))

	var record AuditRecord
	require.NoError(t, json.Unmarshal(resp.Payload, &record))
	require.Equal(t, "TRANSACTION_PROCESSED", record.RecordType)
	require.Equal(t, "1", record.Data["sequenceNumber"])
	require.Equal(t, "Org1MSP", record.Data["submitterMSP"])

	// The public record must not contain any of the private business details.
	public, _ := json.Marshal(record)
	require.NotContains(t, string(public), "a1b2c3-pseudonym")
	require.NotContains(t, string(public), "15000")
	require.NotContains(t, string(public), "US")

	// detailsHash on the public record binds the private payload.
	sum := sha256.Sum256(details)
	require.Equal(t, hex.EncodeToString(sum[:]), record.Data["detailsHash"])

	// Second receipt from the same org gets sequence 2 — gap-free.
	resp = stub.MockInvoke("tx-r2", invokeReceipt(stub, "txhash-002", details))
	require.Equal(t, int32(200), resp.Status, string(resp.Message))
	require.NoError(t, json.Unmarshal(resp.Payload, &record))
	require.Equal(t, "2", record.Data["sequenceNumber"])

	// GetSequenceStatus reports the latest sequence per org.
	resp = stub.MockInvoke("tx-seq", [][]byte{[]byte("GetSequenceStatus")})
	require.Equal(t, int32(200), resp.Status, string(resp.Message))
	var statuses []SequenceStatus
	require.NoError(t, json.Unmarshal(resp.Payload, &statuses))
	require.Len(t, statuses, 1)
	require.Equal(t, "Org1MSP", statuses[0].MSPID)
	require.Equal(t, uint64(2), statuses[0].LatestSequence)

	// GetReceiptDetails returns the private half and verifies it against the hash.
	resp = stub.MockInvoke("tx-details", [][]byte{
		[]byte("GetReceiptDetails"),
		[]byte("txhash-001"),
	})
	require.Equal(t, int32(200), resp.Status, string(resp.Message))
	var detailsResp ReceiptDetailsResponse
	require.NoError(t, json.Unmarshal(resp.Payload, &detailsResp))
	require.True(t, detailsResp.Verified)
	require.JSONEq(t, string(details), string(detailsResp.Details))
}

func TestTransactionReceiptRequiresTransientDetails(t *testing.T) {
	stub := newReceiptStub(t, "Org1MSP")

	args := invokeReceipt(stub, "txhash-001", nil)
	stub.TransientMap = nil
	resp := stub.MockInvoke("tx-r1", args)
	require.Equal(t, int32(500), resp.Status)
	require.Contains(t, resp.Message, "receipt_details")
}

func TestTransactionReceiptRejectsInvalidDetails(t *testing.T) {
	stub := newReceiptStub(t, "Org1MSP")

	resp := stub.MockInvoke("tx-r1", invokeReceipt(stub, "txhash-001",
		[]byte(`{"amountUsd":100}`)))
	require.Equal(t, int32(500), resp.Status)
	require.Contains(t, resp.Message, "customerId is required")

	resp = stub.MockInvoke("tx-r2", invokeReceipt(stub, "txhash-002",
		[]byte(`{"customerId":"c1","amountUsd":-5}`)))
	require.Equal(t, int32(500), resp.Status)
	require.Contains(t, resp.Message, "amountUsd must be non-negative")
}

func TestSequenceCountersAreIndependentPerOrg(t *testing.T) {
	// Two orgs writing to the same ledger state must not share a counter.
	org1 := newReceiptStub(t, "Org1MSP")
	details := []byte(`{"customerId":"c1","amountUsd":10,"currencyCode":"USD","channel":"WIRE","countryCode":"US"}`)

	resp := org1.MockInvoke("tx-a", invokeReceipt(org1, "txhash-a", details))
	require.Equal(t, int32(200), resp.Status, string(resp.Message))

	// Switch the same stub's creator to Org3 — its counter starts at 1.
	creator, err := proto.Marshal(&mspproto.SerializedIdentity{Mspid: "Org3MSP"})
	require.NoError(t, err)
	org1.Creator = creator

	resp = org1.MockInvoke("tx-b", invokeReceipt(org1, "txhash-b", details))
	require.Equal(t, int32(200), resp.Status, string(resp.Message))

	var record AuditRecord
	require.NoError(t, json.Unmarshal(resp.Payload, &record))
	require.Equal(t, "1", record.Data["sequenceNumber"])
	require.Equal(t, "Org3MSP", record.Data["submitterMSP"])

	resp = org1.MockInvoke("tx-seq", [][]byte{[]byte("GetSequenceStatus")})
	require.Equal(t, int32(200), resp.Status, string(resp.Message))
	var statuses []SequenceStatus
	require.NoError(t, json.Unmarshal(resp.Payload, &statuses))
	require.Len(t, statuses, 2)
}
