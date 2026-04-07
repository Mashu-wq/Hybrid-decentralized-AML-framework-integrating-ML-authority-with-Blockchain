package main

import (
	"encoding/json"
	"testing"

	"github.com/hyperledger/fabric-chaincode-go/shimtest"
	"github.com/stretchr/testify/require"
)

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

	resp = stub.MockInvoke("tx-report", [][]byte{
		[]byte("GetComplianceReport"),
		[]byte("2026-04-01T00:00:00Z"),
		[]byte("2026-04-02T00:00:00Z"),
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
