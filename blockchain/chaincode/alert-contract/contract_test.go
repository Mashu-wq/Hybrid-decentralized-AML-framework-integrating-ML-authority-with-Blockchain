package main

import (
	"encoding/json"
	"testing"

	"github.com/hyperledger/fabric-chaincode-go/shimtest"
	"github.com/stretchr/testify/require"
)

func TestAlertChaincodeLifecycle(t *testing.T) {
	stub := shimtest.NewMockStub("alert", new(AlertChaincode))

	resp := stub.MockInvoke("tx-create", [][]byte{
		[]byte("CreateAlert"),
		[]byte("alert-1"),
		[]byte("customer-1"),
		[]byte("tx-abc"),
		[]byte("0.92"),
		[]byte("96.5"),
		[]byte("ensemble-v1"),
	})
	require.Equal(t, int32(200), resp.Status, string(resp.Message))

	var created AlertRecord
	require.NoError(t, json.Unmarshal(resp.Payload, &created))
	require.Equal(t, "CRITICAL", created.RiskLevel)
	require.Equal(t, alertStatusOpen, created.Status)

	resp = stub.MockInvoke("tx-status", [][]byte{
		[]byte("UpdateAlertStatus"),
		[]byte("alert-1"),
		[]byte("INVESTIGATING"),
		[]byte("investigator-9"),
		[]byte("triaging"),
	})
	require.Equal(t, int32(200), resp.Status, string(resp.Message))

	resp = stub.MockInvoke("tx-customer", [][]byte{
		[]byte("GetAlertsByCustomer"),
		[]byte("customer-1"),
	})
	require.Equal(t, int32(200), resp.Status, string(resp.Message))

	var customerAlerts []AlertRecord
	require.NoError(t, json.Unmarshal(resp.Payload, &customerAlerts))
	require.Len(t, customerAlerts, 1)
	require.Equal(t, alertStatusInvestigating, customerAlerts[0].Status)

	resp = stub.MockInvoke("tx-risk", [][]byte{
		[]byte("GetAlertsByRiskLevel"),
		[]byte("CRITICAL"),
	})
	require.Equal(t, int32(200), resp.Status, string(resp.Message))

	var riskAlerts []AlertRecord
	require.NoError(t, json.Unmarshal(resp.Payload, &riskAlerts))
	require.Len(t, riskAlerts, 1)
	require.Equal(t, "alert-1", riskAlerts[0].AlertID)

	resp = stub.MockInvoke("tx-stats", [][]byte{
		[]byte("GetAlertStats"),
	})
	require.Equal(t, int32(200), resp.Status, string(resp.Message))

	var stats AlertStatistics
	require.NoError(t, json.Unmarshal(resp.Payload, &stats))
	require.Equal(t, 1, stats.TotalAlerts)
	require.Equal(t, 1, stats.CriticalAlerts)
	require.Equal(t, 1, stats.InvestigatingAlerts)
}

func TestAlertChaincodeValidation(t *testing.T) {
	stub := shimtest.NewMockStub("alert", new(AlertChaincode))

	resp := stub.MockInvoke("tx-bad", [][]byte{
		[]byte("CreateAlert"),
		[]byte(""),
		[]byte("customer-1"),
		[]byte("tx-abc"),
		[]byte("1.4"),
		[]byte("96.5"),
		[]byte("ensemble-v1"),
	})
	require.Equal(t, int32(500), resp.Status)
	require.Contains(t, resp.Message, "alertID is required")
}
