package main

import (
	"encoding/json"
	"testing"

	"github.com/hyperledger/fabric-chaincode-go/shimtest"
	"github.com/stretchr/testify/require"
)

func TestKYCChaincodeLifecycle(t *testing.T) {
	stub := shimtest.NewMockStub("kyc", new(KYCChaincode))

	resp := stub.MockInvoke("tx-register", [][]byte{
		[]byte("RegisterCustomer"),
		[]byte("customer-1"),
		[]byte("0123456789abcdef0123456789abcdef"),
		[]byte("PENDING"),
		[]byte("LOW"),
		[]byte("verifier-1"),
	})
	require.Equal(t, int32(200), resp.Status, string(resp.Message))

	resp = stub.MockInvoke("tx-update", [][]byte{
		[]byte("UpdateKYCStatus"),
		[]byte("customer-1"),
		[]byte("APPROVED"),
		[]byte("manual review passed"),
	})
	require.Equal(t, int32(200), resp.Status, string(resp.Message))

	resp = stub.MockInvoke("tx-get", [][]byte{
		[]byte("GetKYCRecord"),
		[]byte("customer-1"),
	})
	require.Equal(t, int32(200), resp.Status, string(resp.Message))

	var record KYCRecord
	require.NoError(t, json.Unmarshal(resp.Payload, &record))
	require.Equal(t, "APPROVED", record.KYCStatus)

	resp = stub.MockInvoke("tx-pending", [][]byte{
		[]byte("ListPendingKYC"),
	})
	require.Equal(t, int32(200), resp.Status, string(resp.Message))

	var pending []KYCRecord
	require.NoError(t, json.Unmarshal(resp.Payload, &pending))
	require.Empty(t, pending)

	resp = stub.MockInvoke("tx-history", [][]byte{
		[]byte("GetKYCHistory"),
		[]byte("customer-1"),
	})
	require.Equal(t, int32(200), resp.Status, string(resp.Message))

	var history []KYCRecord
	require.NoError(t, json.Unmarshal(resp.Payload, &history))
	require.Len(t, history, 2)
}

func TestKYCChaincodeValidation(t *testing.T) {
	stub := shimtest.NewMockStub("kyc", new(KYCChaincode))

	resp := stub.MockInvoke("tx-bad", [][]byte{
		[]byte("RegisterCustomer"),
		[]byte("customer-1"),
		[]byte("short"),
		[]byte("PENDING"),
		[]byte("LOW"),
		[]byte("verifier-1"),
	})
	require.Equal(t, int32(500), resp.Status)
	require.Contains(t, resp.Message, "identityHash must be at least 16 characters")
}
