package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	pb "github.com/hyperledger/fabric-protos-go/peer"
)

const (
	kycRecordPrefix  = "KYC_"
	kycStatusIndex   = "kyc~status~customer"
	kycHistoryIndex  = "kyc~history~customer"
	objectTypeKYC    = "kyc_record"
	eventRegistered  = "KYC_REGISTERED"
	eventStatusEvent = "KYC_STATUS_UPDATED"
)

var allowedKYCStatuses = map[string]struct{}{
	"PENDING":   {},
	"APPROVED":  {},
	"REJECTED":  {},
	"SUSPENDED": {},
}

var allowedRiskLevels = map[string]struct{}{
	"UNSPECIFIED": {},
	"LOW":         {},
	"MEDIUM":      {},
	"HIGH":        {},
	"CRITICAL":    {},
}

type KYCRecord struct {
	ObjectType string `json:"objectType"`
	CustomerID string `json:"customerID"`

	IdentityHash string `json:"identityHash"`
	KYCStatus    string `json:"kycStatus"`
	RiskLevel    string `json:"riskLevel"`
	VerifierID   string `json:"verifierID,omitempty"`
	Reason       string `json:"reason,omitempty"`

	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
	TxID      string `json:"txId"`
}

type kycEvent struct {
	EventType  string `json:"eventType"`
	CustomerID string `json:"customerID"`
	KYCStatus  string `json:"kycStatus"`
	RiskLevel  string `json:"riskLevel"`
	VerifierID string `json:"verifierID,omitempty"`
	Reason     string `json:"reason,omitempty"`
	TxID       string `json:"txId"`
	Timestamp  string `json:"timestamp"`
}

type KYCChaincode struct{}

func (c *KYCChaincode) Init(stub shim.ChaincodeStubInterface) pb.Response {
	return shim.Success(nil)
}

func (c *KYCChaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	function, args := stub.GetFunctionAndParameters()

	switch function {
	case "RegisterCustomer":
		return c.RegisterCustomer(stub, args)
	case "UpdateKYCStatus":
		return c.UpdateKYCStatus(stub, args)
	case "GetKYCRecord":
		return c.GetKYCRecord(stub, args)
	case "GetKYCHistory":
		return c.GetKYCHistory(stub, args)
	case "ListPendingKYC":
		return c.ListPendingKYC(stub, args)
	default:
		return shim.Error(fmt.Sprintf("unsupported function %q", function))
	}
}

func (c *KYCChaincode) RegisterCustomer(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 5 {
		return shim.Error("RegisterCustomer requires 5 arguments: customerID, identityHash, kycStatus, riskLevel, verifierID")
	}

	customerID := strings.TrimSpace(args[0])
	identityHash := strings.TrimSpace(args[1])
	kycStatus := normalizeEnum(args[2])
	riskLevel := normalizeEnum(args[3])
	verifierID := strings.TrimSpace(args[4])

	if err := validateCustomerID(customerID); err != nil {
		return shim.Error(err.Error())
	}
	if identityHash == "" {
		return shim.Error("identityHash is required")
	}
	if err := validateHash(identityHash); err != nil {
		return shim.Error(err.Error())
	}
	if err := validateKYCStatus(kycStatus); err != nil {
		return shim.Error(err.Error())
	}
	if err := validateRiskLevel(riskLevel); err != nil {
		return shim.Error(err.Error())
	}

	recordKey := kycStateKey(customerID)
	existing, err := stub.GetState(recordKey)
	if err != nil {
		return shim.Error(fmt.Sprintf("read kyc record: %v", err))
	}
	if len(existing) > 0 {
		return shim.Error("customer already registered on ledger")
	}

	now, err := txTimestamp(stub)
	if err != nil {
		return shim.Error(fmt.Sprintf("resolve transaction timestamp: %v", err))
	}

	record := &KYCRecord{
		ObjectType:   objectTypeKYC,
		CustomerID:   customerID,
		IdentityHash: identityHash,
		KYCStatus:    kycStatus,
		RiskLevel:    riskLevel,
		VerifierID:   verifierID,
		CreatedAt:    now,
		UpdatedAt:    now,
		TxID:         stub.GetTxID(),
	}

	if err := putKYCRecord(stub, record); err != nil {
		return shim.Error(err.Error())
	}
	if err := addKYCStatusIndex(stub, kycStatus, customerID); err != nil {
		return shim.Error(fmt.Sprintf("create kyc status index: %v", err))
	}
	if err := appendKYCSnapshot(stub, record); err != nil {
		return shim.Error(fmt.Sprintf("append kyc history snapshot: %v", err))
	}
	if err := emitKYCEvent(stub, eventRegistered, record); err != nil {
		return shim.Error(fmt.Sprintf("emit kyc event: %v", err))
	}

	payload, _ := json.Marshal(record)
	return shim.Success(payload)
}

func (c *KYCChaincode) UpdateKYCStatus(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 3 {
		return shim.Error("UpdateKYCStatus requires 3 arguments: customerID, newStatus, reason")
	}

	customerID := strings.TrimSpace(args[0])
	newStatus := normalizeEnum(args[1])
	reason := strings.TrimSpace(args[2])

	if err := validateCustomerID(customerID); err != nil {
		return shim.Error(err.Error())
	}
	if err := validateKYCStatus(newStatus); err != nil {
		return shim.Error(err.Error())
	}
	if requiresReason(newStatus) && reason == "" {
		return shim.Error("reason is required when status is REJECTED or SUSPENDED")
	}

	record, err := readKYCRecord(stub, customerID)
	if err != nil {
		return shim.Error(err.Error())
	}
	if err := validateStatusTransition(record.KYCStatus, newStatus); err != nil {
		return shim.Error(err.Error())
	}

	now, err := txTimestamp(stub)
	if err != nil {
		return shim.Error(fmt.Sprintf("resolve transaction timestamp: %v", err))
	}

	oldStatus := record.KYCStatus
	record.KYCStatus = newStatus
	record.Reason = reason
	record.UpdatedAt = now
	record.TxID = stub.GetTxID()

	if err := putKYCRecord(stub, record); err != nil {
		return shim.Error(err.Error())
	}
	if oldStatus != newStatus {
		if err := removeKYCStatusIndex(stub, oldStatus, customerID); err != nil {
			return shim.Error(fmt.Sprintf("remove old kyc status index: %v", err))
		}
		if err := addKYCStatusIndex(stub, newStatus, customerID); err != nil {
			return shim.Error(fmt.Sprintf("create new kyc status index: %v", err))
		}
	}
	if err := appendKYCSnapshot(stub, record); err != nil {
		return shim.Error(fmt.Sprintf("append kyc history snapshot: %v", err))
	}
	if err := emitKYCEvent(stub, eventStatusEvent, record); err != nil {
		return shim.Error(fmt.Sprintf("emit kyc event: %v", err))
	}

	payload, _ := json.Marshal(record)
	return shim.Success(payload)
}

func (c *KYCChaincode) GetKYCRecord(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 1 {
		return shim.Error("GetKYCRecord requires 1 argument: customerID")
	}

	record, err := readKYCRecord(stub, strings.TrimSpace(args[0]))
	if err != nil {
		return shim.Error(err.Error())
	}

	payload, _ := json.Marshal(record)
	return shim.Success(payload)
}

func (c *KYCChaincode) GetKYCHistory(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 1 {
		return shim.Error("GetKYCHistory requires 1 argument: customerID")
	}

	customerID := strings.TrimSpace(args[0])
	if err := validateCustomerID(customerID); err != nil {
		return shim.Error(err.Error())
	}

	recordKey := kycStateKey(customerID)
	iterator, err := stub.GetHistoryForKey(recordKey)
	if err == nil {
		defer iterator.Close()

		history := make([]*KYCRecord, 0)
		for iterator.HasNext() {
			modification, iterErr := iterator.Next()
			if iterErr != nil {
				return shim.Error(fmt.Sprintf("iterate kyc history: %v", iterErr))
			}
			if modification.IsDelete || len(modification.Value) == 0 {
				continue
			}

			var record KYCRecord
			if unmarshalErr := json.Unmarshal(modification.Value, &record); unmarshalErr != nil {
				return shim.Error(fmt.Sprintf("unmarshal kyc history record: %v", unmarshalErr))
			}
			record.TxID = modification.TxId
			if modification.Timestamp != nil {
				record.UpdatedAt = time.Unix(modification.Timestamp.Seconds, int64(modification.Timestamp.Nanos)).UTC().Format(time.RFC3339)
			}
			history = append(history, &record)
		}

		payload, _ := json.Marshal(history)
		return shim.Success(payload)
	}

	history, fallbackErr := readKYCHistorySnapshots(stub, customerID)
	if fallbackErr != nil {
		return shim.Error(fmt.Sprintf("read fallback kyc history: %v", fallbackErr))
	}

	payload, _ := json.Marshal(history)
	return shim.Success(payload)
}

func (c *KYCChaincode) ListPendingKYC(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 0 {
		return shim.Error("ListPendingKYC does not accept arguments")
	}

	iterator, err := stub.GetStateByPartialCompositeKey(kycStatusIndex, []string{"PENDING"})
	if err != nil {
		return shim.Error(fmt.Sprintf("list pending kyc index: %v", err))
	}
	defer iterator.Close()

	records := make([]*KYCRecord, 0)
	for iterator.HasNext() {
		entry, iterErr := iterator.Next()
		if iterErr != nil {
			return shim.Error(fmt.Sprintf("iterate pending kyc index: %v", iterErr))
		}

		_, compositeParts, splitErr := stub.SplitCompositeKey(entry.Key)
		if splitErr != nil || len(compositeParts) != 2 {
			return shim.Error(fmt.Sprintf("split pending kyc index key: %v", splitErr))
		}

		record, readErr := readKYCRecord(stub, compositeParts[1])
		if readErr != nil {
			return shim.Error(readErr.Error())
		}
		records = append(records, record)
	}

	payload, _ := json.Marshal(records)
	return shim.Success(payload)
}

func putKYCRecord(stub shim.ChaincodeStubInterface, record *KYCRecord) error {
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal kyc record: %w", err)
	}
	if err := stub.PutState(kycStateKey(record.CustomerID), payload); err != nil {
		return fmt.Errorf("write kyc record: %w", err)
	}
	return nil
}

func readKYCRecord(stub shim.ChaincodeStubInterface, customerID string) (*KYCRecord, error) {
	if err := validateCustomerID(customerID); err != nil {
		return nil, err
	}

	payload, err := stub.GetState(kycStateKey(customerID))
	if err != nil {
		return nil, fmt.Errorf("read kyc record: %w", err)
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("kyc record %s not found", customerID)
	}

	var record KYCRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		return nil, fmt.Errorf("unmarshal kyc record: %w", err)
	}
	return &record, nil
}

func addKYCStatusIndex(stub shim.ChaincodeStubInterface, status, customerID string) error {
	indexKey, err := stub.CreateCompositeKey(kycStatusIndex, []string{status, customerID})
	if err != nil {
		return err
	}
	return stub.PutState(indexKey, []byte{0})
}

func removeKYCStatusIndex(stub shim.ChaincodeStubInterface, status, customerID string) error {
	indexKey, err := stub.CreateCompositeKey(kycStatusIndex, []string{status, customerID})
	if err != nil {
		return err
	}
	return stub.DelState(indexKey)
}

func appendKYCSnapshot(stub shim.ChaincodeStubInterface, record *KYCRecord) error {
	indexKey, err := stub.CreateCompositeKey(kycHistoryIndex, []string{record.CustomerID, record.UpdatedAt, record.TxID})
	if err != nil {
		return err
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return stub.PutState(indexKey, payload)
}

func readKYCHistorySnapshots(stub shim.ChaincodeStubInterface, customerID string) ([]*KYCRecord, error) {
	iterator, err := stub.GetStateByPartialCompositeKey(kycHistoryIndex, []string{customerID})
	if err != nil {
		return nil, err
	}
	defer iterator.Close()

	history := make([]*KYCRecord, 0)
	for iterator.HasNext() {
		entry, iterErr := iterator.Next()
		if iterErr != nil {
			return nil, iterErr
		}

		var record KYCRecord
		if err := json.Unmarshal(entry.Value, &record); err != nil {
			return nil, err
		}
		history = append(history, &record)
	}
	return history, nil
}

func emitKYCEvent(stub shim.ChaincodeStubInterface, eventType string, record *KYCRecord) error {
	payload, err := json.Marshal(kycEvent{
		EventType:  eventType,
		CustomerID: record.CustomerID,
		KYCStatus:  record.KYCStatus,
		RiskLevel:  record.RiskLevel,
		VerifierID: record.VerifierID,
		Reason:     record.Reason,
		TxID:       record.TxID,
		Timestamp:  record.UpdatedAt,
	})
	if err != nil {
		return err
	}
	return stub.SetEvent(eventType, payload)
}

func kycStateKey(customerID string) string {
	return kycRecordPrefix + customerID
}

func validateCustomerID(customerID string) error {
	if strings.TrimSpace(customerID) == "" {
		return fmt.Errorf("customerID is required")
	}
	return nil
}

func validateHash(identityHash string) error {
	if len(identityHash) < 16 {
		return fmt.Errorf("identityHash must be at least 16 characters")
	}
	return nil
}

func validateKYCStatus(status string) error {
	if _, ok := allowedKYCStatuses[status]; !ok {
		return fmt.Errorf("invalid KYC status %q", status)
	}
	return nil
}

func validateRiskLevel(riskLevel string) error {
	if _, ok := allowedRiskLevels[riskLevel]; !ok {
		return fmt.Errorf("invalid risk level %q", riskLevel)
	}
	return nil
}

func requiresReason(status string) bool {
	return status == "REJECTED" || status == "SUSPENDED"
}

func validateStatusTransition(from, to string) error {
	allowed := map[string]map[string]struct{}{
		"PENDING": {
			"APPROVED": {},
			"REJECTED": {},
		},
		"APPROVED": {
			"SUSPENDED": {},
			"REJECTED":  {},
		},
		"SUSPENDED": {
			"APPROVED": {},
			"REJECTED": {},
		},
		"REJECTED": {
			"PENDING": {},
		},
	}

	validTargets, ok := allowed[from]
	if !ok {
		return fmt.Errorf("unsupported source status %q", from)
	}
	if _, ok := validTargets[to]; !ok {
		return fmt.Errorf("invalid status transition from %s to %s", from, to)
	}
	return nil
}

func txTimestamp(stub shim.ChaincodeStubInterface) (string, error) {
	txTime, err := stub.GetTxTimestamp()
	if err != nil {
		return "", err
	}
	return time.Unix(txTime.Seconds, int64(txTime.Nanos)).UTC().Format(time.RFC3339), nil
}

func normalizeEnum(value string) string {
	return strings.ToUpper(strings.TrimSpace(value))
}
