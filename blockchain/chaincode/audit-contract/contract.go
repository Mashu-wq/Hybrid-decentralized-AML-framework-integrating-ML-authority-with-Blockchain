package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	pb "github.com/hyperledger/fabric-protos-go/peer"
)

const (
	auditRecordPrefix  = "AUDIT_"
	auditEntityIndex   = "audit~entityType~entityID~recordID"
	objectTypeAudit    = "audit_record"
	eventAuditRecorded = "AUDIT_RECORDED"
)

var allowedAuditTypes = map[string]struct{}{
	"INVESTIGATOR_ACTION":    {},
	"MODEL_PREDICTION":       {},
	"TRANSACTION_PROCESSED":  {},
	"SAR_FILED":              {},
}

var allowedEntityTypes = map[string]struct{}{
	"CUSTOMER":    {},
	"CASE":        {},
	"ALERT":       {},
	"MODEL":       {},
	"TRANSACTION": {},
}

type AuditRecord struct {
	ObjectType  string            `json:"objectType"`
	RecordID    string            `json:"recordID"`
	RecordType  string            `json:"recordType"`
	EntityID    string            `json:"entityID"`
	EntityType  string            `json:"entityType"`
	ActorID     string            `json:"actorID"`
	Description string            `json:"description"`
	Data        map[string]string `json:"data"`
	Hash        string            `json:"hash"`
	CreatedAt   string            `json:"createdAt"`
	TxID        string            `json:"txId"`
}

type ComplianceReport struct {
	StartDate              string         `json:"startDate"`
	EndDate                string         `json:"endDate"`
	TotalEvents            int            `json:"totalEvents"`
	InvestigatorActions    int            `json:"investigatorActions"`
	ModelPredictions       int            `json:"modelPredictions"`
	TransactionsProcessed  int            `json:"transactionsProcessed"`
	SARsFiled              int            `json:"sarsFiled"`
	ByEntityType           map[string]int `json:"byEntityType"`
	SampleRecords          []*AuditRecord `json:"sampleRecords"`
}

type auditEvent struct {
	EventType  string            `json:"eventType"`
	RecordID   string            `json:"recordID"`
	RecordType string            `json:"recordType"`
	EntityID   string            `json:"entityID"`
	EntityType string            `json:"entityType"`
	ActorID    string            `json:"actorID"`
	Hash       string            `json:"hash"`
	Data       map[string]string `json:"data"`
	TxID       string            `json:"txId"`
	Timestamp  string            `json:"timestamp"`
}

type AuditChaincode struct{}

func (c *AuditChaincode) Init(stub shim.ChaincodeStubInterface) pb.Response {
	return shim.Success(nil)
}

func (c *AuditChaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	function, args := stub.GetFunctionAndParameters()

	switch function {
	case "RecordInvestigatorAction":
		return c.RecordInvestigatorAction(stub, args)
	case "RecordModelPrediction":
		return c.RecordModelPrediction(stub, args)
	case "RecordTransactionProcessed":
		return c.RecordTransactionProcessed(stub, args)
	case "RecordSARFiled":
		return c.RecordSARFiled(stub, args)
	case "GetAuditTrail":
		return c.GetAuditTrail(stub, args)
	case "GetComplianceReport":
		return c.GetComplianceReport(stub, args)
	default:
		return shim.Error(fmt.Sprintf("unsupported function %q", function))
	}
}

func (c *AuditChaincode) RecordInvestigatorAction(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 5 {
		return shim.Error("RecordInvestigatorAction requires 5 arguments: actionID, investigatorID, caseID, action, evidence")
	}

	record, err := newAuditRecord(
		stub,
		strings.TrimSpace(args[0]),
		"INVESTIGATOR_ACTION",
		strings.TrimSpace(args[2]),
		"CASE",
		strings.TrimSpace(args[1]),
		fmt.Sprintf("Investigator action: %s", strings.TrimSpace(args[3])),
		map[string]string{
			"action":   strings.TrimSpace(args[3]),
			"evidence": strings.TrimSpace(args[4]),
		},
	)
	if err != nil {
		return shim.Error(err.Error())
	}
	if err := writeAuditRecord(stub, record); err != nil {
		return shim.Error(err.Error())
	}

	payload, _ := json.Marshal(record)
	return shim.Success(payload)
}

func (c *AuditChaincode) RecordModelPrediction(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 5 {
		return shim.Error("RecordModelPrediction requires 5 arguments: predictionID, modelVersion, features, prediction, shapValues")
	}

	record, err := newAuditRecord(
		stub,
		strings.TrimSpace(args[0]),
		"MODEL_PREDICTION",
		strings.TrimSpace(args[0]),
		"MODEL",
		strings.TrimSpace(args[1]),
		"Model prediction recorded",
		map[string]string{
			"modelVersion": strings.TrimSpace(args[1]),
			"features":     strings.TrimSpace(args[2]),
			"prediction":   strings.TrimSpace(args[3]),
			"shapValues":   strings.TrimSpace(args[4]),
		},
	)
	if err != nil {
		return shim.Error(err.Error())
	}
	if err := writeAuditRecord(stub, record); err != nil {
		return shim.Error(err.Error())
	}

	payload, _ := json.Marshal(record)
	return shim.Success(payload)
}

// RecordTransactionProcessed writes a tamper-evident processing receipt to the ledger
// for every transaction that passes through the ML pipeline — whether flagged or not.
// This closes the "fabrication gap": a bank cannot omit a transaction from the audit
// trail, because absence of a receipt would itself be detectable by the regulator.
//
// args: recordID, txHash, customerID, amountUSD, currencyCode, channel, countryCode,
//
//	processedAt (RFC3339), fraudProbability (0-1), riskLevel, alertFired (true|false),
//	alertID, modelVersion, predictionID
func (c *AuditChaincode) RecordTransactionProcessed(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	const expectedArgs = 14
	if len(args) != expectedArgs {
		return shim.Error(fmt.Sprintf(
			"RecordTransactionProcessed requires %d arguments: "+
				"recordID, txHash, customerID, amountUSD, currencyCode, channel, countryCode, "+
				"processedAt, fraudProbability, riskLevel, alertFired, alertID, modelVersion, predictionID",
			expectedArgs,
		))
	}

	recordID         := strings.TrimSpace(args[0])
	txHash           := strings.TrimSpace(args[1])
	customerID       := strings.TrimSpace(args[2])
	amountUSDStr     := strings.TrimSpace(args[3])
	currencyCode     := strings.TrimSpace(args[4])
	channel          := strings.TrimSpace(args[5])
	countryCode      := strings.TrimSpace(args[6])
	processedAt      := strings.TrimSpace(args[7])
	fraudProbStr     := strings.TrimSpace(args[8])
	riskLevel        := normalizeEnum(args[9])
	alertFiredStr    := strings.TrimSpace(args[10])
	alertID          := strings.TrimSpace(args[11])
	modelVersion     := strings.TrimSpace(args[12])
	predictionID     := strings.TrimSpace(args[13])

	// Required field checks
	if err := validateAuditID(txHash, "txHash"); err != nil {
		return shim.Error(err.Error())
	}
	if err := validateAuditID(customerID, "customerID"); err != nil {
		return shim.Error(err.Error())
	}

	// Validate amountUSD is a parseable non-negative number
	if amt, err := strconv.ParseFloat(amountUSDStr, 64); err != nil || amt < 0 {
		return shim.Error("amountUSD must be a non-negative float")
	}

	// Validate fraudProbability is in [0, 1]
	fraudProb, err := strconv.ParseFloat(fraudProbStr, 64)
	if err != nil || fraudProb < 0 || fraudProb > 1 {
		return shim.Error("fraudProbability must be a float in [0, 1]")
	}

	// Validate processedAt is parseable RFC3339
	if _, err := time.Parse(time.RFC3339, processedAt); err != nil {
		return shim.Error("processedAt must be RFC3339 format (e.g. 2006-01-02T15:04:05Z)")
	}

	// Validate riskLevel
	allowedRisk := map[string]struct{}{
		"LOW": {}, "MEDIUM": {}, "HIGH": {}, "CRITICAL": {}, "UNSPECIFIED": {},
	}
	if _, ok := allowedRisk[riskLevel]; !ok {
		return shim.Error(fmt.Sprintf("invalid riskLevel %q", riskLevel))
	}

	// Validate alertFired is a parseable boolean
	if _, err := strconv.ParseBool(alertFiredStr); err != nil {
		return shim.Error("alertFired must be \"true\" or \"false\"")
	}

	// actorID = modelVersion (records which model processed this transaction).
	// Fall back to "transaction-service" when model version is empty (heuristic path).
	actorID := modelVersion
	if actorID == "" {
		actorID = "transaction-service"
	}

	record, err := newAuditRecord(
		stub,
		recordID,
		"TRANSACTION_PROCESSED",
		txHash,
		"TRANSACTION",
		actorID,
		"ML pipeline transaction processing receipt",
		map[string]string{
			"txHash":           txHash,
			"customerID":       customerID,
			"amountUSD":        amountUSDStr,
			"currencyCode":     currencyCode,
			"channel":          channel,
			"countryCode":      countryCode,
			"processedAt":      processedAt,
			"fraudProbability": fraudProbStr,
			"riskLevel":        riskLevel,
			"alertFired":       alertFiredStr,
			"alertID":          alertID,
			"modelVersion":     modelVersion,
			"predictionID":     predictionID,
		},
	)
	if err != nil {
		return shim.Error(err.Error())
	}

	if err := writeAuditRecord(stub, record); err != nil {
		return shim.Error(err.Error())
	}

	payload, _ := json.Marshal(record)
	return shim.Success(payload)
}

// RecordSARFiled writes a tamper-evident SAR_FILED record to the audit-channel when a
// Suspicious Activity Report is generated and uploaded to S3. The sarHash (SHA-256 of
// the PDF content) proves the document has not been altered after filing.
//
// args: recordID, caseID, sarHash, s3Key, filedAt (RFC3339), generatedBy
func (c *AuditChaincode) RecordSARFiled(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	const expectedArgs = 6
	if len(args) != expectedArgs {
		return shim.Error(fmt.Sprintf(
			"RecordSARFiled requires %d arguments: recordID, caseID, sarHash, s3Key, filedAt, generatedBy",
			expectedArgs,
		))
	}

	recordID    := strings.TrimSpace(args[0])
	caseID      := strings.TrimSpace(args[1])
	sarHash     := strings.TrimSpace(args[2])
	s3Key       := strings.TrimSpace(args[3])
	filedAt     := strings.TrimSpace(args[4])
	generatedBy := strings.TrimSpace(args[5])

	if err := validateAuditID(caseID, "caseID"); err != nil {
		return shim.Error(err.Error())
	}
	if err := validateAuditID(sarHash, "sarHash"); err != nil {
		return shim.Error(err.Error())
	}
	if err := validateAuditID(s3Key, "s3Key"); err != nil {
		return shim.Error(err.Error())
	}
	if err := validateAuditID(generatedBy, "generatedBy"); err != nil {
		return shim.Error(err.Error())
	}
	if _, err := time.Parse(time.RFC3339, filedAt); err != nil {
		return shim.Error("filedAt must be RFC3339 format (e.g. 2006-01-02T15:04:05Z)")
	}

	record, err := newAuditRecord(
		stub,
		recordID,
		"SAR_FILED",
		caseID,
		"CASE",
		generatedBy,
		fmt.Sprintf("SAR filed for case %s — document hash anchored on-chain", caseID),
		map[string]string{
			"caseID":      caseID,
			"sarHash":     sarHash,
			"s3Key":       s3Key,
			"filedAt":     filedAt,
			"generatedBy": generatedBy,
		},
	)
	if err != nil {
		return shim.Error(err.Error())
	}
	if err := writeAuditRecord(stub, record); err != nil {
		return shim.Error(err.Error())
	}

	payload, _ := json.Marshal(record)
	return shim.Success(payload)
}

func (c *AuditChaincode) GetAuditTrail(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 2 {
		return shim.Error("GetAuditTrail requires 2 arguments: entityID, entityType")
	}

	entityID := strings.TrimSpace(args[0])
	entityType := normalizeEnum(args[1])
	if err := validateAuditID(entityID, "entityID"); err != nil {
		return shim.Error(err.Error())
	}
	if err := validateEntityType(entityType); err != nil {
		return shim.Error(err.Error())
	}

	iterator, err := stub.GetStateByPartialCompositeKey(auditEntityIndex, []string{entityType, entityID})
	if err != nil {
		return shim.Error(fmt.Sprintf("list audit trail: %v", err))
	}
	defer iterator.Close()

	records := make([]*AuditRecord, 0)
	for iterator.HasNext() {
		entry, iterErr := iterator.Next()
		if iterErr != nil {
			return shim.Error(fmt.Sprintf("iterate audit trail: %v", iterErr))
		}
		_, parts, splitErr := stub.SplitCompositeKey(entry.Key)
		if splitErr != nil || len(parts) != 3 {
			return shim.Error(fmt.Sprintf("split audit key: %v", splitErr))
		}
		record, readErr := readAuditRecord(stub, parts[2])
		if readErr != nil {
			return shim.Error(readErr.Error())
		}
		records = append(records, record)
	}

	sort.Slice(records, func(i, j int) bool {
		return records[i].CreatedAt < records[j].CreatedAt
	})

	payload, _ := json.Marshal(records)
	return shim.Success(payload)
}

func (c *AuditChaincode) GetComplianceReport(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 2 {
		return shim.Error("GetComplianceReport requires 2 arguments: startDate, endDate")
	}

	startDate, err := time.Parse(time.RFC3339, strings.TrimSpace(args[0]))
	if err != nil {
		return shim.Error("startDate must be RFC3339")
	}
	endDate, err := time.Parse(time.RFC3339, strings.TrimSpace(args[1]))
	if err != nil {
		return shim.Error("endDate must be RFC3339")
	}
	if endDate.Before(startDate) {
		return shim.Error("endDate must not be before startDate")
	}

	iterator, err := stub.GetStateByRange(auditRecordPrefix, auditRecordPrefix+"~")
	if err != nil {
		return shim.Error(fmt.Sprintf("scan audit records: %v", err))
	}
	defer iterator.Close()

	report := &ComplianceReport{
		StartDate:     startDate.UTC().Format(time.RFC3339),
		EndDate:       endDate.UTC().Format(time.RFC3339),
		ByEntityType:  map[string]int{},
		SampleRecords: make([]*AuditRecord, 0),
	}

	for iterator.HasNext() {
		entry, iterErr := iterator.Next()
		if iterErr != nil {
			return shim.Error(fmt.Sprintf("iterate audit records: %v", iterErr))
		}

		var record AuditRecord
		if err := json.Unmarshal(entry.Value, &record); err != nil {
			return shim.Error(fmt.Sprintf("unmarshal audit record: %v", err))
		}

		recordTime, err := time.Parse(time.RFC3339, record.CreatedAt)
		if err != nil {
			return shim.Error(fmt.Sprintf("parse audit timestamp: %v", err))
		}
		if recordTime.Before(startDate) || recordTime.After(endDate) {
			continue
		}

		report.TotalEvents++
		report.ByEntityType[record.EntityType]++
		switch record.RecordType {
		case "INVESTIGATOR_ACTION":
			report.InvestigatorActions++
		case "MODEL_PREDICTION":
			report.ModelPredictions++
		case "TRANSACTION_PROCESSED":
			report.TransactionsProcessed++
		case "SAR_FILED":
			report.SARsFiled++
		}
		if len(report.SampleRecords) < 10 {
			recordCopy := record
			report.SampleRecords = append(report.SampleRecords, &recordCopy)
		}
	}

	payload, _ := json.Marshal(report)
	return shim.Success(payload)
}

func newAuditRecord(
	stub shim.ChaincodeStubInterface,
	recordID, recordType, entityID, entityType, actorID, description string,
	data map[string]string,
) (*AuditRecord, error) {
	if err := validateAuditID(recordID, "recordID"); err != nil {
		return nil, err
	}
	if err := validateAuditID(entityID, "entityID"); err != nil {
		return nil, err
	}
	if err := validateAuditID(actorID, "actorID"); err != nil {
		return nil, err
	}
	if _, ok := allowedAuditTypes[recordType]; !ok {
		return nil, fmt.Errorf("invalid recordType %q", recordType)
	}
	if err := validateEntityType(entityType); err != nil {
		return nil, err
	}
	if strings.TrimSpace(description) == "" {
		return nil, fmt.Errorf("description is required")
	}

	existing, err := stub.GetState(auditStateKey(recordID))
	if err != nil {
		return nil, fmt.Errorf("read audit record: %w", err)
	}
	if len(existing) > 0 {
		return nil, fmt.Errorf("audit record %s already exists", recordID)
	}

	now, err := txTimestamp(stub)
	if err != nil {
		return nil, fmt.Errorf("resolve transaction timestamp: %w", err)
	}

	record := &AuditRecord{
		ObjectType:  objectTypeAudit,
		RecordID:    recordID,
		RecordType:  recordType,
		EntityID:    entityID,
		EntityType:  entityType,
		ActorID:     actorID,
		Description: description,
		Data:        sanitizeAuditData(data),
		CreatedAt:   now,
		TxID:        stub.GetTxID(),
	}
	record.Hash = hashAuditRecord(record)
	return record, nil
}

func writeAuditRecord(stub shim.ChaincodeStubInterface, record *AuditRecord) error {
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal audit record: %w", err)
	}
	if err := stub.PutState(auditStateKey(record.RecordID), payload); err != nil {
		return fmt.Errorf("write audit record: %w", err)
	}

	indexKey, err := stub.CreateCompositeKey(auditEntityIndex, []string{record.EntityType, record.EntityID, record.RecordID})
	if err != nil {
		return fmt.Errorf("create audit index key: %w", err)
	}
	if err := stub.PutState(indexKey, []byte{0}); err != nil {
		return fmt.Errorf("write audit index: %w", err)
	}
	if err := emitAuditEvent(stub, record); err != nil {
		return fmt.Errorf("emit audit event: %w", err)
	}
	return nil
}

func readAuditRecord(stub shim.ChaincodeStubInterface, recordID string) (*AuditRecord, error) {
	payload, err := stub.GetState(auditStateKey(recordID))
	if err != nil {
		return nil, fmt.Errorf("read audit record: %w", err)
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("audit record %s not found", recordID)
	}

	var record AuditRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		return nil, fmt.Errorf("unmarshal audit record: %w", err)
	}
	return &record, nil
}

func emitAuditEvent(stub shim.ChaincodeStubInterface, record *AuditRecord) error {
	payload, err := json.Marshal(auditEvent{
		EventType:  eventAuditRecorded,
		RecordID:   record.RecordID,
		RecordType: record.RecordType,
		EntityID:   record.EntityID,
		EntityType: record.EntityType,
		ActorID:    record.ActorID,
		Hash:       record.Hash,
		Data:       record.Data,
		TxID:       record.TxID,
		Timestamp:  record.CreatedAt,
	})
	if err != nil {
		return err
	}
	return stub.SetEvent(eventAuditRecorded, payload)
}

func sanitizeAuditData(data map[string]string) map[string]string {
	out := make(map[string]string, len(data))
	for key, value := range data {
		out[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return out
}

func hashAuditRecord(record *AuditRecord) string {
	normalized, _ := json.Marshal(struct {
		RecordID    string            `json:"recordID"`
		RecordType  string            `json:"recordType"`
		EntityID    string            `json:"entityID"`
		EntityType  string            `json:"entityType"`
		ActorID     string            `json:"actorID"`
		Description string            `json:"description"`
		Data        map[string]string `json:"data"`
		CreatedAt   string            `json:"createdAt"`
	}{
		RecordID:    record.RecordID,
		RecordType:  record.RecordType,
		EntityID:    record.EntityID,
		EntityType:  record.EntityType,
		ActorID:     record.ActorID,
		Description: record.Description,
		Data:        record.Data,
		CreatedAt:   record.CreatedAt,
	})
	sum := sha256.Sum256(normalized)
	return hex.EncodeToString(sum[:])
}

func auditStateKey(recordID string) string {
	return auditRecordPrefix + recordID
}

func validateAuditID(value, field string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", field)
	}
	return nil
}

func validateEntityType(entityType string) error {
	if _, ok := allowedEntityTypes[entityType]; !ok {
		return fmt.Errorf("invalid entityType %q", entityType)
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
