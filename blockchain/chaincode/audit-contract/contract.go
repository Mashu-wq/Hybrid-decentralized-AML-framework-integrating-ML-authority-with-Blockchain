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

	"github.com/golang/protobuf/proto" //nolint:staticcheck // fabric-protos-go v0.3.x messages only implement the legacy proto API
	"github.com/hyperledger/fabric-chaincode-go/shim"
	mspproto "github.com/hyperledger/fabric-protos-go/msp"
	pb "github.com/hyperledger/fabric-protos-go/peer"
)

const (
	auditRecordPrefix  = "AUDIT_"
	auditEntityIndex   = "audit~entityType~entityID~recordID"
	objectTypeAudit    = "audit_record"
	eventAuditRecorded = "AUDIT_RECORDED"

	// receiptSeqPrefix keys the per-org receipt counter. It deliberately sorts
	// outside the [AUDIT_, AUDIT_~) range scanned by GetComplianceReport.
	receiptSeqPrefix = "SEQ_TXPROC_"

	// collectionTxDetails is the Private Data Collection holding transaction
	// receipt details (customer pseudonym, amount, corridor). Membership is
	// restricted to the issuing bank and the regulator — see
	// collections_config.json. Only SHA-256(details) appears on the shared ledger.
	collectionTxDetails = "auditTransactionDetails"

	// transientReceiptKey is the transient-map key carrying the private details.
	transientReceiptKey = "receipt_details"
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
	case "GetSequenceStatus":
		return c.GetSequenceStatus(stub, args)
	case "GetReceiptDetails":
		return c.GetReceiptDetails(stub, args)
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

// receiptDetails is the private half of a processing receipt. It travels in the
// transient map (never in the public transaction payload) and is stored only in
// the auditTransactionDetails collection (issuing bank + regulator). The shared
// ledger sees only its SHA-256 digest.
type receiptDetails struct {
	CustomerID   string  `json:"customerId"` // pseudonymized (HMAC) by the submitting org
	AmountUSD    float64 `json:"amountUsd"`
	CurrencyCode string  `json:"currencyCode"`
	Channel      string  `json:"channel"`
	CountryCode  string  `json:"countryCode"`
}

// RecordTransactionProcessed writes a tamper-evident processing receipt to the ledger
// for every transaction that passes through the ML pipeline — whether flagged or not.
//
// Completeness: each receipt is stamped with a chaincode-assigned, per-organization
// sequence number (last+1, gap-free by construction). The regulator reads the latest
// sequence via GetSequenceStatus and reconciles it against the bank's reported
// transaction volume: any processed transaction without a receipt is a provable
// count mismatch, and receipts cannot be backfilled without a visible skew between
// their sequence order and their processedAt timestamps.
//
// Privacy: business details (customer pseudonym, amount, corridor) arrive in the
// transient map and are written only to the auditTransactionDetails private data
// collection. The public record carries fraud metadata plus detailsHash =
// SHA-256(private payload), binding the private data to the shared ledger.
//
// args: recordID, txHash, processedAt (RFC3339), fraudProbability (0-1), riskLevel,
//
//	alertFired (true|false), alertID, modelVersion, predictionID
//
// transient["receipt_details"]: JSON-encoded receiptDetails (required)
func (c *AuditChaincode) RecordTransactionProcessed(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	const expectedArgs = 9
	if len(args) != expectedArgs {
		return shim.Error(fmt.Sprintf(
			"RecordTransactionProcessed requires %d arguments: "+
				"recordID, txHash, processedAt, fraudProbability, riskLevel, "+
				"alertFired, alertID, modelVersion, predictionID "+
				"(private details go in transient key %q)",
			expectedArgs, transientReceiptKey,
		))
	}

	recordID      := strings.TrimSpace(args[0])
	txHash        := strings.TrimSpace(args[1])
	processedAt   := strings.TrimSpace(args[2])
	fraudProbStr  := strings.TrimSpace(args[3])
	riskLevel     := normalizeEnum(args[4])
	alertFiredStr := strings.TrimSpace(args[5])
	alertID       := strings.TrimSpace(args[6])
	modelVersion  := strings.TrimSpace(args[7])
	predictionID  := strings.TrimSpace(args[8])

	// Required field checks
	if err := validateAuditID(txHash, "txHash"); err != nil {
		return shim.Error(err.Error())
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

	// --- Private details (transient map → PDC) ---
	detailsBytes, err := receiptDetailsFromTransient(stub)
	if err != nil {
		return shim.Error(err.Error())
	}
	detailsSum := sha256.Sum256(detailsBytes)
	detailsHash := hex.EncodeToString(detailsSum[:])

	// --- Per-org gap-free sequence number ---
	mspID, err := submitterMSPID(stub)
	if err != nil {
		return shim.Error(err.Error())
	}
	sequence, err := nextReceiptSequence(stub, mspID)
	if err != nil {
		return shim.Error(err.Error())
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
			"processedAt":      processedAt,
			"fraudProbability": fraudProbStr,
			"riskLevel":        riskLevel,
			"alertFired":       alertFiredStr,
			"alertID":          alertID,
			"modelVersion":     modelVersion,
			"predictionID":     predictionID,
			"sequenceNumber":   strconv.FormatUint(sequence, 10),
			"submitterMSP":     mspID,
			"detailsHash":      detailsHash,
		},
	)
	if err != nil {
		return shim.Error(err.Error())
	}

	if err := stub.PutPrivateData(collectionTxDetails, recordID, detailsBytes); err != nil {
		return shim.Error(fmt.Sprintf("write private receipt details: %v", err))
	}
	if err := writeAuditRecord(stub, record); err != nil {
		return shim.Error(err.Error())
	}

	payload, _ := json.Marshal(record)
	return shim.Success(payload)
}

// receiptDetailsFromTransient extracts and validates the private receipt details
// from the transient map, returning the raw bytes that are hashed and stored.
func receiptDetailsFromTransient(stub shim.ChaincodeStubInterface) ([]byte, error) {
	transient, err := stub.GetTransient()
	if err != nil {
		return nil, fmt.Errorf("read transient map: %v", err)
	}
	detailsBytes, ok := transient[transientReceiptKey]
	if !ok || len(detailsBytes) == 0 {
		return nil, fmt.Errorf("transient key %q with private receipt details is required", transientReceiptKey)
	}

	var details receiptDetails
	if err := json.Unmarshal(detailsBytes, &details); err != nil {
		return nil, fmt.Errorf("invalid receipt details JSON: %v", err)
	}
	if strings.TrimSpace(details.CustomerID) == "" {
		return nil, fmt.Errorf("receipt details: customerId is required")
	}
	if details.AmountUSD < 0 {
		return nil, fmt.Errorf("receipt details: amountUsd must be non-negative")
	}
	return detailsBytes, nil
}

// submitterMSPID resolves the MSP ID of the organization that submitted the
// transaction, from the creator's serialized identity.
func submitterMSPID(stub shim.ChaincodeStubInterface) (string, error) {
	creator, err := stub.GetCreator()
	if err != nil {
		return "", fmt.Errorf("get transaction creator: %v", err)
	}
	if len(creator) == 0 {
		return "", fmt.Errorf("transaction creator is empty")
	}
	sid := &mspproto.SerializedIdentity{}
	if err := proto.Unmarshal(creator, sid); err != nil {
		return "", fmt.Errorf("unmarshal creator identity: %v", err)
	}
	if strings.TrimSpace(sid.Mspid) == "" {
		return "", fmt.Errorf("creator MSP ID is empty")
	}
	return sid.Mspid, nil
}

// nextReceiptSequence increments and persists the per-org receipt counter.
// Because the counter lives in world state and every increment is endorsed and
// ordered, the committed receipt series for an org is contiguous by construction:
// receipt N exists for every N ≤ latest. Concurrent submissions from the same org
// serialize via MVCC (the client retries on conflict).
func nextReceiptSequence(stub shim.ChaincodeStubInterface, mspID string) (uint64, error) {
	key := receiptSeqPrefix + mspID

	raw, err := stub.GetState(key)
	if err != nil {
		return 0, fmt.Errorf("read receipt sequence: %v", err)
	}
	var last uint64
	if len(raw) > 0 {
		last, err = strconv.ParseUint(string(raw), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("corrupt receipt sequence state %q: %v", string(raw), err)
		}
	}

	next := last + 1
	if err := stub.PutState(key, []byte(strconv.FormatUint(next, 10))); err != nil {
		return 0, fmt.Errorf("write receipt sequence: %v", err)
	}
	return next, nil
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

// SequenceStatus reports the latest receipt sequence number for one organization.
type SequenceStatus struct {
	MSPID          string `json:"mspId"`
	LatestSequence uint64 `json:"latestSequence"`
}

// GetSequenceStatus returns the latest TRANSACTION_PROCESSED sequence number per
// organization. This is the regulator's completeness checkpoint: the on-chain
// receipt series for an org is gap-free by construction, so latestSequence equals
// the exact number of receipts that org has ever anchored. Reconciling it against
// the bank's independently reported transaction volume makes omission provable.
//
// args: none
func (c *AuditChaincode) GetSequenceStatus(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 0 {
		return shim.Error("GetSequenceStatus takes no arguments")
	}

	iterator, err := stub.GetStateByRange(receiptSeqPrefix, receiptSeqPrefix+"~")
	if err != nil {
		return shim.Error(fmt.Sprintf("scan receipt sequences: %v", err))
	}
	defer iterator.Close()

	statuses := make([]SequenceStatus, 0)
	for iterator.HasNext() {
		entry, iterErr := iterator.Next()
		if iterErr != nil {
			return shim.Error(fmt.Sprintf("iterate receipt sequences: %v", iterErr))
		}
		latest, parseErr := strconv.ParseUint(string(entry.Value), 10, 64)
		if parseErr != nil {
			return shim.Error(fmt.Sprintf("corrupt receipt sequence state for key %s: %v", entry.Key, parseErr))
		}
		statuses = append(statuses, SequenceStatus{
			MSPID:          strings.TrimPrefix(entry.Key, receiptSeqPrefix),
			LatestSequence: latest,
		})
	}

	payload, _ := json.Marshal(statuses)
	return shim.Success(payload)
}

// ReceiptDetailsResponse pairs the private receipt details with the integrity
// verdict obtained by re-hashing them against the public record's detailsHash.
type ReceiptDetailsResponse struct {
	RecordID    string          `json:"recordID"`
	DetailsHash string          `json:"detailsHash"`
	Verified    bool            `json:"verified"`
	Details     json.RawMessage `json:"details"`
}

// GetReceiptDetails returns the private half of a processing receipt from the
// auditTransactionDetails collection and verifies it against the detailsHash
// anchored in the public record. Only collection members (issuing bank and
// regulator) can evaluate this successfully — a non-member peer has no copy of
// the private data.
//
// args: recordID
func (c *AuditChaincode) GetReceiptDetails(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 1 {
		return shim.Error("GetReceiptDetails requires 1 argument: recordID")
	}
	recordID := strings.TrimSpace(args[0])
	if err := validateAuditID(recordID, "recordID"); err != nil {
		return shim.Error(err.Error())
	}

	record, err := readAuditRecord(stub, recordID)
	if err != nil {
		return shim.Error(err.Error())
	}
	if record.RecordType != "TRANSACTION_PROCESSED" {
		return shim.Error(fmt.Sprintf("record %s is not a TRANSACTION_PROCESSED receipt", recordID))
	}

	detailsBytes, err := stub.GetPrivateData(collectionTxDetails, recordID)
	if err != nil {
		return shim.Error(fmt.Sprintf("read private receipt details: %v", err))
	}
	if len(detailsBytes) == 0 {
		return shim.Error(fmt.Sprintf(
			"private details for %s not found (this peer's org may not be a member of collection %s)",
			recordID, collectionTxDetails,
		))
	}

	sum := sha256.Sum256(detailsBytes)
	resp := ReceiptDetailsResponse{
		RecordID:    recordID,
		DetailsHash: record.Data["detailsHash"],
		Verified:    hex.EncodeToString(sum[:]) == record.Data["detailsHash"],
		Details:     json.RawMessage(detailsBytes),
	}

	payload, _ := json.Marshal(resp)
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
