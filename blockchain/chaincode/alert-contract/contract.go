package main

import (
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
	alertRecordPrefix        = "ALERT_"
	alertCustomerIndex       = "alert~customer~alert"
	alertRiskLevelIndex      = "alert~risk~alert"
	alertStatusIndex         = "alert~status~alert"
	alertStatsKey            = "ALERT_STATS"
	objectTypeAlert          = "alert_record"
	eventAlertCreated        = "ALERT_CREATED"
	eventAlertStatusUpdated  = "ALERT_STATUS_UPDATED"
	alertStatusOpen          = "OPEN"
	alertStatusInvestigating = "INVESTIGATING"
	alertStatusResolved      = "RESOLVED"
	alertStatusEscalated     = "ESCALATED"
	alertStatusFalsePositive = "FALSE_POSITIVE"
)

var allowedAlertStatuses = map[string]struct{}{
	alertStatusOpen:          {},
	alertStatusInvestigating: {},
	alertStatusResolved:      {},
	alertStatusEscalated:     {},
	alertStatusFalsePositive: {},
}

var allowedAlertRiskLevels = map[string]struct{}{
	"LOW":      {},
	"MEDIUM":   {},
	"HIGH":     {},
	"CRITICAL": {},
}

type AlertRecord struct {
	ObjectType string `json:"objectType"`
	AlertID    string `json:"alertID"`
	CustomerID string `json:"customerID"`
	TxHash     string `json:"txHash"`

	FraudProb    float64 `json:"fraudProb"`
	RiskScore    float64 `json:"riskScore"`
	RiskLevel    string  `json:"riskLevel"`
	Status       string  `json:"status"`
	ModelVersion string  `json:"modelVersion"`

	InvestigatorID string `json:"investigatorID,omitempty"`
	Notes          string `json:"notes,omitempty"`

	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
	TxID      string `json:"txId"`
}

type AlertStatistics struct {
	TotalAlerts         int     `json:"totalAlerts"`
	OpenAlerts          int     `json:"openAlerts"`
	CriticalAlerts      int     `json:"criticalAlerts"`
	HighAlerts          int     `json:"highAlerts"`
	MediumAlerts        int     `json:"mediumAlerts"`
	LowAlerts           int     `json:"lowAlerts"`
	ResolvedAlerts      int     `json:"resolvedAlerts"`
	FalsePositives      int     `json:"falsePositives"`
	InvestigatingAlerts int     `json:"investigatingAlerts"`
	EscalatedAlerts     int     `json:"escalatedAlerts"`
	AverageFraudProb    float64 `json:"averageFraudProb"`
}

type alertEvent struct {
	EventType      string  `json:"eventType"`
	AlertID        string  `json:"alertID"`
	CustomerID     string  `json:"customerID"`
	Status         string  `json:"status"`
	RiskLevel      string  `json:"riskLevel"`
	FraudProb      float64 `json:"fraudProb"`
	RiskScore      float64 `json:"riskScore"`
	InvestigatorID string  `json:"investigatorID,omitempty"`
	Notes          string  `json:"notes,omitempty"`
	TxID           string  `json:"txId"`
	Timestamp      string  `json:"timestamp"`
}

type AlertChaincode struct{}

func (c *AlertChaincode) Init(stub shim.ChaincodeStubInterface) pb.Response {
	return shim.Success(nil)
}

func (c *AlertChaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	function, args := stub.GetFunctionAndParameters()

	switch function {
	case "CreateAlert":
		return c.CreateAlert(stub, args)
	case "UpdateAlertStatus":
		return c.UpdateAlertStatus(stub, args)
	case "GetAlertsByCustomer":
		return c.GetAlertsByCustomer(stub, args)
	case "GetAlertsByRiskLevel":
		return c.GetAlertsByRiskLevel(stub, args)
	case "GetAlertStats":
		return c.GetAlertStats(stub, args)
	default:
		return shim.Error(fmt.Sprintf("unsupported function %q", function))
	}
}

func (c *AlertChaincode) CreateAlert(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 6 {
		return shim.Error("CreateAlert requires 6 arguments: alertID, customerID, txHash, fraudProb, riskScore, modelVersion")
	}

	alertID := strings.TrimSpace(args[0])
	customerID := strings.TrimSpace(args[1])
	txHash := strings.TrimSpace(args[2])
	fraudProb, err := parseProbability(args[3], "fraudProb")
	if err != nil {
		return shim.Error(err.Error())
	}
	riskScore, err := parseRiskScore(args[4])
	if err != nil {
		return shim.Error(err.Error())
	}
	modelVersion := strings.TrimSpace(args[5])

	if err := validateIdentifier("alertID", alertID); err != nil {
		return shim.Error(err.Error())
	}
	if err := validateIdentifier("customerID", customerID); err != nil {
		return shim.Error(err.Error())
	}
	if err := validateIdentifier("txHash", txHash); err != nil {
		return shim.Error(err.Error())
	}
	if modelVersion == "" {
		return shim.Error("modelVersion is required")
	}

	existing, err := stub.GetState(alertStateKey(alertID))
	if err != nil {
		return shim.Error(fmt.Sprintf("read alert record: %v", err))
	}
	if len(existing) > 0 {
		return shim.Error("alert already exists on ledger")
	}

	now, err := txTimestamp(stub)
	if err != nil {
		return shim.Error(fmt.Sprintf("resolve transaction timestamp: %v", err))
	}

	record := &AlertRecord{
		ObjectType:   objectTypeAlert,
		AlertID:      alertID,
		CustomerID:   customerID,
		TxHash:       txHash,
		FraudProb:    fraudProb,
		RiskScore:    riskScore,
		RiskLevel:    deriveRiskLevel(fraudProb),
		Status:       alertStatusOpen,
		ModelVersion: modelVersion,
		CreatedAt:    now,
		UpdatedAt:    now,
		TxID:         stub.GetTxID(),
	}

	if err := putAlertRecord(stub, record); err != nil {
		return shim.Error(err.Error())
	}
	if err := upsertAlertIndexes(stub, nil, record); err != nil {
		return shim.Error(fmt.Sprintf("create alert indexes: %v", err))
	}
	if err := rebuildAlertStats(stub); err != nil {
		return shim.Error(fmt.Sprintf("rebuild alert stats: %v", err))
	}
	if err := emitAlertEvent(stub, eventAlertCreated, record); err != nil {
		return shim.Error(fmt.Sprintf("emit alert event: %v", err))
	}

	payload, _ := json.Marshal(record)
	return shim.Success(payload)
}

func (c *AlertChaincode) UpdateAlertStatus(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 4 {
		return shim.Error("UpdateAlertStatus requires 4 arguments: alertID, status, investigatorID, notes")
	}

	alertID := strings.TrimSpace(args[0])
	newStatus := normalizeEnum(args[1])
	investigatorID := strings.TrimSpace(args[2])
	notes := strings.TrimSpace(args[3])

	if err := validateIdentifier("alertID", alertID); err != nil {
		return shim.Error(err.Error())
	}
	if err := validateAlertStatus(newStatus); err != nil {
		return shim.Error(err.Error())
	}
	if newStatus != alertStatusOpen && investigatorID == "" {
		return shim.Error("investigatorID is required for non-open statuses")
	}
	if requiresAlertNotes(newStatus) && notes == "" {
		return shim.Error("notes are required for resolved, escalated, or false positive alerts")
	}

	record, err := readAlertRecord(stub, alertID)
	if err != nil {
		return shim.Error(err.Error())
	}
	if err := validateAlertStatusTransition(record.Status, newStatus); err != nil {
		return shim.Error(err.Error())
	}

	now, err := txTimestamp(stub)
	if err != nil {
		return shim.Error(fmt.Sprintf("resolve transaction timestamp: %v", err))
	}

	previous := *record
	record.Status = newStatus
	record.InvestigatorID = investigatorID
	record.Notes = notes
	record.UpdatedAt = now
	record.TxID = stub.GetTxID()

	if err := putAlertRecord(stub, record); err != nil {
		return shim.Error(err.Error())
	}
	if err := upsertAlertIndexes(stub, &previous, record); err != nil {
		return shim.Error(fmt.Sprintf("update alert indexes: %v", err))
	}
	if err := rebuildAlertStats(stub); err != nil {
		return shim.Error(fmt.Sprintf("rebuild alert stats: %v", err))
	}
	if err := emitAlertEvent(stub, eventAlertStatusUpdated, record); err != nil {
		return shim.Error(fmt.Sprintf("emit alert event: %v", err))
	}

	payload, _ := json.Marshal(record)
	return shim.Success(payload)
}

func (c *AlertChaincode) GetAlertsByCustomer(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 1 {
		return shim.Error("GetAlertsByCustomer requires 1 argument: customerID")
	}

	customerID := strings.TrimSpace(args[0])
	if err := validateIdentifier("customerID", customerID); err != nil {
		return shim.Error(err.Error())
	}

	iterator, err := stub.GetStateByPartialCompositeKey(alertCustomerIndex, []string{customerID})
	if err != nil {
		return shim.Error(fmt.Sprintf("list customer alerts: %v", err))
	}
	defer iterator.Close()

	records := make([]*AlertRecord, 0)
	for iterator.HasNext() {
		entry, iterErr := iterator.Next()
		if iterErr != nil {
			return shim.Error(fmt.Sprintf("iterate customer alerts: %v", iterErr))
		}
		_, parts, splitErr := stub.SplitCompositeKey(entry.Key)
		if splitErr != nil || len(parts) != 2 {
			return shim.Error(fmt.Sprintf("split customer alert key: %v", splitErr))
		}
		record, readErr := readAlertRecord(stub, parts[1])
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

func (c *AlertChaincode) GetAlertsByRiskLevel(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 1 {
		return shim.Error("GetAlertsByRiskLevel requires 1 argument: level")
	}

	level := normalizeEnum(args[0])
	if err := validateAlertRiskLevel(level); err != nil {
		return shim.Error(err.Error())
	}

	query := fmt.Sprintf(`{"selector":{"objectType":"%s","riskLevel":"%s"}}`, objectTypeAlert, level)
	iterator, err := stub.GetQueryResult(query)
	if err == nil {
		defer iterator.Close()

		records := make([]*AlertRecord, 0)
		for iterator.HasNext() {
			entry, iterErr := iterator.Next()
			if iterErr != nil {
				return shim.Error(fmt.Sprintf("iterate risk level query: %v", iterErr))
			}
			var record AlertRecord
			if err := json.Unmarshal(entry.Value, &record); err != nil {
				return shim.Error(fmt.Sprintf("unmarshal alert record: %v", err))
			}
			records = append(records, &record)
		}

		sort.Slice(records, func(i, j int) bool {
			return records[i].CreatedAt < records[j].CreatedAt
		})

		payload, _ := json.Marshal(records)
		return shim.Success(payload)
	}

	iterator, err = stub.GetStateByPartialCompositeKey(alertRiskLevelIndex, []string{level})
	if err != nil {
		return shim.Error(fmt.Sprintf("query alerts by risk level: %v", err))
	}
	defer iterator.Close()

	records := make([]*AlertRecord, 0)
	for iterator.HasNext() {
		entry, iterErr := iterator.Next()
		if iterErr != nil {
			return shim.Error(fmt.Sprintf("iterate risk level alerts: %v", iterErr))
		}
		_, parts, splitErr := stub.SplitCompositeKey(entry.Key)
		if splitErr != nil || len(parts) != 2 {
			return shim.Error(fmt.Sprintf("split risk level alert key: %v", splitErr))
		}
		record, readErr := readAlertRecord(stub, parts[1])
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

func (c *AlertChaincode) GetAlertStats(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 0 {
		return shim.Error("GetAlertStats does not accept arguments")
	}

	stats, err := readAlertStats(stub)
	if err != nil {
		return shim.Error(err.Error())
	}

	payload, _ := json.Marshal(stats)
	return shim.Success(payload)
}

func putAlertRecord(stub shim.ChaincodeStubInterface, record *AlertRecord) error {
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal alert record: %w", err)
	}
	if err := stub.PutState(alertStateKey(record.AlertID), payload); err != nil {
		return fmt.Errorf("write alert record: %w", err)
	}
	return nil
}

func readAlertRecord(stub shim.ChaincodeStubInterface, alertID string) (*AlertRecord, error) {
	if err := validateIdentifier("alertID", alertID); err != nil {
		return nil, err
	}

	payload, err := stub.GetState(alertStateKey(alertID))
	if err != nil {
		return nil, fmt.Errorf("read alert record: %w", err)
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("alert record %s not found", alertID)
	}

	var record AlertRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		return nil, fmt.Errorf("unmarshal alert record: %w", err)
	}
	return &record, nil
}

func upsertAlertIndexes(stub shim.ChaincodeStubInterface, previous, current *AlertRecord) error {
	if previous != nil {
		if previous.CustomerID != current.CustomerID {
			if err := deleteCompositeIndex(stub, alertCustomerIndex, []string{previous.CustomerID, previous.AlertID}); err != nil {
				return err
			}
		}
		if previous.RiskLevel != current.RiskLevel {
			if err := deleteCompositeIndex(stub, alertRiskLevelIndex, []string{previous.RiskLevel, previous.AlertID}); err != nil {
				return err
			}
		}
		if previous.Status != current.Status {
			if err := deleteCompositeIndex(stub, alertStatusIndex, []string{previous.Status, previous.AlertID}); err != nil {
				return err
			}
		}
	}

	if err := putCompositeIndex(stub, alertCustomerIndex, []string{current.CustomerID, current.AlertID}); err != nil {
		return err
	}
	if err := putCompositeIndex(stub, alertRiskLevelIndex, []string{current.RiskLevel, current.AlertID}); err != nil {
		return err
	}
	if err := putCompositeIndex(stub, alertStatusIndex, []string{current.Status, current.AlertID}); err != nil {
		return err
	}
	return nil
}

func rebuildAlertStats(stub shim.ChaincodeStubInterface) error {
	iterator, err := stub.GetStateByRange(alertRecordPrefix, alertRecordPrefix+"~")
	if err != nil {
		return fmt.Errorf("scan alert records: %w", err)
	}
	defer iterator.Close()

	stats := &AlertStatistics{}
	var fraudProbTotal float64

	for iterator.HasNext() {
		entry, iterErr := iterator.Next()
		if iterErr != nil {
			return fmt.Errorf("iterate alert records: %w", iterErr)
		}

		var record AlertRecord
		if err := json.Unmarshal(entry.Value, &record); err != nil {
			return fmt.Errorf("unmarshal alert record: %w", err)
		}

		stats.TotalAlerts++
		fraudProbTotal += record.FraudProb

		switch record.RiskLevel {
		case "CRITICAL":
			stats.CriticalAlerts++
		case "HIGH":
			stats.HighAlerts++
		case "MEDIUM":
			stats.MediumAlerts++
		case "LOW":
			stats.LowAlerts++
		}

		switch record.Status {
		case alertStatusOpen:
			stats.OpenAlerts++
		case alertStatusInvestigating:
			stats.InvestigatingAlerts++
		case alertStatusResolved:
			stats.ResolvedAlerts++
		case alertStatusFalsePositive:
			stats.FalsePositives++
		case alertStatusEscalated:
			stats.EscalatedAlerts++
		}
	}

	if stats.TotalAlerts > 0 {
		stats.AverageFraudProb = fraudProbTotal / float64(stats.TotalAlerts)
	}

	payload, err := json.Marshal(stats)
	if err != nil {
		return fmt.Errorf("marshal alert stats: %w", err)
	}
	if err := stub.PutState(alertStatsKey, payload); err != nil {
		return fmt.Errorf("write alert stats: %w", err)
	}
	return nil
}

func readAlertStats(stub shim.ChaincodeStubInterface) (*AlertStatistics, error) {
	payload, err := stub.GetState(alertStatsKey)
	if err != nil {
		return nil, fmt.Errorf("read alert stats: %w", err)
	}
	if len(payload) == 0 {
		return &AlertStatistics{}, nil
	}

	var stats AlertStatistics
	if err := json.Unmarshal(payload, &stats); err != nil {
		return nil, fmt.Errorf("unmarshal alert stats: %w", err)
	}
	return &stats, nil
}

func putCompositeIndex(stub shim.ChaincodeStubInterface, objectType string, attrs []string) error {
	key, err := stub.CreateCompositeKey(objectType, attrs)
	if err != nil {
		return err
	}
	return stub.PutState(key, []byte{0})
}

func deleteCompositeIndex(stub shim.ChaincodeStubInterface, objectType string, attrs []string) error {
	key, err := stub.CreateCompositeKey(objectType, attrs)
	if err != nil {
		return err
	}
	return stub.DelState(key)
}

func emitAlertEvent(stub shim.ChaincodeStubInterface, eventType string, record *AlertRecord) error {
	payload, err := json.Marshal(alertEvent{
		EventType:      eventType,
		AlertID:        record.AlertID,
		CustomerID:     record.CustomerID,
		Status:         record.Status,
		RiskLevel:      record.RiskLevel,
		FraudProb:      record.FraudProb,
		RiskScore:      record.RiskScore,
		InvestigatorID: record.InvestigatorID,
		Notes:          record.Notes,
		TxID:           record.TxID,
		Timestamp:      record.UpdatedAt,
	})
	if err != nil {
		return err
	}
	return stub.SetEvent(eventType, payload)
}

func alertStateKey(alertID string) string {
	return alertRecordPrefix + alertID
}

func deriveRiskLevel(fraudProb float64) string {
	switch {
	case fraudProb > 0.85:
		return "CRITICAL"
	case fraudProb >= 0.70:
		return "HIGH"
	case fraudProb >= 0.50:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func validateAlertStatus(status string) error {
	if _, ok := allowedAlertStatuses[status]; !ok {
		return fmt.Errorf("invalid alert status %q", status)
	}
	return nil
}

func validateAlertRiskLevel(level string) error {
	if _, ok := allowedAlertRiskLevels[level]; !ok {
		return fmt.Errorf("invalid alert risk level %q", level)
	}
	return nil
}

func validateAlertStatusTransition(from, to string) error {
	if from == to {
		return fmt.Errorf("alert already has status %s", to)
	}

	allowed := map[string]map[string]struct{}{
		alertStatusOpen: {
			alertStatusInvestigating: {},
			alertStatusEscalated:     {},
			alertStatusResolved:      {},
			alertStatusFalsePositive: {},
		},
		alertStatusInvestigating: {
			alertStatusResolved:      {},
			alertStatusFalsePositive: {},
			alertStatusEscalated:     {},
		},
		alertStatusEscalated: {
			alertStatusInvestigating: {},
			alertStatusResolved:      {},
		},
		alertStatusResolved:      {},
		alertStatusFalsePositive: {},
	}

	targets, ok := allowed[from]
	if !ok {
		return fmt.Errorf("unsupported source alert status %q", from)
	}
	if _, ok := targets[to]; !ok {
		return fmt.Errorf("invalid alert status transition from %s to %s", from, to)
	}
	return nil
}

func requiresAlertNotes(status string) bool {
	return status == alertStatusResolved || status == alertStatusEscalated || status == alertStatusFalsePositive
}

func parseProbability(raw, field string) (float64, error) {
	value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil {
		return 0, fmt.Errorf("%s must be a valid float", field)
	}
	if value < 0 || value > 1 {
		return 0, fmt.Errorf("%s must be between 0 and 1", field)
	}
	return value, nil
}

func parseRiskScore(raw string) (float64, error) {
	value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil {
		return 0, fmt.Errorf("riskScore must be a valid float")
	}
	if value < 0 || value > 100 {
		return 0, fmt.Errorf("riskScore must be between 0 and 100")
	}
	return value, nil
}

func validateIdentifier(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", field)
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
