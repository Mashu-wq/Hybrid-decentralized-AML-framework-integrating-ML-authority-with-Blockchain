package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fraud-detection/case-service/internal/domain"
	"github.com/fraud-detection/case-service/internal/pdf"
	"github.com/fraud-detection/case-service/internal/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Inline mocks
// ---------------------------------------------------------------------------

type mockStore struct {
	cases      map[string]*domain.Case
	casesByAlert map[string]*domain.Case
	evidence   map[string][]*domain.Evidence
	actions    map[string][]*domain.CaseAction
	createErr  error
	getErr     error
	pingErr    error
}

func newMockStore() *mockStore {
	return &mockStore{
		cases:        make(map[string]*domain.Case),
		casesByAlert: make(map[string]*domain.Case),
		evidence:     make(map[string][]*domain.Evidence),
		actions:      make(map[string][]*domain.CaseAction),
	}
}

func (m *mockStore) CreateCase(_ context.Context, c *domain.Case) error {
	if m.createErr != nil {
		return m.createErr
	}
	if _, exists := m.casesByAlert[c.AlertID]; exists {
		return domain.ErrDuplicateCase
	}
	m.cases[c.CaseID] = c
	m.casesByAlert[c.AlertID] = c
	return nil
}
func (m *mockStore) GetCaseByID(_ context.Context, id string) (*domain.Case, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	c, ok := m.cases[id]
	if !ok {
		return nil, domain.ErrCaseNotFound
	}
	return c, nil
}
func (m *mockStore) GetCaseByAlertID(_ context.Context, alertID string) (*domain.Case, error) {
	c, ok := m.casesByAlert[alertID]
	if !ok {
		return nil, domain.ErrCaseNotFound
	}
	return c, nil
}
func (m *mockStore) ListCases(_ context.Context, _ domain.CaseFilters) ([]*domain.Case, int, error) {
	var out []*domain.Case
	for _, c := range m.cases {
		out = append(out, c)
	}
	return out, len(out), nil
}
func (m *mockStore) UpdateCaseStatus(_ context.Context, caseID, _, notes string, newStatus domain.CaseStatus, res string) (*domain.Case, error) {
	c, ok := m.cases[caseID]
	if !ok {
		return nil, domain.ErrCaseNotFound
	}
	if err := domain.ValidateTransition(c.Status, newStatus); err != nil {
		return nil, domain.ErrInvalidTransition
	}
	c.Status = newStatus
	c.ResolutionSummary = res
	return c, nil
}
func (m *mockStore) AssignCase(_ context.Context, caseID, assigneeID, _ string) (*domain.Case, error) {
	c, ok := m.cases[caseID]
	if !ok {
		return nil, domain.ErrCaseNotFound
	}
	c.AssigneeID = assigneeID
	return c, nil
}
func (m *mockStore) SetSAR(_ context.Context, caseID, s3Key, _ string) (*domain.Case, error) {
	c, ok := m.cases[caseID]
	if !ok {
		return nil, domain.ErrCaseNotFound
	}
	if c.SARS3Key != "" {
		return nil, domain.ErrSARAlreadyExists
	}
	c.SARS3Key = s3Key
	c.Status = domain.CaseStatusPendingSAR
	return c, nil
}
func (m *mockStore) UpdateCaseBlockchainTxID(_ context.Context, caseID, txID string) error {
	if c, ok := m.cases[caseID]; ok {
		c.BlockchainTxID = txID
	}
	return nil
}
func (m *mockStore) AddEvidence(_ context.Context, e *domain.Evidence) error {
	m.evidence[e.CaseID] = append(m.evidence[e.CaseID], e)
	return nil
}
func (m *mockStore) GetEvidence(_ context.Context, caseID, evidenceID string) ([]*domain.Evidence, error) {
	evs := m.evidence[caseID]
	if evidenceID == "" {
		return evs, nil
	}
	for _, e := range evs {
		if e.EvidenceID == evidenceID {
			return []*domain.Evidence{e}, nil
		}
	}
	return nil, domain.ErrEvidenceNotFound
}
func (m *mockStore) DeleteEvidence(_ context.Context, caseID, evidenceID, _ string) error {
	evs := m.evidence[caseID]
	for i, e := range evs {
		if e.EvidenceID == evidenceID {
			m.evidence[caseID] = append(evs[:i], evs[i+1:]...)
			return nil
		}
	}
	return domain.ErrEvidenceNotFound
}
func (m *mockStore) GetActions(_ context.Context, caseID string) ([]*domain.CaseAction, error) {
	return m.actions[caseID], nil
}
func (m *mockStore) LogAction(_ context.Context, a *domain.CaseAction) error {
	m.actions[a.CaseID] = append(m.actions[a.CaseID], a)
	return nil
}
func (m *mockStore) GetInvestigatorWorkload(_ context.Context, _ []string) ([]*domain.InvestigatorWorkload, error) {
	return []*domain.InvestigatorWorkload{{InvestigatorID: "inv-1", ActiveCases: 3}}, nil
}
func (m *mockStore) GetStats(_ context.Context, period string) (*domain.CaseStats, error) {
	return &domain.CaseStats{Period: period, TotalCases: 10}, nil
}
func (m *mockStore) Ping(_ context.Context) error { return m.pingErr }

// ----

type mockEvidenceStore struct {
	putURLs  map[string]string
	getURLs  map[string]string
	deleted  []string
	putErr   error
}

func newMockEvidenceStore() *mockEvidenceStore {
	return &mockEvidenceStore{
		putURLs: make(map[string]string),
		getURLs: make(map[string]string),
	}
}
func (m *mockEvidenceStore) PresignPutURL(_ context.Context, key, _ string) (string, error) {
	return "https://s3.example.com/put/" + key, nil
}
func (m *mockEvidenceStore) PresignGetURL(_ context.Context, key string) (string, error) {
	return "https://s3.example.com/get/" + key, nil
}
func (m *mockEvidenceStore) PutObject(_ context.Context, _, _ string, _ []byte) error {
	return m.putErr
}
func (m *mockEvidenceStore) DeleteObject(_ context.Context, key string) error {
	m.deleted = append(m.deleted, key)
	return nil
}

// ----

type mockBlockchain struct {
	recorded []string
	pingErr  error
}

func (m *mockBlockchain) RecordInvestigatorAction(_ context.Context, actionID, _, caseID, action, _ string) (string, error) {
	m.recorded = append(m.recorded, action)
	return "fabric-tx-" + actionID[:8], nil
}
func (m *mockBlockchain) UpdateAlertStatus(_ context.Context, _, _, _, _ string) (string, error) {
	return "fabric-tx-alert", nil
}
func (m *mockBlockchain) Ping(_ context.Context) error { return m.pingErr }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newSvc(store *mockStore, ev *mockEvidenceStore, bc *mockBlockchain, investigators []string) *service.CaseService {
	sarGen := pdf.NewGenerator("Test Bank", "123 Main St")
	return service.New(store, ev, bc, sarGen, "test-bucket", investigators, 0.85)
}

func validAlertEvent(prob float64) *domain.AlertEvent {
	return &domain.AlertEvent{
		AlertID:          "alert-001",
		CustomerID:       "cust-001",
		TxHash:           "0xabc123",
		FraudProbability: prob,
		RiskScore:        prob * 100,
		ModelVersion:     "v1.0",
		CreatedAt:        time.Now(),
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestCreateCaseFromAlert_Critical(t *testing.T) {
	store := newMockStore()
	ev := newMockEvidenceStore()
	bc := &mockBlockchain{}
	svc := newSvc(store, ev, bc, []string{"inv-1", "inv-2"})

	err := svc.CreateCaseFromAlert(context.Background(), validAlertEvent(0.92))
	require.NoError(t, err)
	assert.Len(t, store.cases, 1)

	for _, c := range store.cases {
		assert.Equal(t, domain.CaseStatusOpen, c.Status)
		assert.Equal(t, domain.CasePriorityCritical, c.Priority)
		assert.True(t, c.SARRequired) // 0.92 >= 0.85
		assert.NotEmpty(t, c.AssigneeID)
	}
}

func TestCreateCaseFromAlert_High(t *testing.T) {
	store := newMockStore()
	svc := newSvc(store, newMockEvidenceStore(), &mockBlockchain{}, nil)

	err := svc.CreateCaseFromAlert(context.Background(), validAlertEvent(0.75))
	require.NoError(t, err)
	assert.Len(t, store.cases, 1)
	for _, c := range store.cases {
		assert.Equal(t, domain.CasePriorityHigh, c.Priority)
		assert.False(t, c.SARRequired) // 0.75 < 0.85
	}
}

func TestCreateCaseFromAlert_Idempotent(t *testing.T) {
	store := newMockStore()
	svc := newSvc(store, newMockEvidenceStore(), &mockBlockchain{}, nil)

	event := validAlertEvent(0.90)
	require.NoError(t, svc.CreateCaseFromAlert(context.Background(), event))
	require.NoError(t, svc.CreateCaseFromAlert(context.Background(), event)) // second call
	assert.Len(t, store.cases, 1) // only one case created
}

func TestCreateCase_DirectGRPC(t *testing.T) {
	store := newMockStore()
	svc := newSvc(store, newMockEvidenceStore(), &mockBlockchain{}, []string{"inv-a"})

	c, err := svc.CreateCase(context.Background(), &service.CreateCaseInput{
		AlertID:          "alert-002",
		CustomerID:       "cust-002",
		TxHash:           "0xdef456",
		FraudProbability: 0.88,
		RiskScore:        88,
		Title:            "Manual case",
	})
	require.NoError(t, err)
	assert.Equal(t, "alert-002", c.AlertID)
	assert.Equal(t, domain.CasePriorityCritical, c.Priority)
	assert.Equal(t, "inv-a", c.AssigneeID)
}

func TestCreateCase_MissingAlertID(t *testing.T) {
	svc := newSvc(newMockStore(), newMockEvidenceStore(), &mockBlockchain{}, nil)
	_, err := svc.CreateCase(context.Background(), &service.CreateCaseInput{CustomerID: "cust"})
	require.Error(t, err)
}

func TestGetCase_Found(t *testing.T) {
	store := newMockStore()
	store.cases["case-1"] = &domain.Case{CaseID: "case-1", Status: domain.CaseStatusOpen}
	svc := newSvc(store, newMockEvidenceStore(), &mockBlockchain{}, nil)

	c, actions, err := svc.GetCase(context.Background(), "case-1")
	require.NoError(t, err)
	assert.Equal(t, "case-1", c.CaseID)
	assert.NotNil(t, actions)
}

func TestGetCase_NotFound(t *testing.T) {
	svc := newSvc(newMockStore(), newMockEvidenceStore(), &mockBlockchain{}, nil)
	_, _, err := svc.GetCase(context.Background(), "nonexistent")
	assert.True(t, domain.IsCaseError(err, "CASE_NOT_FOUND"))
}

func TestUpdateCaseStatus_ValidTransition(t *testing.T) {
	store := newMockStore()
	store.cases["c1"] = &domain.Case{CaseID: "c1", AlertID: "a1", Status: domain.CaseStatusOpen}
	svc := newSvc(store, newMockEvidenceStore(), &mockBlockchain{}, nil)

	updated, err := svc.UpdateCaseStatus(context.Background(), "c1", "inv-1", "starting review", domain.CaseStatusInReview, "")
	require.NoError(t, err)
	assert.Equal(t, domain.CaseStatusInReview, updated.Status)
}

func TestUpdateCaseStatus_InvalidTransition(t *testing.T) {
	store := newMockStore()
	store.cases["c1"] = &domain.Case{CaseID: "c1", AlertID: "a1", Status: domain.CaseStatusClosed}
	svc := newSvc(store, newMockEvidenceStore(), &mockBlockchain{}, nil)

	_, err := svc.UpdateCaseStatus(context.Background(), "c1", "inv-1", "", domain.CaseStatusPendingSAR, "")
	assert.True(t, domain.IsCaseError(err, "INVALID_TRANSITION"))
}

func TestAssignCase(t *testing.T) {
	store := newMockStore()
	store.cases["c1"] = &domain.Case{CaseID: "c1", AlertID: "a1", Status: domain.CaseStatusOpen}
	svc := newSvc(store, newMockEvidenceStore(), &mockBlockchain{}, nil)

	updated, err := svc.AssignCase(context.Background(), "c1", "inv-5", "admin")
	require.NoError(t, err)
	assert.Equal(t, "inv-5", updated.AssigneeID)
}

func TestAutoAssign_RoundRobin(t *testing.T) {
	store := newMockStore()
	investigators := []string{"inv-a", "inv-b", "inv-c"}
	svc := newSvc(store, newMockEvidenceStore(), &mockBlockchain{}, investigators)

	assigned := make(map[string]int)
	for i := 0; i < 6; i++ {
		alertID := fmt.Sprintf("alert-%d", i)
		caseID := fmt.Sprintf("case-%d", i)
		store.cases[caseID] = &domain.Case{CaseID: caseID, AlertID: alertID, Status: domain.CaseStatusOpen}
		c, err := svc.AssignCase(context.Background(), caseID, investigators[i%3], "system")
		require.NoError(t, err)
		assigned[c.AssigneeID]++
	}
	// Each investigator should get 2 assignments
	for _, inv := range investigators {
		assert.Equal(t, 2, assigned[inv])
	}
}

func TestAutoAssign_NoInvestigators(t *testing.T) {
	store := newMockStore()
	store.cases["c1"] = &domain.Case{CaseID: "c1", AlertID: "a1", Status: domain.CaseStatusOpen}
	svc := newSvc(store, newMockEvidenceStore(), &mockBlockchain{}, nil)

	_, err := svc.AutoAssign(context.Background(), "c1", "system")
	assert.True(t, domain.IsCaseError(err, "NO_INVESTIGATORS"))
}

func TestAddEvidence(t *testing.T) {
	store := newMockStore()
	store.cases["c1"] = &domain.Case{CaseID: "c1", AlertID: "a1", Status: domain.CaseStatusInReview}
	svc := newSvc(store, newMockEvidenceStore(), &mockBlockchain{}, nil)

	e, putURL, getURL, err := svc.AddEvidence(context.Background(), &service.AddEvidenceInput{
		CaseID:       "c1",
		UploadedBy:   "inv-1",
		FileName:     "bank_statement.pdf",
		FileSize:     10240,
		ContentType:  "application/pdf",
		EvidenceType: domain.EvidenceTypeDocument,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, e.EvidenceID)
	assert.Contains(t, putURL, "put")
	assert.Contains(t, getURL, "get")
	assert.Len(t, store.evidence["c1"], 1)
}

func TestDeleteEvidence(t *testing.T) {
	store := newMockStore()
	store.cases["c1"] = &domain.Case{CaseID: "c1", AlertID: "a1", Status: domain.CaseStatusInReview}
	ev := newMockEvidenceStore()
	store.evidence["c1"] = []*domain.Evidence{{EvidenceID: "ev-1", CaseID: "c1", S3Key: "evidence/c1/ev-1/file.pdf"}}
	svc := newSvc(store, ev, &mockBlockchain{}, nil)

	err := svc.DeleteEvidence(context.Background(), "c1", "ev-1", "inv-1")
	require.NoError(t, err)
	assert.Len(t, store.evidence["c1"], 0)
	assert.Contains(t, ev.deleted, "evidence/c1/ev-1/file.pdf")
}

func TestGenerateSAR(t *testing.T) {
	store := newMockStore()
	store.cases["c1"] = &domain.Case{
		CaseID:           "c1",
		AlertID:          "a1",
		CustomerID:       "cust-1",
		TxHash:           "0xabc",
		Status:           domain.CaseStatusInReview,
		Priority:         domain.CasePriorityCritical,
		FraudProbability: 0.93,
		RiskScore:        93,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
	ev := newMockEvidenceStore()
	svc := newSvc(store, ev, &mockBlockchain{}, nil)

	s3Key, downloadURL, err := svc.GenerateSAR(context.Background(), "c1", "inv-1", "")
	require.NoError(t, err)
	assert.Contains(t, s3Key, "sar/c1/")
	assert.Contains(t, downloadURL, "get")
	assert.Equal(t, domain.CaseStatusPendingSAR, store.cases["c1"].Status)
}

func TestGenerateSAR_AlreadyExists(t *testing.T) {
	store := newMockStore()
	store.cases["c1"] = &domain.Case{
		CaseID: "c1", AlertID: "a1", CustomerID: "cust-1", TxHash: "0x",
		Status: domain.CaseStatusPendingSAR, SARS3Key: "sar/c1/existing.pdf",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	svc := newSvc(store, newMockEvidenceStore(), &mockBlockchain{}, nil)

	_, _, err := svc.GenerateSAR(context.Background(), "c1", "inv-1", "")
	require.Error(t, err)
	assert.True(t, domain.IsCaseError(err, "SAR_EXISTS"))
}

func TestHealthCheck_AllOK(t *testing.T) {
	svc := newSvc(newMockStore(), newMockEvidenceStore(), &mockBlockchain{}, nil)
	status := svc.HealthCheck(context.Background())
	assert.Equal(t, "ok", status["postgres"])
	assert.Equal(t, "ok", status["blockchain"])
}

func TestHealthCheck_PostgresDown(t *testing.T) {
	store := newMockStore()
	store.pingErr = errors.New("connection refused")
	svc := newSvc(store, newMockEvidenceStore(), &mockBlockchain{}, nil)
	status := svc.HealthCheck(context.Background())
	assert.NotEqual(t, "ok", status["postgres"])
}

func TestPriorityBoundaries(t *testing.T) {
	cases := []struct {
		prob     float64
		expected domain.CasePriority
	}{
		{0.0, domain.CasePriorityLow},
		{0.49, domain.CasePriorityLow},
		{0.50, domain.CasePriorityMedium},
		{0.70, domain.CasePriorityHigh},
		{0.85, domain.CasePriorityHigh},
		{0.851, domain.CasePriorityCritical},
		{1.0, domain.CasePriorityCritical},
	}
	for _, tc := range cases {
		got := domain.PriorityFromFraudProb(tc.prob)
		assert.Equal(t, tc.expected, got, "prob=%.3f", tc.prob)
	}
}

func TestGetStats(t *testing.T) {
	svc := newSvc(newMockStore(), newMockEvidenceStore(), &mockBlockchain{}, nil)
	stats, err := svc.GetCaseStats(context.Background(), "7d")
	require.NoError(t, err)
	assert.Equal(t, "7d", stats.Period)
	assert.Equal(t, 10, stats.TotalCases)
}

// fmt is needed for the round-robin test
var _ = fmt.Sprintf
