package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fraud-detection/alert-service/internal/domain"
	"github.com/fraud-detection/alert-service/internal/notification"
	"github.com/fraud-detection/alert-service/internal/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Inline mocks
// ---------------------------------------------------------------------------

type mockStore struct {
	created      []*domain.Alert
	alerts       map[string]*domain.Alert
	createErr    error
	getErr       error
	updateErr    error
	statsResult  *domain.AlertStats
	candidates   []*domain.Alert
	pingErr      error
}

func newMockStore() *mockStore {
	return &mockStore{alerts: make(map[string]*domain.Alert)}
}

func (m *mockStore) Create(_ context.Context, a *domain.Alert) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.created = append(m.created, a)
	m.alerts[a.AlertID] = a
	return nil
}

func (m *mockStore) GetByID(_ context.Context, id string) (*domain.Alert, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	a, ok := m.alerts[id]
	if !ok {
		return nil, domain.ErrAlertNotFound
	}
	return a, nil
}

func (m *mockStore) List(_ context.Context, _ domain.AlertFilters) ([]*domain.Alert, int, error) {
	var out []*domain.Alert
	for _, a := range m.alerts {
		out = append(out, a)
	}
	return out, len(out), nil
}

func (m *mockStore) GetByCustomer(_ context.Context, id string, _, _ int) ([]*domain.Alert, error) {
	var out []*domain.Alert
	for _, a := range m.alerts {
		if a.CustomerID == id {
			out = append(out, a)
		}
	}
	return out, nil
}

func (m *mockStore) UpdateStatus(_ context.Context, alertID, _, notes string, newStatus domain.AlertStatus) (*domain.Alert, error) {
	if m.updateErr != nil {
		return nil, m.updateErr
	}
	a, ok := m.alerts[alertID]
	if !ok {
		return nil, domain.ErrAlertNotFound
	}
	a.Status = newStatus
	a.ResolutionNotes = notes
	return a, nil
}

func (m *mockStore) Assign(_ context.Context, alertID, assigneeID string) (*domain.Alert, error) {
	a, ok := m.alerts[alertID]
	if !ok {
		return nil, domain.ErrAlertNotFound
	}
	a.AssigneeID = assigneeID
	return a, nil
}

func (m *mockStore) GetEscalationCandidates(_ context.Context, _ time.Duration) ([]*domain.Alert, error) {
	return m.candidates, nil
}

func (m *mockStore) GetStats(_ context.Context, _ string) (*domain.AlertStats, error) {
	if m.statsResult != nil {
		return m.statsResult, nil
	}
	return &domain.AlertStats{}, nil
}

func (m *mockStore) LogNotification(_ context.Context, _, _, _ string, _ bool, _, _ string) error {
	return nil
}

func (m *mockStore) Ping(_ context.Context) error { return m.pingErr }

// ----

type mockDedup struct {
	isDup    bool
	dedupErr error
	pingErr  error
	evicted  []string
}

func (m *mockDedup) IsDuplicate(_ context.Context, _, _, _ string) (bool, string, error) {
	return m.isDup, "testhash", m.dedupErr
}

func (m *mockDedup) Evict(_ context.Context, hash string) {
	m.evicted = append(m.evicted, hash)
}

func (m *mockDedup) Ping(_ context.Context) error { return m.pingErr }

// ----

type mockBroadcaster struct {
	messages []*domain.WSMessage
}

func (m *mockBroadcaster) BroadcastAlert(msg *domain.WSMessage) {
	m.messages = append(m.messages, msg)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func validEvent(prob float64) *domain.AlertIngestEvent {
	return &domain.AlertIngestEvent{
		AlertID:          "alert-001",
		CustomerID:       "cust-001",
		TxHash:           "0xabc123",
		FraudProbability: prob,
		RiskScore:        prob * 100,
		ModelVersion:     "v1.0.0",
		CreatedAt:        time.Now(),
	}
}

func newSvc(store *mockStore, dedup *mockDedup, hub *mockBroadcaster) *service.AlertService {
	dispatcher := notification.NewDispatcher(nil, nil, nil, nil, store)
	return service.New(store, dedup, dispatcher, hub)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestIngestAlert_HappyPath_Low(t *testing.T) {
	store := newMockStore()
	dedup := &mockDedup{}
	hub := &mockBroadcaster{}
	svc := newSvc(store, dedup, hub)

	err := svc.IngestAlert(context.Background(), validEvent(0.3))
	require.NoError(t, err)
	assert.Len(t, store.created, 1)
	assert.Equal(t, domain.PriorityLow, store.created[0].Priority)
	assert.Equal(t, domain.StatusOpen, store.created[0].Status)
	assert.Len(t, hub.messages, 1)
	assert.Equal(t, domain.WSAlertCreated, hub.messages[0].Type)
}

func TestIngestAlert_CriticalPriority(t *testing.T) {
	store := newMockStore()
	dedup := &mockDedup{}
	hub := &mockBroadcaster{}
	svc := newSvc(store, dedup, hub)

	err := svc.IngestAlert(context.Background(), validEvent(0.9))
	require.NoError(t, err)
	assert.Equal(t, domain.PriorityCritical, store.created[0].Priority)
}

func TestIngestAlert_Duplicate_Redis(t *testing.T) {
	store := newMockStore()
	dedup := &mockDedup{isDup: true}
	hub := &mockBroadcaster{}
	svc := newSvc(store, dedup, hub)

	err := svc.IngestAlert(context.Background(), validEvent(0.9))
	require.NoError(t, err)
	assert.Empty(t, store.created)
	assert.Empty(t, hub.messages)
}

func TestIngestAlert_Duplicate_Postgres(t *testing.T) {
	store := newMockStore()
	store.createErr = domain.ErrDuplicateAlert
	dedup := &mockDedup{}
	hub := &mockBroadcaster{}
	svc := newSvc(store, dedup, hub)

	err := svc.IngestAlert(context.Background(), validEvent(0.9))
	require.NoError(t, err) // not an error from caller's perspective
	assert.Contains(t, dedup.evicted, "testhash")
}

func TestIngestAlert_StoreError_EvictsRedis(t *testing.T) {
	store := newMockStore()
	store.createErr = errors.New("db down")
	dedup := &mockDedup{}
	hub := &mockBroadcaster{}
	svc := newSvc(store, dedup, hub)

	err := svc.IngestAlert(context.Background(), validEvent(0.8))
	require.Error(t, err)
	assert.Contains(t, dedup.evicted, "testhash")
}

func TestIngestAlert_InvalidEvent(t *testing.T) {
	store := newMockStore()
	dedup := &mockDedup{}
	svc := newSvc(store, dedup, nil)

	bad := validEvent(0.5)
	bad.AlertID = "" // required field missing

	err := svc.IngestAlert(context.Background(), bad)
	require.Error(t, err)
	assert.Empty(t, store.created)
}

func TestIngestAlert_FraudProbOutOfRange(t *testing.T) {
	store := newMockStore()
	dedup := &mockDedup{}
	svc := newSvc(store, dedup, nil)

	bad := validEvent(1.5)
	err := svc.IngestAlert(context.Background(), bad)
	require.Error(t, err)
}

func TestGetAlert_Found(t *testing.T) {
	store := newMockStore()
	store.alerts["alert-001"] = &domain.Alert{AlertID: "alert-001", Status: domain.StatusOpen}
	svc := newSvc(store, &mockDedup{}, nil)

	a, err := svc.GetAlert(context.Background(), "alert-001")
	require.NoError(t, err)
	assert.Equal(t, "alert-001", a.AlertID)
}

func TestGetAlert_NotFound(t *testing.T) {
	store := newMockStore()
	svc := newSvc(store, &mockDedup{}, nil)

	_, err := svc.GetAlert(context.Background(), "nonexistent")
	assert.ErrorIs(t, err, domain.ErrAlertNotFound)
}

func TestUpdateStatus_ValidTransition(t *testing.T) {
	store := newMockStore()
	store.alerts["a1"] = &domain.Alert{AlertID: "a1", Status: domain.StatusOpen}
	hub := &mockBroadcaster{}
	svc := newSvc(store, &mockDedup{}, hub)

	updated, err := svc.UpdateStatus(context.Background(), "a1", "user1", "", domain.StatusInvestigating)
	require.NoError(t, err)
	assert.Equal(t, domain.StatusInvestigating, updated.Status)
	assert.Len(t, hub.messages, 1)
	assert.Equal(t, domain.WSAlertUpdated, hub.messages[0].Type)
}

func TestUpdateStatus_StoreError(t *testing.T) {
	store := newMockStore()
	store.updateErr = domain.ErrInvalidTransition
	svc := newSvc(store, &mockDedup{}, nil)

	_, err := svc.UpdateStatus(context.Background(), "a1", "user1", "", domain.StatusResolved)
	assert.Error(t, err)
}

func TestEscalateAlert_AssignsAnalyst(t *testing.T) {
	store := newMockStore()
	store.alerts["a1"] = &domain.Alert{AlertID: "a1", Status: domain.StatusOpen, Priority: domain.PriorityCritical}
	hub := &mockBroadcaster{}
	svc := newSvc(store, &mockDedup{}, hub)

	escalated, err := svc.EscalateAlert(context.Background(), "a1", "analyst-42", "overdue")
	require.NoError(t, err)
	assert.Equal(t, domain.StatusEscalated, escalated.Status)
	assert.Equal(t, "analyst-42", escalated.AssigneeID)
	assert.Len(t, hub.messages, 1)
	assert.Equal(t, domain.WSAlertEscalated, hub.messages[0].Type)
}

func TestHealthCheck_AllOK(t *testing.T) {
	svc := newSvc(newMockStore(), &mockDedup{}, nil)
	status := svc.HealthCheck(context.Background())
	assert.Equal(t, "ok", status["postgres"])
	assert.Equal(t, "ok", status["redis"])
}

func TestHealthCheck_PostgresDown(t *testing.T) {
	store := newMockStore()
	store.pingErr = errors.New("connection refused")
	svc := newSvc(store, &mockDedup{}, nil)
	status := svc.HealthCheck(context.Background())
	assert.NotEqual(t, "ok", status["postgres"])
}

func TestPriorityBoundaries(t *testing.T) {
	cases := []struct {
		prob     float64
		expected domain.AlertPriority
	}{
		{0.0, domain.PriorityLow},
		{0.49, domain.PriorityLow},
		{0.50, domain.PriorityMedium},
		{0.70, domain.PriorityHigh},
		{0.85, domain.PriorityHigh},
		{0.851, domain.PriorityCritical},
		{1.0, domain.PriorityCritical},
	}
	for _, tc := range cases {
		got := domain.PriorityFromFraudProb(tc.prob)
		assert.Equal(t, tc.expected, got, "prob=%.3f", tc.prob)
	}
}
