// internal/audit/audit_logger.go
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/olivere/elastic/v7"
)

type AuditEvent struct {
	EventID     string                 `json:"event_id"`
	UserID      string                 `json:"user_id,omitempty"`
	EventType   string                 `json:"event_type"`
	Action      string                 `json:"action"`
	IPAddress   string                 `json:"ip_address,omitempty"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	Resource    string                 `json:"resource,omitempty"`
	ResourceID  string                 `json:"resource_id,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Status      string                 `json:"status"`
	Timestamp   time.Time              `json:"timestamp"`
}

type AuditLogger struct {
	client   *elastic.Client
	index    string
	useRedis bool
}

func NewAuditLogger(client *elastic.Client, index string) *AuditLogger {
	return &AuditLogger{
		client: client,
		index:  index,
	}
}

func (l *AuditLogger) Log(event AuditEvent) error {
	if l.client == nil {
		// Fallback to console logging if Elasticsearch is not available
		data, _ := json.Marshal(event)
		fmt.Printf("AUDIT: %s\n", string(data))
		return nil
	}
	
	ctx := context.Background()
	_, err := l.client.Index().
		Index(l.index).
		BodyJson(event).
		Do(ctx)
	
	return err
}

func (l *AuditLogger) Search(query string, from, size int) ([]AuditEvent, error) {
	if l.client == nil {
		return []AuditEvent{}, nil
	}
	
	ctx := context.Background()
	searchResult, err := l.client.Search().
		Index(l.index).
		Query(elastic.NewMatchAllQuery()).
		From(from).
		Size(size).
		Sort("timestamp", false).
		Do(ctx)
	
	if err != nil {
		return nil, err
	}
	
	var events []AuditEvent
	for _, hit := range searchResult.Hits.Hits {
		var event AuditEvent
		err := json.Unmarshal(hit.Source, &event)
		if err == nil {
			events = append(events, event)
		}
	}
	
	return events, nil
}