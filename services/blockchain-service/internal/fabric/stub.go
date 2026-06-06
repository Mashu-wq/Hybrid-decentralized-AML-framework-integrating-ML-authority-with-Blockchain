package fabric

import (
	"context"
	"errors"
)

// unavailableGateway is used when the Fabric network is unreachable at startup.
// All operations return an error; Health reports the channel as unavailable.
type unavailableGateway struct {
	reason string
}

// NewUnavailable returns a Gateway stub that reports all channels as unavailable.
func NewUnavailable(reason string) Gateway {
	return &unavailableGateway{reason: reason}
}

func (g *unavailableGateway) Invoke(_ context.Context, channelName, _, _ string, _ [][]byte) (string, []byte, error) {
	return "", nil, errors.New("fabric unavailable: " + g.reason)
}

func (g *unavailableGateway) Query(_ context.Context, channelName, _, _ string, _ [][]byte) ([]byte, error) {
	return nil, errors.New("fabric unavailable: " + g.reason)
}

func (g *unavailableGateway) StartEventListeners(_ context.Context) error {
	return nil // non-fatal: no events to listen for
}

func (g *unavailableGateway) Health(_ context.Context) map[string]string {
	return map[string]string{
		"fabric": "error: " + g.reason,
	}
}

func (g *unavailableGateway) Close() {}
