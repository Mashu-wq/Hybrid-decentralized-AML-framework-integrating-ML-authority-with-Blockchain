// Package websocket implements the real-time alert broadcast hub.
package websocket

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/fraud-detection/alert-service/internal/domain"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

// client represents a single connected WebSocket dashboard client.
type client struct {
	conn     *websocket.Conn
	send     chan []byte
	hub      *Hub
	pingInt  time.Duration
	writeTO  time.Duration
}

// Hub manages all connected WebSocket clients and broadcasts alert messages.
type Hub struct {
	clients    map[*client]struct{}
	mu         sync.RWMutex
	broadcast  chan []byte
	register   chan *client
	unregister chan *client
	pingInt    time.Duration
	writeTO    time.Duration
}

// NewHub creates a Hub with the given heartbeat settings.
func NewHub(pingInterval, writeTimeout time.Duration) *Hub {
	return &Hub{
		clients:    make(map[*client]struct{}),
		broadcast:  make(chan []byte, 256),
		register:   make(chan *client, 32),
		unregister: make(chan *client, 32),
		pingInt:    pingInterval,
		writeTO:    writeTimeout,
	}
}

// Run processes register/unregister/broadcast events. Call in a goroutine.
func (h *Hub) Run() {
	for {
		select {
		case c := <-h.register:
			h.mu.Lock()
			h.clients[c] = struct{}{}
			h.mu.Unlock()
			log.Debug().Int("clients", len(h.clients)).Msg("WebSocket client connected")

		case c := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[c]; ok {
				delete(h.clients, c)
				close(c.send)
			}
			h.mu.Unlock()
			log.Debug().Int("clients", len(h.clients)).Msg("WebSocket client disconnected")

		case msg := <-h.broadcast:
			h.mu.RLock()
			for c := range h.clients {
				select {
				case c.send <- msg:
				default:
					// slow client — drop and disconnect
					close(c.send)
					delete(h.clients, c)
				}
			}
			h.mu.RUnlock()
		}
	}
}

// BroadcastAlert serialises a WSMessage and enqueues it for broadcast.
func (h *Hub) BroadcastAlert(msg *domain.WSMessage) {
	data, err := json.Marshal(msg)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal WS message")
		return
	}
	h.broadcast <- data
}

// ClientCount returns the number of currently connected WebSocket clients.
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// ---------------------------------------------------------------------------
// Per-client pumps
// ---------------------------------------------------------------------------

// writePump drains the send channel and writes messages to the WebSocket.
func (c *client) writePump() {
	ticker := time.NewTicker(c.pingInt)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case msg, ok := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(c.writeTO))
			if !ok {
				_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}

		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(c.writeTO))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// readPump reads control frames from the client and handles pong.
func (c *client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(512)
	_ = c.conn.SetReadDeadline(time.Now().Add(c.pingInt + c.writeTO))
	c.conn.SetPongHandler(func(string) error {
		return c.conn.SetReadDeadline(time.Now().Add(c.pingInt + c.writeTO))
	})

	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Debug().Err(err).Msg("WebSocket unexpected close")
			}
			break
		}
	}
}
