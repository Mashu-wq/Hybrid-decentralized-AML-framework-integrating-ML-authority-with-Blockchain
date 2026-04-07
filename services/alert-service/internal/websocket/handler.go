package websocket

import (
	"net/http"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 4096,
	// In production, restrict to known dashboard origins.
	CheckOrigin: func(r *http.Request) bool { return true },
}

// ServeWS upgrades an HTTP connection to WebSocket and registers the client.
func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Error().Err(err).Msg("WebSocket upgrade failed")
		return
	}

	c := &client{
		conn:    conn,
		send:    make(chan []byte, 64),
		hub:     h,
		pingInt: h.pingInt,
		writeTO: h.writeTO,
	}
	h.register <- c

	go c.writePump()
	go c.readPump()
}
