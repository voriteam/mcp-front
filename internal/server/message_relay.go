package server

import "sync"

// messageRelay distributes JSON-RPC responses from POST handlers to active SSE GET connections.
// Used to bridge SSE transport clients (like Claude Code) to streamable-http backends.
type messageRelay struct {
	mu   sync.Mutex
	subs map[string][]chan []byte // userEmail → subscriber channels
}

func newMessageRelay() *messageRelay {
	return &messageRelay{subs: make(map[string][]chan []byte)}
}

// subscribe registers a new SSE connection for a user and returns a channel and cleanup func.
func (r *messageRelay) subscribe(userEmail string) (chan []byte, func()) {
	ch := make(chan []byte, 32)
	r.mu.Lock()
	r.subs[userEmail] = append(r.subs[userEmail], ch)
	r.mu.Unlock()
	return ch, func() {
		r.mu.Lock()
		subs := r.subs[userEmail]
		for i, s := range subs {
			if s == ch {
				r.subs[userEmail] = append(subs[:i], subs[i+1:]...)
				break
			}
		}
		if len(r.subs[userEmail]) == 0 {
			delete(r.subs, userEmail)
		}
		r.mu.Unlock()
	}
}

// publish sends data to all active SSE connections for a user.
// Returns true if at least one subscriber received the message.
func (r *messageRelay) publish(userEmail string, data []byte) bool {
	r.mu.Lock()
	subs := make([]chan []byte, len(r.subs[userEmail]))
	copy(subs, r.subs[userEmail])
	r.mu.Unlock()
	if len(subs) == 0 {
		return false
	}
	for _, ch := range subs {
		select {
		case ch <- data:
		default:
		}
	}
	return true
}

// hasSubscribers reports whether any SSE connections are active for a user.
func (r *messageRelay) hasSubscribers(userEmail string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.subs[userEmail]) > 0
}
