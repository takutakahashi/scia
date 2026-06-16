package approval

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

type Status string

const (
	Pending  Status = "pending"
	Approved Status = "approved"
	Denied   Status = "denied"
)

type Request struct {
	ID        string    `json:"id"`
	Method    string    `json:"method"`
	URL       string    `json:"url"`
	Rule      string    `json:"rule"`
	Note      string    `json:"note,omitempty"`
	Status    Status    `json:"status"`
	CreatedAt time.Time `json:"createdAt"`
}

type pendingRequest struct {
	request Request
	done    chan Status
}

type Manager struct {
	mu      sync.Mutex
	pending map[string]*pendingRequest
	ttl     time.Duration
}

func NewManager(ttl time.Duration) *Manager {
	return &Manager{pending: map[string]*pendingRequest{}, ttl: ttl}
}

func (m *Manager) Wait(ctx context.Context, req Request) (Status, error) {
	req.ID = newID()
	req.Status = Pending
	req.CreatedAt = time.Now().UTC()
	pending := &pendingRequest{request: req, done: make(chan Status, 1)}

	m.mu.Lock()
	m.pending[req.ID] = pending
	m.mu.Unlock()

	timer := time.NewTimer(m.ttl)
	defer timer.Stop()
	defer m.delete(req.ID)

	select {
	case status := <-pending.done:
		return status, nil
	case <-timer.C:
		return Denied, errors.New("approval timed out")
	case <-ctx.Done():
		return Denied, ctx.Err()
	}
}

func (m *Manager) List() []Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	items := make([]Request, 0, len(m.pending))
	for _, pending := range m.pending {
		items = append(items, pending.request)
	}
	return items
}

func (m *Manager) Resolve(id string, status Status) bool {
	if status != Approved && status != Denied {
		return false
	}
	m.mu.Lock()
	pending, ok := m.pending[id]
	m.mu.Unlock()
	if !ok {
		return false
	}
	pending.done <- status
	return true
}

func (m *Manager) delete(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.pending, id)
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return hex.EncodeToString([]byte(time.Now().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(b[:])
}
