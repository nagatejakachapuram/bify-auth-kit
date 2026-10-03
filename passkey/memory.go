package passkey

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// MemoryStore is an in-memory Store with the same semantics as DynamoStore, for tests and local
// development. Sessions must be added with AddSession before they can be confirmed.
type MemoryStore struct {
	mu         sync.Mutex
	passkeys   map[string]map[string]StoredPasskey // user -> key -> passkey
	owners     map[string]string                   // key -> user
	ceremonies map[string]Ceremony
	sessions   map[string]*memorySession
}

type memorySession struct{ created, stepUp time.Time }

// AddSession registers a portal session created at createdAt, as the portal's own session record would.
func (m *MemoryStore) AddSession(key string, createdAt time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[key] = &memorySession{created: createdAt}
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{passkeys: map[string]map[string]StoredPasskey{}, owners: map[string]string{}, ceremonies: map[string]Ceremony{}, sessions: map[string]*memorySession{}}
}

func (m *MemoryStore) ListPasskeys(_ context.Context, userID string) ([]StoredPasskey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []StoredPasskey
	for _, passkey := range m.passkeys[userID] {
		out = append(out, passkey)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}
func (m *MemoryStore) PasskeyOwner(_ context.Context, id []byte) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if owner, ok := m.owners[keyOf(id)]; ok {
		return owner, nil
	}
	return "", ErrNotFound
}
func (m *MemoryStore) AddPasskey(_ context.Context, userID string, passkey StoredPasskey, max int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := keyOf(passkey.Credential.ID)
	if len(m.passkeys[userID]) >= max {
		return ErrLimit
	}
	if _, taken := m.owners[key]; taken {
		return ErrExists
	}
	if m.passkeys[userID] == nil {
		m.passkeys[userID] = map[string]StoredPasskey{}
	}
	m.passkeys[userID][key] = passkey
	m.owners[key] = userID
	return nil
}
func (m *MemoryStore) UpdatePasskeyUse(_ context.Context, userID string, credential webauthn.Credential, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := keyOf(credential.ID)
	passkey, ok := m.passkeys[userID][key]
	if !ok {
		return ErrNotFound
	}
	if !counterAdvances(passkey.Credential, credential) {
		return ErrVerification
	}
	if passkey.LastUsedAt.After(at) {
		at = passkey.LastUsedAt
	}
	passkey.Credential, passkey.LastUsedAt = credential, at
	m.passkeys[userID][key] = passkey
	return nil
}
func (m *MemoryStore) RenamePasskey(_ context.Context, userID string, id []byte, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := keyOf(id)
	passkey, ok := m.passkeys[userID][key]
	if !ok {
		return ErrNotFound
	}
	passkey.Name = name
	m.passkeys[userID][key] = passkey
	return nil
}
func (m *MemoryStore) DeletePasskey(_ context.Context, userID string, id []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := keyOf(id)
	if _, ok := m.passkeys[userID][key]; !ok || m.owners[key] != userID {
		return ErrNotFound
	}
	delete(m.passkeys[userID], key)
	delete(m.owners, key)
	return nil
}
func (m *MemoryStore) SaveCeremony(_ context.Context, c Ceremony) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ceremonies[c.ID] = c
	return nil
}
func (m *MemoryStore) TakeCeremony(_ context.Context, id string) (Ceremony, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.ceremonies[id]
	if !ok {
		return Ceremony{}, ErrNotFound
	}
	delete(m.ceremonies, id)
	return c, nil
}
func (m *MemoryStore) MarkStepUp(_ context.Context, key string, until time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.sessions[key]
	if !ok {
		return ErrNotFound
	}
	session.stepUp = until
	return nil
}
func (m *MemoryStore) SessionTimes(_ context.Context, key string) (time.Time, time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.sessions[key]
	if !ok {
		return time.Time{}, time.Time{}, ErrNotFound
	}
	return session.created, session.stepUp, nil
}
