package passkey

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// softAuthenticator is a software passkey (ES256), standing in for Face ID / Touch ID / a security key.
// It produces exactly the attestation and assertion responses a browser hands back.
type softAuthenticator struct {
	key       *ecdsa.PrivateKey
	id        []byte
	userID    []byte
	rpID      string
	origin    string
	signCount uint32
	synced    bool
}

func newAuthenticator(t *testing.T, rpID, origin string) *softAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	_, _ = rand.Read(id)
	return &softAuthenticator{key: key, id: id, rpID: rpID, origin: origin, synced: true}
}

func b64(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

func (a *softAuthenticator) flags(attested bool) byte {
	flags := byte(0x01 | 0x04) // user present, user verified
	if a.synced {
		flags |= 0x08 | 0x10 // backup eligible, backed up
	}
	if attested {
		flags |= 0x40
	}
	return flags
}

func (a *softAuthenticator) authData(attested bool) []byte {
	rpHash := sha256.Sum256([]byte(a.rpID))
	out := append([]byte{}, rpHash[:]...)
	out = append(out, a.flags(attested))
	out = binary.BigEndian.AppendUint32(out, a.signCount)
	if attested {
		out = append(out, make([]byte, 16)...) // AAGUID
		out = binary.BigEndian.AppendUint16(out, uint16(len(a.id)))
		out = append(out, a.id...)
		x, y := a.key.PublicKey.X.FillBytes(make([]byte, 32)), a.key.PublicKey.Y.FillBytes(make([]byte, 32))
		coseKey, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
		out = append(out, coseKey...)
	}
	return out
}

func clientData(kind, challenge, origin string) []byte {
	raw, _ := json.Marshal(map[string]any{"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false})
	return raw
}

// register answers navigator.credentials.create for the given options.
func (a *softAuthenticator) register(t *testing.T, creation *protocol.CredentialCreation) []byte {
	t.Helper()
	// In-process options carry the user handle as bytes; options that went through JSON carry base64url.
	switch id := creation.Response.User.ID.(type) {
	case protocol.URLEncodedBase64:
		a.userID = []byte(id)
	case string:
		decoded, err := base64.RawURLEncoding.DecodeString(id)
		if err != nil {
			t.Fatalf("user handle %q: %v", id, err)
		}
		a.userID = decoded
	default:
		t.Fatalf("unexpected user handle type %T", id)
	}
	attestation, _ := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": a.authData(true)})
	body, _ := json.Marshal(map[string]any{
		"id": b64(a.id), "rawId": b64(a.id), "type": "public-key", "authenticatorAttachment": "platform",
		"response": map[string]any{
			"clientDataJSON":    b64(clientData("webauthn.create", creation.Response.Challenge.String(), a.origin)),
			"attestationObject": b64(attestation),
			"transports":        []string{"internal", "hybrid"},
		},
		"clientExtensionResults": map[string]any{},
	})
	return body
}

// assert answers navigator.credentials.get for the given options.
func (a *softAuthenticator) assert(t *testing.T, assertion *protocol.CredentialAssertion) []byte {
	t.Helper()
	data := a.authData(false)
	client := clientData("webauthn.get", assertion.Response.Challenge.String(), a.origin)
	clientHash := sha256.Sum256(client)
	digest := sha256.Sum256(append(append([]byte{}, data...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{
		"id": b64(a.id), "rawId": b64(a.id), "type": "public-key", "authenticatorAttachment": "platform",
		"response": map[string]any{
			"clientDataJSON":    b64(client),
			"authenticatorData": b64(data),
			"signature":         b64(signature),
			"userHandle":        b64(a.userID),
		},
		"clientExtensionResults": map[string]any{},
	})
	return body
}

// memStore is an in-memory Store with the same semantics as DynamoStore.
type memStore struct {
	mu         sync.Mutex
	passkeys   map[string]map[string]StoredPasskey // user -> key -> passkey
	owners     map[string]string                   // key -> user
	ceremonies map[string]Ceremony
	sessions   map[string]*sessionTimes
}

type sessionTimes struct{ created, stepUp time.Time }

func newMemStore() *memStore {
	return &memStore{passkeys: map[string]map[string]StoredPasskey{}, owners: map[string]string{}, ceremonies: map[string]Ceremony{}, sessions: map[string]*sessionTimes{}}
}

func (m *memStore) ListPasskeys(_ context.Context, userID string) ([]StoredPasskey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []StoredPasskey
	for _, passkey := range m.passkeys[userID] {
		out = append(out, passkey)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}
func (m *memStore) PasskeyOwner(_ context.Context, id []byte) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if owner, ok := m.owners[keyOf(id)]; ok {
		return owner, nil
	}
	return "", ErrNotFound
}
func (m *memStore) AddPasskey(_ context.Context, userID string, passkey StoredPasskey, max int) error {
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
func (m *memStore) UpdatePasskeyUse(_ context.Context, userID string, credential webauthn.Credential, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := keyOf(credential.ID)
	passkey, ok := m.passkeys[userID][key]
	if !ok {
		return ErrNotFound
	}
	passkey.Credential, passkey.LastUsedAt = credential, at
	m.passkeys[userID][key] = passkey
	return nil
}
func (m *memStore) RenamePasskey(_ context.Context, userID string, id []byte, name string) error {
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
func (m *memStore) DeletePasskey(_ context.Context, userID string, id []byte) error {
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
func (m *memStore) SaveCeremony(_ context.Context, c Ceremony) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ceremonies[c.ID] = c
	return nil
}
func (m *memStore) TakeCeremony(_ context.Context, id string) (Ceremony, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.ceremonies[id]
	if !ok {
		return Ceremony{}, ErrNotFound
	}
	delete(m.ceremonies, id)
	return c, nil
}
func (m *memStore) MarkStepUp(_ context.Context, key string, until time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.sessions[key]
	if !ok {
		return ErrNotFound
	}
	session.stepUp = until
	return nil
}
func (m *memStore) SessionTimes(_ context.Context, key string) (time.Time, time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.sessions[key]
	if !ok {
		return time.Time{}, time.Time{}, ErrNotFound
	}
	return session.created, session.stepUp, nil
}

const (
	testRP     = "account.bify.io"
	testOrigin = "https://account.bify.io"
)

type fixture struct {
	svc   *Service
	store *memStore
	now   time.Time
	user  User
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{store: newMemStore(), now: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC), user: User{ID: "7c9e6679-7425-40de-944b-e07fc1f90ae7", Name: "buyer@example.com"}}
	cfg, err := ConfigFromOrigin(testOrigin, "BIFY Account")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Now = func() time.Time { return f.now }
	f.svc, err = New(cfg, f.store)
	if err != nil {
		t.Fatal(err)
	}
	// An old session: signed in an hour ago, so it is not "recent".
	f.store.sessions["session-a"] = &sessionTimes{created: f.now.Add(-time.Hour)}
	f.store.sessions["session-b"] = &sessionTimes{created: f.now.Add(-time.Hour)}
	return f
}

func (f *fixture) registerPasskey(t *testing.T, a *softAuthenticator) Passkey {
	t.Helper()
	id, creation, err := f.svc.BeginRegistration(context.Background(), f.user, "session-a")
	if err != nil {
		t.Fatal(err)
	}
	passkey, err := f.svc.FinishRegistration(context.Background(), f.user, "session-a", id, "iPhone", a.register(t, creation))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	return passkey
}

func TestRegisterThenSignIn(t *testing.T) {
	f := newFixture(t)
	a := newAuthenticator(t, testRP, testOrigin)
	passkey := f.registerPasskey(t, a)
	if passkey.Name != "iPhone" || !passkey.Synced || passkey.ID != b64(a.id) {
		t.Fatalf("registered passkey = %+v", passkey)
	}
	list, _ := f.svc.List(context.Background(), f.user.ID)
	if len(list) != 1 || list[0].LastUsedAt != nil {
		t.Fatalf("list = %+v", list)
	}

	id, assertion, err := f.svc.BeginLogin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(assertion.Response.AllowedCredentials) != 0 || assertion.Response.UserVerification != protocol.VerificationRequired {
		t.Fatalf("sign-in must let the browser offer any passkey and require verification: %+v", assertion.Response)
	}
	owner, err := f.svc.FinishLogin(context.Background(), id, a.assert(t, assertion))
	if err != nil || owner != f.user.ID {
		t.Fatalf("FinishLogin = %q, %v", owner, err)
	}
	list, _ = f.svc.List(context.Background(), f.user.ID)
	if list[0].LastUsedAt == nil || !list[0].LastUsedAt.Equal(f.now) {
		t.Fatalf("last use not recorded: %+v", list[0])
	}
}

func TestACeremonyCanBeUsedOnce(t *testing.T) {
	f := newFixture(t)
	a := newAuthenticator(t, testRP, testOrigin)
	f.registerPasskey(t, a)
	id, assertion, _ := f.svc.BeginLogin(context.Background())
	response := a.assert(t, assertion)
	if _, err := f.svc.FinishLogin(context.Background(), id, response); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.FinishLogin(context.Background(), id, response); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replayed sign-in = %v, want ErrNotFound", err)
	}
}

func TestACeremonyExpires(t *testing.T) {
	f := newFixture(t)
	a := newAuthenticator(t, testRP, testOrigin)
	f.registerPasskey(t, a)
	id, assertion, _ := f.svc.BeginLogin(context.Background())
	f.now = f.now.Add(6 * time.Minute)
	if _, err := f.svc.FinishLogin(context.Background(), id, a.assert(t, assertion)); err == nil {
		t.Fatal("an expired ceremony signed in")
	}
}

func TestRegistrationIsBoundToTheSessionThatStartedIt(t *testing.T) {
	f := newFixture(t)
	a := newAuthenticator(t, testRP, testOrigin)
	id, creation, _ := f.svc.BeginRegistration(context.Background(), f.user, "session-a")
	if _, err := f.svc.FinishRegistration(context.Background(), f.user, "session-b", id, "x", a.register(t, creation)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("finished from another session = %v", err)
	}
	other := User{ID: "11111111-1111-1111-1111-111111111111", Name: "other@example.com"}
	id, creation, _ = f.svc.BeginRegistration(context.Background(), f.user, "session-a")
	if _, err := f.svc.FinishRegistration(context.Background(), other, "session-a", id, "x", a.register(t, creation)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("finished for another user = %v", err)
	}
}

func TestAPasskeyFromAnotherSiteIsRefused(t *testing.T) {
	f := newFixture(t)
	phishing := newAuthenticator(t, testRP, "https://account-bify.io") // look-alike page origin
	id, creation, _ := f.svc.BeginRegistration(context.Background(), f.user, "session-a")
	if _, err := f.svc.FinishRegistration(context.Background(), f.user, "session-a", id, "x", phishing.register(t, creation)); !errors.Is(err, ErrVerification) {
		t.Fatalf("registration from another origin = %v", err)
	}
	wrongRP := newAuthenticator(t, "evil.example", testOrigin)
	id, creation, _ = f.svc.BeginRegistration(context.Background(), f.user, "session-a")
	if _, err := f.svc.FinishRegistration(context.Background(), f.user, "session-a", id, "x", wrongRP.register(t, creation)); !errors.Is(err, ErrVerification) {
		t.Fatalf("registration for another relying party = %v", err)
	}

	a := newAuthenticator(t, testRP, testOrigin)
	f.registerPasskey(t, a)
	a.origin = "https://account-bify.io"
	id, assertion, _ := f.svc.BeginLogin(context.Background())
	if _, err := f.svc.FinishLogin(context.Background(), id, a.assert(t, assertion)); !errors.Is(err, ErrVerification) {
		t.Fatalf("sign-in from another origin = %v", err)
	}
}

func TestSignInRefusesAUserHandleThatIsNotTheOwner(t *testing.T) {
	f := newFixture(t)
	a := newAuthenticator(t, testRP, testOrigin)
	f.registerPasskey(t, a)
	a.userID = []byte("11111111-1111-1111-1111-111111111111")
	id, assertion, _ := f.svc.BeginLogin(context.Background())
	if _, err := f.svc.FinishLogin(context.Background(), id, a.assert(t, assertion)); !errors.Is(err, ErrVerification) {
		t.Fatalf("mismatched user handle = %v", err)
	}
}

func TestARemovedPasskeyCannotSignIn(t *testing.T) {
	f := newFixture(t)
	a := newAuthenticator(t, testRP, testOrigin)
	passkey := f.registerPasskey(t, a)
	if err := f.svc.Delete(context.Background(), f.user.ID, passkey.ID); err != nil {
		t.Fatal(err)
	}
	id, assertion, _ := f.svc.BeginLogin(context.Background())
	if _, err := f.svc.FinishLogin(context.Background(), id, a.assert(t, assertion)); err == nil {
		t.Fatal("a removed passkey signed in")
	}
}

func TestAPossiblyClonedPasskeyIsRefused(t *testing.T) {
	f := newFixture(t)
	a := newAuthenticator(t, testRP, testOrigin)
	a.synced = false
	a.signCount = 5
	f.registerPasskey(t, a)
	a.signCount = 6
	id, assertion, _ := f.svc.BeginLogin(context.Background())
	if _, err := f.svc.FinishLogin(context.Background(), id, a.assert(t, assertion)); err != nil {
		t.Fatalf("a rising counter = %v", err)
	}
	a.signCount = 3 // went backwards: a copy of the key is in use somewhere
	id, assertion, _ = f.svc.BeginLogin(context.Background())
	if _, err := f.svc.FinishLogin(context.Background(), id, a.assert(t, assertion)); !errors.Is(err, ErrVerification) {
		t.Fatalf("a counter that went backwards = %v", err)
	}
}

func TestStepUpMarksTheSessionRecentForTheWindow(t *testing.T) {
	f := newFixture(t)
	a := newAuthenticator(t, testRP, testOrigin)
	if _, _, err := f.svc.BeginStepUp(context.Background(), f.user, "session-a"); !errors.Is(err, ErrNoPasskeys) {
		t.Fatalf("step-up without passkeys = %v", err)
	}
	f.registerPasskey(t, a)
	if recent, _ := f.svc.RecentlyAuthenticated(context.Background(), "session-a"); recent {
		t.Fatal("an hour-old session counted as recent")
	}
	id, assertion, err := f.svc.BeginStepUp(context.Background(), f.user, "session-a")
	if err != nil || len(assertion.Response.AllowedCredentials) != 1 {
		t.Fatalf("step-up options = %+v, %v", assertion, err)
	}
	if err := f.svc.FinishStepUp(context.Background(), f.user, "session-a", id, a.assert(t, assertion)); err != nil {
		t.Fatal(err)
	}
	if recent, _ := f.svc.RecentlyAuthenticated(context.Background(), "session-a"); !recent {
		t.Fatal("a confirmed session is not recent")
	}
	if recent, _ := f.svc.RecentlyAuthenticated(context.Background(), "session-b"); recent {
		t.Fatal("confirming one session confirmed another")
	}
	f.now = f.now.Add(5*time.Minute + time.Second)
	if recent, _ := f.svc.RecentlyAuthenticated(context.Background(), "session-a"); recent {
		t.Fatal("a confirmation outlived its window")
	}
}

func TestAFreshSignInCountsAsRecent(t *testing.T) {
	f := newFixture(t)
	f.store.sessions["fresh"] = &sessionTimes{created: f.now.Add(-2 * time.Minute)}
	if recent, _ := f.svc.RecentlyAuthenticated(context.Background(), "fresh"); !recent {
		t.Fatal("a two-minute-old sign-in is not recent")
	}
}

func TestPasskeyLimitAndDuplicates(t *testing.T) {
	f := newFixture(t)
	f.svc.cfg.MaxPerUser = 2
	f.registerPasskey(t, newAuthenticator(t, testRP, testOrigin))
	a := newAuthenticator(t, testRP, testOrigin)
	f.registerPasskey(t, a)
	if _, _, err := f.svc.BeginRegistration(context.Background(), f.user, "session-a"); !errors.Is(err, ErrLimit) {
		t.Fatalf("over the limit = %v", err)
	}
	f.svc.cfg.MaxPerUser = 10
	id, creation, _ := f.svc.BeginRegistration(context.Background(), f.user, "session-a")
	if len(creation.Response.CredentialExcludeList) != 2 {
		t.Fatalf("existing passkeys are not excluded: %d", len(creation.Response.CredentialExcludeList))
	}
	if _, err := f.svc.FinishRegistration(context.Background(), f.user, "session-a", id, "again", a.register(t, creation)); !errors.Is(err, ErrExists) {
		t.Fatalf("the same passkey twice = %v", err)
	}
}

func TestNamesAreCleaned(t *testing.T) {
	if got := CleanName("  My\x00 MacBook\n Pro  "); got != "My MacBook Pro" {
		t.Fatalf("CleanName = %q", got)
	}
	if got := CleanName("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); len([]rune(got)) != 40 {
		t.Fatalf("long name kept %d characters", len([]rune(got)))
	}
}

func TestConfigFromOrigin(t *testing.T) {
	cfg, err := ConfigFromOrigin("https://developer.bify.io/", "BIFY Developers")
	if err != nil || cfg.RPID != "developer.bify.io" || cfg.Origins[0] != "https://developer.bify.io" {
		t.Fatalf("cfg = %+v, %v", cfg, err)
	}
	if _, err := ConfigFromOrigin("http://developer.bify.io", "x"); err == nil {
		t.Fatal("accepted plain http on a public host")
	}
	if cfg, err := ConfigFromOrigin("http://localhost:3000", "x"); err != nil || cfg.RPID != "localhost" {
		t.Fatalf("localhost = %+v, %v", cfg, err)
	}
}
