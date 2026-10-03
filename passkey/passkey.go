// Package passkey adds passkeys (WebAuthn: Face ID, Touch ID, Windows Hello, security keys) to a BIFY
// portal: signing in, managing them in Security settings, and confirming sensitive actions ("step-up").
//
// It is shared by the BIFY developer portal and BIFY Account, which have the same account, session and
// DynamoDB conventions. Each portal supplies a Store (DynamoStore fits both) and a few Hooks into its
// own sessions; the ceremonies, checks and HTTP endpoints are identical.
//
// Security properties this package relies on and enforces:
//   - Passkeys are bound to the relying party ID (the portal's host), so a look-alike site cannot use them.
//   - Every ceremony is single-use and expires: its challenge is stored server-side and deleted when used.
//   - User verification (biometric or device PIN) is required, so a passkey is two factors on its own.
//   - Adding or removing a passkey is itself a sensitive action and requires a recent confirmation.
//   - Only public keys are stored; a database leak yields nothing that can sign in.
package passkey

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	// ErrNotFound means the passkey, ceremony or owner does not exist (or the ceremony expired).
	ErrNotFound = errors.New("passkey: not found")
	// ErrLimit means the account already has the maximum number of passkeys.
	ErrLimit = errors.New("passkey: limit reached")
	// ErrExists means this passkey is already registered.
	ErrExists = errors.New("passkey: already registered")
	// ErrNoPasskeys means the account has no passkey to confirm with.
	ErrNoPasskeys = errors.New("passkey: none registered")
	// ErrVerification means the browser's response did not verify. Its detail is never shown to users.
	ErrVerification = errors.New("passkey: verification failed")
)

// Config describes the relying party: the portal passkeys are bound to.
type Config struct {
	// RPID is the portal's host, for example "account.bify.io". Passkeys only work on this host.
	RPID string
	// RPDisplayName is shown by the browser and password manager, for example "BIFY Account".
	RPDisplayName string
	// Origins are the exact page origins allowed to use passkeys, for example "https://account.bify.io".
	Origins []string
	// CeremonyTTL bounds how long a started ceremony stays usable. Default 5 minutes.
	CeremonyTTL time.Duration
	// StepUpWindow is how long a confirmation (or a fresh sign-in) counts as recent. Default 5 minutes.
	StepUpWindow time.Duration
	// MaxPerUser caps passkeys per account. Default 10.
	MaxPerUser int
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// ConfigFromOrigin derives the relying party from the portal's own origin, so a portal needs no new
// configuration: passkeys belong to exactly the host its pages are served from.
func ConfigFromOrigin(portalOrigin, displayName string) (Config, error) {
	parsed, err := url.Parse(strings.TrimRight(strings.TrimSpace(portalOrigin), "/"))
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLocal(parsed.Hostname()))) {
		return Config{}, fmt.Errorf("passkey: portal origin %q must be https (or http on localhost)", portalOrigin)
	}
	return Config{RPID: parsed.Hostname(), RPDisplayName: displayName, Origins: []string{parsed.Scheme + "://" + parsed.Host}}, nil
}

func isLocal(host string) bool { return host == "localhost" || host == "127.0.0.1" }

// User is the account passkeys are registered to.
type User struct {
	ID          string // stable account id; becomes the passkey's user handle
	Name        string // what the password manager lists, for example the email or wallet
	DisplayName string // the person's name, or Name when they have none
}

// Passkey is what Security settings shows about one registered passkey.
type Passkey struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	// Synced reports a passkey kept in iCloud Keychain, Google Password Manager or similar, so it
	// survives losing the device.
	Synced     bool     `json:"synced"`
	Transports []string `json:"transports,omitempty"`
}

// StoredPasskey is a passkey as persisted: the public credential and its label.
type StoredPasskey struct {
	Credential webauthn.Credential
	Name       string
	CreatedAt  time.Time
	LastUsedAt time.Time
}

// Ceremony is a started registration, sign-in or confirmation, waiting for the browser's answer.
type Ceremony struct {
	ID         string
	Kind       string // kindRegister, kindLogin or kindStepUp
	UserID     string // empty for sign-in, where the user is not known yet
	SessionKey string // the session that started it; empty for sign-in
	Data       webauthn.SessionData
	ExpiresAt  time.Time
}

const (
	kindRegister = "register"
	kindLogin    = "login"
	kindStepUp   = "step-up"
)

// Store persists passkeys, ceremonies and step-up confirmations. DynamoStore implements it.
type Store interface {
	ListPasskeys(ctx context.Context, userID string) ([]StoredPasskey, error)
	PasskeyOwner(ctx context.Context, credentialID []byte) (string, error)
	AddPasskey(ctx context.Context, userID string, passkey StoredPasskey, max int) error
	UpdatePasskeyUse(ctx context.Context, userID string, credential webauthn.Credential, at time.Time) error
	RenamePasskey(ctx context.Context, userID string, credentialID []byte, name string) error
	DeletePasskey(ctx context.Context, userID string, credentialID []byte) error
	SaveCeremony(ctx context.Context, ceremony Ceremony) error
	TakeCeremony(ctx context.Context, id string) (Ceremony, error)
	MarkStepUp(ctx context.Context, sessionKey string, until time.Time) error
	SessionTimes(ctx context.Context, sessionKey string) (createdAt, stepUpUntil time.Time, err error)
}

// Service runs passkey ceremonies for one portal.
type Service struct {
	wa    *webauthn.WebAuthn
	store Store
	cfg   Config
}

// New validates cfg and returns a Service.
func New(cfg Config, store Store) (*Service, error) {
	if store == nil || cfg.RPID == "" || len(cfg.Origins) == 0 {
		return nil, errors.New("passkey: a store, relying party ID and origin are required")
	}
	if cfg.RPDisplayName == "" {
		cfg.RPDisplayName = "BIFY"
	}
	if cfg.CeremonyTTL <= 0 {
		cfg.CeremonyTTL = 5 * time.Minute
	}
	if cfg.StepUpWindow <= 0 {
		cfg.StepUpWindow = 5 * time.Minute
	}
	if cfg.MaxPerUser <= 0 {
		cfg.MaxPerUser = 10
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     cfg.Origins,
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: cfg.CeremonyTTL, TimeoutUVD: cfg.CeremonyTTL},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: cfg.CeremonyTTL, TimeoutUVD: cfg.CeremonyTTL},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("passkey: %w", err)
	}
	return &Service{wa: wa, store: store, cfg: cfg}, nil
}

// StepUpWindow is how long a confirmation counts as recent.
func (s *Service) StepUpWindow() time.Duration { return s.cfg.StepUpWindow }

// waUser adapts a User and their credentials to go-webauthn.
type waUser struct {
	user        User
	credentials []webauthn.Credential
}

func (u waUser) WebAuthnID() []byte                         { return []byte(u.user.ID) }
func (u waUser) WebAuthnName() string                       { return u.user.Name }
func (u waUser) WebAuthnDisplayName() string                { return u.user.DisplayName }
func (u waUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func (s *Service) loadUser(ctx context.Context, user User) (waUser, []StoredPasskey, error) {
	stored, err := s.store.ListPasskeys(ctx, user.ID)
	if err != nil {
		return waUser{}, nil, err
	}
	credentials := make([]webauthn.Credential, 0, len(stored))
	for _, passkey := range stored {
		credentials = append(credentials, passkey.Credential)
	}
	if user.DisplayName == "" {
		user.DisplayName = user.Name
	}
	return waUser{user: user, credentials: credentials}, stored, nil
}

// List returns the account's passkeys, newest first.
func (s *Service) List(ctx context.Context, userID string) ([]Passkey, error) {
	stored, err := s.store.ListPasskeys(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]Passkey, 0, len(stored))
	for _, passkey := range stored {
		out = append(out, view(passkey))
	}
	for i := 1; i < len(out); i++ { // tiny lists: insertion sort, newest first
		for j := i; j > 0 && out[j].CreatedAt.After(out[j-1].CreatedAt); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out, nil
}

func view(passkey StoredPasskey) Passkey {
	out := Passkey{ID: encodeID(passkey.Credential.ID), Name: passkey.Name, CreatedAt: passkey.CreatedAt, Synced: passkey.Credential.Flags.BackupState}
	if !passkey.LastUsedAt.IsZero() {
		used := passkey.LastUsedAt
		out.LastUsedAt = &used
	}
	for _, transport := range passkey.Credential.Transport {
		out.Transports = append(out.Transports, string(transport))
	}
	return out
}

// HasPasskeys reports whether the account has at least one passkey.
func (s *Service) HasPasskeys(ctx context.Context, userID string) (bool, error) {
	stored, err := s.store.ListPasskeys(ctx, userID)
	return len(stored) > 0, err
}

// BeginRegistration starts adding a passkey to user's account from the session identified by sessionKey.
// It returns the ceremony id and the options for navigator.credentials.create.
func (s *Service) BeginRegistration(ctx context.Context, user User, sessionKey string) (string, *protocol.CredentialCreation, error) {
	account, stored, err := s.loadUser(ctx, user)
	if err != nil {
		return "", nil, err
	}
	if len(stored) >= s.cfg.MaxPerUser {
		return "", nil, ErrLimit
	}
	exclusions := make([]protocol.CredentialDescriptor, 0, len(account.credentials))
	for _, credential := range account.credentials {
		exclusions = append(exclusions, credential.Descriptor())
	}
	creation, data, err := s.wa.BeginRegistration(account,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
		webauthn.WithExclusions(exclusions),
	)
	if err != nil {
		return "", nil, fmt.Errorf("passkey: begin registration: %w", err)
	}
	id, err := s.saveCeremony(ctx, kindRegister, user.ID, sessionKey, *data)
	return id, creation, err
}

// FinishRegistration verifies the browser's answer to BeginRegistration and stores the new passkey.
func (s *Service) FinishRegistration(ctx context.Context, user User, sessionKey, ceremonyID, name string, response []byte) (Passkey, error) {
	ceremony, err := s.takeCeremony(ctx, ceremonyID, kindRegister, user.ID, sessionKey)
	if err != nil {
		return Passkey{}, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return Passkey{}, ErrVerification
	}
	account, _, err := s.loadUser(ctx, user)
	if err != nil {
		return Passkey{}, err
	}
	credential, err := s.wa.CreateCredential(account, ceremony.Data, parsed)
	if err != nil || !credential.Flags.UserVerified {
		return Passkey{}, ErrVerification
	}
	now := s.cfg.Now().UTC()
	stored := StoredPasskey{Credential: *credential, Name: CleanName(name), CreatedAt: now}
	if stored.Name == "" {
		stored.Name = "Passkey"
	}
	if err := s.store.AddPasskey(ctx, user.ID, stored, s.cfg.MaxPerUser); err != nil {
		return Passkey{}, err
	}
	return view(stored), nil
}

// BeginLogin starts a sign-in with any passkey for this portal (the browser lists the user's passkeys).
func (s *Service) BeginLogin(ctx context.Context) (string, *protocol.CredentialAssertion, error) {
	assertion, data, err := s.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return "", nil, fmt.Errorf("passkey: begin login: %w", err)
	}
	id, err := s.saveCeremony(ctx, kindLogin, "", "", *data)
	return id, assertion, err
}

// FinishLogin verifies a sign-in and returns the id of the account it belongs to.
func (s *Service) FinishLogin(ctx context.Context, ceremonyID string, response []byte) (string, error) {
	ceremony, err := s.takeCeremony(ctx, ceremonyID, kindLogin, "", "")
	if err != nil {
		return "", err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return "", ErrVerification
	}
	var owner string
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		id, err := s.store.PasskeyOwner(ctx, rawID)
		if err != nil {
			return nil, err
		}
		// The authenticator names the account it was registered to; it must be this passkey's owner.
		if string(userHandle) != id {
			return nil, ErrVerification
		}
		owner = id
		account, _, err := s.loadUser(ctx, User{ID: id})
		return account, err
	}
	_, credential, err := s.wa.ValidatePasskeyLogin(handler, ceremony.Data, parsed)
	if err != nil || owner == "" {
		return "", ErrVerification
	}
	if err := s.recordUse(ctx, owner, credential); err != nil {
		return "", err
	}
	return owner, nil
}

// BeginStepUp starts confirming a sensitive action with one of user's passkeys.
func (s *Service) BeginStepUp(ctx context.Context, user User, sessionKey string) (string, *protocol.CredentialAssertion, error) {
	account, stored, err := s.loadUser(ctx, user)
	if err != nil {
		return "", nil, err
	}
	if len(stored) == 0 {
		return "", nil, ErrNoPasskeys
	}
	assertion, data, err := s.wa.BeginLogin(account, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return "", nil, fmt.Errorf("passkey: begin step-up: %w", err)
	}
	id, err := s.saveCeremony(ctx, kindStepUp, user.ID, sessionKey, *data)
	return id, assertion, err
}

// FinishStepUp verifies a confirmation and marks the session as recently confirmed.
func (s *Service) FinishStepUp(ctx context.Context, user User, sessionKey, ceremonyID string, response []byte) error {
	ceremony, err := s.takeCeremony(ctx, ceremonyID, kindStepUp, user.ID, sessionKey)
	if err != nil {
		return err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return ErrVerification
	}
	account, _, err := s.loadUser(ctx, user)
	if err != nil {
		return err
	}
	credential, err := s.wa.ValidateLogin(account, ceremony.Data, parsed)
	if err != nil {
		return ErrVerification
	}
	if err := s.recordUse(ctx, user.ID, credential); err != nil {
		return err
	}
	return s.MarkStepUp(ctx, sessionKey)
}

// MarkStepUp records that the session just confirmed it is its owner (by passkey, or by a fallback such
// as an authenticator or email code that the portal verified itself).
func (s *Service) MarkStepUp(ctx context.Context, sessionKey string) error {
	return s.store.MarkStepUp(ctx, sessionKey, s.cfg.Now().UTC().Add(s.cfg.StepUpWindow))
}

// RecentlyAuthenticated reports whether the session confirmed itself, or signed in, within the step-up
// window. A fresh sign-in counts: the person just proved who they are.
func (s *Service) RecentlyAuthenticated(ctx context.Context, sessionKey string) (bool, error) {
	createdAt, until, err := s.store.SessionTimes(ctx, sessionKey)
	if err != nil {
		return false, err
	}
	now := s.cfg.Now()
	return until.After(now) || (!createdAt.IsZero() && now.Sub(createdAt) < s.cfg.StepUpWindow), nil
}

// Rename relabels one of the account's passkeys.
func (s *Service) Rename(ctx context.Context, userID, passkeyID, name string) error {
	id, err := decodeID(passkeyID)
	if err != nil {
		return ErrNotFound
	}
	name = CleanName(name)
	if name == "" {
		return errors.New("passkey: a name is required")
	}
	return s.store.RenamePasskey(ctx, userID, id, name)
}

// Delete removes one of the account's passkeys.
func (s *Service) Delete(ctx context.Context, userID, passkeyID string) error {
	id, err := decodeID(passkeyID)
	if err != nil {
		return ErrNotFound
	}
	return s.store.DeletePasskey(ctx, userID, id)
}

func (s *Service) recordUse(ctx context.Context, userID string, credential *webauthn.Credential) error {
	// A counter that went backwards means the passkey may have been cloned. Synced passkeys always
	// report 0, which go-webauthn does not flag.
	if credential.Authenticator.CloneWarning {
		return ErrVerification
	}
	return s.store.UpdatePasskeyUse(ctx, userID, *credential, s.cfg.Now().UTC())
}

func (s *Service) saveCeremony(ctx context.Context, kind, userID, sessionKey string, data webauthn.SessionData) (string, error) {
	id, err := randomID()
	if err != nil {
		return "", err
	}
	ceremony := Ceremony{ID: id, Kind: kind, UserID: userID, SessionKey: sessionKey, Data: data, ExpiresAt: s.cfg.Now().UTC().Add(s.cfg.CeremonyTTL)}
	if err := s.store.SaveCeremony(ctx, ceremony); err != nil {
		return "", err
	}
	return id, nil
}

// takeCeremony consumes a ceremony (single use) and checks it belongs to this step, user and session.
func (s *Service) takeCeremony(ctx context.Context, id, kind, userID, sessionKey string) (Ceremony, error) {
	if !validCeremonyID(id) {
		return Ceremony{}, ErrNotFound
	}
	ceremony, err := s.store.TakeCeremony(ctx, id)
	if err != nil {
		return Ceremony{}, err
	}
	if ceremony.Kind != kind || ceremony.UserID != userID || ceremony.SessionKey != sessionKey || !s.cfg.Now().Before(ceremony.ExpiresAt) {
		return Ceremony{}, ErrNotFound
	}
	return ceremony, nil
}

// CleanName keeps a passkey label printable and short.
func CleanName(name string) string {
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(name))
	if runes := []rune(name); len(runes) > 40 {
		name = strings.TrimSpace(string(runes[:40]))
	}
	return name
}

func encodeID(id []byte) string { return base64.RawURLEncoding.EncodeToString(id) }

func decodeID(id string) ([]byte, error) {
	if id == "" || len(id) > 1400 {
		return nil, ErrNotFound
	}
	return base64.RawURLEncoding.DecodeString(id)
}

// keyOf is the storage key for a credential id: credential ids can be up to 1023 bytes, longer than a
// DynamoDB sort key allows once encoded, so records are keyed by its SHA-256.
func keyOf(credentialID []byte) string {
	sum := sha256.Sum256(credentialID)
	return hex.EncodeToString(sum[:])
}

func randomID() (string, error) {
	challenge, err := protocol.CreateChallenge()
	if err != nil {
		return "", err
	}
	return challenge.String(), nil
}

func validCeremonyID(id string) bool {
	if len(id) < 20 || len(id) > 64 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// marshalCredential and unmarshalCredential keep the stored format in one place.
func marshalCredential(credential webauthn.Credential) (string, error) {
	raw, err := json.Marshal(credential)
	return string(raw), err
}

func unmarshalCredential(raw string) (webauthn.Credential, error) {
	var credential webauthn.Credential
	err := json.Unmarshal([]byte(raw), &credential)
	return credential, err
}
