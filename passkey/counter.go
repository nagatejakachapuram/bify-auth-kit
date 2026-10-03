package passkey

import "github.com/go-webauthn/webauthn/webauthn"

// Counterless authenticators (including synced passkeys) legitimately return zero. Once either
// side has a nonzero counter, WebAuthn requires strictly increasing values. Apply this check in
// the same critical section as persistence; signature verification alone uses a stale snapshot.
func counterAdvances(stored, next webauthn.Credential) bool {
	previous, incoming := stored.Authenticator.SignCount, next.Authenticator.SignCount
	return !next.Authenticator.CloneWarning && ((previous == 0 && incoming == 0) || incoming > previous)
}
