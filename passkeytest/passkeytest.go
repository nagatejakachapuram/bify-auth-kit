// Package passkeytest provides a software passkey for tests: it answers registration and sign-in
// exactly as a browser with Face ID, Touch ID or a security key would, so portals can test passkey
// endpoints end to end without a device.
package passkeytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"
)

// Authenticator is a software passkey (ES256), standing in for Face ID / Touch ID / a security key.
// It produces exactly the attestation and assertion responses a browser hands back.
type Authenticator struct {
	key *ecdsa.PrivateKey
	// ID is the credential id; UserID the account handle it was registered to.
	ID     []byte
	UserID []byte
	// RPID and Origin are what the authenticator signs for; change them to act as a phishing site.
	RPID   string
	Origin string
	// SignCount is reported on every use; Synced marks it as a backed-up (synced) passkey.
	SignCount uint32
	Synced    bool
}

// NewAuthenticator returns a synced software passkey for rpID used from origin.
func NewAuthenticator(t testing.TB, rpID, origin string) *Authenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	_, _ = rand.Read(id)
	return &Authenticator{key: key, ID: id, RPID: rpID, Origin: origin, Synced: true}
}

// B64 is unpadded base64url, the encoding WebAuthn JSON uses.
func B64(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

func (a *Authenticator) flags(attested bool) byte {
	flags := byte(0x01 | 0x04) // user present, user verified
	if a.Synced {
		flags |= 0x08 | 0x10 // backup eligible, backed up
	}
	if attested {
		flags |= 0x40
	}
	return flags
}

func (a *Authenticator) authData(attested bool) []byte {
	rpHash := sha256.Sum256([]byte(a.RPID))
	out := append([]byte{}, rpHash[:]...)
	out = append(out, a.flags(attested))
	out = binary.BigEndian.AppendUint32(out, a.SignCount)
	if attested {
		out = append(out, make([]byte, 16)...) // AAGUID
		out = binary.BigEndian.AppendUint16(out, uint16(len(a.ID)))
		out = append(out, a.ID...)
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
func (a *Authenticator) Register(t *testing.T, creation *protocol.CredentialCreation) []byte {
	t.Helper()
	// In-process options carry the user handle as bytes; options that went through JSON carry base64url.
	switch id := creation.Response.User.ID.(type) {
	case protocol.URLEncodedBase64:
		a.UserID = []byte(id)
	case string:
		decoded, err := base64.RawURLEncoding.DecodeString(id)
		if err != nil {
			t.Fatalf("user handle %q: %v", id, err)
		}
		a.UserID = decoded
	default:
		t.Fatalf("unexpected user handle type %T", id)
	}
	attestation, _ := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": a.authData(true)})
	body, _ := json.Marshal(map[string]any{
		"id": B64(a.ID), "rawId": B64(a.ID), "type": "public-key", "authenticatorAttachment": "platform",
		"response": map[string]any{
			"clientDataJSON":    B64(clientData("webauthn.create", creation.Response.Challenge.String(), a.Origin)),
			"attestationObject": B64(attestation),
			"transports":        []string{"internal", "hybrid"},
		},
		"clientExtensionResults": map[string]any{},
	})
	return body
}

// assert answers navigator.credentials.get for the given options.
func (a *Authenticator) Assert(t *testing.T, assertion *protocol.CredentialAssertion) []byte {
	t.Helper()
	data := a.authData(false)
	client := clientData("webauthn.get", assertion.Response.Challenge.String(), a.Origin)
	clientHash := sha256.Sum256(client)
	digest := sha256.Sum256(append(append([]byte{}, data...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{
		"id": B64(a.ID), "rawId": B64(a.ID), "type": "public-key", "authenticatorAttachment": "platform",
		"response": map[string]any{
			"clientDataJSON":    B64(client),
			"authenticatorData": B64(data),
			"signature":         B64(signature),
			"userHandle":        B64(a.UserID),
		},
		"clientExtensionResults": map[string]any{},
	})
	return body
}
