package passkey

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/nagatejakachapuram/bify-auth-kit/passkeytest"
)

type httpFixture struct {
	*fixture
	mux      *http.ServeMux
	signedIn string
	events   []string
	session  string
}

func newHTTPFixture(t *testing.T) *httpFixture {
	f := &httpFixture{fixture: newFixture(t), mux: http.NewServeMux(), session: "session-a"}
	hooks := Hooks{
		Current: func(r *http.Request) (User, string, error) {
			if r.Header.Get("Cookie") != "signed-in" {
				return User{}, "", errors.New("no session")
			}
			return f.user, f.session, nil
		},
		SignIn: func(w http.ResponseWriter, _ *http.Request, userID string) error {
			f.signedIn = userID
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "new"})
			return nil
		},
		CheckOrigin: func(r *http.Request) error {
			if r.Header.Get("Origin") != testOrigin {
				return errors.New("cross-site")
			}
			return nil
		},
		Fallbacks: func(*http.Request, User) []string { return []string{"totp"} },
		Event:     func(_ *http.Request, name string) { f.events = append(f.events, name) },
	}
	f.svc.Mount(hooks, func(method, path string, h http.HandlerFunc) { f.mux.HandleFunc(method+" "+path, h) })
	f.mux.Handle("POST /v1/developer/api-keys", f.svc.RequireRecentAuth(hooks)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})))
	return f
}

func (f *httpFixture) do(t *testing.T, method, path string, body any, signedIn bool) *httptest.ResponseRecorder {
	t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set("Origin", testOrigin)
	if signedIn {
		req.Header.Set("Cookie", "signed-in")
	}
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
	return out
}

func TestAddingAPasskeyNeedsARecentConfirmation(t *testing.T) {
	f := newHTTPFixture(t)
	rec := f.do(t, "POST", PathRegisterOptions, nil, true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("register options on an old session = %d", rec.Code)
	}
	refusal := decode[struct {
		Code    string   `json:"code"`
		Methods []string `json:"methods"`
	}](t, rec)
	if refusal.Code != StepUpRequiredCode || len(refusal.Methods) != 1 || refusal.Methods[0] != "totp" {
		t.Fatalf("refusal = %+v", refusal)
	}
	// After a fallback confirmation (here: the portal verified a TOTP code) it is allowed.
	if err := f.svc.MarkStepUp(t.Context(), f.session); err != nil {
		t.Fatal(err)
	}
	rec = f.do(t, "POST", PathRegisterOptions, nil, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("register options after confirming = %d %s", rec.Code, rec.Body.String())
	}
	started := decode[struct {
		CeremonyID string                      `json:"ceremonyId"`
		Options    protocol.CredentialCreation `json:"options"`
	}](t, rec)
	a := passkeytest.NewAuthenticator(t, testRP, testOrigin)
	rec = f.do(t, "POST", PathRegisterVerify, map[string]any{"ceremonyId": started.CeremonyID, "name": "iPhone", "credential": json.RawMessage(a.Register(t, &started.Options))}, true)
	if rec.Code != http.StatusOK || len(f.events) != 1 || f.events[0] != "passkey_added" {
		t.Fatalf("register verify = %d %s, events %v", rec.Code, rec.Body.String(), f.events)
	}
	// Now the account has a passkey, which is offered first.
	f.now = f.now.Add(10 * time.Minute)
	rec = f.do(t, "POST", "/v1/developer/api-keys", nil, true)
	refusal = decode[struct {
		Code    string   `json:"code"`
		Methods []string `json:"methods"`
	}](t, rec)
	if rec.Code != http.StatusForbidden || len(refusal.Methods) != 2 || refusal.Methods[0] != "passkey" {
		t.Fatalf("sensitive action = %d %+v", rec.Code, refusal)
	}
}

func TestPasskeySignInStartsASession(t *testing.T) {
	f := newHTTPFixture(t)
	a := passkeytest.NewAuthenticator(t, testRP, testOrigin)
	f.registerPasskey(t, a)
	rec := f.do(t, "POST", PathLoginOptions, nil, false)
	started := decode[struct {
		CeremonyID string                       `json:"ceremonyId"`
		Options    protocol.CredentialAssertion `json:"options"`
	}](t, rec)
	rec = f.do(t, "POST", PathLoginVerify, map[string]any{"ceremonyId": started.CeremonyID, "credential": json.RawMessage(a.Assert(t, &started.Options))}, false)
	if rec.Code != http.StatusOK || f.signedIn != f.user.ID || rec.Header().Get("Set-Cookie") == "" {
		t.Fatalf("passkey sign-in = %d %s, signed in %q", rec.Code, rec.Body.String(), f.signedIn)
	}
	// A failed sign-in says nothing about whether the account or passkey exists.
	rec = f.do(t, "POST", PathLoginVerify, map[string]any{"ceremonyId": started.CeremonyID, "credential": json.RawMessage(a.Assert(t, &started.Options))}, false)
	if rec.Code != http.StatusUnauthorized || decode[map[string]string](t, rec)["code"] != "passkey_failed" {
		t.Fatalf("replayed sign-in = %d %s", rec.Code, rec.Body.String())
	}
}

func TestStepUpThroughTheEndpoints(t *testing.T) {
	f := newHTTPFixture(t)
	a := passkeytest.NewAuthenticator(t, testRP, testOrigin)
	f.registerPasskey(t, a)
	status := decode[struct {
		Recent  bool     `json:"recent"`
		Methods []string `json:"methods"`
	}](t, f.do(t, "GET", PathStepUpStatus, nil, true))
	if status.Recent || len(status.Methods) != 2 {
		t.Fatalf("status before = %+v", status)
	}
	started := decode[struct {
		CeremonyID string                       `json:"ceremonyId"`
		Options    protocol.CredentialAssertion `json:"options"`
	}](t, f.do(t, "POST", PathStepUpOptions, nil, true))
	rec := f.do(t, "POST", PathStepUpVerify, map[string]any{"ceremonyId": started.CeremonyID, "credential": json.RawMessage(a.Assert(t, &started.Options))}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("step-up verify = %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.do(t, "POST", "/v1/developer/api-keys", nil, true); rec.Code != http.StatusCreated {
		t.Fatalf("sensitive action after confirming = %d", rec.Code)
	}
	list := decode[struct {
		Data []Passkey `json:"data"`
	}](t, f.do(t, "GET", PathList, nil, true))
	if len(list.Data) != 1 {
		t.Fatalf("list = %+v", list)
	}
	if rec := f.do(t, "POST", PathDelete, map[string]string{"id": list.Data[0].ID}, true); rec.Code != http.StatusNoContent {
		t.Fatalf("delete within the window = %d %s", rec.Code, rec.Body.String())
	}
}

func TestEndpointsRefuseCrossSiteAndSignedOutRequests(t *testing.T) {
	f := newHTTPFixture(t)
	req := httptest.NewRequest("POST", PathLoginOptions, nil)
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-site sign-in options = %d", rec.Code)
	}
	for _, path := range []string{PathRegisterOptions, PathStepUpOptions, PathDelete, PathRename} {
		if rec := f.do(t, "POST", path, nil, false); rec.Code != http.StatusUnauthorized {
			t.Fatalf("signed-out %s = %d", path, rec.Code)
		}
	}
	if rec := f.do(t, "GET", PathList, nil, false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("signed-out list = %d", rec.Code)
	}
}
