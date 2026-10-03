package passkey

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/nagatejakachapuram/bify-auth-kit/passkeytest"
)

const (
	testRP     = "account.bify.io"
	testOrigin = "https://account.bify.io"
)

type fixture struct {
	svc   *Service
	store *MemoryStore
	now   time.Time
	user  User
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{store: NewMemoryStore(), now: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC), user: User{ID: "7c9e6679-7425-40de-944b-e07fc1f90ae7", Name: "buyer@example.com"}}
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
	f.store.AddSession("session-a", f.now.Add(-time.Hour))
	f.store.AddSession("session-b", f.now.Add(-time.Hour))
	return f
}

func (f *fixture) registerPasskey(t *testing.T, a *passkeytest.Authenticator) Passkey {
	t.Helper()
	id, creation, err := f.svc.BeginRegistration(context.Background(), f.user, "session-a")
	if err != nil {
		t.Fatal(err)
	}
	passkey, err := f.svc.FinishRegistration(context.Background(), f.user, "session-a", id, "iPhone", a.Register(t, creation))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	return passkey
}

func TestRegisterThenSignIn(t *testing.T) {
	f := newFixture(t)
	a := passkeytest.NewAuthenticator(t, testRP, testOrigin)
	passkey := f.registerPasskey(t, a)
	if passkey.Name != "iPhone" || !passkey.Synced || passkey.ID != passkeytest.B64(a.ID) {
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
	owner, err := f.svc.FinishLogin(context.Background(), id, a.Assert(t, assertion))
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
	a := passkeytest.NewAuthenticator(t, testRP, testOrigin)
	f.registerPasskey(t, a)
	id, assertion, _ := f.svc.BeginLogin(context.Background())
	response := a.Assert(t, assertion)
	if _, err := f.svc.FinishLogin(context.Background(), id, response); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.FinishLogin(context.Background(), id, response); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replayed sign-in = %v, want ErrNotFound", err)
	}
}

func TestACeremonyExpires(t *testing.T) {
	f := newFixture(t)
	a := passkeytest.NewAuthenticator(t, testRP, testOrigin)
	f.registerPasskey(t, a)
	id, assertion, _ := f.svc.BeginLogin(context.Background())
	f.now = f.now.Add(6 * time.Minute)
	if _, err := f.svc.FinishLogin(context.Background(), id, a.Assert(t, assertion)); err == nil {
		t.Fatal("an expired ceremony signed in")
	}
}

func TestRegistrationIsBoundToTheSessionThatStartedIt(t *testing.T) {
	f := newFixture(t)
	a := passkeytest.NewAuthenticator(t, testRP, testOrigin)
	id, creation, _ := f.svc.BeginRegistration(context.Background(), f.user, "session-a")
	if _, err := f.svc.FinishRegistration(context.Background(), f.user, "session-b", id, "x", a.Register(t, creation)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("finished from another session = %v", err)
	}
	other := User{ID: "11111111-1111-1111-1111-111111111111", Name: "other@example.com"}
	id, creation, _ = f.svc.BeginRegistration(context.Background(), f.user, "session-a")
	if _, err := f.svc.FinishRegistration(context.Background(), other, "session-a", id, "x", a.Register(t, creation)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("finished for another user = %v", err)
	}
}

func TestAPasskeyFromAnotherSiteIsRefused(t *testing.T) {
	f := newFixture(t)
	phishing := passkeytest.NewAuthenticator(t, testRP, "https://account-bify.io") // look-alike page origin
	id, creation, _ := f.svc.BeginRegistration(context.Background(), f.user, "session-a")
	if _, err := f.svc.FinishRegistration(context.Background(), f.user, "session-a", id, "x", phishing.Register(t, creation)); !errors.Is(err, ErrVerification) {
		t.Fatalf("registration from another origin = %v", err)
	}
	wrongRP := passkeytest.NewAuthenticator(t, "evil.example", testOrigin)
	id, creation, _ = f.svc.BeginRegistration(context.Background(), f.user, "session-a")
	if _, err := f.svc.FinishRegistration(context.Background(), f.user, "session-a", id, "x", wrongRP.Register(t, creation)); !errors.Is(err, ErrVerification) {
		t.Fatalf("registration for another relying party = %v", err)
	}

	a := passkeytest.NewAuthenticator(t, testRP, testOrigin)
	f.registerPasskey(t, a)
	a.Origin = "https://account-bify.io"
	id, assertion, _ := f.svc.BeginLogin(context.Background())
	if _, err := f.svc.FinishLogin(context.Background(), id, a.Assert(t, assertion)); !errors.Is(err, ErrVerification) {
		t.Fatalf("sign-in from another origin = %v", err)
	}
}

func TestSignInRefusesAUserHandleThatIsNotTheOwner(t *testing.T) {
	f := newFixture(t)
	a := passkeytest.NewAuthenticator(t, testRP, testOrigin)
	f.registerPasskey(t, a)
	a.UserID = []byte("11111111-1111-1111-1111-111111111111")
	id, assertion, _ := f.svc.BeginLogin(context.Background())
	if _, err := f.svc.FinishLogin(context.Background(), id, a.Assert(t, assertion)); !errors.Is(err, ErrVerification) {
		t.Fatalf("mismatched user handle = %v", err)
	}
}

func TestARemovedPasskeyCannotSignIn(t *testing.T) {
	f := newFixture(t)
	a := passkeytest.NewAuthenticator(t, testRP, testOrigin)
	passkey := f.registerPasskey(t, a)
	if err := f.svc.Delete(context.Background(), f.user.ID, passkey.ID); err != nil {
		t.Fatal(err)
	}
	id, assertion, _ := f.svc.BeginLogin(context.Background())
	if _, err := f.svc.FinishLogin(context.Background(), id, a.Assert(t, assertion)); err == nil {
		t.Fatal("a removed passkey signed in")
	}
}

func TestAPossiblyClonedPasskeyIsRefused(t *testing.T) {
	f := newFixture(t)
	a := passkeytest.NewAuthenticator(t, testRP, testOrigin)
	a.Synced = false
	a.SignCount = 5
	f.registerPasskey(t, a)
	a.SignCount = 6
	id, assertion, _ := f.svc.BeginLogin(context.Background())
	if _, err := f.svc.FinishLogin(context.Background(), id, a.Assert(t, assertion)); err != nil {
		t.Fatalf("a rising counter = %v", err)
	}
	a.SignCount = 3 // went backwards: a copy of the key is in use somewhere
	id, assertion, _ = f.svc.BeginLogin(context.Background())
	if _, err := f.svc.FinishLogin(context.Background(), id, a.Assert(t, assertion)); !errors.Is(err, ErrVerification) {
		t.Fatalf("a counter that went backwards = %v", err)
	}
}

func TestStepUpMarksTheSessionRecentForTheWindow(t *testing.T) {
	f := newFixture(t)
	a := passkeytest.NewAuthenticator(t, testRP, testOrigin)
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
	if err := f.svc.FinishStepUp(context.Background(), f.user, "session-a", id, a.Assert(t, assertion)); err != nil {
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
	f.store.AddSession("fresh", f.now.Add(-2*time.Minute))
	if recent, _ := f.svc.RecentlyAuthenticated(context.Background(), "fresh"); !recent {
		t.Fatal("a two-minute-old sign-in is not recent")
	}
}

func TestPasskeyLimitAndDuplicates(t *testing.T) {
	f := newFixture(t)
	f.svc.cfg.MaxPerUser = 2
	f.registerPasskey(t, passkeytest.NewAuthenticator(t, testRP, testOrigin))
	a := passkeytest.NewAuthenticator(t, testRP, testOrigin)
	f.registerPasskey(t, a)
	if _, _, err := f.svc.BeginRegistration(context.Background(), f.user, "session-a"); !errors.Is(err, ErrLimit) {
		t.Fatalf("over the limit = %v", err)
	}
	f.svc.cfg.MaxPerUser = 10
	id, creation, _ := f.svc.BeginRegistration(context.Background(), f.user, "session-a")
	if len(creation.Response.CredentialExcludeList) != 2 {
		t.Fatalf("existing passkeys are not excluded: %d", len(creation.Response.CredentialExcludeList))
	}
	if _, err := f.svc.FinishRegistration(context.Background(), f.user, "session-a", id, "again", a.Register(t, creation)); !errors.Is(err, ErrExists) {
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
