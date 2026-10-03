package passkey

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// Hooks connect the passkey endpoints to a portal's own sessions.
type Hooks struct {
	// Current returns the signed-in, fully authenticated user for r and the key of their session (the
	// hash the portal stores the session under). Any error answers 401.
	Current func(r *http.Request) (User, string, error)
	// SignIn starts a fully authenticated session for userID, with any second factor satisfied (a passkey
	// is two factors itself), and sets the session cookie on w.
	SignIn func(w http.ResponseWriter, r *http.Request, userID string) error
	// CheckOrigin rejects cross-site requests; it runs before every POST.
	CheckOrigin func(r *http.Request) error
	// Fallbacks lists how a user confirms a sensitive action without a passkey, for example "totp" or
	// "email". The portal serves those confirmations and calls Service.MarkStepUp when one succeeds.
	Fallbacks func(r *http.Request, user User) []string
	// Event, when set, records security events: passkey_added, passkey_removed, passkey_renamed,
	// passkey_sign_in and step_up_passkey.
	Event func(r *http.Request, name string)
}

// Paths of the endpoints Mount registers.
const (
	PathList            = "/v1/auth/passkeys"
	PathRegisterOptions = "/v1/auth/passkeys/registration/options"
	PathRegisterVerify  = "/v1/auth/passkeys/registration/verify"
	PathRename          = "/v1/auth/passkeys/rename"
	PathDelete          = "/v1/auth/passkeys/delete"
	PathLoginOptions    = "/v1/auth/passkeys/login/options"
	PathLoginVerify     = "/v1/auth/passkeys/login/verify"
	PathStepUpOptions   = "/v1/auth/passkeys/step-up/options"
	PathStepUpVerify    = "/v1/auth/passkeys/step-up/verify"
	PathStepUpStatus    = "/v1/auth/step-up"
)

// StepUpRequiredCode is the "code" of the 403 answered when an action needs a recent confirmation.
const StepUpRequiredCode = "step_up_required"

// Mount registers the passkey endpoints with the portal's router through handle (for chi:
// func(method, path string, h http.HandlerFunc) { r.Method(method, path, h) }).
func (s *Service) Mount(hooks Hooks, handle func(method, path string, handler http.HandlerFunc)) {
	handle(http.MethodGet, PathList, s.handleList(hooks))
	handle(http.MethodPost, PathRegisterOptions, s.post(hooks, s.handleRegisterOptions(hooks)))
	handle(http.MethodPost, PathRegisterVerify, s.post(hooks, s.handleRegisterVerify(hooks)))
	handle(http.MethodPost, PathRename, s.post(hooks, s.handleRename(hooks)))
	handle(http.MethodPost, PathDelete, s.post(hooks, s.handleDelete(hooks)))
	handle(http.MethodPost, PathLoginOptions, s.post(hooks, s.handleLoginOptions(hooks)))
	handle(http.MethodPost, PathLoginVerify, s.post(hooks, s.handleLoginVerify(hooks)))
	handle(http.MethodPost, PathStepUpOptions, s.post(hooks, s.handleStepUpOptions(hooks)))
	handle(http.MethodPost, PathStepUpVerify, s.post(hooks, s.handleStepUpVerify(hooks)))
	handle(http.MethodGet, PathStepUpStatus, s.handleStepUpStatus(hooks))
}

// RequireRecentAuth wraps a sensitive endpoint: the session must have signed in or confirmed itself
// within the step-up window, or it is answered 403 with code step_up_required and the ways to confirm.
func (s *Service) RequireRecentAuth(hooks Hooks) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, sessionKey, err := hooks.Current(r)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "authentication required", "")
				return
			}
			if !s.recentOrRefuse(w, r, hooks, user, sessionKey) {
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// recentOrRefuse answers 403 step_up_required (and returns false) unless the session is recent.
func (s *Service) recentOrRefuse(w http.ResponseWriter, r *http.Request, hooks Hooks, user User, sessionKey string) bool {
	recent, err := s.RecentlyAuthenticated(r.Context(), sessionKey)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Confirmation is temporarily unavailable. Try again.", "")
		return false
	}
	if recent {
		return true
	}
	writeJSON(w, http.StatusForbidden, map[string]any{
		"error":   "Confirm it's you to continue.",
		"code":    StepUpRequiredCode,
		"methods": s.methods(r, hooks, user),
	})
	return false
}

// methods lists how this user can confirm: their passkeys first, then the portal's fallbacks.
func (s *Service) methods(r *http.Request, hooks Hooks, user User) []string {
	methods := []string{}
	if has, err := s.HasPasskeys(r.Context(), user.ID); err == nil && has {
		methods = append(methods, "passkey")
	}
	if hooks.Fallbacks != nil {
		methods = append(methods, hooks.Fallbacks(r, user)...)
	}
	return methods
}

func (s *Service) post(hooks Hooks, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hooks.CheckOrigin != nil && hooks.CheckOrigin(r) != nil {
			writeError(w, http.StatusForbidden, "request origin is not allowed", "")
			return
		}
		next(w, r)
	}
}

func event(hooks Hooks, r *http.Request, name string) {
	if hooks.Event != nil {
		hooks.Event(r, name)
	}
}

type ceremonyBody struct {
	CeremonyID string          `json:"ceremonyId"`
	Credential json.RawMessage `json:"credential"`
	Name       string          `json:"name"`
	ID         string          `json:"id"`
}

func readBody(r *http.Request) (ceremonyBody, error) {
	var body ceremonyBody
	if r.Body == nil {
		return body, nil
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 64<<10+1))
	if err != nil || len(raw) > 64<<10 {
		return body, errors.New("request too large")
	}
	if len(raw) == 0 {
		return body, nil
	}
	err = json.Unmarshal(raw, &body)
	return body, err
}

func (s *Service) handleList(hooks Hooks) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, _, err := hooks.Current(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "authentication required", "")
			return
		}
		passkeys, err := s.List(r.Context(), user.ID)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "Passkeys are temporarily unavailable.", "")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, map[string]any{"data": passkeys, "limit": s.cfg.MaxPerUser})
	}
}

func (s *Service) handleRegisterOptions(hooks Hooks) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, sessionKey, err := hooks.Current(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "authentication required", "")
			return
		}
		// Adding a passkey grants lasting access to the account, so it is a sensitive action itself.
		if !s.recentOrRefuse(w, r, hooks, user, sessionKey) {
			return
		}
		id, creation, err := s.BeginRegistration(r.Context(), user, sessionKey)
		if errors.Is(err, ErrLimit) {
			writeError(w, http.StatusUnprocessableEntity, "This account already has the maximum number of passkeys. Remove one to add another.", "passkey_limit")
			return
		}
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "Passkeys are temporarily unavailable.", "")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ceremonyId": id, "options": creation})
	}
}

func (s *Service) handleRegisterVerify(hooks Hooks) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, sessionKey, err := hooks.Current(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "authentication required", "")
			return
		}
		body, err := readBody(r)
		if err != nil || body.CeremonyID == "" || len(body.Credential) == 0 {
			writeError(w, http.StatusBadRequest, "invalid request", "")
			return
		}
		passkey, err := s.FinishRegistration(r.Context(), user, sessionKey, body.CeremonyID, body.Name, body.Credential)
		switch {
		case err == nil:
			event(hooks, r, "passkey_added")
			writeJSON(w, http.StatusOK, map[string]any{"data": passkey})
		case errors.Is(err, ErrExists):
			writeError(w, http.StatusConflict, "This passkey is already saved to your account.", "passkey_exists")
		case errors.Is(err, ErrLimit):
			writeError(w, http.StatusUnprocessableEntity, "This account already has the maximum number of passkeys. Remove one to add another.", "passkey_limit")
		case errors.Is(err, ErrNotFound), errors.Is(err, ErrVerification):
			writeError(w, http.StatusBadRequest, "The passkey could not be saved. Try again.", "passkey_failed")
		default:
			writeError(w, http.StatusServiceUnavailable, "Passkeys are temporarily unavailable.", "")
		}
	}
}

func (s *Service) handleRename(hooks Hooks) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, _, err := hooks.Current(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "authentication required", "")
			return
		}
		body, err := readBody(r)
		if err != nil || body.ID == "" || CleanName(body.Name) == "" {
			writeError(w, http.StatusBadRequest, "Enter a name for this passkey.", "")
			return
		}
		switch err := s.Rename(r.Context(), user.ID, body.ID, body.Name); {
		case err == nil:
			event(hooks, r, "passkey_renamed")
			w.WriteHeader(http.StatusNoContent)
		case errors.Is(err, ErrNotFound):
			writeError(w, http.StatusNotFound, "This passkey was not found.", "")
		default:
			writeError(w, http.StatusServiceUnavailable, "Passkeys are temporarily unavailable.", "")
		}
	}
}

func (s *Service) handleDelete(hooks Hooks) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, sessionKey, err := hooks.Current(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "authentication required", "")
			return
		}
		if !s.recentOrRefuse(w, r, hooks, user, sessionKey) {
			return
		}
		body, err := readBody(r)
		if err != nil || body.ID == "" {
			writeError(w, http.StatusBadRequest, "invalid request", "")
			return
		}
		switch err := s.Delete(r.Context(), user.ID, body.ID); {
		case err == nil:
			event(hooks, r, "passkey_removed")
			w.WriteHeader(http.StatusNoContent)
		case errors.Is(err, ErrNotFound):
			writeError(w, http.StatusNotFound, "This passkey was not found.", "")
		default:
			writeError(w, http.StatusServiceUnavailable, "Passkeys are temporarily unavailable.", "")
		}
	}
}

func (s *Service) handleLoginOptions(hooks Hooks) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, assertion, err := s.BeginLogin(r.Context())
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "Passkey sign-in is temporarily unavailable.", "")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ceremonyId": id, "options": assertion})
	}
}

func (s *Service) handleLoginVerify(hooks Hooks) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readBody(r)
		if err != nil || body.CeremonyID == "" || len(body.Credential) == 0 {
			writeError(w, http.StatusBadRequest, "invalid request", "")
			return
		}
		userID, err := s.FinishLogin(r.Context(), body.CeremonyID, body.Credential)
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrVerification) {
			// One answer for an unknown, removed or forged passkey: nothing to learn about accounts.
			writeError(w, http.StatusUnauthorized, "This passkey could not be used to sign in. Try again, or use another sign-in method.", "passkey_failed")
			return
		}
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "Passkey sign-in is temporarily unavailable.", "")
			return
		}
		if err := hooks.SignIn(w, r, userID); err != nil {
			writeError(w, http.StatusServiceUnavailable, "Passkey sign-in is temporarily unavailable.", "")
			return
		}
		event(hooks, r, "passkey_sign_in")
		writeJSON(w, http.StatusOK, map[string]string{"status": "authenticated"})
	}
}

func (s *Service) handleStepUpOptions(hooks Hooks) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, sessionKey, err := hooks.Current(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "authentication required", "")
			return
		}
		id, assertion, err := s.BeginStepUp(r.Context(), user, sessionKey)
		if errors.Is(err, ErrNoPasskeys) {
			writeError(w, http.StatusConflict, "This account has no passkey yet.", "no_passkeys")
			return
		}
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "Confirmation is temporarily unavailable. Try again.", "")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ceremonyId": id, "options": assertion})
	}
}

func (s *Service) handleStepUpVerify(hooks Hooks) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, sessionKey, err := hooks.Current(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "authentication required", "")
			return
		}
		body, err := readBody(r)
		if err != nil || body.CeremonyID == "" || len(body.Credential) == 0 {
			writeError(w, http.StatusBadRequest, "invalid request", "")
			return
		}
		err = s.FinishStepUp(r.Context(), user, sessionKey, body.CeremonyID, body.Credential)
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrVerification) {
			writeError(w, http.StatusUnauthorized, "That passkey could not confirm it's you. Try again.", "passkey_failed")
			return
		}
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "Confirmation is temporarily unavailable. Try again.", "")
			return
		}
		event(hooks, r, "step_up_passkey")
		writeJSON(w, http.StatusOK, map[string]any{"status": "confirmed", "validForSeconds": int(s.cfg.StepUpWindow.Seconds())})
	}
}

func (s *Service) handleStepUpStatus(hooks Hooks) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, sessionKey, err := hooks.Current(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "authentication required", "")
			return
		}
		recent, err := s.RecentlyAuthenticated(r.Context(), sessionKey)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "Confirmation is temporarily unavailable. Try again.", "")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, map[string]any{"recent": recent, "methods": s.methods(r, hooks, user)})
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, message, code string) {
	body := map[string]string{"error": message}
	if code != "" {
		body["code"] = code
	}
	writeJSON(w, status, body)
}
