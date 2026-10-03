# bify-auth-kit

Passkeys (Face ID, Touch ID, Windows Hello, security keys) shared by the BIFY developer portal and BIFY Account.

- **`passkey/`** (Go, `github.com/nagatejakachapuram/bify-auth-kit/passkey`): sign-in, registration and step-up
  ceremonies on [go-webauthn](https://github.com/go-webauthn/webauthn), a DynamoDB store matching both portals'
  single-table conventions, HTTP endpoints, and `RequireRecentAuth` middleware for sensitive actions.
- **`js/`** (`@bify/passkeys`): browser helpers, an API client, and React components: `PasskeySignInButton`,
  `PasskeyManager` (Security settings), and `StepUpProvider` / `useStepUp` with the "Confirm it's you" dialog.

## How a portal uses it

Backend:

```go
cfg, _ := passkey.ConfigFromOrigin(portalOrigin, "BIFY Account") // passkeys bind to the portal's own host
svc, _ := passkey.New(cfg, passkey.DynamoStore{DB: dynamo, Table: table})
hooks := passkey.Hooks{Current: ..., SignIn: ..., CheckOrigin: ..., Fallbacks: ...}
svc.Mount(hooks, func(m, p string, h http.HandlerFunc) { router.Method(m, p, h) })
router.With(svc.RequireRecentAuth(hooks)).Post("/v1/.../sensitive", handler)
```

Frontend:

```tsx
import { createPasskeyClient, PasskeyManager, PasskeySignInButton, StepUpProvider, useStepUp } from "@bify/passkeys";
import "@bify/passkeys/styles.css";
```

## Rules it enforces

- Passkeys work only on the portal's host (relying party ID), so look-alike sites cannot use them.
- Every ceremony is single-use, bound to the session that started it, and expires after 5 minutes.
- User verification (biometric or device PIN) is required: a passkey is two factors by itself.
- Adding or removing a passkey requires a recent confirmation (passkey, fallback code, or a sign-in within 5 minutes).
- Only public keys are stored. A counter that goes backwards (a cloned key) is refused.

## Tests

`go test -race ./...` runs real ceremonies against a software authenticator and the DynamoDB store against an
expression-checking fake. `cd js && npm test` covers the browser conversions, the client and the dialog.
