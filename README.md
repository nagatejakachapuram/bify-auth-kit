# bify-auth-kit

Passkeys (Face ID, Touch ID, Windows Hello, security keys) shared by the BIFY developer portal and BIFY Account.

- **`passkey/`** (Go, `github.com/nagatejakachapuram/bify-auth-kit/passkey`): sign-in, registration and step-up
  ceremonies on [go-webauthn](https://github.com/go-webauthn/webauthn), a DynamoDB store matching both portals'
  single-table conventions, HTTP endpoints, and `RequireRecentAuth` middleware for sensitive actions.
- **`js/`** (`@bify/passkeys`): the browser side on [SimpleWebAuthn](https://github.com/MasterKale/SimpleWebAuthn),
  an API client, and React components built from the portals' own classes and lucide icons:
  `PasskeySignInButton`, `PasskeyManager` (Security settings), and `StepUpProvider` / `useStepUp` with the
  "Confirm it's you" dialog.

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
- Every ceremony is single-use and expires after 5 minutes. Registration and confirmation ceremonies are also
  bound to the session that started them.
- User verification (biometric or device PIN) is required: a passkey is two factors by itself.
- Adding or removing a passkey requires a recent confirmation (passkey, fallback code, or a sign-in within 5 minutes).
- `RequireConfirmationEachTime` guards the most important actions (for example where money is paid): they
  ask every time, whatever the 5-minute window or a fresh sign-in, and each confirmation allows one of them
  within 2 minutes before it is used up.
- Only public credential data is stored, never private keys. A signature counter that does not advance (a
  possibly cloned key) is refused, with a compare-and-swap so concurrent sign-ins cannot overwrite a newer count.
- The per-account passkey limit holds under concurrent registrations (a membership revision written in the same
  transaction). Never delete the `PASSKEY-MEMBERSHIP` record on its own.
- Method lookups fail closed: if the server cannot tell how an account confirms, it answers 503 rather than
  letting a sensitive action through.
- The WebAuthn Signal API keeps people's password managers in step, so removed passkeys stop being offered.

## Tests

`go test -race ./...` runs real ceremonies against a software authenticator and the DynamoDB store against an
expression-checking fake, including concurrent registrations and sign-ins. `cd js && npm test` covers the client,
the signals and the dialog.
