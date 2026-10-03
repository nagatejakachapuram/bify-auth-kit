"use client";
// Passkey UI shared by the BIFY developer portal and BIFY Account: a sign-in button, the Security
// settings manager, and the "Confirm it's you" dialog for sensitive actions. Styled by styles.css with the
// design tokens both portals define (--surface, --text, --muted, --border, --green, --red, ...).
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import { PasskeyError, withStepUp, type Passkey, type PasskeyClient, type StepUpMethod } from "./client.js";
import { passkeysSupported, suggestedPasskeyName } from "./webauthn.js";

// ── Icons (inline so the package has no icon dependency) ─────────────────────────────────────────
const svg = (path: ReactNode, size = 17) => <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{path}</svg>;
export const PasskeyIcon = ({ size = 17 }: { size?: number }) => svg(<><circle cx="10" cy="7.5" r="3.5" /><path d="M3.5 19.5c.6-3.4 3.2-5.5 6.5-5.5 1.1 0 2.1.2 3 .7" /><path d="M18 13.5a2.5 2.5 0 1 0-2 2.45V20l1 1 1.5-1.5-1-1 1-1-1-1a2.5 2.5 0 0 0 .5-2.95" /></>, size);
const ChevronIcon = () => svg(<path d="m9 6 6 6-6 6" />, 15);
const CheckIcon = () => svg(<path d="M20 6 9 17l-5-5" />, 14);
const SpinnerIcon = () => <span className="bpk-spinner" aria-hidden="true" />;

function relative(iso: string | undefined, now = Date.now()): string {
  if (!iso) return "";
  const then = Date.parse(iso);
  if (!Number.isFinite(then)) return "";
  const minutes = Math.round((now - then) / 60000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} hour${hours === 1 ? "" : "s"} ago`;
  return new Date(then).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
}

// ── Step-up ("Confirm it's you") ─────────────────────────────────────────────────────────────────

/** Fallbacks the portal verifies itself for people without a passkey. Each resolves once confirmed. */
export type StepUpFallbacks = {
  totp?: (code: string) => Promise<void>;
  email?: { request: () => Promise<void>; verify: (code: string) => Promise<void> };
};

type StepUpContextValue = {
  /** Asks the person to confirm it's them (skipped if they did recently). Rejects with a cancelled PasskeyError if they close it. */
  confirm: (methods?: StepUpMethod[]) => Promise<void>;
  /** fetch that confirms and retries once when the server answers "confirm it's you". */
  fetch: typeof fetch;
};

const StepUpContext = createContext<StepUpContextValue | null>(null);

/** useStepUp returns the portal's step-up helpers; without a StepUpProvider it confirms nothing. */
export function useStepUp(): StepUpContextValue {
  return useContext(StepUpContext) ?? { confirm: async () => undefined, fetch: (...args) => fetch(...args) };
}

type Pending = { methods: StepUpMethod[]; resolve: () => void; reject: (error: unknown) => void };

export function StepUpProvider({ client, fallbacks = {}, children }: { client: PasskeyClient; fallbacks?: StepUpFallbacks; children: ReactNode }) {
  const [pending, setPending] = useState<Pending | null>(null);
  const queue = useRef<Promise<void> | null>(null);

  const confirm = useCallback((methods?: StepUpMethod[]) => {
    // One dialog at a time: concurrent requests wait for the same confirmation.
    if (queue.current) return queue.current;
    const run = (async () => {
      let available = methods;
      if (!available) {
        // If the status can't be read, carry on: the server still asks when it must, and the request
        // retries through withStepUp.
        const status = await client.stepUpStatus().catch(() => null);
        if (!status || status.recent) return;
        available = status.methods;
      }
      // No way to confirm (a wallet-only account): the server lets the action through, so there is nothing to ask.
      if (available.length === 0) return;
      await new Promise<void>((resolve, reject) => setPending({ methods: available!, resolve, reject }));
    })().finally(() => { queue.current = null; });
    queue.current = run;
    return run;
  }, [client]);

  const value = useMemo<StepUpContextValue>(() => ({ confirm, fetch: withStepUp((...args) => fetch(...args), (methods) => confirm(methods)) }), [confirm]);

  return <StepUpContext.Provider value={value}>
    {children}
    {pending ? <StepUpDialog client={client} methods={pending.methods} fallbacks={fallbacks}
      onConfirmed={() => { pending.resolve(); setPending(null); }}
      onCancel={() => { pending.reject(new PasskeyError("Cancelled.", "cancelled")); setPending(null); }} /> : null}
  </StepUpContext.Provider>;
}

export function StepUpDialog({ client, methods, fallbacks, onConfirmed, onCancel }: { client: PasskeyClient; methods: StepUpMethod[]; fallbacks: StepUpFallbacks; onConfirmed: () => void; onCancel: () => void }) {
  const canPasskey = methods.includes("passkey") && passkeysSupported();
  const codeMethods = methods.filter((m): m is "totp" | "email" => (m === "totp" && !!fallbacks.totp) || (m === "email" && !!fallbacks.email));
  const [mode, setMode] = useState<"passkey" | "totp" | "email">(canPasskey ? "passkey" : codeMethods[0] ?? "passkey");
  const [code, setCode] = useState("");
  const [emailSent, setEmailSent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => { if (event.key === "Escape" && !busy) onCancel(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [busy, onCancel]);

  async function attempt(action: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await action();
      setDone(true);
      window.setTimeout(onConfirmed, 450); // a beat to see it worked before the action continues
    } catch (caught) {
      if (caught instanceof PasskeyError && caught.cancelled) setError("");
      else setError(caught instanceof Error ? caught.message : "That didn't work. Try again.");
    } finally {
      setBusy(false);
    }
  }

  async function requestEmailCode() {
    setBusy(true);
    setError("");
    try {
      await fallbacks.email!.request();
      setEmailSent(true);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "We couldn't send a code. Try again.");
    } finally {
      setBusy(false);
    }
  }

  const submitCode = (event: FormEvent) => {
    event.preventDefault();
    const clean = code.replace(/\s/g, "");
    if (!/^\d{6}$/.test(clean)) { setError("Enter the 6-digit code."); return; }
    void attempt(() => mode === "totp" ? fallbacks.totp!(clean) : fallbacks.email!.verify(clean));
  };

  const nothingAvailable = !canPasskey && codeMethods.length === 0;

  return <div className="bpk-overlay" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !busy) onCancel(); }}>
    <div className="bpk-dialog" role="dialog" aria-modal="true" aria-labelledby="bpk-step-up-title">
      <span className={`bpk-dialog-icon ${done ? "bpk-done" : ""}`}>{done ? <CheckIcon /> : <PasskeyIcon size={22} />}</span>
      <h2 id="bpk-step-up-title">{done ? "Confirmed" : "Confirm it's you"}</h2>
      {done ? <p className="bpk-dialog-copy">You won't be asked again for a few minutes.</p> : <>
        <p className="bpk-dialog-copy">
          {mode === "passkey" ? "This action is protected. Use your passkey to continue: Face ID, a fingerprint or your device PIN."
            : mode === "totp" ? "This action is protected. Enter the 6-digit code from your authenticator app."
            : emailSent ? "We emailed you a 6-digit code. Enter it to continue." : "This action is protected. We'll email you a 6-digit code to confirm it's you."}
        </p>
        {nothingAvailable ? <p className="bpk-dialog-copy">Add a passkey or an authenticator app in Security settings to do this.</p> : null}
        {mode === "passkey" && canPasskey ? <button type="button" className="bpk-primary" disabled={busy} autoFocus onClick={() => void attempt(() => client.confirm())}>
          {busy ? <SpinnerIcon /> : <PasskeyIcon />}{busy ? "Waiting for your passkey…" : "Use passkey"}
        </button> : null}
        {mode === "email" && !emailSent ? <button type="button" className="bpk-primary" disabled={busy} autoFocus onClick={() => void requestEmailCode()}>
          {busy ? <SpinnerIcon /> : null}Email me a code
        </button> : null}
        {(mode === "totp" || (mode === "email" && emailSent)) ? <form className="bpk-code" onSubmit={submitCode}>
          <input inputMode="numeric" autoComplete="one-time-code" maxLength={7} placeholder="000000" aria-label="6-digit code" value={code} autoFocus disabled={busy}
            onChange={(event) => setCode(event.target.value.replace(/[^\d ]/g, ""))} />
          <button type="submit" className="bpk-primary" disabled={busy || code.replace(/\s/g, "").length !== 6}>{busy ? <SpinnerIcon /> : null}Confirm</button>
        </form> : null}
        {error ? <p className="bpk-error" role="alert">{error}</p> : null}
        <div className="bpk-dialog-links">
          {mode !== "passkey" && canPasskey ? <button type="button" className="bpk-link" disabled={busy} onClick={() => { setMode("passkey"); setError(""); }}>Use passkey instead</button> : null}
          {codeMethods.filter((m) => m !== mode).map((m) => <button key={m} type="button" className="bpk-link" disabled={busy} onClick={() => { setMode(m); setCode(""); setError(""); }}>
            {m === "totp" ? "Use authenticator code instead" : "Email me a code instead"}
          </button>)}
          <button type="button" className="bpk-link bpk-muted" disabled={busy} onClick={onCancel}>Cancel</button>
        </div>
      </>}
    </div>
  </div>;
}

// ── Sign in ──────────────────────────────────────────────────────────────────────────────────────

/**
 * A sign-in option for passkeys, laid out like the portals' other sign-in options (icon, title, hint,
 * chevron); pass the portal's option class. Hidden in browsers without passkeys.
 */
export function PasskeySignInButton({ client, onSignedIn, onError, className = "bpk-option", disabled = false, chevron = true }: { client: PasskeyClient; onSignedIn: () => void; onError: (message: string) => void; className?: string; disabled?: boolean; chevron?: boolean }) {
  const [supported, setSupported] = useState(false);
  const [busy, setBusy] = useState(false);
  useEffect(() => setSupported(passkeysSupported()), []);
  if (!supported) return null;
  return <button type="button" className={className} disabled={disabled || busy} onClick={async () => {
    setBusy(true);
    onError("");
    try {
      await client.signIn();
      onSignedIn();
    } catch (error) {
      if (!(error instanceof PasskeyError && error.cancelled)) onError(error instanceof Error ? error.message : "Passkey sign-in failed. Try again.");
    } finally {
      setBusy(false);
    }
  }}>
    {busy ? <SpinnerIcon /> : <PasskeyIcon />}
    <span><strong>{busy ? "Waiting for your passkey…" : "Sign in with a passkey"}</strong><small>Face ID, fingerprint or security key</small></span>
    {chevron ? <ChevronIcon /> : null}
  </button>;
}

// ── Security settings ────────────────────────────────────────────────────────────────────────────

export function PasskeyManager({ client, title = "Passkeys", description = "Sign in with Face ID, Touch ID, Windows Hello or a security key instead of codes. Passkeys can't be phished, and only work on this site." }: { client: PasskeyClient; title?: string; description?: string }) {
  const { confirm } = useStepUp();
  const [passkeys, setPasskeys] = useState<Passkey[] | null>(null);
  const [limit, setLimit] = useState(10);
  const [supported, setSupported] = useState(true);
  const [busy, setBusy] = useState<string>("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [renaming, setRenaming] = useState<{ id: string; name: string } | null>(null);
  const [removing, setRemoving] = useState("");

  const load = useCallback(async () => {
    try {
      const out = await client.list();
      setPasskeys(out.passkeys);
      setLimit(out.limit);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Passkeys could not be loaded.");
      setPasskeys([]);
    }
  }, [client]);

  useEffect(() => { setSupported(passkeysSupported()); void load(); }, [load]);

  // Sensitive changes confirm first when the server asks, then run once more.
  async function guarded<T>(action: () => Promise<T>): Promise<T> {
    try {
      return await action();
    } catch (caught) {
      if (caught instanceof PasskeyError && caught.code === "step_up_required") {
        await confirm();
        return action();
      }
      throw caught;
    }
  }

  async function run(key: string, action: () => Promise<void>, success: string) {
    setBusy(key);
    setError("");
    setNotice("");
    try {
      await action();
      await load();
      setNotice(success);
    } catch (caught) {
      if (!(caught instanceof PasskeyError && caught.cancelled)) setError(caught instanceof Error ? caught.message : "That didn't work. Try again.");
    } finally {
      setBusy("");
    }
  }

  const add = () => run("add", async () => { await guarded(() => client.register(suggestedPasskeyName())); }, "Passkey added. You can now sign in with it.");
  const full = passkeys !== null && passkeys.length >= limit;

  return <section className="bpk-manager" aria-labelledby="bpk-manager-title">
    <div className="bpk-manager-head">
      <div>
        <h2 id="bpk-manager-title">{title}</h2>
        <p>{description}</p>
      </div>
      {supported ? <button type="button" className="bpk-primary bpk-add" disabled={!!busy || full || passkeys === null} onClick={() => void add()}>
        {busy === "add" ? <SpinnerIcon /> : <PasskeyIcon />}{busy === "add" ? "Follow your device's prompt…" : "Add a passkey"}
      </button> : null}
    </div>
    {!supported ? <p className="bpk-note">This browser doesn't support passkeys. Open this page in an up-to-date Safari, Chrome, Edge or Firefox to add one.</p> : null}
    {full ? <p className="bpk-note">You've reached the limit of {limit} passkeys. Remove one to add another.</p> : null}
    {error ? <p className="bpk-error" role="alert">{error}</p> : null}
    {notice ? <p className="bpk-success" role="status"><CheckIcon />{notice}</p> : null}
    {passkeys === null ? <div className="bpk-skeleton" aria-hidden="true" /> : passkeys.length === 0 ? <p className="bpk-empty">No passkeys yet. Add one to sign in with a glance or a touch.</p> : <ul className="bpk-list">
      {passkeys.map((passkey) => <li key={passkey.id} className="bpk-row">
        <span className="bpk-row-icon"><PasskeyIcon /></span>
        {renaming?.id === passkey.id ? <form className="bpk-rename" onSubmit={(event) => { event.preventDefault(); const name = renaming.name.trim(); if (!name) return; void run(passkey.id, () => client.rename(passkey.id, name), "Passkey renamed.").then(() => setRenaming(null)); }}>
          <input value={renaming.name} maxLength={40} autoFocus aria-label="Passkey name" onChange={(event) => setRenaming({ id: passkey.id, name: event.target.value })} onKeyDown={(event) => { if (event.key === "Escape") setRenaming(null); }} />
          <button type="submit" className="bpk-secondary" disabled={busy === passkey.id || !renaming.name.trim()}>Save</button>
          <button type="button" className="bpk-link bpk-muted" onClick={() => setRenaming(null)}>Cancel</button>
        </form> : <div className="bpk-row-copy">
          <strong>{passkey.name}</strong>
          <span>{[passkey.synced ? "Synced across your devices" : "On this device only", `Added ${relative(passkey.createdAt)}`, passkey.lastUsedAt ? `Last used ${relative(passkey.lastUsedAt)}` : "Not used yet"].join(" · ")}</span>
        </div>}
        {renaming?.id === passkey.id ? null : removing === passkey.id ? <span className="bpk-row-actions">
          <button type="button" className="bpk-danger" disabled={busy === passkey.id} onClick={() => void run(passkey.id, () => guarded(() => client.remove(passkey.id)), "Passkey removed.").then(() => setRemoving(""))}>{busy === passkey.id ? <SpinnerIcon /> : null}Remove</button>
          <button type="button" className="bpk-link bpk-muted" disabled={busy === passkey.id} onClick={() => setRemoving("")}>Keep</button>
        </span> : <span className="bpk-row-actions">
          <button type="button" className="bpk-secondary" disabled={!!busy} onClick={() => { setRenaming({ id: passkey.id, name: passkey.name }); setRemoving(""); }}>Rename</button>
          <button type="button" className="bpk-secondary" disabled={!!busy} onClick={() => { setRemoving(passkey.id); setRenaming(null); }}>Remove</button>
        </span>}
      </li>)}
    </ul>}
  </section>;
}
