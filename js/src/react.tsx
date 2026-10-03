"use client";
// Passkey UI shared by the BIFY developer portal and BIFY Account: a sign-in option, the Security settings
// list, and the "Confirm it's you" dialog for sensitive actions. It is built from the classes both portals
// already style (modal, modal-body, modal-footer, auth-provider, primary-button, ghost-button,
// danger-button, eyebrow, auth-error) and their lucide icons, so it reads as part of each portal rather than
// an embedded widget. styles.css only adds layout for the pieces the portals have no class for.
import { ChevronRight, CircleCheck, KeyRound, Laptop, LoaderCircle, Mail, Pencil, ScanFace, ShieldAlert, ShieldCheck, Smartphone, Tablet, Trash2, X, type LucideIcon } from "lucide-react";
import { createContext, useCallback, useContext, useEffect, useId, useMemo, useRef, useState, type ComponentType, type FormEvent, type ReactNode } from "react";
import { PasskeyError, withStepUp, type Passkey, type PasskeyClient, type StepUpMethod } from "./client.js";
import { cancelPasskeyPrompt, passkeysSupported, suggestedPasskeyName } from "./webauthn.js";

const Spinner = ({ size = 15 }: { size?: number }) => <LoaderCircle className="bpk-spin" size={size} aria-hidden="true" />;

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

const messageOf = (caught: unknown, fallback: string) => caught instanceof Error && caught.message ? caught.message : fallback;
const isCancelled = (caught: unknown) => caught instanceof PasskeyError && caught.cancelled;

// ── Step-up ("Confirm it's you") ─────────────────────────────────────────────────────────────────

/** Fallbacks the portal verifies itself for people without a passkey. Each resolves once confirmed. */
export type StepUpFallbacks = {
  totp?: (code: string) => Promise<void>;
  email?: { request: () => Promise<void>; verify: (code: string) => Promise<void> };
};

/** The portal's own 6-digit code field, so the dialog's code entry is the one people already know. */
export type CodeInputProps = { id: string; value: string; onChange: (value: string) => void; disabled?: boolean; autoFocus?: boolean };

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

export function StepUpProvider({ client, fallbacks = {}, CodeInput, children }: { client: PasskeyClient; fallbacks?: StepUpFallbacks; CodeInput?: ComponentType<CodeInputProps>; children: ReactNode }) {
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
    {pending ? <StepUpDialog client={client} methods={pending.methods} fallbacks={fallbacks} CodeInput={CodeInput}
      onConfirmed={() => { pending.resolve(); setPending(null); }}
      onCancel={() => { pending.reject(new PasskeyError("Cancelled.", "cancelled")); setPending(null); }} /> : null}
  </StepUpContext.Provider>;
}

type CodeMethod = "totp" | "email";

const METHOD_COPY: Record<"passkey" | CodeMethod, { icon: LucideIcon; title: string; detail: string }> = {
  passkey: { icon: ScanFace, title: "Use a passkey", detail: "Face ID, fingerprint or security key" },
  email: { icon: Mail, title: "Email me a code", detail: "We'll send a 6-digit code to your email" },
  totp: { icon: Smartphone, title: "Use your authenticator app", detail: "Enter the 6-digit code from the app" },
};

export function StepUpDialog({ client, methods, fallbacks, CodeInput, onConfirmed, onCancel }: { client: PasskeyClient; methods: StepUpMethod[]; fallbacks: StepUpFallbacks; CodeInput?: ComponentType<CodeInputProps>; onConfirmed: () => void; onCancel: () => void }) {
  const ids = useId();
  const canPasskey = methods.includes("passkey") && passkeysSupported();
  const codeMethods = methods.filter((m): m is CodeMethod => (m === "totp" && !!fallbacks.totp) || (m === "email" && !!fallbacks.email));
  const options: Array<"passkey" | CodeMethod> = [...(canPasskey ? ["passkey" as const] : []), ...codeMethods];
  // With only an authenticator app there is nothing to choose: go straight to the code.
  const [view, setView] = useState<"choose" | CodeMethod>(options.length === 1 && options[0] === "totp" ? "totp" : "choose");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState<"" | "passkey" | "email" | "code">("");
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);

  const close = useCallback(() => {
    if (busy === "passkey") cancelPasskeyPrompt();
    onCancel();
  }, [busy, onCancel]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => { if (event.key === "Escape" && busy !== "code" && busy !== "email") close(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [busy, close]);

  async function finish(kind: "passkey" | "code", action: () => Promise<void>) {
    setBusy(kind);
    setError("");
    try {
      await action();
      setDone(true);
      window.setTimeout(onConfirmed, 600); // a beat to see it worked before the action carries on
    } catch (caught) {
      if (!isCancelled(caught)) setError(messageOf(caught, "That didn't work. Try again."));
    } finally {
      setBusy("");
    }
  }

  async function sendEmail() {
    setBusy("email");
    setError("");
    try {
      await fallbacks.email!.request();
      setCode("");
      setView("email");
    } catch (caught) {
      setError(messageOf(caught, "We couldn't send a code. Try again."));
    } finally {
      setBusy("");
    }
  }

  function choose(option: "passkey" | CodeMethod) {
    if (option === "passkey") void finish("passkey", () => client.confirm());
    else if (option === "email") void sendEmail();
    else { setError(""); setCode(""); setView("totp"); }
  }

  const submitCode = (event: FormEvent) => {
    event.preventDefault();
    const clean = code.replace(/\D/g, "");
    if (clean.length !== 6) { setError("Enter the 6-digit code."); return; }
    void finish("code", () => view === "totp" ? fallbacks.totp!(clean) : fallbacks.email!.verify(clean));
  };

  const formId = `${ids}-code`;
  const titleId = `${ids}-title`;
  const inCode = view !== "choose";
  const canGoBack = inCode && options.length > 1;
  const locked = busy === "code" || busy === "email" || done;

  let title = "Confirm it's you";
  let copy = options.length > 1 ? "This change is protected. Choose how you'd like to confirm it's you."
    : options[0] === "passkey" ? "This change is protected. Confirm with your passkey to continue."
    : options[0] === "email" ? "This change is protected. We'll email you a 6-digit code to confirm it's you."
    : "This change is protected.";
  if (view === "email") { title = "Check your email"; copy = "We sent a 6-digit code to your email address. It expires in 10 minutes."; }
  if (view === "totp") { title = "Enter your code"; copy = "Open your authenticator app and enter the 6-digit code for BIFY."; }
  if (done) { title = "You're confirmed"; copy = "Continuing with your change."; }

  return <div className="modal-backdrop bpk-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget && !locked) close(); }}>
    <section className="modal bpk-step-up" role="dialog" aria-modal="true" aria-labelledby={titleId}>
      {done ? null : <button type="button" className="icon-button bpk-close" aria-label="Close" disabled={locked} onClick={close}><X size={16} /></button>}
      <div className="modal-body">
        {done ? <span className="bpk-confirmed" aria-hidden="true"><CircleCheck size={22} /></span> : <span className="eyebrow">Security check</span>}
        <h2 id={titleId}>{title}</h2>
        <p>{copy}</p>
        {done ? null : !inCode ? <div className="auth-actions bpk-methods">
          {options.map((option, index) => {
            const { icon: Icon, title: label, detail } = METHOD_COPY[option];
            const working = busy === option;
            return <button key={option} type="button" className="auth-provider" disabled={!!busy} autoFocus={index === 0} onClick={() => choose(option)}>
              {working ? <Spinner size={17} /> : <Icon size={17} />}
              <span><strong>{working ? option === "passkey" ? "Waiting for your passkey…" : "Sending your code…" : label}</strong><small>{detail}</small></span>
              <ChevronRight className="bpk-chevron" size={15} />
            </button>;
          })}
          {options.length === 0 ? <p className="bpk-note">Add a passkey or an authenticator app in Security settings to make this change.</p> : null}
        </div> : <form id={formId} className="bpk-code-form" onSubmit={submitCode}>
          <label htmlFor={`${formId}-field`}>Verification code</label>
          {CodeInput ? <CodeInput id={`${formId}-field`} value={code} onChange={(value) => { setCode(value); setError(""); }} disabled={locked} autoFocus />
            : <input id={`${formId}-field`} className="bpk-code-field" inputMode="numeric" autoComplete="one-time-code" maxLength={6} placeholder="000000" value={code} autoFocus disabled={locked}
              onChange={(event) => { setCode(event.target.value.replace(/\D/g, "")); setError(""); }} />}
          {view === "email" ? <button type="button" className="text-button bpk-resend" disabled={locked} onClick={() => void sendEmail()}>Send a new code</button> : null}
        </form>}
        {error ? <div className="auth-error bpk-alert" role="alert"><ShieldAlert size={15} /><span>{error}</span></div> : null}
      </div>
      {done ? null : <div className="modal-footer">
        {canGoBack ? <button type="button" className="ghost-button" disabled={locked} onClick={() => { setView("choose"); setError(""); }}>Back</button>
          : <button type="button" className="ghost-button" disabled={locked} onClick={close}>Cancel</button>}
        {inCode ? <button type="submit" form={formId} className="primary-button" disabled={locked || code.replace(/\D/g, "").length !== 6}>
          {busy === "code" ? <Spinner size={14} /> : <ShieldCheck size={14} />}{busy === "code" ? "Confirming…" : "Confirm"}
        </button> : null}
      </div>}
    </section>
  </div>;
}

// ── Sign in ──────────────────────────────────────────────────────────────────────────────────────

/**
 * A sign-in option for passkeys, laid out like the portals' other sign-in options (icon, title, hint,
 * chevron); pass the portal's option class. Hidden in browsers without passkeys.
 */
export function PasskeySignInButton({ client, onSignedIn, onError, className = "auth-provider", disabled = false, chevron = true }: { client: PasskeyClient; onSignedIn: () => void; onError: (message: string) => void; className?: string; disabled?: boolean; chevron?: boolean }) {
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
    } catch (caught) {
      if (!isCancelled(caught)) onError(messageOf(caught, "Passkey sign-in failed. Try again."));
    } finally {
      setBusy(false);
    }
  }}>
    {busy ? <Spinner size={17} /> : <ScanFace size={17} />}
    <span><strong>{busy ? "Waiting for your passkey…" : "Sign in with a passkey"}</strong><small>Face ID, fingerprint or security key</small></span>
    {chevron ? <ChevronRight size={15} /> : null}
  </button>;
}

// ── Security settings ────────────────────────────────────────────────────────────────────────────

// The icon a person recognises their passkey by: the device it lives on, or a security key.
function deviceIcon(passkey: Passkey): LucideIcon {
  const name = passkey.name.toLowerCase();
  if (/iphone|phone|android|pixel|galaxy/.test(name)) return Smartphone;
  if (/ipad|tablet/.test(name)) return Tablet;
  if (/mac|windows|pc|chromebook|laptop|linux|computer/.test(name)) return Laptop;
  const transports = passkey.transports ?? [];
  if (!passkey.synced && transports.length > 0 && transports.every((t) => t === "usb" || t === "nfc" || t === "ble")) return KeyRound;
  return ScanFace;
}

/**
 * The Security settings list of passkeys. renderHead draws the portal's own panel header around the
 * "Add a passkey" action, and bodyClassName is the portal's panel body, so the list sits in the page's
 * existing panel design.
 */
export function PasskeyManager({ client, renderHead, bodyClassName = "" }: { client: PasskeyClient; renderHead?: (action: ReactNode) => ReactNode; bodyClassName?: string }) {
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
      setError(messageOf(caught, "Passkeys could not be loaded."));
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
      if (!isCancelled(caught)) setError(messageOf(caught, "That didn't work. Try again."));
    } finally {
      setBusy("");
    }
  }

  const add = () => run("add", async () => { await guarded(() => client.register(suggestedPasskeyName())); }, "Passkey added. You can sign in with it now.");
  const full = passkeys !== null && passkeys.length >= limit;

  const action = supported ? <button type="button" className="primary-button bpk-add" disabled={!!busy || full || passkeys === null} onClick={() => void add()}>
    {busy === "add" ? <Spinner size={14} /> : <ScanFace size={14} />}{busy === "add" ? "Follow your device…" : "Add a passkey"}
  </button> : null;

  return <>
    {renderHead ? renderHead(action) : <div className="bpk-head"><div><h2>Passkeys</h2><p>Sign in with Face ID, fingerprint or a security key, and confirm changes with one touch.</p></div>{action}</div>}
    <div className={`bpk-body ${bodyClassName}`.trim()}>
      {!supported ? <p className="bpk-note">This browser can&apos;t use passkeys. Open this page in an up-to-date Safari, Chrome, Edge or Firefox to add one.</p> : null}
      {full ? <p className="bpk-note">You&apos;ve reached the limit of {limit} passkeys. Remove one to add another.</p> : null}
      {error ? <div className="auth-error bpk-alert" role="alert"><ShieldAlert size={15} /><span>{error}</span></div> : null}
      {notice ? <p className="bpk-success" role="status"><CircleCheck size={15} />{notice}</p> : null}
      {passkeys === null ? <div className="bpk-skeleton" aria-hidden="true" />
        : passkeys.length === 0 ? <div className="bpk-empty"><span className="bpk-row-icon"><ScanFace size={17} /></span><div><strong>No passkeys yet</strong><span>Add one to sign in with a glance or a touch. It can&apos;t be phished and only works on this site.</span></div></div>
        : <ul className="bpk-list">
          {passkeys.map((passkey) => {
            const Icon = deviceIcon(passkey);
            const editing = renaming?.id === passkey.id;
            const confirmingRemove = removing === passkey.id;
            return <li key={passkey.id} className="bpk-row">
              <span className="bpk-row-icon"><Icon size={17} /></span>
              {editing ? <form className="bpk-rename" onSubmit={(event) => { event.preventDefault(); const name = renaming.name.trim(); if (!name) return; void run(passkey.id, () => client.rename(passkey.id, name), "Passkey renamed.").then(() => setRenaming(null)); }}>
                <input className="bpk-input" value={renaming.name} maxLength={40} autoFocus aria-label="Passkey name" onChange={(event) => setRenaming({ id: passkey.id, name: event.target.value })} onKeyDown={(event) => { if (event.key === "Escape") setRenaming(null); }} />
                <button type="button" className="ghost-button" onClick={() => setRenaming(null)}>Cancel</button>
                <button type="submit" className="primary-button" disabled={busy === passkey.id || !renaming.name.trim()}>{busy === passkey.id ? <Spinner size={14} /> : null}Save</button>
              </form> : <div className="bpk-row-copy">
                <strong>{passkey.name}{passkey.synced ? <span className="bpk-tag">Synced</span> : null}</strong>
                <span>{[passkey.synced ? "Available on your signed-in devices" : "On this device only", `added ${relative(passkey.createdAt)}`, passkey.lastUsedAt ? `last used ${relative(passkey.lastUsedAt)}` : "not used yet"].join(" · ")}</span>
              </div>}
              {editing ? null : confirmingRemove ? <div className="bpk-row-actions">
                <span className="bpk-ask">Remove this passkey?</span>
                <button type="button" className="ghost-button" disabled={busy === passkey.id} onClick={() => setRemoving("")}>Keep</button>
                <button type="button" className="danger-button" disabled={busy === passkey.id} onClick={() => void run(passkey.id, () => guarded(() => client.remove(passkey.id)), "Passkey removed.").then(() => setRemoving(""))}>{busy === passkey.id ? <Spinner size={14} /> : <Trash2 size={14} />}Remove</button>
              </div> : <div className="bpk-row-actions">
                <button type="button" className="ghost-button" disabled={!!busy} onClick={() => { setRenaming({ id: passkey.id, name: passkey.name }); setRemoving(""); }}><Pencil size={13} />Rename</button>
                <button type="button" className="ghost-button" disabled={!!busy} onClick={() => { setRemoving(passkey.id); setRenaming(null); }}><Trash2 size={13} />Remove</button>
              </div>}
            </li>;
          })}
        </ul>}
    </div>
  </>;
}
