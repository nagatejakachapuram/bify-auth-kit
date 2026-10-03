// The passkey API of a BIFY portal backend (bify-auth-kit/passkey), as typed calls.
import { alreadyRegistered, cancelled, createPasskey, signalAcceptedPasskeys, signalRemovedPasskey, suggestedPasskeyName, usePasskey, type PublicKeyCredentialCreationOptionsJSON, type PublicKeyCredentialRequestOptionsJSON } from "./webauthn.js";

export type Passkey = { id: string; name: string; createdAt: string; lastUsedAt?: string; synced: boolean; transports?: string[] };
/** How a person can confirm a sensitive action: their passkey, or a portal fallback such as "totp" or "email". */
export type StepUpMethod = "passkey" | "totp" | "email" | (string & {});
export type StepUpStatus = { recent: boolean; methods: StepUpMethod[] };

/** PasskeyError carries the server's message (safe to show) and code, or "cancelled" when the person dismissed the prompt. */
export class PasskeyError extends Error {
  constructor(message: string, readonly code = "", readonly status = 0) {
    super(message);
    this.name = "PasskeyError";
  }
  get cancelled() { return this.code === "cancelled"; }
}

export const STEP_UP_REQUIRED = "step_up_required";

export type PasskeyClientOptions = {
  /** Origin of the portal's auth API, for example "https://auth.developer.bify.io" or "" for same-origin. */
  baseUrl: string;
  fetch?: typeof fetch;
};

export type PasskeyClient = ReturnType<typeof createPasskeyClient>;

// go-webauthn answers with the standard WebAuthn JSON options under "publicKey".
type CreationOptions = { publicKey: PublicKeyCredentialCreationOptionsJSON };
type RequestOptions = { publicKey: PublicKeyCredentialRequestOptionsJSON };

export function createPasskeyClient({ baseUrl, fetch: fetchImpl }: PasskeyClientOptions) {
  const base = baseUrl.replace(/\/$/, "");
  const send = (path: string, init: RequestInit = {}) => (fetchImpl ?? fetch)(`${base}${path}`, {
    credentials: "include",
    cache: "no-store",
    ...init,
    headers: { Accept: "application/json", ...(init.body ? { "Content-Type": "application/json" } : {}), ...(init.headers ?? {}) },
  });

  async function json<T>(path: string, init?: RequestInit): Promise<T> {
    let response: Response;
    try {
      response = await send(path, init);
    } catch {
      throw new PasskeyError("We couldn't reach BIFY. Check your connection and try again.", "network");
    }
    if (response.status === 204) return undefined as T;
    const body = await response.json().catch(() => ({})) as Record<string, unknown>;
    if (!response.ok) throw new PasskeyError(typeof body.error === "string" ? body.error : "Something went wrong. Try again.", typeof body.code === "string" ? body.code : "", response.status);
    return body as T;
  }

  const post = <T>(path: string, body?: unknown) => json<T>(path, { method: "POST", body: body === undefined ? undefined : JSON.stringify(body) });

  // The browser prompts, through SimpleWebAuthn. Errors become messages a person can act on.
  async function create(options: CreationOptions) {
    try {
      return await createPasskey(options.publicKey);
    } catch (error) {
      if (cancelled(error)) throw new PasskeyError("Cancelled.", "cancelled");
      if (alreadyRegistered(error)) throw new PasskeyError("This device already has a passkey for your account.", "passkey_exists");
      throw new PasskeyError("Your device couldn't create a passkey. Try again or use another device.", "device");
    }
  }

  async function get(options: RequestOptions) {
    try {
      return await usePasskey(options.publicKey);
    } catch (error) {
      if (cancelled(error)) throw new PasskeyError("Cancelled.", "cancelled");
      throw new PasskeyError("Your device couldn't use a passkey. Try again.", "device");
    }
  }

  return {
    /** The account's passkeys, newest first, and how many it may hold. */
    async list(): Promise<{ passkeys: Passkey[]; limit: number }> {
      const body = await json<{ data?: Passkey[]; limit?: number; rpId?: string; userHandle?: string }>("/v1/auth/passkeys");
      const passkeys = Array.isArray(body.data) ? body.data : [];
      // Keep the person's password manager in step: passkeys removed here stop being offered there.
      signalAcceptedPasskeys(body.rpId ?? "", body.userHandle ?? "", passkeys.map((passkey) => passkey.id));
      return { passkeys, limit: body.limit ?? 10 };
    },
    /** Creates a passkey on this device and saves it to the account. Needs a recent confirmation. */
    async register(name = suggestedPasskeyName()): Promise<Passkey> {
      const started = await post<{ ceremonyId: string; options: CreationOptions }>("/v1/auth/passkeys/registration/options");
      const credential = await create(started.options);
      const saved = await post<{ data: Passkey }>("/v1/auth/passkeys/registration/verify", { ceremonyId: started.ceremonyId, name, credential });
      return saved.data;
    },
    rename: (id: string, name: string) => post<void>("/v1/auth/passkeys/rename", { id, name }),
    /** Removes a passkey. Needs a recent confirmation. */
    remove: (id: string) => post<void>("/v1/auth/passkeys/delete", { id }),
    /** Signs in with any passkey for this portal; the browser lets the person pick one. */
    async signIn(): Promise<void> {
      const started = await post<{ ceremonyId: string; options: RequestOptions }>("/v1/auth/passkeys/login/options");
      const credential = await get(started.options);
      try {
        await post("/v1/auth/passkeys/login/verify", { ceremonyId: started.ceremonyId, credential });
      } catch (error) {
        // A passkey removed from the account: tell the browser so it stops offering it.
        if (error instanceof PasskeyError && error.code === "passkey_unknown") signalRemovedPasskey(started.options.publicKey.rpId ?? location.hostname, credential.id);
        throw error;
      }
    },
    /** Confirms a sensitive action with one of the account's passkeys. */
    async confirm(): Promise<void> {
      const started = await post<{ ceremonyId: string; options: RequestOptions }>("/v1/auth/passkeys/step-up/options");
      const credential = await get(started.options);
      await post("/v1/auth/passkeys/step-up/verify", { ceremonyId: started.ceremonyId, credential });
    },
    /** Whether the session confirmed itself recently, and how it can confirm. */
    stepUpStatus: () => json<StepUpStatus>("/v1/auth/step-up"),
  };
}

/** stepUpMethods reads a 403 "confirm it's you" answer; it returns null for any other response. */
export async function stepUpMethods(response: Response): Promise<StepUpMethod[] | null> {
  if (response.status !== 403) return null;
  const body = await response.clone().json().catch(() => null) as { code?: unknown; methods?: unknown } | null;
  if (!body || body.code !== STEP_UP_REQUIRED) return null;
  return Array.isArray(body.methods) ? body.methods.filter((m): m is string => typeof m === "string") : [];
}

/**
 * withStepUp wraps fetch so a sensitive request answered "confirm it's you" asks the person to confirm
 * (confirm resolves once they did, or rejects if they cancelled) and is then retried once.
 */
export function withStepUp(fetchImpl: typeof fetch, confirm: (methods: StepUpMethod[]) => Promise<void>): typeof fetch {
  return async (input, init) => {
    const response = await fetchImpl(input, init);
    const methods = await stepUpMethods(response);
    if (!methods) return response;
    await confirm(methods);
    return fetchImpl(input, init);
  };
}
