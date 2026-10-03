// Browser side of passkeys: turning the server's JSON options into what navigator.credentials needs, and
// the browser's answer back into JSON. Uses the built-in WebAuthn JSON helpers where the browser has them
// and an equivalent manual conversion where it does not (older Safari and Firefox).

export function base64urlToBuffer(value: string): ArrayBuffer {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

export function bufferToBase64url(buffer: ArrayBuffer | ArrayBufferView): string {
  const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

type JSONDescriptor = { id: string; type: string; transports?: string[] };
type CreationJSON = { challenge: string; user: { id: string; name: string; displayName: string }; excludeCredentials?: JSONDescriptor[]; [key: string]: unknown };
type RequestJSON = { challenge: string; allowCredentials?: JSONDescriptor[]; [key: string]: unknown };

const descriptor = (d: JSONDescriptor): PublicKeyCredentialDescriptor => ({ type: "public-key", id: base64urlToBuffer(d.id), transports: d.transports as AuthenticatorTransport[] | undefined });

type JSONCapableCredential = typeof PublicKeyCredential & {
  parseCreationOptionsFromJSON?: (options: unknown) => PublicKeyCredentialCreationOptions;
  parseRequestOptionsFromJSON?: (options: unknown) => PublicKeyCredentialRequestOptions;
};

/** creationOptions converts the server's "publicKey" registration options for navigator.credentials.create. */
export function creationOptions(json: CreationJSON): PublicKeyCredentialCreationOptions {
  const native = (globalThis.PublicKeyCredential as JSONCapableCredential | undefined)?.parseCreationOptionsFromJSON;
  if (native) return native(json);
  return {
    ...(json as unknown as PublicKeyCredentialCreationOptions),
    challenge: base64urlToBuffer(json.challenge),
    user: { ...json.user, id: base64urlToBuffer(json.user.id) },
    excludeCredentials: (json.excludeCredentials ?? []).map(descriptor),
  };
}

/** requestOptions converts the server's "publicKey" sign-in or confirmation options for navigator.credentials.get. */
export function requestOptions(json: RequestJSON): PublicKeyCredentialRequestOptions {
  const native = (globalThis.PublicKeyCredential as JSONCapableCredential | undefined)?.parseRequestOptionsFromJSON;
  if (native) return native(json);
  return {
    ...(json as unknown as PublicKeyCredentialRequestOptions),
    challenge: base64urlToBuffer(json.challenge),
    allowCredentials: (json.allowCredentials ?? []).map(descriptor),
  };
}

type JSONCapable = PublicKeyCredential & { toJSON?: () => unknown };

/** credentialJSON turns the browser's answer into the JSON the server verifies. */
export function credentialJSON(credential: PublicKeyCredential): unknown {
  const native = (credential as JSONCapable).toJSON;
  if (typeof native === "function") {
    try { return native.call(credential); } catch { /* some password-manager extensions break toJSON; fall back */ }
  }
  const response = credential.response as AuthenticatorAttestationResponse & AuthenticatorAssertionResponse;
  const out: Record<string, unknown> = {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment ?? undefined,
    clientExtensionResults: credential.getClientExtensionResults?.() ?? {},
  };
  if ("attestationObject" in response && response.attestationObject) {
    out.response = {
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      attestationObject: bufferToBase64url(response.attestationObject),
      transports: typeof response.getTransports === "function" ? response.getTransports() : undefined,
    };
  } else {
    out.response = {
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      authenticatorData: bufferToBase64url(response.authenticatorData),
      signature: bufferToBase64url(response.signature),
      userHandle: response.userHandle ? bufferToBase64url(response.userHandle) : undefined,
    };
  }
  return out;
}

/** passkeysSupported reports whether this browser can use passkeys at all. */
export function passkeysSupported(): boolean {
  return typeof window !== "undefined" && typeof window.PublicKeyCredential === "function" && typeof navigator !== "undefined" && !!navigator.credentials;
}

/** suggestedPasskeyName guesses a friendly label for a passkey made on this device. */
export function suggestedPasskeyName(userAgent = typeof navigator === "undefined" ? "" : navigator.userAgent): string {
  if (/iPhone/.test(userAgent)) return "iPhone";
  if (/iPad/.test(userAgent)) return "iPad";
  if (/Android/.test(userAgent)) return /Mobile/.test(userAgent) ? "Android phone" : "Android tablet";
  if (/Macintosh|Mac OS X/.test(userAgent)) return "Mac";
  if (/Windows/.test(userAgent)) return "Windows PC";
  if (/CrOS/.test(userAgent)) return "Chromebook";
  if (/Linux/.test(userAgent)) return "Linux computer";
  return "Passkey";
}

/** cancelled reports a browser prompt the person dismissed (or that timed out), which is not an error to show. */
export function cancelled(error: unknown): boolean {
  return error instanceof DOMException && (error.name === "NotAllowedError" || error.name === "AbortError");
}
