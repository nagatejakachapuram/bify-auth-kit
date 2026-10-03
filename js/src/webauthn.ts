// Browser side of passkeys, on SimpleWebAuthn (@simplewebauthn/browser): it turns the server's options into
// the navigator.credentials call, returns the browser's answer as the JSON the server verifies, and sends
// WebAuthn signals so the person's password manager stays in step with their account. Nothing here
// handles keys: creating and using a passkey happens in the browser and the device's authenticator.
import { browserSupportsWebAuthn, sendSignal, startAuthentication, startRegistration, WebAuthnAbortService, WebAuthnError } from "@simplewebauthn/browser";
import type { AuthenticationResponseJSON, PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON, RegistrationResponseJSON } from "@simplewebauthn/browser";

export type { AuthenticationResponseJSON, PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON, RegistrationResponseJSON };

/** createPasskey runs the browser's "create a passkey" prompt for the server's registration options. */
export function createPasskey(optionsJSON: PublicKeyCredentialCreationOptionsJSON): Promise<RegistrationResponseJSON> {
  return startRegistration({ optionsJSON });
}

/** usePasskey runs the browser's "use a passkey" prompt for the server's sign-in or confirmation options. */
export function usePasskey(optionsJSON: PublicKeyCredentialRequestOptionsJSON): Promise<AuthenticationResponseJSON> {
  return startAuthentication({ optionsJSON });
}

/** cancelPasskeyPrompt closes a passkey prompt that is still open, for example when its dialog closes. */
export function cancelPasskeyPrompt(): void {
  WebAuthnAbortService.cancelCeremony();
}

/** passkeysSupported reports whether this browser can use passkeys at all. */
export function passkeysSupported(): boolean {
  return typeof window !== "undefined" && browserSupportsWebAuthn();
}

/** cancelled reports a browser prompt the person dismissed (or that timed out), which is not an error to show. */
export function cancelled(error: unknown): boolean {
  if (error instanceof WebAuthnError && error.code === "ERROR_CEREMONY_ABORTED") return true;
  const name = error instanceof Error || (typeof DOMException !== "undefined" && error instanceof DOMException) ? (error as Error).name : "";
  return name === "NotAllowedError" || name === "AbortError";
}

/** alreadyRegistered reports the browser refusing a second passkey for this account on the same authenticator. */
export function alreadyRegistered(error: unknown): boolean {
  if (error instanceof WebAuthnError) return error.code === "ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED";
  return error instanceof Error && error.name === "InvalidStateError";
}

/**
 * Tells the browser's password manager which passkeys this account still accepts, so ones removed here
 * stop being offered. Best effort: browsers without the WebAuthn Signal API ignore it.
 */
export function signalAcceptedPasskeys(rpID: string, userID: string, credentialIDs: string[]): void {
  if (!rpID || !userID || typeof window === "undefined") return;
  void sendSignal({ signalName: "allAcceptedCredentials", rpID, userID, allAcceptedCredentialIDs: credentialIDs }).catch(() => undefined);
}

/** Tells the browser's password manager that a passkey it offered is not registered here any more. */
export function signalRemovedPasskey(rpID: string, credentialID: string): void {
  if (!rpID || !credentialID || typeof window === "undefined") return;
  void sendSignal({ signalName: "unknownCredential", rpID, credentialID }).catch(() => undefined);
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
