export { createPasskeyClient, PasskeyError, STEP_UP_REQUIRED, stepUpMethods, withStepUp } from "./client.js";
export type { Passkey, PasskeyClient, PasskeyClientOptions, StepUpMethod, StepUpStatus } from "./client.js";
export { base64urlToBuffer, bufferToBase64url, cancelled, creationOptions, credentialJSON, passkeysSupported, requestOptions, suggestedPasskeyName } from "./webauthn.js";
export { PasskeyIcon, PasskeyManager, PasskeySignInButton, StepUpDialog, StepUpProvider, useStepUp } from "./react.js";
export type { StepUpFallbacks } from "./react.js";
