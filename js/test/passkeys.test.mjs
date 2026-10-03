import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createPasskeyClient, PasskeyError, StepUpDialog, stepUpMethods, suggestedPasskeyName, withStepUp } from "../dist/index.js";

const json = (status, body) => new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const bytes = (...b) => new Uint8Array(b).buffer;

// A browser with WebAuthn: PublicKeyCredential (with the Signal API) and navigator.credentials.
function browser(t, credentials) {
  const signals = [];
  const previous = { window: globalThis.window, navigator: globalThis.navigator, PublicKeyCredential: globalThis.PublicKeyCredential };
  const PublicKeyCredential = Object.assign(function PublicKeyCredential() {}, {
    signalUnknownCredential: async (options) => { signals.push(["unknown", options]); },
    signalAllAcceptedCredentials: async (options) => { signals.push(["accepted", options]); },
  });
  globalThis.PublicKeyCredential = PublicKeyCredential;
  globalThis.window = { PublicKeyCredential, location: { hostname: "account.bify.io" } };
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: { credentials, userAgent: "" } });
  t.after(() => {
    globalThis.window = previous.window;
    globalThis.PublicKeyCredential = previous.PublicKeyCredential;
    Object.defineProperty(globalThis, "navigator", { configurable: true, value: previous.navigator });
  });
  return signals;
}

const assertion = () => ({ id: "AQI", rawId: bytes(1, 2), type: "public-key", authenticatorAttachment: "platform", getClientExtensionResults: () => ({}),
  response: { clientDataJSON: bytes(1), authenticatorData: bytes(2), signature: bytes(3), userHandle: bytes(4) } });

test("passkeys get a friendly default name for the device they were made on", () => {
  assert.equal(suggestedPasskeyName("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)"), "iPhone");
  assert.equal(suggestedPasskeyName("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"), "Mac");
  assert.equal(suggestedPasskeyName("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"), "Windows PC");
  assert.equal(suggestedPasskeyName("Mozilla/5.0 (Linux; Android 15; Pixel 9) Mobile"), "Android phone");
  assert.equal(suggestedPasskeyName(""), "Passkey");
});

test("the client signs in through the browser and the server's two steps", async (t) => {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push([url, init?.method ?? "GET", init?.body ? JSON.parse(init.body) : null, init?.credentials]);
    if (url.endsWith("/login/options")) return json(200, { ceremonyId: "c1", options: { publicKey: { challenge: "AAEC", rpId: "account.bify.io", userVerification: "required" } } });
    if (url.endsWith("/login/verify")) return json(200, { status: "authenticated" });
    return json(404, {});
  };
  browser(t, { get: async ({ publicKey }) => {
    assert.deepEqual(new Uint8Array(publicKey.challenge), new Uint8Array([0, 1, 2]));
    assert.equal(publicKey.userVerification, "required");
    return assertion();
  } });
  await createPasskeyClient({ baseUrl: "https://auth.example/", fetch }).signIn();
  assert.equal(calls[0][0], "https://auth.example/v1/auth/passkeys/login/options");
  assert.equal(calls[0][3], "include", "the session cookie must be sent");
  assert.equal(calls[1][2].ceremonyId, "c1");
  assert.equal(calls[1][2].credential.id, "AQI");
  assert.deepEqual(calls[1][2].credential.response, { authenticatorData: "Ag", clientDataJSON: "AQ", signature: "Aw", userHandle: "BA" });
});

test("signing in with a passkey removed from the account tells the browser to stop offering it", async (t) => {
  const fetch = async (url) => url.endsWith("/login/options")
    ? json(200, { ceremonyId: "c1", options: { publicKey: { challenge: "AAEC", rpId: "account.bify.io" } } })
    : json(401, { error: "This passkey was removed from your account.", code: "passkey_unknown" });
  const signals = browser(t, { get: async () => assertion() });
  await assert.rejects(createPasskeyClient({ baseUrl: "", fetch }).signIn(), (error) => error.code === "passkey_unknown");
  await new Promise(setImmediate);
  assert.deepEqual(signals, [["unknown", { rpId: "account.bify.io", credentialId: "AQI" }]]);
});

test("listing passkeys keeps the browser's password manager in step", async (t) => {
  const signals = browser(t, {});
  const fetch = async () => json(200, { data: [{ id: "AQI", name: "iPhone", createdAt: "2026-10-01T00:00:00Z", synced: true }], limit: 10, rpId: "account.bify.io", userHandle: "dXNlcg" });
  const { passkeys } = await createPasskeyClient({ baseUrl: "", fetch }).list();
  assert.equal(passkeys.length, 1);
  await new Promise(setImmediate);
  assert.deepEqual(signals, [["accepted", { rpId: "account.bify.io", userId: "dXNlcg", allAcceptedCredentialIds: ["AQI"] }]]);
});

test("a dismissed browser prompt is reported as cancelled, not as an error", async (t) => {
  const fetch = async () => json(200, { ceremonyId: "c1", options: { publicKey: { challenge: "AAEC", rpId: "account.bify.io" } } });
  browser(t, { get: async () => { throw new DOMException("The operation either timed out or was not allowed.", "NotAllowedError"); } });
  await assert.rejects(createPasskeyClient({ baseUrl: "", fetch }).confirm(), (error) => error instanceof PasskeyError && error.cancelled);
});

test("server errors keep their message and code", async () => {
  const client = createPasskeyClient({ baseUrl: "", fetch: async () => json(403, { error: "Confirm it's you to continue.", code: "step_up_required", methods: ["passkey"] }) });
  await assert.rejects(client.remove("x"), (error) => error.code === "step_up_required" && error.status === 403 && error.message === "Confirm it's you to continue.");
  const offline = createPasskeyClient({ baseUrl: "", fetch: async () => { throw new TypeError("Failed to fetch"); } });
  await assert.rejects(offline.list(), (error) => error.code === "network");
});

test("withStepUp confirms once and retries a sensitive request", async () => {
  let attempts = 0;
  const fetch = async () => ++attempts === 1 ? json(403, { code: "step_up_required", methods: ["passkey", "totp"] }) : json(201, { ok: true });
  const asked = [];
  const guarded = withStepUp(fetch, async (methods) => { asked.push(methods); });
  const response = await guarded("/v1/developer/api-keys", { method: "POST" });
  assert.equal(response.status, 201);
  assert.deepEqual(asked, [["passkey", "totp"]]);
  assert.equal(attempts, 2);
  // Other 403s pass straight through, and a cancelled confirmation does not retry.
  assert.equal(await stepUpMethods(json(403, { error: "forbidden" })), null);
  let tries = 0;
  const cancelling = withStepUp(async () => { tries++; return json(403, { code: "step_up_required", methods: [] }); }, async () => { throw new PasskeyError("Cancelled.", "cancelled"); });
  await assert.rejects(cancelling("/x"), (error) => error.cancelled);
  assert.equal(tries, 1);
});

test("the confirmation dialog lists the ways this account can confirm, passkey first", (t) => {
  browser(t, {});
  const render = (methods, fallbacks, CodeInput) => renderToStaticMarkup(createElement(StepUpDialog, { client: {}, methods, fallbacks, CodeInput, onConfirmed() {}, onCancel() {} }));
  const all = render(["passkey", "email", "totp"], { totp: async () => {}, email: { request: async () => {}, verify: async () => {} } });
  assert.match(all, /class="modal-backdrop bpk-backdrop"/, "uses the portal's modal");
  assert.match(all, /Confirm it(&#x27;|')s you/);
  const order = ["Use a passkey", "Email me a code", "Use your authenticator app"].map((label) => all.indexOf(label));
  assert.ok(order.every((index) => index > 0) && order[0] < order[1] && order[1] < order[2], "passkey, then email, then app");
  // Only an authenticator app: straight to the code, in the portal's own code field.
  const codeOnly = render(["totp"], { totp: async () => {} }, ({ id }) => createElement("div", { "data-portal-code": id }));
  assert.match(codeOnly, /Enter your code/);
  assert.match(codeOnly, /data-portal-code=/);
  assert.doesNotMatch(codeOnly, /Use a passkey/);
  // A method the portal has no fallback for is not offered.
  assert.match(render(["totp"], {}), /Add a passkey or an authenticator app/);
});
