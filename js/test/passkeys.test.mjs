import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import {
  base64urlToBuffer, bufferToBase64url, createPasskeyClient, creationOptions, credentialJSON, PasskeyError,
  requestOptions, StepUpDialog, stepUpMethods, suggestedPasskeyName, withStepUp,
} from "../dist/index.js";

const json = (status, body) => new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

test("base64url round-trips arbitrary bytes", () => {
  const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255, 62, 63]);
  const encoded = bufferToBase64url(bytes);
  assert.doesNotMatch(encoded, /[+/=]/);
  assert.deepEqual(new Uint8Array(base64urlToBuffer(encoded)), bytes);
});

test("server options become browser options when the browser has no JSON helpers", () => {
  const creation = creationOptions({ challenge: "AAEC", rp: { id: "account.bify.io", name: "BIFY Account" }, user: { id: "dXNlcg", name: "a@b.c", displayName: "A" }, pubKeyCredParams: [{ type: "public-key", alg: -7 }], excludeCredentials: [{ type: "public-key", id: "AQI", transports: ["internal"] }] });
  assert.deepEqual(new Uint8Array(creation.challenge), new Uint8Array([0, 1, 2]));
  assert.equal(new TextDecoder().decode(creation.user.id), "user");
  assert.deepEqual(new Uint8Array(creation.excludeCredentials[0].id), new Uint8Array([1, 2]));
  assert.equal(creation.rp.id, "account.bify.io");
  const request = requestOptions({ challenge: "AAEC", rpId: "account.bify.io", allowCredentials: [{ type: "public-key", id: "AQI" }], userVerification: "required" });
  assert.deepEqual(new Uint8Array(request.allowCredentials[0].id), new Uint8Array([1, 2]));
  assert.equal(request.userVerification, "required");
});

test("a browser answer becomes the JSON the server verifies", () => {
  const buf = (...b) => new Uint8Array(b).buffer;
  const assertion = credentialJSON({ id: "AQI", rawId: buf(1, 2), type: "public-key", authenticatorAttachment: "platform", getClientExtensionResults: () => ({}),
    response: { clientDataJSON: buf(3), authenticatorData: buf(4), signature: buf(5), userHandle: buf(6) } });
  assert.deepEqual(assertion.response, { clientDataJSON: "Aw", authenticatorData: "BA", signature: "BQ", userHandle: "Bg" });
  const attestation = credentialJSON({ id: "AQI", rawId: buf(1, 2), type: "public-key", getClientExtensionResults: () => ({}),
    response: { clientDataJSON: buf(3), attestationObject: buf(7), getTransports: () => ["internal"] } });
  assert.deepEqual(attestation.response, { clientDataJSON: "Aw", attestationObject: "Bw", transports: ["internal"] });
});

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
  const original = globalThis.navigator;
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: { credentials: { get: async ({ publicKey }) => {
    assert.deepEqual(new Uint8Array(publicKey.challenge), new Uint8Array([0, 1, 2]));
    return { id: "AQI", rawId: new Uint8Array([1, 2]).buffer, type: "public-key", getClientExtensionResults: () => ({}), response: { clientDataJSON: new Uint8Array([1]).buffer, authenticatorData: new Uint8Array([2]).buffer, signature: new Uint8Array([3]).buffer, userHandle: null } };
  } } } });
  t.after(() => Object.defineProperty(globalThis, "navigator", { configurable: true, value: original }));
  await createPasskeyClient({ baseUrl: "https://auth.example/", fetch }).signIn();
  assert.equal(calls[0][0], "https://auth.example/v1/auth/passkeys/login/options");
  assert.equal(calls[0][3], "include", "the session cookie must be sent");
  assert.equal(calls[1][2].ceremonyId, "c1");
  assert.equal(calls[1][2].credential.id, "AQI");
});

test("a dismissed browser prompt is reported as cancelled, not as an error", async (t) => {
  const fetch = async () => json(200, { ceremonyId: "c1", options: { publicKey: { challenge: "AAEC" } } });
  const original = globalThis.navigator;
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: { credentials: { get: async () => { throw new DOMException("The operation either timed out or was not allowed.", "NotAllowedError"); } } } });
  t.after(() => Object.defineProperty(globalThis, "navigator", { configurable: true, value: original }));
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

test("the confirmation dialog offers the passkey first and the portal's fallbacks", () => {
  const original = globalThis.window;
  globalThis.window = { PublicKeyCredential: function () {} };
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: { credentials: {} } });
  try {
    const html = renderToStaticMarkup(createElement(StepUpDialog, { client: {}, methods: ["passkey", "totp"], fallbacks: { totp: async () => {} }, onConfirmed() {}, onCancel() {} }));
    assert.match(html, /Confirm it(&#x27;|')s you/);
    assert.match(html, /Use passkey/);
    assert.match(html, /Use authenticator code instead/);
    const codeOnly = renderToStaticMarkup(createElement(StepUpDialog, { client: {}, methods: ["totp"], fallbacks: { totp: async () => {} }, onConfirmed() {}, onCancel() {} }));
    assert.match(codeOnly, /authenticator app/);
    assert.doesNotMatch(codeOnly, /Use passkey/);
    const nothing = renderToStaticMarkup(createElement(StepUpDialog, { client: {}, methods: ["totp"], fallbacks: {}, onConfirmed() {}, onCancel() {} }));
    assert.match(nothing, /Add a passkey or an authenticator app/);
  } finally {
    globalThis.window = original;
  }
});
