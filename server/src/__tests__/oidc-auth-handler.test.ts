import { createServer, type Server } from "node:http";
import { createSign, generateKeyPairSync, randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildOidcAuthOptions, probeOidcDiscovery, resolveOidcAuthConfig } from "../auth/oidc.js";

// A real Better Auth handler with the OIDC options, against a small identity
// provider that signs ID tokens with a throwaway RSA key.
const b64 = (value: Buffer | string) => Buffer.from(value).toString("base64url");
const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: "jwk" }), kid: "k1", alg: "RS256", use: "sig" };

let idp: Server;
let issuer = "";
let claimsToIssue: Record<string, unknown> = {};
const pending = new Map<string, { nonce: string; clientId: string }>();

function signIdToken(claims: Record<string, unknown>) {
  const input = `${b64(JSON.stringify({ alg: "RS256", kid: "k1", typ: "JWT" }))}.${b64(JSON.stringify(claims))}`;
  return `${input}.${createSign("RSA-SHA256").update(input).sign(privateKey).toString("base64url")}`;
}

beforeAll(async () => {
  idp = createServer((req, res) => {
    const url = new URL(req.url ?? "/", issuer);
    const send = (body: unknown) => {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(body));
    };
    if (url.pathname === "/.well-known/openid-configuration") {
      return send({
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`,
        id_token_signing_alg_values_supported: ["RS256"],
      });
    }
    if (url.pathname === "/jwks") return send({ keys: [jwk] });
    if (url.pathname === "/token") {
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        const code = new URLSearchParams(body).get("code") ?? "";
        const request = pending.get(code);
        const now = Math.floor(Date.now() / 1000);
        send({
          access_token: "at",
          token_type: "Bearer",
          id_token: signIdToken({
            iss: issuer, aud: request?.clientId, sub: "sub-1", iat: now, exp: now + 300,
            nonce: request?.nonce, ...claimsToIssue,
          }),
        });
      });
      return;
    }
    res.statusCode = 404;
    res.end();
  });
  await new Promise<void>((resolve) => idp.listen(0, "127.0.0.1", resolve));
  issuer = `http://127.0.0.1:${(idp.address() as AddressInfo).port}`;
});

afterAll(() => new Promise<void>((resolve) => idp.close(() => resolve())));

const origin = "http://localhost:3999";

function makeAuth(env: Record<string, string>, opts: { disableSignUp: boolean }) {
  const config = resolveOidcAuthConfig({
    PAPERCLIP_AUTH_OIDC_ISSUER: issuer,
    PAPERCLIP_AUTH_OIDC_CLIENT_ID: "paperclip",
    PAPERCLIP_AUTH_OIDC_CLIENT_SECRET: "s3cret",
    ...env,
  } as NodeJS.ProcessEnv)!;
  const db = { user: [], session: [], account: [], verification: [] };
  const auth = betterAuth({
    baseURL: origin,
    secret: randomBytes(16).toString("hex"),
    trustedOrigins: [origin],
    database: memoryAdapter(db),
    emailAndPassword: { enabled: true, requireEmailVerification: false },
    ...buildOidcAuthOptions(config, opts),
  });
  return { auth, db };
}

async function signInWithOidc(
  auth: ReturnType<typeof betterAuth>,
  claims: Record<string, unknown>,
  body: Record<string, unknown> = {},
) {
  claimsToIssue = { email: "ada@example.test", name: "Ada", email_verified: true, groups: ["paperclip-users"], ...claims };
  const start = await auth.handler(new Request(`${origin}/api/auth/sign-in/social`, {
    method: "POST",
    headers: { "content-type": "application/json", origin },
    body: JSON.stringify({ provider: "oidc", callbackURL: "/", errorCallbackURL: "/auth", ...body }),
  }));
  const { url } = (await start.json()) as { url: string };
  const authorize = new URL(url);
  const state = authorize.searchParams.get("state")!;
  pending.set("code-1", { nonce: authorize.searchParams.get("nonce")!, clientId: "paperclip" });
  const cookie = start.headers.getSetCookie().map((value) => value.split(";")[0]).join("; ");
  const callback = await auth.handler(new Request(
    `${origin}/api/auth/callback/oidc?code=code-1&state=${state}`,
    { headers: { cookie, origin } },
  ));
  return { location: callback.headers.get("location") ?? "", status: callback.status, setCookie: callback.headers.getSetCookie() };
}

const env = { PAPERCLIP_AUTH_OIDC_REQUIRED_GROUP: "paperclip-users" };

describe("OIDC sign-in through a real Better Auth handler", () => {
  it("signs in and creates a user when the claims are good", async () => {
    const { auth, db } = makeAuth(env, { disableSignUp: false });
    const res = await signInWithOidc(auth, {});
    expect(res.location).toBe("/");
    expect(db.user).toHaveLength(1);
  });

  // F1: a missing or string "false" email_verified must not reach account linking.
  it.each([[undefined], ["false"], [false]])("refuses email_verified=%s and links nothing", async (flag) => {
    const { auth, db } = makeAuth(env, { disableSignUp: true });
    await auth.api.signUpEmail({ body: { email: "ada@example.test", name: "Local Ada", password: "correct horse battery" } });
    const res = await signInWithOidc(auth, { email_verified: flag });
    expect(res.location).toContain("error=email_not_verified");
    expect(res.setCookie.some((c) => c.includes("session_token"))).toBe(false);
    expect(db.account.filter((a: { providerId: string }) => a.providerId === "oidc")).toHaveLength(0);
  });

  it("links a verified token to the existing local user with the same email", async () => {
    const { auth, db } = makeAuth(env, { disableSignUp: true });
    await auth.api.signUpEmail({ body: { email: "ada@example.test", name: "Local Ada", password: "correct horse battery" } });
    const res = await signInWithOidc(auth, {});
    expect(res.location).toBe("/");
    expect(db.user).toHaveLength(1);
    expect(db.account.some((a: { providerId: string }) => a.providerId === "oidc")).toBe(true);
  });

  // F2: a client-sent requestSignUp must not override a closed sign-up.
  it("does not create a user for requestSignUp when sign-up is off", async () => {
    const { auth, db } = makeAuth({ ...env, PAPERCLIP_AUTH_OIDC_ALLOW_SIGN_UP: "false" }, { disableSignUp: false });
    const res = await signInWithOidc(auth, {}, { requestSignUp: true });
    expect(res.location).toContain("error=");
    expect(db.user).toHaveLength(0);
  });

  // F3: a refused group is a redirect to the UI, not a JSON 403.
  it("redirects a user outside the required group to the error page", async () => {
    const { auth, db } = makeAuth(env, { disableSignUp: false });
    const res = await signInWithOidc(auth, { groups: ["someone-else"] });
    expect(res.status).toBe(302);
    expect(res.location).toMatch(/^\/auth\?error=group_not_allowed/);
    expect(db.user).toHaveLength(0);
  });
});

describe("OIDC discovery probe", () => {
  it("reports an unreachable provider without throwing", async () => {
    const config = resolveOidcAuthConfig({
      PAPERCLIP_AUTH_OIDC_ISSUER: "http://127.0.0.1:1",
      PAPERCLIP_AUTH_OIDC_CLIENT_ID: "x",
      PAPERCLIP_AUTH_OIDC_CLIENT_SECRET: "y",
    } as NodeJS.ProcessEnv)!;
    await expect(probeOidcDiscovery(config)).resolves.toBe(false);
  });

  it("accepts a complete discovery document", async () => {
    const config = resolveOidcAuthConfig({
      PAPERCLIP_AUTH_OIDC_ISSUER: issuer,
      PAPERCLIP_AUTH_OIDC_CLIENT_ID: "x",
      PAPERCLIP_AUTH_OIDC_CLIENT_SECRET: "y",
    } as NodeJS.ProcessEnv)!;
    await expect(probeOidcDiscovery(config)).resolves.toBe(true);
  });
});
