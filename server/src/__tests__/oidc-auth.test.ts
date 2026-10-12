import { describe, expect, it } from "vitest";
import {
  validateOidcUserInfo,
  buildOidcProviderConfig,
  isPasswordLoginEnabled,
  resolveOidcAuthConfig,
  resolveSignInOptions,
  setOidcAvailable,
} from "../auth/oidc.js";

const baseEnv = {
  PAPERCLIP_AUTH_OIDC_ISSUER: "https://idp.example.test/realms/lab/",
  PAPERCLIP_AUTH_OIDC_CLIENT_ID: "paperclip",
  PAPERCLIP_AUTH_OIDC_CLIENT_SECRET: "s3cret",
} as NodeJS.ProcessEnv;

describe("OIDC sign-in configuration", () => {
  it("stays off unless issuer, client id and secret are all set", () => {
    expect(resolveOidcAuthConfig({})).toBeNull();
    expect(resolveOidcAuthConfig({ ...baseEnv, PAPERCLIP_AUTH_OIDC_CLIENT_SECRET: "" })).toBeNull();
    expect(resolveSignInOptions({})).toEqual({ passwordEnabled: true, oidc: null });
  });

  it("applies defaults and normalises the issuer and scopes", () => {
    const config = resolveOidcAuthConfig({ ...baseEnv, PAPERCLIP_AUTH_OIDC_SCOPES: "email,profile" });
    expect(config).toMatchObject({
      issuer: "https://idp.example.test/realms/lab",
      scopes: ["openid", "email", "profile"],
      label: "SSO",
      requiredGroup: null,
      groupsClaim: "groups",
      allowSignUp: null,
    });
  });

  it("builds a PKCE provider with ID token verification and discovery", () => {
    const provider = buildOidcProviderConfig(resolveOidcAuthConfig(baseEnv)!, { disableSignUp: true });
    expect(provider).toMatchObject({
      providerId: "oidc",
      discoveryUrl: "https://idp.example.test/realms/lab/.well-known/openid-configuration",
      pkce: true,
      requireIdTokenVerification: true,
      disableImplicitSignUp: true,
    });
  });

  it("lets the OIDC sign-up switch override the global one", () => {
    const follow = resolveOidcAuthConfig(baseEnv)!;
    expect(buildOidcProviderConfig(follow, { disableSignUp: true })).toMatchObject({ disableImplicitSignUp: true, disableSignUp: true });
    expect(buildOidcProviderConfig(follow, { disableSignUp: false }).disableImplicitSignUp).toBe(false);
    const allow = resolveOidcAuthConfig({ ...baseEnv, PAPERCLIP_AUTH_OIDC_ALLOW_SIGN_UP: "true" })!;
    expect(buildOidcProviderConfig(allow, { disableSignUp: true }).disableImplicitSignUp).toBe(false);
    const deny = resolveOidcAuthConfig({ ...baseEnv, PAPERCLIP_AUTH_OIDC_ALLOW_SIGN_UP: "false" })!;
    expect(buildOidcProviderConfig(deny, { disableSignUp: false }).disableImplicitSignUp).toBe(true);
  });

  it("only turns password login off while OIDC is configured", () => {
    expect(isPasswordLoginEnabled({ PAPERCLIP_AUTH_PASSWORD_LOGIN: "false" })).toBe(true);
    expect(isPasswordLoginEnabled({ ...baseEnv, PAPERCLIP_AUTH_PASSWORD_LOGIN: "false" })).toBe(false);
    setOidcAvailable(true);
    expect(resolveSignInOptions({ ...baseEnv, PAPERCLIP_AUTH_OIDC_LABEL: "Keycloak" })).toEqual({
      passwordEnabled: true,
      oidc: { providerId: "oidc", label: "Keycloak" },
    });
  });
});

function oauthInput(profile: Record<string, unknown>, action = "sign-in") {
  return {
    user: { email: "a@example.test" },
    source: { action, method: "oauth", oauth: { providerId: "oidc", profile } },
  };
}

describe("OIDC user validation", () => {
  const open = resolveOidcAuthConfig(baseEnv)!;
  const grouped = resolveOidcAuthConfig({
    ...baseEnv,
    PAPERCLIP_AUTH_OIDC_REQUIRED_GROUP: "/paperclip-users",
  })!;

  it("ignores other sign-in methods and providers", () => {
    expect(validateOidcUserInfo({ user: {}, source: { method: "email-password" } }, grouped)).toBeUndefined();
    expect(
      validateOidcUserInfo({ user: {}, source: { method: "oauth", oauth: { providerId: "other" } } }, grouped),
    ).toBeUndefined();
  });

  it("accepts only a boolean true email_verified claim", () => {
    expect(validateOidcUserInfo(oauthInput({ email_verified: true }), open)).toBeUndefined();
    for (const bad of [undefined, false, "false", "true", 1]) {
      expect(validateOidcUserInfo(oauthInput({ email_verified: bad }), open)?.error).toBe("email_not_verified");
    }
  });

  it("accepts a missing email_verified claim only when PAPERCLIP_AUTH_OIDC_TRUST_EMAIL is true", () => {
    const trusting = resolveOidcAuthConfig({ ...baseEnv, PAPERCLIP_AUTH_OIDC_TRUST_EMAIL: "true" })!;
    expect(validateOidcUserInfo(oauthInput({}), trusting)).toBeUndefined();
    expect(buildOidcProviderConfig(trusting).mapProfileToUser?.({})).toEqual({ emailVerified: true });
    for (const bad of [false, "false", 0]) {
      expect(validateOidcUserInfo(oauthInput({ email_verified: bad }), trusting)?.error).toBe("email_not_verified");
    }
  });

  it("accepts a matching group with or without the Keycloak leading slash", () => {
    expect(validateOidcUserInfo(oauthInput({ email_verified: true, groups: ["/paperclip-users"] }), grouped)).toBeUndefined();
    expect(validateOidcUserInfo(oauthInput({ email_verified: true, groups: ["paperclip-users", "x"] }), grouped)).toBeUndefined();
  });

  it("refuses a missing, empty or different groups claim", () => {
    for (const groups of [undefined, [], ["/someone-else"], "paperclip-users-extra"]) {
      expect(validateOidcUserInfo(oauthInput({ email_verified: true, groups }), grouped)?.error).toBe("group_not_allowed");
    }
  });

  it("reads a nested claim path such as realm_access.roles", () => {
    const roleConfig = resolveOidcAuthConfig({
      ...baseEnv,
      PAPERCLIP_AUTH_OIDC_REQUIRED_GROUP: "paperclip",
      PAPERCLIP_AUTH_OIDC_GROUPS_CLAIM: "realm_access.roles",
    })!;
    expect(validateOidcUserInfo(oauthInput({ email_verified: true, realm_access: { roles: ["paperclip"] } }), roleConfig)).toBeUndefined();
    expect(validateOidcUserInfo(oauthInput({ email_verified: true, realm_access: { roles: ["x"] } }), roleConfig)?.error).toBe("group_not_allowed");
  });
});
