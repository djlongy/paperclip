import { describe, expect, it } from "vitest";
import {
  assertOidcGroupAllowed,
  buildOidcProviderConfig,
  isPasswordLoginEnabled,
  resolveOidcAuthConfig,
  resolveSignInOptions,
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
    expect(buildOidcProviderConfig(follow, { disableSignUp: true }).disableImplicitSignUp).toBe(true);
    expect(buildOidcProviderConfig(follow, { disableSignUp: false }).disableImplicitSignUp).toBe(false);
    const allow = resolveOidcAuthConfig({ ...baseEnv, PAPERCLIP_AUTH_OIDC_ALLOW_SIGN_UP: "true" })!;
    expect(buildOidcProviderConfig(allow, { disableSignUp: true }).disableImplicitSignUp).toBe(false);
    const deny = resolveOidcAuthConfig({ ...baseEnv, PAPERCLIP_AUTH_OIDC_ALLOW_SIGN_UP: "false" })!;
    expect(buildOidcProviderConfig(deny, { disableSignUp: false }).disableImplicitSignUp).toBe(true);
  });

  it("only turns password login off while OIDC is configured", () => {
    expect(isPasswordLoginEnabled({ PAPERCLIP_AUTH_PASSWORD_LOGIN: "false" })).toBe(true);
    expect(isPasswordLoginEnabled({ ...baseEnv, PAPERCLIP_AUTH_PASSWORD_LOGIN: "false" })).toBe(false);
    expect(resolveSignInOptions({ ...baseEnv, PAPERCLIP_AUTH_OIDC_LABEL: "Keycloak" })).toEqual({
      passwordEnabled: true,
      oidc: { providerId: "oidc", label: "Keycloak" },
    });
  });
});

describe("OIDC required group", () => {
  const config = resolveOidcAuthConfig({
    ...baseEnv,
    PAPERCLIP_AUTH_OIDC_REQUIRED_GROUP: "/paperclip-users",
  })!;

  it("allows everyone when no group is required", () => {
    expect(() => assertOidcGroupAllowed({ email: "a@example.test" }, resolveOidcAuthConfig(baseEnv)!)).not.toThrow();
  });

  it("refuses an email the provider reports as unverified", () => {
    const open = resolveOidcAuthConfig(baseEnv)!;
    expect(() => assertOidcGroupAllowed({ email: "a@example.test", emailVerified: false }, open)).toThrow();
    expect(() => assertOidcGroupAllowed({ email: "a@example.test", emailVerified: true }, open)).not.toThrow();
    expect(() => assertOidcGroupAllowed({ email: "a@example.test" }, open)).not.toThrow();
  });

  it("accepts a matching group with or without the Keycloak leading slash", () => {
    expect(() => assertOidcGroupAllowed({ groups: ["/paperclip-users"] }, config)).not.toThrow();
    expect(() => assertOidcGroupAllowed({ groups: ["paperclip-users", "other"] }, config)).not.toThrow();
  });

  it("refuses a missing, empty or different groups claim", () => {
    expect(() => assertOidcGroupAllowed({}, config)).toThrow();
    expect(() => assertOidcGroupAllowed({ groups: [] }, config)).toThrow();
    expect(() => assertOidcGroupAllowed({ groups: ["/someone-else"] }, config)).toThrow();
    expect(() => assertOidcGroupAllowed({ groups: "paperclip-users-extra" }, config)).toThrow();
  });

  it("reads a nested claim path such as realm_access.roles", () => {
    const roleConfig = resolveOidcAuthConfig({
      ...baseEnv,
      PAPERCLIP_AUTH_OIDC_REQUIRED_GROUP: "paperclip",
      PAPERCLIP_AUTH_OIDC_GROUPS_CLAIM: "realm_access.roles",
    })!;
    expect(() => assertOidcGroupAllowed({ realm_access: { roles: ["paperclip"] } }, roleConfig)).not.toThrow();
    expect(() => assertOidcGroupAllowed({ realm_access: { roles: ["x"] } }, roleConfig)).toThrow();
  });
});
