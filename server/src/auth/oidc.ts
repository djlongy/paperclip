import { genericOAuth, type GenericOAuthConfig, type GenericOAuthUserInfo } from "better-auth/plugins";
import { APIError } from "better-auth/api";

/**
 * Optional OpenID Connect sign-in, configured only by environment variables.
 * Unset (the default) leaves Paperclip's email/password-only behaviour unchanged.
 *
 *   PAPERCLIP_AUTH_OIDC_ISSUER          issuer URL; discovery is read from
 *                                       `<issuer>/.well-known/openid-configuration`
 *   PAPERCLIP_AUTH_OIDC_CLIENT_ID
 *   PAPERCLIP_AUTH_OIDC_CLIENT_SECRET
 *   PAPERCLIP_AUTH_OIDC_SCOPES          space or comma separated, default `openid email profile`
 *   PAPERCLIP_AUTH_OIDC_LABEL           button label, default `SSO`
 *   PAPERCLIP_AUTH_OIDC_REQUIRED_GROUP  optional; sign-in needs this value in the groups claim
 *   PAPERCLIP_AUTH_OIDC_GROUPS_CLAIM    claim holding groups or roles, default `groups`
 *                                       (dotted path allowed, e.g. `realm_access.roles`)
 *   PAPERCLIP_AUTH_OIDC_ALLOW_SIGN_UP   `true`/`false` lets a first OIDC sign-in create a user; default
 *                                       follows PAPERCLIP_AUTH_DISABLE_SIGN_UP. A new user has no
 *                                       company access until invited.
 *   PAPERCLIP_AUTH_PASSWORD_LOGIN       `false` turns email/password sign-in off
 */
export const OIDC_PROVIDER_ID = "oidc";

export type OidcAuthConfig = {
  issuer: string;
  clientId: string;
  clientSecret: string;
  scopes: string[];
  label: string;
  requiredGroup: string | null;
  groupsClaim: string;
  allowSignUp: boolean | null;
};

export type SignInOptions = {
  passwordEnabled: boolean;
  oidc: { providerId: string; label: string } | null;
};

export function resolveOidcAuthConfig(env: NodeJS.ProcessEnv = process.env): OidcAuthConfig | null {
  const issuer = env.PAPERCLIP_AUTH_OIDC_ISSUER?.trim().replace(/\/+$/, "");
  const clientId = env.PAPERCLIP_AUTH_OIDC_CLIENT_ID?.trim();
  const clientSecret = env.PAPERCLIP_AUTH_OIDC_CLIENT_SECRET?.trim();
  if (!issuer || !clientId || !clientSecret) return null;
  const scopes = (env.PAPERCLIP_AUTH_OIDC_SCOPES ?? "openid email profile")
    .split(/[\s,]+/)
    .filter(Boolean);
  return {
    issuer,
    clientId,
    clientSecret,
    scopes: scopes.includes("openid") ? scopes : ["openid", ...scopes],
    label: env.PAPERCLIP_AUTH_OIDC_LABEL?.trim() || "SSO",
    requiredGroup: env.PAPERCLIP_AUTH_OIDC_REQUIRED_GROUP?.trim().replace(/^\//, "") || null,
    groupsClaim: env.PAPERCLIP_AUTH_OIDC_GROUPS_CLAIM?.trim() || "groups",
    allowSignUp: env.PAPERCLIP_AUTH_OIDC_ALLOW_SIGN_UP === undefined
      ? null
      : env.PAPERCLIP_AUTH_OIDC_ALLOW_SIGN_UP.trim().toLowerCase() === "true",
  };
}

export function isPasswordLoginEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  // Never lock everyone out: password sign-in can only be turned off while OIDC is configured.
  return resolveOidcAuthConfig(env) === null || env.PAPERCLIP_AUTH_PASSWORD_LOGIN?.trim().toLowerCase() !== "false";
}

export function resolveSignInOptions(env: NodeJS.ProcessEnv = process.env): SignInOptions {
  const oidc = resolveOidcAuthConfig(env);
  return {
    passwordEnabled: isPasswordLoginEnabled(env),
    oidc: oidc ? { providerId: OIDC_PROVIDER_ID, label: oidc.label } : null,
  };
}

function claimValues(profile: Record<string, unknown>, path: string): string[] {
  const value = path.split(".").reduce<unknown>(
    (node, key) => (node && typeof node === "object" ? (node as Record<string, unknown>)[key] : undefined),
    profile,
  );
  const list = Array.isArray(value) ? value : typeof value === "string" ? [value] : [];
  // Keycloak group claims carry full paths ("/team"); match with or without the leading slash.
  return list.filter((item): item is string => typeof item === "string").map((item) => item.replace(/^\//, ""));
}

export function assertOidcGroupAllowed(profile: GenericOAuthUserInfo, config: OidcAuthConfig): void {
  // The email is what maps the sign-in to an account, so an address the provider flags as unverified is refused.
  if (profile.emailVerified === false) {
    throw new APIError("FORBIDDEN", { message: "The email address on your account is not verified" });
  }
  if (!config.requiredGroup) return;
  if (claimValues(profile, config.groupsClaim).includes(config.requiredGroup)) return;
  throw new APIError("FORBIDDEN", { message: "Your account is not allowed to sign in to this instance" });
}

export function buildOidcProviderConfig(
  config: OidcAuthConfig,
  opts: { disableSignUp?: boolean } = {},
): GenericOAuthConfig {
  return {
    providerId: OIDC_PROVIDER_ID,
    discoveryUrl: `${config.issuer}/.well-known/openid-configuration`,
    clientId: config.clientId,
    clientSecret: config.clientSecret,
    scopes: config.scopes,
    pkce: true,
    // With sign-up off, only existing users (matched by email) can sign in.
    disableImplicitSignUp: !(config.allowSignUp ?? !opts.disableSignUp),
    // Reject a login whose ID token fails signature, issuer, audience or nonce checks.
    requireIdTokenVerification: true,
    mapProfileToUser: (profile) => {
      assertOidcGroupAllowed(profile, config);
      return {};
    },
  };
}

export function buildOidcPlugin(config: OidcAuthConfig, opts: { disableSignUp?: boolean } = {}) {
  return genericOAuth({ config: [buildOidcProviderConfig(config, opts)] });
}
