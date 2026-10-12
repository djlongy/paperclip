import { genericOAuth, type GenericOAuthConfig } from "better-auth/plugins";
import { logger } from "../middleware/logger.js";

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

// False until the provider's discovery document has been fetched once, so the
// login page never offers a button that cannot work (see probeOidcDiscovery).
let oidcAvailable = false;

export function setOidcAvailable(value: boolean): void {
  oidcAvailable = value;
}

export function resolveSignInOptions(env: NodeJS.ProcessEnv = process.env): SignInOptions {
  const oidc = resolveOidcAuthConfig(env);
  return {
    passwordEnabled: isPasswordLoginEnabled(env),
    oidc: oidc && oidcAvailable ? { providerId: OIDC_PROVIDER_ID, label: oidc.label } : null,
  };
}

/**
 * Fetch the discovery document the way the plugin will. The plugin throws from
 * its async init when this fails, and that rejection would take the whole
 * server down, so the plugin is only registered after this has succeeded.
 */
export async function probeOidcDiscovery(
  config: OidcAuthConfig,
  fetchImpl: typeof fetch = fetch,
): Promise<boolean> {
  try {
    const res = await fetchImpl(`${config.issuer}/.well-known/openid-configuration`, {
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return false;
    const doc = (await res.json()) as Record<string, unknown>;
    return ["issuer", "jwks_uri", "authorization_endpoint", "token_endpoint"].every(
      (key) => typeof doc[key] === "string" && doc[key] !== "",
    );
  } catch (err) {
    logger.warn({ err, issuer: config.issuer }, "OIDC discovery failed; single sign-on stays off until it succeeds");
    return false;
  }
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

export type OidcAuditEvent = "auth.oidc.denied" | "auth.oidc.linked" | "auth.oidc.created" | "auth.oidc.sign_in";

function audit(event: OidcAuditEvent, fields: Record<string, unknown>): void {
  // Sign-in happens before any company context exists, so these go to the
  // structured server log rather than the per-company activity log.
  logger.info({ audit: true, event, providerId: OIDC_PROVIDER_ID, ...fields }, event);
}

type ValidateInput = {
  user: Partial<{ id: string; email: string }> & Record<string, unknown>;
  source: { action?: string; method?: string; oauth?: { providerId?: string; profile?: Record<string, unknown> } };
};

/**
 * Gate for `user.validateUserInfo`. Only OIDC sign-ins are judged. Returning an
 * error makes Better Auth redirect to the UI with `?error=<code>`.
 * The raw `email_verified` claim must be the boolean true: a missing claim or
 * the string "false" must not reach account linking.
 */
export function validateOidcUserInfo(
  data: ValidateInput,
  config: OidcAuthConfig,
): { error: string; errorDescription: string } | undefined {
  const { source } = data;
  if (source.method !== "oauth" || source.oauth?.providerId !== OIDC_PROVIDER_ID) return undefined;
  const profile = source.oauth.profile ?? {};
  const email = typeof data.user.email === "string" ? data.user.email : undefined;
  const deny = (error: string, errorDescription: string) => {
    audit("auth.oidc.denied", { reason: error, email });
    return { error, errorDescription };
  };
  if (profile.email_verified !== true) {
    return deny("email_not_verified", "The identity provider has not verified your email address");
  }
  if (config.requiredGroup && !claimValues(profile, config.groupsClaim).includes(config.requiredGroup)) {
    return deny("group_not_allowed", "Your account is not allowed to sign in to this instance");
  }
  const action = source.action === "link-account" ? "linked" : source.action === "create-user" ? "created" : "sign_in";
  audit(`auth.oidc.${action}`, { email, userId: data.user.id });
  return undefined;
}

export function buildOidcProviderConfig(
  config: OidcAuthConfig,
  opts: { disableSignUp?: boolean } = {},
): GenericOAuthConfig {
  const signUpOff = !(config.allowSignUp ?? !opts.disableSignUp);
  return {
    providerId: OIDC_PROVIDER_ID,
    discoveryUrl: `${config.issuer}/.well-known/openid-configuration`,
    clientId: config.clientId,
    clientSecret: config.clientSecret,
    scopes: config.scopes,
    pkce: true,
    // With sign-up off, only existing users (matched by email) can sign in.
    // disableSignUp, unlike disableImplicitSignUp, ignores a client-sent requestSignUp.
    disableSignUp: signUpOff,
    disableImplicitSignUp: signUpOff,
    // Reject a login whose ID token fails signature, issuer, audience or nonce checks.
    requireIdTokenVerification: true,
    // Strictly boolean, so linking never sees a truthy string; validateOidcUserInfo refuses anything else.
    mapProfileToUser: (profile) => ({ emailVerified: profile.email_verified === true }),
  };
}

export function buildOidcPlugin(config: OidcAuthConfig, opts: { disableSignUp?: boolean } = {}) {
  return genericOAuth({ config: [buildOidcProviderConfig(config, opts)] });
}

/** The `user.validateUserInfo` hook for createBetterAuthInstance. */
export function buildOidcUserValidator(config: OidcAuthConfig) {
  return (data: ValidateInput) => validateOidcUserInfo(data, config);
}

/**
 * Everything the OIDC sign-in adds to the Better Auth options. The provider is
 * the operator's choice, so its email (checked by validateOidcUserInfo) links
 * to the existing account with the same address. Local accounts are never
 * email-verified, and while self-service sign-up is open anyone could have
 * registered the address first, so the local-verification check only relaxes
 * once sign-up is closed.
 */
export function buildOidcAuthOptions(config: OidcAuthConfig, opts: { disableSignUp: boolean }) {
  return {
    plugins: [buildOidcPlugin(config, opts)],
    user: { validateUserInfo: buildOidcUserValidator(config) },
    account: {
      accountLinking: {
        enabled: true,
        trustedProviders: [OIDC_PROVIDER_ID],
        requireLocalEmailVerified: !opts.disableSignUp,
      },
    },
  };
}
