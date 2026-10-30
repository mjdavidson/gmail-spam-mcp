// OAuth resource-server checks. WorkOS AuthKit is the authorization server:
// Claude sends the user through AuthKit's login and presents the resulting
// access token here as a bearer JWT.

import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from "jose";

export interface AuthConfig {
  /** AuthKit domain, such as https://example-123.authkit.app */
  issuer: string;
  /** WorkOS user ids allowed to use the server. Empty means nobody. */
  allowedSubjects: string[];
  /** Extra accepted `aud` values besides this server's own URL. */
  extraAudiences?: string[];
  /** Key source override, for tests. */
  keys?: JWTVerifyGetKey;
}

export class AuthError extends Error {
  readonly status: 401 | 403;

  constructor(status: 401 | 403, message: string) {
    super(message);
    this.name = "AuthError";
    this.status = status;
  }
}

export function normalizeIssuer(issuer: string): string {
  const trimmed = issuer.trim().replace(/\/+$/, "");
  return /^https?:\/\//.test(trimmed) ? trimmed : `https://${trimmed}`;
}

export function createAuthenticator(config: AuthConfig) {
  const issuer = normalizeIssuer(config.issuer);
  const keys = config.keys ?? createRemoteJWKSet(new URL(`${issuer}/oauth2/jwks`));
  const allowed = new Set(config.allowedSubjects);

  /** Verify a bearer token and return the WorkOS user id it belongs to. */
  return async function authenticate(authorization: string | undefined, origin: string): Promise<string> {
    const token = /^Bearer\s+(.+)$/i.exec(authorization ?? "")?.[1];
    if (!token) throw new AuthError(401, "Authorization needed");

    let subject: string | undefined;
    try {
      const { payload } = await jwtVerify(token, keys, {
        issuer,
        // Clients name the resource with or without the /mcp path.
        audience: [`${origin}/mcp`, origin, `${origin}/`, ...(config.extraAudiences ?? [])],
      });
      subject = payload.sub;
    } catch (error) {
      const reason = error instanceof Error ? error.message : "verification failed";
      throw new AuthError(401, `Invalid access token: ${reason}`);
    }

    if (!subject || !allowed.has(subject)) {
      // The id is logged so the owner can find their own on first sign-in.
      console.warn(`Rejected sign-in from WorkOS user ${subject}: not in ALLOWED_SUBJECTS`);
      throw new AuthError(403, `WorkOS user ${subject} is not allowed to use this server`);
    }
    return subject;
  };
}
