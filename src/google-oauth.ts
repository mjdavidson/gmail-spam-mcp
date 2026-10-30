// The one-time Google sign-in used by scripts/connect-google.ts: building the
// consent URL, exchanging the code, and checking that the grant is for the
// allowed account with the right scope before anything is stored.

import { AUTH_URL, GMAIL_SCOPE, sameEmail, TOKEN_URL } from "./google.ts";

export const SCOPES = ["openid", "email", GMAIL_SCOPE];

export interface AuthUrlOptions {
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
  loginHint?: string;
}

export function buildAuthUrl(options: AuthUrlOptions): string {
  const params = new URLSearchParams({
    client_id: options.clientId,
    redirect_uri: options.redirectUri,
    response_type: "code",
    scope: SCOPES.join(" "),
    // Offline access is what returns a refresh token, and prompt=consent makes
    // Google issue a new one even if this client was approved before.
    access_type: "offline",
    prompt: "consent",
    include_granted_scopes: "false",
    state: options.state,
    code_challenge: options.codeChallenge,
    code_challenge_method: "S256",
  });
  if (options.loginHint) params.set("login_hint", options.loginHint);
  return `${AUTH_URL}?${params}`;
}

export interface TokenResponse {
  access_token?: string;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
  error?: string;
  error_description?: string;
}

export async function exchangeCode(
  fetchImpl: typeof fetch,
  options: { clientId: string; clientSecret: string; code: string; redirectUri: string; codeVerifier: string },
): Promise<TokenResponse> {
  const res = await fetchImpl(TOKEN_URL, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: options.code,
      redirect_uri: options.redirectUri,
      client_id: options.clientId,
      client_secret: options.clientSecret,
      code_verifier: options.codeVerifier,
    }),
    signal: AbortSignal.timeout(15_000),
  });
  const body = (await res.json().catch(() => ({}))) as TokenResponse;
  if (!res.ok) throw new Error(`Google refused the code: ${body.error ?? res.status}${body.error_description ? ` (${body.error_description})` : ""}`);
  return body;
}

/** The claims of a JWT, without verifying its signature. */
export function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const part = jwt.split(".")[1];
  if (!part) throw new Error("Google returned a malformed ID token");
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
}

/**
 * Checks a token response before it is stored, and returns the account's
 * email. The ID token came straight from Google's token endpoint over TLS, so
 * its claims can be read without checking the signature (OpenID Connect Core
 * 3.1.3.7).
 */
export function checkGrant(tokens: TokenResponse, options: { clientId: string; allowedEmail: string }): string {
  if (!tokens.id_token) throw new Error("Google returned no ID token, so the account cannot be identified");
  const claims = decodeJwtPayload(tokens.id_token);
  if (claims.iss !== "https://accounts.google.com" && claims.iss !== "accounts.google.com") {
    throw new Error("The ID token was not issued by Google");
  }
  if (claims.aud !== options.clientId) throw new Error("The ID token was issued to a different OAuth client");
  const email = typeof claims.email === "string" ? claims.email : "";
  if (!email || claims.email_verified !== true) throw new Error("Google did not return a verified email for the account");
  if (!sameEmail(email, options.allowedEmail)) {
    throw new Error(`Signed in as ${email}, but only ${options.allowedEmail} (ALLOWED_GOOGLE_EMAIL) is allowed`);
  }
  if (!tokens.scope?.split(" ").includes(GMAIL_SCOPE)) {
    throw new Error("The gmail.modify permission was not granted: tick the Gmail box on Google's consent screen");
  }
  if (!tokens.refresh_token) throw new Error("Google returned no refresh token");
  return email;
}
