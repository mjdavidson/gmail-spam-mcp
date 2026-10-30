import { describe, expect, test } from "vitest";
import { buildAuthUrl, checkGrant, type TokenResponse } from "../src/google-oauth.ts";
import { GMAIL_SCOPE } from "../src/google.ts";

const CLIENT_ID = "123-abc.apps.googleusercontent.com";
const ALLOWED = "owner@example.com";

const idToken = (claims: Record<string, unknown>) =>
  ["e30", Buffer.from(JSON.stringify(claims)).toString("base64url"), "sig"].join(".");

const tokens = (claims: Record<string, unknown> = {}, extra: Partial<TokenResponse> = {}): TokenResponse => ({
  access_token: "a",
  refresh_token: "r",
  scope: `openid ${GMAIL_SCOPE} https://www.googleapis.com/auth/userinfo.email`,
  id_token: idToken({ iss: "https://accounts.google.com", aud: CLIENT_ID, email: ALLOWED, email_verified: true, ...claims }),
  ...extra,
});

describe("buildAuthUrl", () => {
  test("asks for offline access to gmail.modify with PKCE and a fresh consent", () => {
    const url = new URL(
      buildAuthUrl({ clientId: CLIENT_ID, redirectUri: "http://127.0.0.1:5555/callback", state: "s", codeChallenge: "c", loginHint: ALLOWED }),
    );
    expect(url.origin + url.pathname).toBe("https://accounts.google.com/o/oauth2/v2/auth");
    expect(url.searchParams.get("scope")).toBe(`openid email ${GMAIL_SCOPE}`);
    expect(url.searchParams.get("access_type")).toBe("offline");
    expect(url.searchParams.get("prompt")).toBe("consent");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("login_hint")).toBe(ALLOWED);
  });
});

describe("checkGrant", () => {
  test("accepts the allowed account, ignoring case", () => {
    expect(checkGrant(tokens({ email: "Owner@Example.com" }), { clientId: CLIENT_ID, allowedEmail: ALLOWED })).toBe("Owner@Example.com");
  });

  test("refuses any other Google account", () => {
    expect(() => checkGrant(tokens({ email: "other@example.com" }), { clientId: CLIENT_ID, allowedEmail: ALLOWED })).toThrow(
      /only owner@example.com/,
    );
  });

  test("refuses an unverified email, a foreign client or a foreign issuer", () => {
    const opts = { clientId: CLIENT_ID, allowedEmail: ALLOWED };
    expect(() => checkGrant(tokens({ email_verified: false }), opts)).toThrow(/verified/);
    expect(() => checkGrant(tokens({ aud: "other.apps.googleusercontent.com" }), opts)).toThrow(/different OAuth client/);
    expect(() => checkGrant(tokens({ iss: "https://evil.test" }), opts)).toThrow(/not issued by Google/);
  });

  test("refuses a grant without gmail.modify or without a refresh token", () => {
    const opts = { clientId: CLIENT_ID, allowedEmail: ALLOWED };
    expect(() => checkGrant(tokens({}, { scope: "openid email" }), opts)).toThrow(/gmail.modify/);
    expect(() => checkGrant(tokens({}, { refresh_token: undefined }), opts)).toThrow(/no refresh token/);
  });
});
