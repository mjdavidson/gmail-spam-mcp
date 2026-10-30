// Google OAuth and the Gmail API calls this server needs.
//
// The Google grant (client id, client secret and refresh token) is made once by
// scripts/connect-google.ts and stored as an encrypted SSM parameter. Here it
// is exchanged for short-lived access tokens, which live only in memory.
// Nothing in this file logs a token.

import type { GmailPart } from "./mime.ts";

export const GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.modify";
export const TOKEN_URL = "https://oauth2.googleapis.com/token";
export const AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const GMAIL_API = "https://gmail.googleapis.com/gmail/v1/users/me";
const TIMEOUT_MS = 10_000;

export interface GoogleGrant {
  clientId: string;
  clientSecret: string;
  refreshToken: string;
  /** The Google account the grant belongs to, as reported by Google at sign-in. */
  email: string;
}

export interface GrantStore {
  load(): Promise<GoogleGrant | null>;
  save(grant: GoogleGrant): Promise<void>;
}

/** The Google account needs to be connected again. */
export class ReconnectError extends Error {
  constructor(reason: string) {
    super(`${reason} Run \`npm run connect-google\` to sign in to Google again.`);
    this.name = "ReconnectError";
  }
}

export class GmailApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "GmailApiError";
    this.status = status;
  }
}

export const sameEmail = (a: string, b: string) => a.trim().toLowerCase() === b.trim().toLowerCase();

/** Gmail message ids are short hex strings; this also keeps them out of URL paths they do not belong in. */
export const MESSAGE_ID = /^[A-Za-z0-9_-]{1,64}$/;

export interface GmailMessage {
  id: string;
  threadId: string;
  labelIds?: string[];
  snippet?: string;
  internalDate?: string;
  sizeEstimate?: number;
  payload?: GmailPart;
}

export interface MessageList {
  messages?: { id: string; threadId: string }[];
  nextPageToken?: string;
  resultSizeEstimate?: number;
}

export interface GmailClientOptions {
  store: GrantStore;
  /** The only Google account this server will act on. */
  allowedEmail: string;
  fetch?: typeof fetch;
  now?: () => number;
}

export class GmailClient {
  private readonly store: GrantStore;
  private readonly allowedEmail: string;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => number;
  private grant: GoogleGrant | null = null;
  private accessToken: string | null = null;
  private expiresAt = 0;
  private accountChecked = false;

  constructor(options: GmailClientOptions) {
    if (!options.allowedEmail.includes("@")) throw new Error("ALLOWED_GOOGLE_EMAIL must be an email address");
    this.store = options.store;
    this.allowedEmail = options.allowedEmail;
    this.fetchImpl = options.fetch ?? fetch;
    this.now = options.now ?? Date.now;
  }

  private async loadGrant(): Promise<GoogleGrant> {
    if (this.grant) return this.grant;
    const grant = await this.store.load();
    if (!grant) throw new ReconnectError("No Google account is connected.");
    if (!sameEmail(grant.email, this.allowedEmail)) {
      throw new ReconnectError(`The stored Google grant is for ${grant.email}, not the allowed account.`);
    }
    this.grant = grant;
    return grant;
  }

  private async refresh(reloaded = false): Promise<string> {
    const cached = this.grant !== null;
    const grant = await this.loadGrant();
    let res: Response;
    try {
      res = await this.fetchImpl(TOKEN_URL, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: grant.refreshToken,
          client_id: grant.clientId,
          client_secret: grant.clientSecret,
        }),
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch {
      throw new GmailApiError(504, "Google's token endpoint did not respond in time");
    }
    const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (!res.ok || typeof body.access_token !== "string") {
      if (body.error === "invalid_grant") {
        // Forget the dead grant. If it came from memory, the account may have
        // been reconnected since, so read the stored one and try once more.
        this.grant = null;
        if (cached && !reloaded) return this.refresh(true);
        throw new ReconnectError(
          "Google rejected the stored refresh token: it has expired or been revoked. " +
            "Apps in testing mode get refresh tokens that expire after 7 days.",
        );
      }
      if (body.error === "invalid_client" || body.error === "unauthorized_client") {
        throw new ReconnectError("Google rejected the OAuth client id or secret.");
      }
      throw new GmailApiError(res.status, `Google token refresh failed (HTTP ${res.status}${body.error ? `, ${String(body.error)}` : ""})`);
    }
    if (typeof body.scope === "string" && !body.scope.split(" ").includes(GMAIL_SCOPE)) {
      throw new ReconnectError("The Google grant does not include the gmail.modify scope.");
    }
    // Google rarely rotates refresh tokens, but keep the new one if it does.
    if (typeof body.refresh_token === "string" && body.refresh_token !== grant.refreshToken) {
      this.grant = { ...grant, refreshToken: body.refresh_token };
      await this.store.save(this.grant);
    }
    this.accessToken = body.access_token;
    const lifetime = typeof body.expires_in === "number" ? body.expires_in : 3600;
    // Refresh a minute early so a token never expires mid-request.
    this.expiresAt = this.now() + (lifetime - 60) * 1000;
    return this.accessToken;
  }

  private async token(force = false): Promise<string> {
    if (!force && this.accessToken && this.now() < this.expiresAt) return this.accessToken;
    return this.refresh();
  }

  private async request<T>(path: string, init: { method?: string; body?: unknown } = {}, retried = false): Promise<T> {
    const token = await this.token(retried);
    let res: Response;
    try {
      res = await this.fetchImpl(`${GMAIL_API}${path}`, {
        method: init.method ?? "GET",
        headers: {
          authorization: `Bearer ${token}`,
          ...(init.body === undefined ? {} : { "content-type": "application/json" }),
        },
        body: init.body === undefined ? undefined : JSON.stringify(init.body),
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch {
      throw new GmailApiError(504, "Gmail did not respond in time");
    }
    // An access token can be revoked before it expires: refresh once and retry.
    if (res.status === 401 && !retried) return this.request(path, init, true);
    const body = (await res.json().catch(() => null)) as any;
    if (!res.ok) {
      const message = typeof body?.error?.message === "string" ? body.error.message : res.statusText;
      if (res.status === 404) throw new GmailApiError(404, "No message with that id");
      throw new GmailApiError(res.status, `Gmail API error (HTTP ${res.status}): ${message}`);
    }
    return body as T;
  }

  /**
   * Confirms, once per execution environment, that the token really belongs to
   * the allowed account, in case the stored email and the grant ever disagree.
   */
  private async checkAccount(): Promise<void> {
    if (this.accountChecked) return;
    const profile = await this.request<{ emailAddress?: string }>("/profile");
    if (!profile.emailAddress || !sameEmail(profile.emailAddress, this.allowedEmail)) {
      this.grant = null;
      this.accessToken = null;
      throw new ReconnectError(`The connected Google account (${profile.emailAddress ?? "unknown"}) is not the allowed account.`);
    }
    this.accountChecked = true;
  }

  async listMessages(q: string, maxResults: number, pageToken?: string): Promise<MessageList> {
    await this.checkAccount();
    const params = new URLSearchParams({ q, maxResults: String(maxResults), includeSpamTrash: "true" });
    if (pageToken) params.set("pageToken", pageToken);
    return this.request<MessageList>(`/messages?${params}`);
  }

  async getMessage(id: string, format: "full" | "metadata", metadataHeaders: string[] = []): Promise<GmailMessage> {
    if (!MESSAGE_ID.test(id)) throw new GmailApiError(400, "That is not a Gmail message id");
    await this.checkAccount();
    const params = new URLSearchParams({ format });
    for (const name of metadataHeaders) params.append("metadataHeaders", name);
    return this.request<GmailMessage>(`/messages/${id}?${params}`);
  }

  async modifyLabels(id: string, addLabelIds: string[], removeLabelIds: string[]): Promise<GmailMessage> {
    if (!MESSAGE_ID.test(id)) throw new GmailApiError(400, "That is not a Gmail message id");
    await this.checkAccount();
    return this.request<GmailMessage>(`/messages/${id}/modify`, { method: "POST", body: { addLabelIds, removeLabelIds } });
  }
}
