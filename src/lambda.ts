// Lambda entry point: wires the handler to SSM, Gmail and WorkOS AuthKit.

import { createAuthenticator } from "./auth.ts";
import { GmailClient } from "./google.ts";
import { createHandler } from "./handler.ts";
import { createSsmStore } from "./store.ts";

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set`);
  return value;
}

const list = (value: string | undefined) =>
  (value ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);

const issuer = required("AUTHKIT_DOMAIN");

// One client per execution environment, so the access token survives warm invokes.
const gmail = new GmailClient({
  store: createSsmStore(process.env.PARAMETER_PREFIX ?? "/gmail-spam-mcp"),
  allowedEmail: required("ALLOWED_GOOGLE_EMAIL"),
});

export const handler = createHandler({
  gmail,
  issuer,
  authenticate: createAuthenticator({
    issuer,
    allowedSubjects: list(process.env.ALLOWED_SUBJECTS),
    extraAudiences: list(process.env.EXTRA_AUDIENCES),
  }),
  originSecret: process.env.ORIGIN_SECRET || undefined,
});
