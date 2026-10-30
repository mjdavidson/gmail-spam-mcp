// Connects the Google account: runs Google's OAuth consent in your browser,
// checks that the account is ALLOWED_GOOGLE_EMAIL, and stores the client id,
// client secret and refresh token as one encrypted SSM SecureString.
//
//   npm run connect-google             # store in SSM for the Lambda
//   npm run connect-google -- --local  # write .google-token.json for npm run dev
//
// Run it again whenever Google stops accepting the refresh token (weekly while
// the OAuth app is in testing mode). Nothing secret is printed or logged.

import { createHash, randomBytes } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { createInterface } from "node:readline/promises";
import { GetParameterCommand, PutParameterCommand, SSMClient } from "@aws-sdk/client-ssm";
import { buildAuthUrl, checkGrant, exchangeCode } from "../src/google-oauth.ts";
import type { GoogleGrant } from "../src/google.ts";
import { GRANT_PARAMETER, parseGrant } from "../src/store.ts";

try {
  process.loadEnvFile(new URL("../.env", import.meta.url));
} catch {
  // No .env: settings come from the environment.
}

const LOCAL = process.argv.includes("--local");
const LOCAL_FILE = new URL("../.google-token.json", import.meta.url);
const PARAMETER = `${process.env.PARAMETER_PREFIX ?? "/gmail-spam-mcp"}/${GRANT_PARAMETER}`;
const allowedEmail = process.env.ALLOWED_GOOGLE_EMAIL;
if (!allowedEmail) {
  console.error("Set ALLOWED_GOOGLE_EMAIL in .env first (see .env.example).");
  process.exit(1);
}

const ssm = new SSMClient({});

async function existingGrant(): Promise<GoogleGrant | null> {
  try {
    if (LOCAL) return parseGrant(await readFile(LOCAL_FILE, "utf8"));
    const out = await ssm.send(new GetParameterCommand({ Name: PARAMETER, WithDecryption: true }));
    return out.Parameter?.Value ? parseGrant(out.Parameter.Value) : null;
  } catch {
    return null;
  }
}

/** Reads a line; with `hidden`, nothing typed is echoed. */
async function ask(question: string, hidden = false): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  if (hidden) {
    const write = (rl as any)._writeToOutput.bind(rl);
    (rl as any)._writeToOutput = (text: string) => write(text.startsWith(question) ? question : "");
  }
  const answer = await rl.question(question);
  rl.close();
  if (hidden) process.stdout.write("\n");
  return answer.trim();
}

async function clientCredentials(): Promise<{ clientId: string; clientSecret: string }> {
  const current = await existingGrant();
  if (current) {
    const keep = await ask(`Use the stored OAuth client ${current.clientId}? [Y/n] `);
    if (!/^n/i.test(keep)) return { clientId: current.clientId, clientSecret: current.clientSecret };
  }
  const clientId = process.env.GOOGLE_CLIENT_ID || (await ask("Google OAuth client ID: "));
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET || (await ask("Google OAuth client secret (not shown): ", true));
  if (!clientId.endsWith(".apps.googleusercontent.com") || !clientSecret) {
    throw new Error("That does not look like a Google OAuth client ID and secret");
  }
  return { clientId, clientSecret };
}

/** Listens on a free loopback port for Google's redirect back with the code. */
async function startCallbackServer(state: string): Promise<{ redirectUri: string; code: Promise<string>; close: () => void }> {
  let resolveCode!: (code: string) => void;
  let rejectCode!: (error: Error) => void;
  const code = new Promise<string>((resolve, reject) => {
    resolveCode = resolve;
    rejectCode = reject;
  });
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    if (url.pathname !== "/callback") {
      res.writeHead(404).end();
      return;
    }
    const reply = (status: number, message: string) => res.writeHead(status, { "content-type": "text/plain; charset=utf-8" }).end(message);
    if (url.searchParams.get("state") !== state) {
      reply(400, "State mismatch: start again from the terminal.");
      return;
    }
    const error = url.searchParams.get("error");
    const value = url.searchParams.get("code");
    if (error || !value) {
      reply(400, "Google sign-in failed. You can close this tab.");
      rejectCode(new Error(`Google sign-in failed: ${error ?? "no code"}`));
      return;
    }
    reply(200, "Signed in. You can close this tab and return to the terminal.");
    resolveCode(value);
  });
  // Port 0 picks a free port. Google allows any loopback port for desktop clients.
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return { redirectUri: `http://127.0.0.1:${port}/callback`, code, close: () => server.close() };
}

async function revoke(token: string) {
  await fetch("https://oauth2.googleapis.com/revoke", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ token }),
  }).catch(() => undefined);
}

async function main() {
  const { clientId, clientSecret } = await clientCredentials();
  const state = randomBytes(16).toString("hex");
  const codeVerifier = randomBytes(32).toString("base64url");
  const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");

  const { redirectUri, code: codePromise, close } = await startCallbackServer(state);
  console.log(`\nOpen this URL in your browser and sign in as ${allowedEmail}:\n\n${buildAuthUrl({ clientId, redirectUri, state, codeChallenge, loginHint: allowedEmail })}\n`);
  console.log("Waiting for Google to redirect back...");

  const code = await codePromise.finally(close);
  const tokens = await exchangeCode(fetch, { clientId, clientSecret, code, redirectUri, codeVerifier });
  let email: string;
  try {
    email = checkGrant(tokens, { clientId, allowedEmail: allowedEmail! });
  } catch (error) {
    // Do not leave a usable grant behind for an account that was refused.
    if (tokens.refresh_token) await revoke(tokens.refresh_token);
    throw error;
  }

  const grant: GoogleGrant = { clientId, clientSecret, refreshToken: tokens.refresh_token!, email };
  if (LOCAL) {
    await writeFile(LOCAL_FILE, JSON.stringify(grant), { mode: 0o600 });
    console.log(`Connected ${email}. Saved to .google-token.json for npm run dev.`);
  } else {
    await ssm.send(new PutParameterCommand({ Name: PARAMETER, Value: JSON.stringify(grant), Type: "SecureString", Overwrite: true }));
    const region = await ssm.config.region();
    console.log(`Connected ${email}. Stored ${PARAMETER} in ${region}. The Lambda picks it up on its next call.`);
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : "Failed");
  process.exit(1);
});
