// Local development server: runs the same handler on http://localhost:8787/mcp
// with no OAuth in front of it, using the Google grant that
// `npm run connect-google -- --local` saved to .google-token.json.
//
//   npm run dev
//
// It listens on loopback only. Never deploy this file.

import { readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { GmailClient } from "./google.ts";
import { createHandler } from "./handler.ts";
import { parseGrant } from "./store.ts";

try {
  process.loadEnvFile(new URL("../.env", import.meta.url));
} catch {
  // No .env: settings come from the environment.
}

const PORT = Number(process.env.PORT ?? 8787);
const GRANT_FILE = new URL("../.google-token.json", import.meta.url);

const allowedEmail = process.env.ALLOWED_GOOGLE_EMAIL;
if (!allowedEmail) {
  console.error("Set ALLOWED_GOOGLE_EMAIL in .env");
  process.exit(1);
}

const gmail = new GmailClient({
  allowedEmail,
  store: {
    load: async () => {
      try {
        return parseGrant(await readFile(GRANT_FILE, "utf8"));
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
        throw error;
      }
    },
    save: (grant) => writeFile(GRANT_FILE, JSON.stringify(grant), { mode: 0o600 }),
  },
});

const handler = createHandler({
  gmail,
  issuer: "https://local.invalid",
  authenticate: async () => "local",
});

createServer(async (req, res) => {
  // There is no login here, so refuse anything not addressed to loopback: a
  // web page that rebinds its own hostname to 127.0.0.1 fails this check.
  if (req.headers.host !== `localhost:${PORT}` && req.headers.host !== `127.0.0.1:${PORT}`) {
    res.writeHead(403).end();
    return;
  }
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(req.headers)) {
    if (value !== undefined) headers[name] = Array.isArray(value) ? value.join(", ") : value;
  }
  const event = {
    rawPath: new URL(req.url ?? "/", "http://localhost").pathname,
    headers,
    body: Buffer.concat(chunks).toString("utf8"),
    isBase64Encoded: false,
    requestContext: { domainName: `localhost:${PORT}`, http: { method: req.method ?? "GET" } },
  } as unknown as APIGatewayProxyEventV2;
  try {
    const result = await handler(event);
    res.writeHead(result.statusCode ?? 200, result.headers as Record<string, string>);
    res.end(result.body);
  } catch (error) {
    console.error(error instanceof Error ? error.message : "request failed");
    res.writeHead(500).end();
  }
}).listen(PORT, "127.0.0.1", () => {
  console.log(`Gmail spam MCP (no auth) listening on http://localhost:${PORT}/mcp`);
});
