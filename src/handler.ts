// HTTP entry point, shaped as a Lambda Function URL handler. Serves the OAuth
// discovery documents and a stateless MCP endpoint at /mcp.

import { timingSafeEqual } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import type { APIGatewayProxyEventV2, APIGatewayProxyStructuredResultV2 } from "aws-lambda";
import { AuthError, normalizeIssuer } from "./auth.ts";
import type { GmailClient } from "./google.ts";
import { registerTools, SERVER_INSTRUCTIONS } from "./tools.ts";

export interface HandlerDeps {
  gmail: GmailClient;
  issuer: string;
  /** Returns the caller's user id, or throws AuthError. */
  authenticate: (authorization: string | undefined, origin: string) => Promise<string>;
  /**
   * Secret that CloudFront adds to every request it forwards. When set, the
   * function URL refuses requests without it, and the public hostname is the
   * one CloudFront reports rather than the function URL's own.
   */
  originSecret?: string;
  fetch?: typeof fetch;
}

type Result = APIGatewayProxyStructuredResultV2;

const METADATA_TIMEOUT_MS = 5_000;

function json(statusCode: number, body: unknown, headers: Record<string, string> = {}): Result {
  return {
    statusCode,
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  };
}

function rpcError(statusCode: number, message: string, headers: Record<string, string> = {}): Result {
  return json(statusCode, { jsonrpc: "2.0", error: { code: -32000, message }, id: null }, headers);
}

function sameSecret(given: string | undefined, expected: string): boolean {
  const a = Buffer.from(given ?? "");
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

export function createHandler(deps: HandlerDeps) {
  const issuer = normalizeIssuer(deps.issuer);
  const fetchImpl = deps.fetch ?? fetch;
  // AuthKit's metadata rarely changes, so one copy serves this environment.
  let authServerMetadata: string | null = null;

  return async function handler(event: APIGatewayProxyEventV2): Promise<Result> {
    if (deps.originSecret && !sameSecret(event.headers["x-origin-verify"], deps.originSecret)) {
      return json(403, { error: "forbidden" });
    }

    const method = event.requestContext.http.method.toUpperCase();
    const path = event.rawPath.replace(/\/+$/, "") || "/";
    // x-forwarded-host is only believed once the secret has shown that the
    // request came through CloudFront, which sets it from the real Host.
    const host = (deps.originSecret && event.headers["x-forwarded-host"]) || event.requestContext.domainName;
    const origin = `https://${host}`;
    const metadataUrl = `${origin}/.well-known/oauth-protected-resource/mcp`;

    // RFC 9728 protected resource metadata: tells the client which
    // authorization server issues tokens for this server.
    if (path === "/.well-known/oauth-protected-resource" || path === "/.well-known/oauth-protected-resource/mcp") {
      return json(200, {
        resource: `${origin}/mcp`,
        authorization_servers: [issuer],
        bearer_methods_supported: ["header"],
      });
    }

    // Older clients look for authorization server metadata on the MCP host
    // itself, so AuthKit's document is relayed for them.
    if (path === "/.well-known/oauth-authorization-server") {
      if (!authServerMetadata) {
        try {
          const res = await fetchImpl(`${issuer}/.well-known/oauth-authorization-server`, {
            signal: AbortSignal.timeout(METADATA_TIMEOUT_MS),
          });
          if (!res.ok) return json(502, { error: "authorization_server_unavailable" });
          authServerMetadata = await res.text();
        } catch {
          return json(502, { error: "authorization_server_unavailable" });
        }
      }
      return { statusCode: 200, headers: { "content-type": "application/json" }, body: authServerMetadata };
    }

    if (path !== "/mcp") return json(404, { error: "not_found" });

    try {
      await deps.authenticate(event.headers.authorization, origin);
    } catch (error) {
      if (!(error instanceof AuthError)) throw error;
      // Only a missing or invalid token should send the client back to log in.
      if (error.status === 403) return rpcError(403, error.message);
      const challenge = `Bearer error="invalid_token", error_description="${error.message.replace(/"/g, "'")}", resource_metadata="${metadataUrl}"`;
      if (deps.originSecret) {
        // A function URL renames WWW-Authenticate, and CloudFront does not run
        // its response function when the origin answers with an error status.
        // So the challenge leaves here as a 200 carrying a marker header, and
        // the CloudFront function in infra/template.yaml turns it into the 401.
        // (Not an x-edge- or x-amz- name: CloudFront strips those.)
        return rpcError(200, error.message, { "x-mcp-challenge": challenge });
      }
      return rpcError(401, error.message, { "www-authenticate": challenge });
    }

    // The server is stateless, so there is no stream to open or session to end.
    if (method !== "POST") return rpcError(405, "Method not allowed", { allow: "POST" });

    const body = event.isBase64Encoded ? Buffer.from(event.body ?? "", "base64").toString("utf8") : (event.body ?? "");
    const headers = new Headers();
    for (const [name, value] of Object.entries(event.headers)) {
      if (value !== undefined && name !== "x-origin-verify") headers.set(name, value);
    }

    const server = new McpServer({ name: "gmail-spam", version: "0.1.0" }, { instructions: SERVER_INSTRUCTIONS });
    registerTools(server, deps.gmail);
    const transport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      // Function URLs buffer responses, so answer with plain JSON, not SSE.
      enableJsonResponse: true,
    });
    await server.connect(transport);
    try {
      const response = await transport.handleRequest(new Request(`${origin}/mcp`, { method, headers, body }));
      return {
        statusCode: response.status,
        headers: Object.fromEntries(response.headers),
        body: await response.text(),
      };
    } finally {
      await server.close();
    }
  };
}
