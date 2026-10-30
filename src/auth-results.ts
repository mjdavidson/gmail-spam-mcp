// Parses Authentication-Results headers (RFC 8601) into an SPF/DKIM/DMARC
// summary.
//
// A sender can put any Authentication-Results header it likes into its own
// message, so only the one added by Gmail's receiving server counts. Gmail
// prepends its header, which makes it the first one with Gmail's authserv-id.
// The output is limited to known result words and domain-name characters, so
// it is safe to show outside the untrusted-data fence.

export const GMAIL_AUTHSERV_ID = "mx.google.com";

const RESULTS = new Set(["pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "policy", "bestguesspass"]);

export interface MethodResult {
  result: string;
  /** The domain or address the result is about, such as header.from for DMARC. */
  subject?: string;
}

export interface AuthSummary {
  /** False when no header from the trusted server was found. */
  found: boolean;
  spf: MethodResult | null;
  dkim: MethodResult[];
  dmarc: MethodResult | null;
}

/** Removes RFC 5322 comments, which can nest: `(a (b) c)`. */
function stripComments(value: string): string {
  let out = "";
  let depth = 0;
  let escaped = false;
  for (const ch of value) {
    if (escaped) {
      escaped = false;
      if (depth === 0) out += ch;
      continue;
    }
    if (ch === "\\") {
      escaped = true;
      if (depth === 0) out += ch;
      continue;
    }
    if (ch === "(") depth++;
    else if (ch === ")" && depth > 0) depth--;
    else if (depth === 0) out += ch;
  }
  return out;
}

/** Keeps only characters that can appear in a domain or address. */
function safeToken(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const cleaned = value.replace(/^"|"$/g, "").replace(/[^A-Za-z0-9.@_+\-]/g, "").slice(0, 253);
  return cleaned || undefined;
}

interface ParsedHeader {
  authservId: string;
  methods: { method: string; result: string; props: Record<string, string> }[];
}

export function parseAuthenticationResults(header: string): ParsedHeader | null {
  const parts = stripComments(header.replace(/\r?\n[ \t]+/g, " "))
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean);
  if (parts.length === 0) return null;
  // The authserv-id may be followed by a version number.
  const authservId = parts[0]!.split(/\s+/)[0]!.toLowerCase();
  const methods: ParsedHeader["methods"] = [];
  for (const part of parts.slice(1)) {
    const tokens = part.split(/\s+/);
    const head = /^([a-z0-9-]+)\s*=\s*([a-z]+)$/i.exec(tokens[0] ?? "");
    if (!head) continue;
    const props: Record<string, string> = {};
    for (const token of tokens.slice(1)) {
      const prop = /^([a-z0-9-]+\.[a-z0-9-]+)=(.*)$/i.exec(token);
      if (prop) props[prop[1]!.toLowerCase()] = prop[2]!;
    }
    methods.push({ method: head[1]!.toLowerCase(), result: head[2]!.toLowerCase(), props });
  }
  return { authservId, methods };
}

const result = (value: string) => (RESULTS.has(value) ? value : "unknown");

/** Summarises the first Authentication-Results header from `trustedId`. */
export function summarizeAuthResults(headers: string[], trustedId = GMAIL_AUTHSERV_ID): AuthSummary {
  const trusted = headers.map(parseAuthenticationResults).find((parsed) => parsed?.authservId === trustedId.toLowerCase());
  if (!trusted) return { found: false, spf: null, dkim: [], dmarc: null };

  let spf: MethodResult | null = null;
  let dmarc: MethodResult | null = null;
  const dkim: MethodResult[] = [];
  for (const { method, result: raw, props } of trusted.methods) {
    if (method === "spf" && !spf) {
      const mailfrom = props["smtp.mailfrom"] ?? props["smtp.helo"];
      spf = { result: result(raw), subject: safeToken(mailfrom?.includes("@") ? mailfrom.split("@").pop() : mailfrom) };
    } else if (method === "dkim") {
      const signer = props["header.d"] ?? props["header.i"]?.replace(/^.*@/, "");
      dkim.push({ result: result(raw), subject: safeToken(signer) });
    } else if (method === "dmarc" && !dmarc) {
      dmarc = { result: result(raw), subject: safeToken(props["header.from"]) };
    }
  }
  return { found: true, spf, dkim, dmarc };
}

/** The DKIM result that matters most: any pass, otherwise the first one. */
function overallDkim(dkim: MethodResult[]): MethodResult | null {
  return dkim.find((entry) => entry.result === "pass") ?? dkim[0] ?? null;
}

const describe = (name: string, entry: MethodResult | null) =>
  entry ? `${name}=${entry.result}${entry.subject ? ` (${entry.subject})` : ""}` : `${name}=none`;

/** One line such as `SPF=pass (example.com), DKIM=pass (example.com), DMARC=fail (example.com)`. */
export function formatAuthSummary(summary: AuthSummary, detailed = true): string {
  if (!summary.found) return "no Authentication-Results from Gmail";
  if (!detailed) {
    return [`SPF=${summary.spf?.result ?? "none"}`, `DKIM=${overallDkim(summary.dkim)?.result ?? "none"}`, `DMARC=${summary.dmarc?.result ?? "none"}`].join(" ");
  }
  const dkim = summary.dkim.length > 0 ? summary.dkim.map((entry) => describe("DKIM", entry)).join(", ") : "DKIM=none";
  return [describe("SPF", summary.spf), dkim, describe("DMARC", summary.dmarc)].join(", ");
}
