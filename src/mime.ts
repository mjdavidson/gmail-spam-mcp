// Turns a Gmail API message payload into plain text: header lookup, body
// decoding, HTML-to-text conversion and the attachment list. Nothing here
// fetches anything: links are written out as text and images are never loaded.

import { Parser } from "htmlparser2";
import { sanitize } from "./untrusted.ts";

/** The parts of the Gmail API's MessagePart that this server reads. */
export interface GmailHeader {
  name: string;
  value: string;
}

export interface GmailPart {
  partId?: string;
  mimeType?: string;
  filename?: string;
  headers?: GmailHeader[];
  body?: { size?: number; data?: string; attachmentId?: string };
  parts?: GmailPart[];
}

export interface Attachment {
  filename: string;
  mimeType: string;
  size: number;
}

/** All values of a header, in message order. Names are case-insensitive. */
export function headerValues(headers: GmailHeader[] | undefined, name: string): string[] {
  const lower = name.toLowerCase();
  return (headers ?? []).filter((h) => h.name.toLowerCase() === lower).map((h) => decodeEncodedWords(h.value));
}

export function header(headers: GmailHeader[] | undefined, name: string): string | undefined {
  return headerValues(headers, name)[0];
}

function decoder(charset: string | undefined): TextDecoder {
  try {
    return new TextDecoder(charset?.trim().toLowerCase() || "utf-8");
  } catch {
    return new TextDecoder("utf-8");
  }
}

/**
 * Decodes RFC 2047 encoded words such as `=?UTF-8?B?SGk=?=`. The Gmail API
 * usually decodes headers itself, but not always.
 */
export function decodeEncodedWords(value: string): string {
  // Whitespace between two adjacent encoded words is not part of the text.
  const joined = value.replace(/(\?=)\s+(=\?)/g, "$1$2");
  return joined.replace(/=\?([^?]+)\?([bq])\?([^?]*)\?=/gi, (whole, charset: string, encoding: string, text: string) => {
    try {
      const bytes =
        encoding.toLowerCase() === "b"
          ? Buffer.from(text, "base64")
          : Buffer.from(
              text.replace(/_/g, " ").replace(/=([0-9a-f]{2})/gi, (_m, hex: string) => String.fromCharCode(parseInt(hex, 16))),
              "latin1",
            );
      // RFC 2231 allows a language suffix: UTF-8*en
      return decoder(charset.split("*")[0]).decode(bytes);
    } catch {
      return whole;
    }
  });
}

/** The charset parameter of a Content-Type header. */
export function charsetOf(part: GmailPart): string | undefined {
  const contentType = header(part.headers, "Content-Type") ?? "";
  return /charset\s*=\s*"?([^";\s]+)"?/i.exec(contentType)?.[1];
}

/** Decodes a part's inline body. Gmail sends it base64url-encoded, in the part's own charset. */
export function decodeBody(part: GmailPart): string {
  const data = part.body?.data;
  if (!data) return "";
  return decoder(charsetOf(part)).decode(Buffer.from(data, "base64url"));
}

function walk(part: GmailPart, visit: (part: GmailPart) => void) {
  visit(part);
  for (const child of part.parts ?? []) walk(child, visit);
}

const isAttachment = (part: GmailPart) =>
  Boolean(part.filename) || /^\s*attachment/i.test(header(part.headers, "Content-Disposition") ?? "");

/** Names, types and sizes of attachments. Their content is never fetched. */
export function listAttachments(payload: GmailPart): Attachment[] {
  const out: Attachment[] = [];
  walk(payload, (part) => {
    if (part.parts?.length || !isAttachment(part)) return;
    out.push({
      filename: part.filename || "(unnamed)",
      mimeType: part.mimeType ?? "application/octet-stream",
      size: part.body?.size ?? 0,
    });
  });
  return out;
}

/**
 * The message body as plain text. HTML is preferred when there is any, since
 * it is what Gmail shows the reader; the plain-text alternative of a spam
 * message can say something quite different.
 */
export function extractBody(payload: GmailPart): { text: string; source: "html" | "plain" | "none" } {
  const html: string[] = [];
  const plain: string[] = [];
  walk(payload, (part) => {
    if (part.parts?.length || isAttachment(part)) return;
    const type = (part.mimeType ?? "").toLowerCase();
    if (type === "text/html") html.push(decodeBody(part));
    else if (type === "text/plain") plain.push(decodeBody(part));
  });
  if (html.length > 0) return { text: htmlToText(html.join("\n")), source: "html" };
  if (plain.length > 0) return { text: tidy(sanitize(plain.join("\n"))), source: "plain" };
  return { text: "", source: "none" };
}

const BLOCK = new Set([
  "address", "article", "aside", "blockquote", "center", "dd", "div", "dl", "dt", "fieldset", "figcaption", "figure",
  "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr", "li", "main", "nav", "ol", "p", "pre",
  "section", "table", "tbody", "thead", "tfoot", "tr", "ul",
]);
// Their content is never shown to a reader.
const SKIP = new Set(["head", "script", "style", "template", "noscript", "title", "svg", "math", "object", "iframe"]);
const VOID = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"]);

/**
 * True for inline styles and attributes that hide an element. Hidden text is a
 * favourite way to slip instructions past a human reader, so it is dropped.
 */
export function isHidden(attribs: Record<string, string>): boolean {
  if ("hidden" in attribs || attribs["aria-hidden"] === "true") return true;
  const style = (attribs.style ?? "").toLowerCase().replace(/\s+/g, "");
  return (
    /display:none|visibility:hidden|opacity:0(?:\.0+)?(?:;|$|!)|font-size:0(?:px|pt|em|rem|%)?(?:;|$|!)|max-height:0(?:px)?(?:;|$|!)/.test(style) ||
    /(?:^|;)(?:height|width):0(?:px)?(?:;|$|!)/.test(style) && /overflow:hidden/.test(style)
  );
}

/** Collapses runs of blank lines and trailing spaces. */
function tidy(text: string): string {
  return text
    .split("\n")
    .map((line) => line.replace(/[ \t ]+/g, " ").trim())
    .join("\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

/**
 * Converts HTML to readable text. Links keep their full URL after the link
 * text, as `text [URL: https://...]`; images become `[image: alt]` and are not
 * loaded. Scripts, styles and hidden elements are dropped.
 */
export function htmlToText(html: string): string {
  let out = "";
  // Each open element records whether it started a skipped or hidden region.
  const stack: { name: string; skipping: boolean }[] = [];
  let skipDepth = 0;
  let pre = 0;
  const links: { href: string | undefined; start: number }[] = [];

  const write = (text: string) => {
    if (skipDepth === 0) out += text;
  };
  const newline = () => {
    if (skipDepth === 0 && !out.endsWith("\n")) out += "\n";
  };

  const parser = new Parser(
    {
      onopentag(name, attribs) {
        const skipping = SKIP.has(name) || isHidden(attribs);
        if (!VOID.has(name)) {
          stack.push({ name, skipping });
          if (skipping) skipDepth++;
        }
        if (skipping) return;
        if (BLOCK.has(name)) newline();
        if (name === "br") write("\n");
        else if (name === "hr") write("---\n");
        else if (name === "li") write("- ");
        else if (name === "td" || name === "th") write(" ");
        else if (name === "pre") pre++;
        else if (name === "a") links.push({ href: attribs.href, start: out.length });
        else if (name === "img") {
          const alt = (attribs.alt ?? "").trim();
          write(alt ? `[image: ${alt}]` : "[image]");
        }
      },
      ontext(text) {
        write(pre > 0 ? text : text.replace(/\s+/g, " "));
      },
      onclosetag(name) {
        if (VOID.has(name)) return;
        // htmlparser2 closes unclosed children itself, so the top matches.
        const top = stack.pop();
        if (!top) return;
        if (top.skipping) {
          skipDepth--;
          return;
        }
        if (name === "pre") pre = Math.max(0, pre - 1);
        if (name === "a") {
          const link = links.pop();
          const href = link?.href?.trim();
          if (href && !/^(?:#|javascript:|data:|cid:)/i.test(href) && skipDepth === 0) {
            const text = out.slice(link!.start).trim();
            const target = href.replace(/\s+/g, "");
            // A bare URL as its own link text needs saying only once.
            if (text !== target) out += `${text ? " " : ""}[URL: ${target}]`;
          }
        }
        if (BLOCK.has(name)) newline();
      },
    },
    { decodeEntities: true, lowerCaseTags: true, lowerCaseAttributeNames: true },
  );
  parser.write(html);
  parser.end();
  return tidy(sanitize(out));
}

/** Caps text at `max` characters, saying how much was cut. */
export function truncate(text: string, max: number): string {
  if (text.length <= max) return text;
  return `${text.slice(0, max)}\n[... truncated: ${text.length - max} more characters]`;
}
