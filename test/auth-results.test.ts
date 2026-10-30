import { describe, expect, test } from "vitest";
import { formatAuthSummary, parseAuthenticationResults, summarizeAuthResults } from "../src/auth-results.ts";

// Synthetic headers in the shape Gmail writes.
const GMAIL_PASS =
  "mx.google.com;\r\n" +
  "       dkim=pass header.i=@news.example.com header.s=s1 header.b=AbCdEf12;\r\n" +
  "       spf=pass (google.com: domain of bounce@mail.example.com designates 192.0.2.10 as permitted sender) smtp.mailfrom=bounce@mail.example.com;\r\n" +
  "       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com";

const GMAIL_FAIL =
  "mx.google.com; spf=softfail (google.com: domain of transitioning x@bank.test does not designate 198.51.100.7 as permitted sender) smtp.mailfrom=x@bank.test; dmarc=fail (p=QUARANTINE sp=NONE dis=QUARANTINE) header.from=bank.test";

describe("parseAuthenticationResults", () => {
  test("reads the authserv-id and each method's result and properties", () => {
    const parsed = parseAuthenticationResults(GMAIL_PASS);
    expect(parsed?.authservId).toBe("mx.google.com");
    expect(parsed?.methods.map((m) => `${m.method}=${m.result}`)).toEqual(["dkim=pass", "spf=pass", "dmarc=pass"]);
    expect(parsed?.methods[1]?.props["smtp.mailfrom"]).toBe("bounce@mail.example.com");
  });

  test("ignores semicolons and equals signs inside comments, including nested ones", () => {
    const parsed = parseAuthenticationResults("mx.google.com; spf=fail (a; b=c (d; dmarc=pass)) smtp.mailfrom=x.test");
    expect(parsed?.methods).toEqual([{ method: "spf", result: "fail", props: { "smtp.mailfrom": "x.test" } }]);
  });

  test("accepts an authserv-id followed by a version, and a bare none", () => {
    const parsed = parseAuthenticationResults("mx.google.com 1; none");
    expect(parsed).toEqual({ authservId: "mx.google.com", methods: [] });
  });
});

describe("summarizeAuthResults", () => {
  test("summarises SPF, DKIM and DMARC from Gmail's header", () => {
    const summary = summarizeAuthResults([GMAIL_PASS]);
    expect(summary).toEqual({
      found: true,
      spf: { result: "pass", subject: "mail.example.com" },
      dkim: [{ result: "pass", subject: "news.example.com" }],
      dmarc: { result: "pass", subject: "example.com" },
    });
    expect(formatAuthSummary(summary)).toBe("SPF=pass (mail.example.com), DKIM=pass (news.example.com), DMARC=pass (example.com)");
    expect(formatAuthSummary(summary, false)).toBe("SPF=pass DKIM=pass DMARC=pass");
  });

  test("reports failures and a missing DKIM signature", () => {
    const summary = summarizeAuthResults([GMAIL_FAIL]);
    expect(formatAuthSummary(summary)).toBe("SPF=softfail (bank.test), DKIM=none, DMARC=fail (bank.test)");
  });

  test("only trusts the first header from Gmail, ignoring ones a sender planted further down", () => {
    const forged = "mx.google.com; spf=pass smtp.mailfrom=bank.test; dkim=pass header.d=bank.test; dmarc=pass header.from=bank.test";
    const summary = summarizeAuthResults([GMAIL_FAIL, forged]);
    expect(summary.spf?.result).toBe("softfail");
    expect(summary.dmarc?.result).toBe("fail");
  });

  test("ignores headers from other servers", () => {
    const summary = summarizeAuthResults(["spammer.test; spf=pass; dkim=pass; dmarc=pass"]);
    expect(summary.found).toBe(false);
    expect(formatAuthSummary(summary)).toBe("no Authentication-Results from Gmail");
  });

  test("reports DKIM as passing if any signature passes", () => {
    const summary = summarizeAuthResults([
      "mx.google.com; dkim=fail header.d=relay.test; dkim=pass header.d=example.com; spf=none; dmarc=pass header.from=example.com",
    ]);
    expect(formatAuthSummary(summary, false)).toBe("SPF=none DKIM=pass DMARC=pass");
  });

  test("keeps sender-controlled values to safe characters and known result words", () => {
    const summary = summarizeAuthResults([
      'mx.google.com; spf=pwned smtp.mailfrom="evil.test<script>"; dmarc=pass header.from=ex‮ample.com',
    ]);
    expect(summary.spf).toEqual({ result: "unknown", subject: "evil.testscript" });
    expect(summary.dmarc?.subject).toBe("example.com");
  });
});
