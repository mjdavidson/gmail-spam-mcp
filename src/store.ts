// The Google grant lives in SSM Parameter Store as one SecureString parameter,
// encrypted with the account's default KMS key and free at this volume.

import { GetParameterCommand, PutParameterCommand, SSMClient } from "@aws-sdk/client-ssm";
import type { GoogleGrant, GrantStore } from "./google.ts";

export const GRANT_PARAMETER = "google-grant";

/** Validates a stored grant without echoing any of it, since the parser's message would quote the secret. */
export function parseGrant(raw: string): GoogleGrant {
  let parsed: any;
  try {
    parsed = JSON.parse(raw);
  } catch {
    parsed = null;
  }
  for (const field of ["clientId", "clientSecret", "refreshToken", "email"]) {
    if (typeof parsed?.[field] !== "string" || !parsed[field]) {
      throw new Error(`The stored Google grant has no ${field}: run \`npm run connect-google\``);
    }
  }
  return { clientId: parsed.clientId, clientSecret: parsed.clientSecret, refreshToken: parsed.refreshToken, email: parsed.email };
}

export function createSsmStore(prefix: string, ssm = new SSMClient({})): GrantStore {
  const name = `${prefix}/${GRANT_PARAMETER}`;
  return {
    async load() {
      try {
        const out = await ssm.send(new GetParameterCommand({ Name: name, WithDecryption: true }));
        return out.Parameter?.Value ? parseGrant(out.Parameter.Value) : null;
      } catch (error) {
        if (error instanceof Error && error.name === "ParameterNotFound") return null;
        throw error;
      }
    },
    async save(grant) {
      await ssm.send(new PutParameterCommand({ Name: name, Value: JSON.stringify(grant), Type: "SecureString", Overwrite: true }));
    },
  };
}
