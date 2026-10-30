import { build } from "esbuild";

await build({
  entryPoints: ["src/lambda.ts"],
  outfile: "dist/index.mjs",
  bundle: true,
  platform: "node",
  target: "node22",
  format: "esm",
  minify: true,
  // The Lambda Node.js runtime already includes the AWS SDK.
  external: ["@aws-sdk/*"],
  // Bundled CommonJS dependencies call require() for Node built-ins.
  banner: { js: "import { createRequire } from 'node:module'; const require = createRequire(import.meta.url);" },
  logLevel: "info",
});
