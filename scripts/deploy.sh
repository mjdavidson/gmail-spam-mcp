#!/usr/bin/env bash
# Build and deploy. Safe to re-run: it updates the stack and the code in place.
# Settings come from .env (see .env.example) or the environment.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

STACK="${STACK_NAME:-gmail-spam-mcp}"
: "${AUTHKIT_DOMAIN:?Set AUTHKIT_DOMAIN to your WorkOS AuthKit domain}"
: "${ALLOWED_GOOGLE_EMAIL:?Set ALLOWED_GOOGLE_EMAIL to the Google account the server may use}"

npm run build
rm -f dist/function.zip
(cd dist && zip -q function.zip index.mjs)

aws cloudformation deploy \
  --stack-name "$STACK" \
  --template-file infra/template.yaml \
  --capabilities CAPABILITY_IAM \
  --no-fail-on-empty-changeset \
  --parameter-overrides \
    "AuthKitDomain=$AUTHKIT_DOMAIN" \
    "AllowedSubjects=${ALLOWED_SUBJECTS:-}" \
    "ExtraAudiences=${EXTRA_AUDIENCES:-}" \
    "AllowedGoogleEmail=$ALLOWED_GOOGLE_EMAIL" \
    "ReservedConcurrency=${RESERVED_CONCURRENCY:-25}"

aws lambda wait function-updated --function-name "$STACK"
aws lambda update-function-code \
  --function-name "$STACK" \
  --zip-file fileb://dist/function.zip \
  --query CodeSha256 --output text > /dev/null
aws lambda wait function-updated --function-name "$STACK"

url="$(aws cloudformation describe-stacks --stack-name "$STACK" \
  --query "Stacks[0].Outputs[?OutputKey=='McpUrl'].OutputValue" --output text)"
echo
echo "Deployed. MCP URL: $url"
if [ -z "${ALLOWED_SUBJECTS:-}" ]; then
  echo "ALLOWED_SUBJECTS is empty, so every sign-in is rejected until you set it and redeploy."
fi
if ! aws ssm get-parameter --name "${PARAMETER_PREFIX:-/gmail-spam-mcp}/google-grant" --query Parameter.Name --output text > /dev/null 2>&1; then
  echo "No Google account is connected yet: run npm run connect-google."
fi
