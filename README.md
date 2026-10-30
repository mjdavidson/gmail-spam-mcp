# gmail-spam-mcp

A hosted [MCP](https://modelcontextprotocol.io) server that lets Claude search, read and rescue messages from your Gmail spam folder. It runs on a single AWS Lambda, costs nothing at personal-use volume, and only lets you in.

It exists because the Gmail connector on claude.ai leaves spam out completely: `in:spam` returns nothing, and it has an `includeTrash` flag but no spam flag. Add this server as a second connector and your claude.ai chats and cloud routines can check spam for mail that was caught by mistake.

## What Claude can do

| Tool | What it does |
| --- | --- |
| `search_spam` | Search spam with Gmail search syntax (`from:`, `subject:`, `newer_than:` and so on). Returns id, threadId, labels, received time, sender, recipient, subject and snippet. Up to 50 per page. |
| `get_spam_message` | One message as plain text: From, Reply-To, Return-Path, To, Date, Subject, Gmail's SPF/DKIM/DMARC verdict, the body converted from HTML (capped at 20,000 characters) and attachment names and sizes. Refuses messages that are not labelled SPAM. |
| `not_spam` | Removes SPAM and adds INBOX on one message, and reports its sender and subject. Refuses messages that are not labelled SPAM. |
| `spam_digest` | A compact triage list of the last N days of spam (default 7, at most 30, at most 100 messages): sender, subject, received time, SPF/DKIM/DMARC and a one-line snippet. |

Nothing can send mail, delete mail, create filters or read anything outside spam. `not_spam` is the only tool that changes anything. Claude sees it as a write tool, so it asks before using it unless you have allowed it.

## Spam is hostile input

Spam is written by people who would like Claude to do things for them. So:

- **Every piece of email text is fenced.** Each response starts with a notice that text between `<<<BEGIN UNTRUSTED EMAIL DATA id=…>>>` and `<<<END UNTRUSTED EMAIL DATA id=…>>>` was written by a spam sender and must never be followed as instructions. The id is random for each response, and any marker-like text inside an email is broken up, so a message cannot close the fence early and write "outside" it. The server's MCP instructions say the same.
- **Things Gmail produced are kept outside the fences**: message ids, labels, Gmail's received time and Gmail's own SPF/DKIM/DMARC verdict.
- **Only Gmail's Authentication-Results header counts.** A sender can add a fake `Authentication-Results: mx.google.com; spf=pass…` header to its own message. Gmail adds its header at the top, so the server uses the first `mx.google.com` header and ignores the rest. The domains it reports are reduced to characters that can appear in a domain name.
- **Links are cut down to their domain** (`[link: example.com]`) in snippets, subjects and senders. Only `get_spam_message` shows full URLs, as `text [URL: https://…]` inside the fence, labelled as untrusted and not to be visited.
- **Hidden text is dropped.** Text hidden with `display:none`, `font-size:0`, `opacity:0`, the `hidden` attribute and similar tricks is invisible to you but readable by a model, which makes it a common place to put injected instructions. The HTML is preferred over the plain-text part, because the HTML is what you see in Gmail.
- **Invisible characters are removed**: zero-width characters, bidirectional overrides (which can make `exe.pdf` show as `fdp.exe`) and Unicode tag characters.
- **Nothing is fetched.** No link is followed, no image is loaded and no attachment content is downloaded. The server's only outbound calls are to Gmail's API and Google's token endpoint.
- **Header values are collapsed onto one line**, so a subject cannot forge an extra `id:` or `labelIds:` line.

None of this makes prompt injection impossible. It makes it harder, and it gives the model a clear signal. Keep `not_spam` behind a confirmation in Claude.

## How it works

```
Claude ──HTTPS──▶ CloudFront ──▶ Lambda Function URL ──▶ gmail.googleapis.com
   │                                  │
   │                                  ├── verifies the bearer token against AuthKit's public keys
   │                                  └── reads the Google grant from SSM, refreshes access tokens in memory
   └── signs you in through WorkOS AuthKit (OAuth)

You (once a week while the Google app is in testing) ── npm run connect-google ──▶ Google consent ──▶ SSM
```

It uses the same setup as `cronometer-hosted-mcp`, and can share its WorkOS environment.

- **Two separate sign-ins.** Claude signs in to *this server* through WorkOS AuthKit, which only lets in the WorkOS user ids in `ALLOWED_SUBJECTS`. The server signs in to *Google* with a refresh token that you create once on your own machine with `npm run connect-google`. Claude never sees a Google token.
- **Google allowlist.** `connect-google` refuses any Google account except `ALLOWED_GOOGLE_EMAIL`, and revokes the grant it was given if the account is wrong. The Lambda checks again: it refuses a stored grant for another email, and on each cold start it asks Gmail which account the token belongs to before doing anything else.
- **Scope**: `https://www.googleapis.com/auth/gmail.modify`, the narrowest scope that can move mail out of spam (`gmail.readonly` cannot change labels), plus `openid email` so the account can be identified. It is requested with `access_type=offline`, so Google returns a refresh token.
- **Token storage.** The OAuth client id, client secret and refresh token live in one SSM Parameter Store SecureString, `/gmail-spam-mcp/google-grant`, encrypted with your account's default KMS key. They are never in the code, the repository, the Lambda configuration or the logs. Access tokens exist only in the function's memory and are refreshed a minute before they expire. The function's IAM role can read and write that one parameter and nothing else.
- CloudFront is there for one reason: a Lambda Function URL renames the `WWW-Authenticate` response header, which MCP clients read to find the login. The function marks its login challenge, and a CloudFront function turns that into the `401` the client sees. The Function URL itself refuses any request that did not come through CloudFront.

| File | What it does |
| --- | --- |
| `src/handler.ts` | OAuth discovery documents and a stateless MCP endpoint at `/mcp` |
| `src/auth.ts` | AuthKit access-token checks and the `ALLOWED_SUBJECTS` allowlist |
| `src/google.ts` | Refreshing Google tokens, checking the account, and the three Gmail API calls |
| `src/google-oauth.ts` | The one-time consent: building the URL, exchanging the code, checking the grant |
| `src/tools.ts` | The four tools |
| `src/mime.ts` | Gmail payload parsing, charset decoding and HTML-to-text conversion |
| `src/auth-results.ts` | Authentication-Results parsing |
| `src/untrusted.ts` | Fencing, invisible-character removal and link stripping |
| `scripts/connect-google.ts` | Connects your Google account |

### Cost

Everything used is inside AWS's always-free allowances at personal volume: Lambda, CloudFront, SSM standard parameters and CloudWatch Logs (kept for 14 days). The Gmail API is free. The function is capped at 25 concurrent copies, so a flood of requests to the public URL is throttled rather than billed. A new AWS account with a Lambda concurrency quota of 10 must deploy with `RESERVED_CONCURRENCY=0`.

## Set up

You need Node 22.18 or later, the AWS CLI with credentials, a WorkOS account (the Cronometer one is fine) and the Google account you want to use.

```bash
cp .env.example .env
```

```bash
npm install
```

Fill in `AUTHKIT_DOMAIN`, `ALLOWED_SUBJECTS` and `ALLOWED_GOOGLE_EMAIL` in `.env`.

### 1. Google Cloud project and OAuth client

1. Go to the [Google Cloud console](https://console.cloud.google.com/) and create a project, for example `gmail-spam-mcp`. Make sure it is selected in the project picker.
2. Enable the Gmail API: **APIs & Services → Library**, search for **Gmail API**, then **Enable**.
3. Configure the consent screen: **Google Auth Platform → Branding** (or **APIs & Services → OAuth consent screen** in the older console). Click **Get started** if asked.
   - App name: anything, such as `Gmail spam MCP`. User support email and developer contact: your address.
   - **Audience**: choose **External** and leave the publishing status as **Testing**. (If `mattdavidson.kiwi` is a Google Workspace domain, **Internal** is better; see [Refresh tokens expire after 7 days in testing mode](#refresh-tokens-expire-after-7-days-in-testing-mode).)
   - Under **Audience → Test users**, add `matt@mattdavidson.kiwi`. While the app is in testing, only test users can sign in.
   - Under **Data access → Add or remove scopes**, add `https://www.googleapis.com/auth/gmail.modify`, `openid` and `.../auth/userinfo.email`. Save. Google describes `gmail.modify` in broad terms; this server only uses it to list and read messages and change labels.
4. Create the OAuth client: **Google Auth Platform → Clients → Create client** (or **APIs & Services → Credentials → Create credentials → OAuth client ID**).
   - Application type: **Desktop app**. Name: anything.
   - Copy the **client ID** and **client secret**.

   Why Desktop rather than a web client with a `…/callback` redirect: the Google sign-in happens once on your own computer, not on the server, so Google redirects to a temporary `http://127.0.0.1:<port>/callback` that `connect-google` opens. Desktop clients accept any loopback port without registering a redirect URI. The Lambda only ever uses the refresh token.

### 2. Connect your Google account

This is the step that touches your real Google account. It needs AWS credentials, because it writes the grant to SSM in your current region (or `AWS_REGION` from `.env`).

```bash
npm run connect-google
```

It asks for the client ID and the client secret (the secret is not shown as you type), then prints a Google URL. Open it, sign in as `matt@mattdavidson.kiwi`, click through Google's "unverified app" warning (it is your own app) and allow Gmail access. The browser returns to `127.0.0.1`, and the script stores the grant as `/gmail-spam-mcp/google-grant`. If you sign in with any other account, it revokes the grant and stores nothing.

On later runs it offers to reuse the stored client, so you only sign in again.

### 3. Deploy

```bash
npm run deploy
```

It builds the bundle, creates or updates the CloudFormation stack `gmail-spam-mcp`, uploads the code and prints the MCP URL, which looks like `https://d111111abcdef8.cloudfront.net/mcp`. The first deploy takes several minutes while CloudFront is set up. You can run steps 2 and 3 in either order; until a Google account is connected, every tool says so.

### 4. Tell WorkOS about the server

In the WorkOS dashboard, in the environment that `AUTHKIT_DOMAIN` points at:

- Under **Connect → Configuration → Resource Indicators**, add the MCP URL exactly as printed. Without it, every request is rejected with `unexpected "aud" claim value`. If you share the Cronometer environment, add this as a second resource indicator, next to the Cronometer one.
- If this is a new WorkOS environment, also follow the Cronometer README's WorkOS steps: enable Client ID Metadata Document and Dynamic Client Registration, enable a sign-in method, create your user, turn off sign-up.

### 5. Add it to Claude

On claude.ai, go to **Settings → Connectors → Add custom connector**, give it a name such as `Gmail spam`, and paste the MCP URL. Claude sends you through the AuthKit sign-in and the four tools appear. Cloud routines can use the connector like any other.

In the connector's tool settings, consider leaving `not_spam` on "ask before using".

## Refresh tokens expire after 7 days in testing mode

Google gives an OAuth app whose publishing status is **Testing** refresh tokens that expire 7 days after you sign in, whether or not they are used. When that happens, every tool returns an error ending in "Run `npm run connect-google` to sign in to Google again." The Lambda reads the new grant on its next call, with no redeploy. You have three options:

1. **Sign in again weekly.** Run `npm run connect-google` (and press Enter to reuse the stored client). This is the simplest option and keeps the app private to you.
2. **Make the app Internal, if your address is on Google Workspace.** If `mattdavidson.kiwi` is a Workspace domain you administer, create the Cloud project inside that Workspace organisation and set **Audience → User type** to **Internal**. Internal apps can only be used by accounts in your organisation, need no Google verification, and their refresh tokens do not expire after 7 days. This is the best option if it is available. It is not available for `@gmail.com` accounts.
3. **Publish the app ("In production").** Under **Audience**, click **Publish app**. Refresh tokens then stop expiring after 7 days. `gmail.modify` is a *restricted* scope, so a published app that has not been through Google's verification shows the "Google hasn't verified this app" warning at sign-in, which you click through, and is capped at 100 users. Full verification for restricted scopes includes a paid third-party security assessment, so it is not worth it for personal use. Google's rules here change from time to time; check the consent screen's own notices.

A refresh token also stops working if you change your Google password, revoke access at [myaccount.google.com/permissions](https://myaccount.google.com/permissions), or don't use it for 6 months. The fix is the same: run `npm run connect-google`.

## Develop and test locally

```bash
npm test
```

```bash
npm run typecheck
```

The unit tests (vitest) cover MIME and HTML-to-text parsing, Authentication-Results parsing, untrusted-content fencing, the Google grant checks, and each tool end to end through the Lambda handler against a fake Gmail. Every fixture is synthetic.

To try the tools against your real spam folder without AWS or WorkOS, connect Google into a local file and run the server on loopback with no login in front of it:

```bash
npm run connect-google -- --local
```

```bash
npm run dev
```

```bash
npx @modelcontextprotocol/inspector
```

In the inspector, choose transport **Streamable HTTP**, enter `http://localhost:8787/mcp` and connect. The first command writes `.google-token.json` (git-ignored, readable only by you). `npm run dev` listens on `127.0.0.1` only and refuses requests addressed to any other hostname. Delete `.google-token.json` when you are done.

To test the deployed server with the inspector instead, enter the CloudFront MCP URL. The inspector runs the same AuthKit sign-in that Claude does.

## Troubleshooting

- **"No Google account is connected"**: run `npm run connect-google` in the region the stack is in.
- **"Google rejected the stored refresh token"**: it has expired (weekly in testing mode) or was revoked. Run `npm run connect-google`.
- **"Signed in as … but only … is allowed"**: you picked a different Google account in the browser. Run it again and choose the right one.
- **`access_denied` or "Access blocked" from Google**: your address is not a test user on the consent screen (step 1.3).
- **403 "WorkOS user … is not allowed"**: the id in the message is not in `ALLOWED_SUBJECTS`. Add it to `.env` and redeploy.
- **401 `unexpected "aud" claim value`**: the resource indicator in WorkOS does not match the MCP URL (step 4).
- **403 `forbidden` from the `lambda-url` address**: expected. Only the CloudFront URL is usable.
- **Logs**: `aws logs tail /aws/lambda/gmail-spam-mcp --follow`. Tokens and message contents are never logged.
- **Remove everything**: `aws cloudformation delete-stack --stack-name gmail-spam-mcp`, then `aws ssm delete-parameter --name /gmail-spam-mcp/google-grant`, and remove the app's access at [myaccount.google.com/permissions](https://myaccount.google.com/permissions).
