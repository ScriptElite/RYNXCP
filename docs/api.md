# API guide

The RYNXCP API is a JSON HTTP API served by `rynx-api` on the same host and port
as the web panel. The default production URL is:

```
https://<panel-host>:2083
```

All request and response bodies use `application/json`. Errors have the shape:

```json
{ "error": { "code": "bad_request", "message": "invalid webhook name" } }
```

Common status codes are `400` (validation), `401` (missing or invalid
credentials), `403` (role or account scope), `404` (not found), `409`
(conflict), `429` (rate limited) and `500` (internal failure).

## Authentication

There are two ways to authenticate.

### Browser session

`POST /api/v1/auth/login` with a username and password creates a session
cookie. When SMTP is configured, the response asks for a second factor and the
session is only created after `POST /api/v1/auth/verify-2fa` or the WebAuthn
passkey flow. See [passkeys.md](passkeys.md).

Mutating requests made with a session cookie must also send the
`x-csrf-token` header returned by login or `GET /api/v1/auth/me`.

```bash
PANEL="https://panel.example.com:2083"

curl -sS -c cookies.txt \
  -H 'content-type: application/json' \
  -d '{"username":"admin","password":"Strong-Pass1"}' \
  "$PANEL/api/v1/auth/login" > login.json

# If login.json contains two_factor_required, submit the emailed code:
# curl -sS -c cookies.txt -b cookies.txt \
#   -H 'content-type: application/json' \
#   -d '{"challenge":"<challenge>","code":"123456"}' \
#   "$PANEL/api/v1/auth/verify-2fa" > login.json

CSRF="$(jq -r .csrf_token login.json)"
curl -sS -b cookies.txt -H "x-csrf-token: $CSRF" \
  "$PANEL/api/v1/auth/me"
```

### Personal API token

API tokens are intended for scripts, CI and integrations. Create one in the
panel under **API > Tokens API**, or with the API itself:

```bash
curl -sS -b cookies.txt \
  -H "x-csrf-token: $CSRF" \
  -H 'content-type: application/json' \
  -d '{"name":"ci-deploy"}' \
  "$PANEL/api/v1/tokens" > token.json

TOKEN="$(jq -r .token token.json)"
```

The `token` field is shown once. RYNXCP stores only its SHA-256 hash. Send it
as a Bearer token:

```bash
curl -sS -H "Authorization: Bearer $TOKEN" "$PANEL/api/v1/auth/me"
```

Bearer requests do not need a CSRF header. A token inherits the role and account
scope of the user who created it, so create it with the least privileged user
that can perform the task. Revoke tokens from the **API** view or with
`DELETE /api/v1/tokens/{id}`.

Always use HTTPS and keep tokens out of logs, shell history and repositories.

## Common examples

### Passkeys

Passkey management uses the browser WebAuthn API:

```text
GET|POST /api/v1/passkeys             list or begin registration
POST     /api/v1/passkeys/finish      complete registration
DELETE   /api/v1/passkeys/{id}

POST     /api/v1/auth/passkey/begin   begin a login assertion
POST     /api/v1/auth/passkey/finish  complete a login assertion
```

Registration requires a normal authenticated session. Login uses the challenge
returned by `/auth/login` and is only available when the user has a passkey and
the panel is served over HTTPS. Full browser flow and payload shapes are in
[passkeys.md](passkeys.md).

### List websites

```bash
curl -sS -H "Authorization: Bearer $TOKEN" "$PANEL/api/v1/websites"
```

### Read a site log

```bash
curl -sS -H "Authorization: Bearer $TOKEN" \
  "$PANEL/api/v1/websites/example.com/logs?kind=error&lines=200"
```

`kind` is `access`, `error` or `php`. `lines` is clamped to `1..500`.

### Clone a website

```bash
curl -sS -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"target":"staging.example.com","with_database":true}' \
  "$PANEL/api/v1/websites/example.com/clone"
```

The target must differ from the source. If the target already exists, its
document root is replaced with the clone. Database cloning supports at most one
site database; static and PHP-only sites can be cloned without one.

### Mail queue

```bash
# List the queue
curl -sS -H "Authorization: Bearer $TOKEN" "$PANEL/api/v1/mail/queue"

# Flush every deferred message
curl -sS -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"action":"flush"}' \
  "$PANEL/api/v1/mail/queue"

# Act on one message
curl -sS -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"action":"hold","id":"4C0F1A2B3C"}' \
  "$PANEL/api/v1/mail/queue"
```

Valid actions are `flush`, `delete`, `hold` and `release`. `flush` ignores the
id; the others require one. Mail queue access is limited to global admins.

### Create a backup

```bash
curl -sS -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"username":"acct1"}' \
  "$PANEL/api/v1/backups"
```

### Register a webhook

```bash
curl -sS -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"name":"alerts","url":"https://hooks.example.com/rynx","events":["agent.alert"]}' \
  "$PANEL/api/v1/webhooks"
```

The response contains the webhook and its `secret`, which is shown only once.
See [webhooks.md](webhooks.md) for payloads and signature verification.

## Conventions

- Mutating endpoints require the `owner`, `admin` or `operator` role; `viewer`
  is read-only.
- Linked hosting users only see their own account resources.
- List endpoints that accept a `limit` cap it server-side.
- Timestamps are RFC 3339 strings unless an endpoint documents epoch seconds.
- Passwords, tokens, private keys and webhook secrets are never returned by
  list endpoints.
