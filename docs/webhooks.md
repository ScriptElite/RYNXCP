# Webhooks

Webhooks let RYNXCP notify another service when something happens in the panel.
They are per-user, outbound only, and separate from the websites hosted on the
server.

## Supported events

| Event | When it fires | `data` fields |
| --- | --- | --- |
| `agent.alert` | The AI agent records new high/critical findings | `findings[]` with `severity`, `category`, `title`, `summary` |
| `certificate.issued` | A certificate job succeeds | `domain`, `message` |
| `certificate.failed` | A certificate job fails | `domain`, `message` |
| `backup.created` | A hosting account backup completes | `username`, `id`, `size_bytes`, `path` |
| `website.cloned` | A website clone succeeds | `source`, `target`, `with_database` |

## Create a webhook

Use **API > Webhooks > Nuevo webhook** or `POST /api/v1/webhooks`:

```bash
curl -sS -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "name": "ops-alerts",
    "url": "https://hooks.example.com/rynxcp",
    "events": ["agent.alert", "certificate.failed", "backup.created"]
  }' \
  "https://panel.example.com:2083/api/v1/webhooks"
```

The response includes the webhook and a one-time `secret`:

```json
{
  "webhook": {
    "id": "2f6d...",
    "name": "ops-alerts",
    "url": "https://hooks.example.com/rynxcp",
    "events": ["agent.alert", "certificate.failed", "backup.created"],
    "enabled": true,
    "created_at": "2026-11-01T15:00:00Z"
  },
  "secret": "0123...cdef"
}
```

Store the secret in the receiving service. It cannot be retrieved again; delete
and recreate the webhook to rotate it.

Requirements and safeguards:

- The URL must use HTTPS and have no embedded credentials.
- The host must resolve only to public addresses. Loopback, private, link-local
  and metadata addresses are rejected.
- Redirects are not followed.
- Each delivery has a 10 second timeout.
- Deliveries are attempted once. A non-2xx response or timeout is logged and is
  not retried automatically.

## Delivery format

RYNXCP sends an HTTP `POST` with `content-type: application/json` and these
headers:

```
x-rynx-event: agent.alert
x-rynx-signature: sha256=<hex hmac>
```

The body is:

```json
{
  "event": "agent.alert",
  "at": "2026-11-01T15:04:59Z",
  "data": {
    "findings": [
      {
        "severity": "high",
        "category": "service",
        "title": "Service mariadb is not running",
        "summary": "mariadb is inactive"
      }
    ]
  }
}
```

Examples for the other events:

```json
{"event":"certificate.failed","at":"2026-11-01T15:10:00Z","data":{"domain":"example.com","message":"ACME challenge failed"}}
{"event":"backup.created","at":"2026-11-01T15:20:00Z","data":{"username":"acct1","id":"20261101T152000Z-acct1","size_bytes":1048576,"path":"/var/backups/rynxcp/..."}}
{"event":"website.cloned","at":"2026-11-01T15:30:00Z","data":{"source":"example.com","target":"staging.example.com","with_database":true}}
```

## Verify the signature

The signature is `sha256=` followed by the lowercase hex HMAC-SHA256 of the
**raw request body**, using the webhook secret as the key. Verify the raw bytes,
not a re-serialized JSON object.

### Node.js

```js
const crypto = require('crypto');

function verify(rawBody, signature, secret) {
  const expected =
    'sha256=' + crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
  const a = Buffer.from(expected);
  const b = Buffer.from(signature || '');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
```

### Python

```python
import hashlib
import hmac

def verify(raw_body: bytes, signature: str, secret: str) -> bool:
    expected = "sha256=" + hmac.new(
        secret.encode(), raw_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature or "")
```

### PHP

```php
$expected = 'sha256=' . hash_hmac('sha256', $rawBody, $secret);
$ok = hash_equals($expected, $_SERVER['HTTP_X_RYNX_SIGNATURE'] ?? '');
```

Reject the request when the signature does not match. Optionally reject events
whose `at` timestamp is too old for your replay window, and de-duplicate by
event body if your workflow is not idempotent.

## Test locally

A minimal receiver that prints the event and checks the signature:

```python
from http.server import BaseHTTPRequestHandler, HTTPServer
import hashlib, hmac, json, os

SECRET = os.environ["RYNX_WEBHOOK_SECRET"]

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers["content-length"]))
        expected = "sha256=" + hmac.new(
            SECRET.encode(), raw, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, self.headers.get("x-rynx-signature", "")):
            self.send_response(401)
            self.end_headers()
            return
        print(self.headers.get("x-rynx-event"), json.loads(raw))
        self.send_response(204)
        self.end_headers()

HTTPServer(("127.0.0.1", 9000), Handler).serve_forever()
```

Expose it through an HTTPS reverse proxy: RYNXCP rejects plain HTTP and private
destinations, including `127.0.0.1`.

## Troubleshooting

- Check `journalctl -u rynx-api -n 100 --no-pager` for `webhook delivery failed`.
- Confirm the endpoint returns a 2xx status and responds within 10 seconds.
- Confirm DNS resolves to a public address at delivery time.
- The panel does not retry failed deliveries; use the receiving service's queue
  or trigger the action again.
- Deleting a webhook stops future deliveries immediately.
