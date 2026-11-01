# Passkeys (WebAuthn)

RYNXCP supports WebAuthn passkeys as an additional login factor. After a valid
password, a user with a registered passkey can confirm the login with Face ID,
Touch ID, Windows Hello, a phone or a hardware security key instead of typing
the email code.

Passkeys do not replace the password in this release. They are a second factor
and coexist with the email code.

## Requirements

- The panel must be served over HTTPS with a public domain name. Passkeys are
  not offered for plain HTTP or IP-address installations.
- `public_url` in `/etc/rynxcp/api.toml` must match the browser origin, for
  example `https://panel.example.com:2083`.
- The browser must support WebAuthn. Current Chrome, Edge, Firefox and Safari
  all do.

The WebAuthn relying-party ID is derived from the host in `public_url`. Changing
the panel hostname makes previously registered passkeys unusable.

## Register a passkey

Open **API > Passkeys > Añadir passkey**, give the credential a name (for
example `Laptop` or `YubiKey`) and confirm with the device.

The underlying API uses a two-step ceremony:

```text
POST /api/v1/passkeys
{ "name": "Laptop" }

200 OK
{ "flow": "<short-lived token>", "options": { "publicKey": { ... } } }
```

Pass `options.publicKey` to `navigator.credentials.create()`, converting
`challenge`, `user.id` and `excludeCredentials[].id` from base64url to
`ArrayBuffer`. Then send the credential:

```text
POST /api/v1/passkeys/finish
{
  "flow": "<short-lived token>",
  "credential": {
    "id": "...",
    "rawId": "...",
    "type": "public-key",
    "response": {
      "attestationObject": "...",
      "clientDataJSON": "..."
    }
  }
}
```

The flow token expires after five minutes and is single-use. Up to 20 passkeys
can be registered per panel user. Remove one with:

```text
DELETE /api/v1/passkeys/{id}
```

## Log in with a passkey

After the password step, login returns:

```json
{
  "two_factor_required": true,
  "challenge": "<email-second-factor challenge>",
  "email": "a***@example.com",
  "expires_in": 600,
  "email_sent": true,
  "passkey_available": true
}
```

If the email code could not be sent but the user has a passkey, the response
still succeeds with `email_sent: false`; the passkey button remains available.

Start the assertion:

```text
POST /api/v1/auth/passkey/begin
{ "challenge": "<challenge from login>" }

200 OK
{ "flow": "<short-lived token>", "options": { "publicKey": { ... } } }
```

Pass `options.publicKey` to `navigator.credentials.get()`, converting
`challenge` and `allowCredentials[].id` from base64url to `ArrayBuffer`. Then:

```text
POST /api/v1/auth/passkey/finish
{
  "flow": "<short-lived token>",
  "credential": {
    "id": "...",
    "rawId": "...",
    "type": "public-key",
    "response": {
      "authenticatorData": "...",
      "clientDataJSON": "...",
      "signature": "...",
      "userHandle": null
    }
  }
}
```

A successful response has the same shape as a normal login: `user`,
`csrf_token`, `expires_at` and `impersonated_by`, plus the session cookie. The
email challenge is consumed, so it cannot be reused.

## Security notes

- The password is still required; a passkey alone does not start a session.
- Challenge and registration state are kept in server memory and expire after
  five minutes.
- Credential public keys are stored in `panel.db`; private keys never leave the
  authenticator.
- Removing a passkey takes effect immediately. Deleting the last passkey leaves
  the email code as the only second factor.
- Use a passkey name that identifies the device so users can revoke a lost
  device without deleting the others.

## Troubleshooting

- The **Añadir passkey** button only appears with HTTPS and a public domain.
- `passkey_available` is false when the user has no credentials, the panel is
  not HTTPS, or the build does not include WebAuthn support.
- If the browser shows a security error, confirm `public_url` exactly matches
  the address in the browser, including the port.
- If the authenticator prompt is cancelled, no credential is created and the
  flow token is discarded; start again.
- Check `journalctl -u rynx-api -n 100 --no-pager` for failed assertions.
