# Middesk OAuth key rotation demo

A Node.js client for the Middesk API that authenticates as an OAuth `client_credentials` client
using `private_key_jwt` with RSA keys, and rotates its own keys without an API key.

A slide deck version of this walkthrough lives in [`docs/index.html`](docs/index.html).

`npm run demo` walks through:

1. **Bootstrap with an API key.** Generate RSA key `k1` and register a client with
   `token_endpoint_auth_method: private_key_jwt`, `jwks: { keys: [k1] }`, and
   `access_token_ttl: 600`, so tokens last 10 minutes instead of the default hour. The client has
   no usable secret.
2. **Get a token.** Sign an RFC 7523 client assertion with `k1` and exchange it at `/oauth/token`.
   The response carries `expires_in: 600`.
3. **Create a business** with `POST /v1/businesses`, using the access token.
4. **Add a key.** Generate `k2` and `PUT /oauth/clients/:client_id/jwks` with `[k1, k2]`, signing
   the request with `k1`.
5. **Use the new key.** Get a token with an assertion signed by `k2`.
6. **Guard rail.** A key set that drops the key signing the request is refused, so a client
   cannot lock itself out.
7. **Retire the old key.** `PUT` the key set `[k2]`, signing with `k2`.
8. **The old key is dead.** An assertion signed by `k1` is rejected with `invalid_client`.
9. **Audit.** `GET /v1/security_event_logs` with the `k2` token shows both rotations as
   `change_settings` events with the key IDs before and after.

The demo deletes its OAuth client at the end; set `KEEP_CLIENT=1` to keep it. An account can have
at most five OAuth clients.

## How the key rotation endpoint authenticates

`PUT /oauth/clients/:client_id/jwks` takes no API key, access token or client secret. The client
signs a client assertion with one of its registered keys and sends it as the
`client_assertion_type` and `client_assertion` form fields, as it does at `/oauth/token`. Only
`private_key_jwt` clients can use it. Clients that authenticate with a secret are refused, even if
they have keys stored: those keys would become trusted the moment an admin switched the client to
`private_key_jwt`, and would outlive the secret they were written with.

Rules for the assertion:

- **Audience:** `aud` must be `<issuer>/oauth/clients/<client_id>/jwks`. The token endpoint does
  not accept this audience, and this endpoint does not accept the token endpoint's.
- **Single use:** each `jti` is accepted once, and the lifetime (`exp - iat`) is at most 10
  minutes.
- **Keep the signing key:** the new key set must still contain the key that signed the request,
  with the same `kid` and the same key material. Rotation therefore takes two steps: add the new
  key signing with the old one, then remove the old key signing with the new one.

The request body is form-encoded, and `jwks` is a JSON string:

```text
PUT /oauth/clients/<client_id>/jwks
Content-Type: application/x-www-form-urlencoded

client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=<signed JWT>
&jwks={"keys":[{"kty":"RSA","kid":"k2","n":"...","e":"AQAB"}]}
```

Only `jwks` can change. Changes to the redirect URI, grant types, token lifetime and
authentication method still need the account's API key or the dashboard.

| Status | `error` | Cause |
|---|---|---|
| 200 | | Success. The body is `{ "client_id": ..., "jwks": ... }`. |
| 400 | `invalid_request` | `jwks` is missing. |
| 400 | `invalid_client_metadata` | `jwks` is not valid JSON or not a valid key set, contains private key material, or leaves out the signing key. |
| 401 | `invalid_client` | Authentication failed. |

## Running it

Requires Node.js 20 or later.

```bash
npm install
```

```bash
cp .env.example .env
```

Set `MIDDESK_API_KEY` in `.env` to an API key for the account. The issuer defaults to
`MIDDESK_API_URL`; set `MIDDESK_ISSUER` if the API expects a different audience. Then:

```bash
npm run demo
```

### Against a local Middesk API

Running against a local checkout of the Middesk API needs:

- **Database:** migrated to the current schema, with the package named by `MIDDESK_PACKAGE`
  (`identity` by default) enabled on the account.
- **API:** `bundle exec rails s` on port 3002.
- **Worker:** `bundle exec sidekiq -q low_priority`. Security events are written by a background
  job on that queue, and step 9 waits for them.

## Files

- `src/keys.js`: RSA key generation, JWK export and client assertion signing, using
  [`jose`](https://github.com/panva/jose)
- `src/middesk.js`: a small API client, grouped by how each call authenticates (API key, client
  assertion, or access token)
- `src/demo.js`: the walkthrough
