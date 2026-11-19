import { setTimeout as sleep } from 'node:timers/promises';
import { generateSigningKey, jwksOf } from './keys.js';
import { Middesk, MiddeskError } from './middesk.js';

const ACCESS_TOKEN_TTL_SECONDS = 600;

const apiUrl = process.env.MIDDESK_API_URL ?? 'http://localhost:3002';
const apiKey = process.env.MIDDESK_API_KEY;
if (!apiKey) {
  console.error('Set MIDDESK_API_KEY (see .env.example).');
  process.exit(1);
}

const middesk = new Middesk({ apiUrl, issuer: process.env.MIDDESK_ISSUER ?? apiUrl });

let step = 0;
function heading(title) {
  step += 1;
  console.log(`\n${step}. ${title}`);
}
function detail(label, value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  console.log(`   ${label}: ${text}`);
}
const kids = (jwks) => jwks.keys.map((key) => key.kid);

async function expectRejected(promise, expectedStatus) {
  try {
    await promise;
  } catch (error) {
    if (error instanceof MiddeskError && error.status === expectedStatus) return error.body;
    throw error;
  }
  throw new Error(`expected the request to be rejected with ${expectedStatus}`);
}

async function rotationEvents(accessToken, clientId, expected) {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const { data } = await middesk.listSecurityEventLogs(accessToken, {
      action: 'change_settings',
      include_payload: 'true',
      per_page: '20',
    });
    const events = data
      .map((event) => ({ ...event, payload: parsePayload(event.payload) }))
      .filter((event) => event.payload?.oauth_client_id === clientId);
    if (events.length >= expected) return events;
    await sleep(1000);
  }
  throw new Error('security events did not appear; is Sidekiq processing the low_priority queue?');
}

function parsePayload(payload) {
  return typeof payload === 'string' ? JSON.parse(payload) : payload;
}

async function main() {
  heading('Bootstrap: generate key k1 and register a private_key_jwt client with the API key');
  const k1 = await generateSigningKey(`k1-${Date.now()}`);
  const client = await middesk.createOAuthClient(apiKey, {
    name: 'Key rotation demo',
    redirect_uri: 'https://example.com/oauth/unused',
    allowed_grant_types: ['client_credentials'],
    token_endpoint_auth_method: 'private_key_jwt',
    access_token_ttl: ACCESS_TOKEN_TTL_SECONDS,
    jwks: jwksOf(k1),
  });
  const clientId = client.client_id;
  detail('client_id', clientId);
  detail('token_endpoint_auth_method', client.token_endpoint_auth_method);
  detail('access_token_ttl', `${client.access_token_ttl}s`);
  detail('registered kids', kids(client.jwks));
  detail('secret', `${client.secret} (withheld for private_key_jwt clients)`);

  try {
    heading('Request an access token with a client assertion signed by k1');
    const token1 = await middesk.requestToken({ clientId, key: k1 });
    detail('expires_in', `${token1.expires_in}s`);
    detail('scope', token1.scope);

    heading('Create a business with the access token');
    const business = await middesk.createBusiness(token1.access_token, {
      name: 'Middesk Inc',
      addresses: [
        {
          address_line1: '85 Second Street',
          address_line2: 'Suite 710',
          city: 'San Francisco',
          state: 'CA',
          postal_code: '94105',
        },
      ],
      orders: [{ package: process.env.MIDDESK_PACKAGE ?? 'identity' }],
    });
    detail('business', { id: business.id, name: business.name, status: business.status });

    heading('Rotate, part 1: generate k2 and register it, signing the request with k1');
    const k2 = await generateSigningKey(`k2-${Date.now()}`);
    const added = await middesk.replaceJwks({ clientId, key: k1, jwks: jwksOf(k1, k2) });
    detail('registered kids', kids(added.jwks));

    heading('Request an access token with an assertion signed by the new key k2');
    const token2 = await middesk.requestToken({ clientId, key: k2 });
    detail('expires_in', `${token2.expires_in}s`);

    heading('The API refuses a key set that drops the key signing the request');
    const refused = await expectRejected(
      middesk.replaceJwks({ clientId, key: k1, jwks: jwksOf(k2) }),
      400,
    );
    detail('response', refused);

    heading('Rotate, part 2: retire k1, signing the request with k2');
    const retired = await middesk.replaceJwks({ clientId, key: k2, jwks: jwksOf(k2) });
    detail('registered kids', kids(retired.jwks));

    heading('k1 can no longer obtain tokens');
    detail('response', await expectRejected(middesk.requestToken({ clientId, key: k1 }), 401));

    heading('Read the rotations back from the security event logs with the k2 token');
    const events = await rotationEvents(token2.access_token, clientId, 2);
    for (const event of events.reverse()) {
      detail(
        event.created_at,
        `${event.action}: ${event.payload.old_settings.jwks_kids.join(',')} -> ` +
          `${event.payload.new_settings.jwks_kids.join(',')}`,
      );
    }
  } finally {
    if (process.env.KEEP_CLIENT) {
      console.log(`\nKept OAuth client ${clientId}.`);
    } else {
      await middesk.deleteOAuthClient(apiKey, clientId);
      console.log(`\nDeleted OAuth client ${clientId}.`);
    }
  }
}

main().catch((error) => {
  console.error(`\n${error.message}`);
  process.exit(1);
});
