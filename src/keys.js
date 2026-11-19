import { randomUUID } from 'node:crypto';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';

const ALG = 'RS256';
const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

export async function generateSigningKey(kid) {
  const { privateKey, publicKey } = await generateKeyPair(ALG, {
    modulusLength: 2048,
    extractable: true,
  });
  const publicJwk = { ...(await exportJWK(publicKey)), kid, alg: ALG, use: 'sig' };

  return { kid, privateKey, publicJwk };
}

export function jwksOf(...keys) {
  return { keys: keys.map((key) => key.publicJwk) };
}

// RFC 7523 client assertion: iss and sub are the client_id, aud names the endpoint it is
// presented to, and the API accepts each jti once and lifetimes of at most ten minutes.
export async function clientAssertion({ clientId, key, audience }) {
  const assertion = await new SignJWT({})
    .setProtectedHeader({ alg: ALG, kid: key.kid })
    .setIssuer(clientId)
    .setSubject(clientId)
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime('2m')
    .setJti(randomUUID())
    .sign(key.privateKey);

  return { client_assertion_type: CLIENT_ASSERTION_TYPE, client_assertion: assertion };
}
