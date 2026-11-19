import { clientAssertion } from './keys.js';

export class MiddeskError extends Error {
  constructor(method, path, status, body) {
    super(`${method} ${path} failed with ${status}: ${JSON.stringify(body)}`);
    this.status = status;
    this.body = body;
  }
}

export class Middesk {
  constructor({ apiUrl, issuer = apiUrl }) {
    this.apiUrl = apiUrl.replace(/\/$/, '');
    this.issuer = issuer.replace(/\/$/, '');
  }

  // Account administration, authenticated with an API key. The demo uses it only to create
  // the OAuth client and to delete it afterwards.

  createOAuthClient(apiKey, attributes) {
    return this.#json('POST', '/v1/oauth_clients', { bearer: apiKey, body: attributes });
  }

  deleteOAuthClient(apiKey, clientId) {
    return this.#json('DELETE', `/v1/oauth_clients/${clientId}`, { bearer: apiKey });
  }

  // Client authentication: each call proves possession of a registered private key with a
  // fresh, single-use client assertion addressed to that endpoint.

  async requestToken({ clientId, key, scope }) {
    const assertion = await clientAssertion({
      clientId,
      key,
      audience: `${this.issuer}/oauth/token`,
    });

    return this.#form('/oauth/token', {
      grant_type: 'client_credentials',
      ...(scope ? { scope } : {}),
      ...assertion,
    });
  }

  async replaceJwks({ clientId, key, jwks }) {
    const path = `/oauth/clients/${clientId}/jwks`;
    const assertion = await clientAssertion({
      clientId,
      key,
      audience: `${this.issuer}${path}`,
    });

    return this.#form(path, { jwks: JSON.stringify(jwks), ...assertion }, 'PUT');
  }

  // Resource calls, authenticated with the short-lived access token.

  createBusiness(accessToken, business) {
    return this.#json('POST', '/v1/businesses', { bearer: accessToken, body: business });
  }

  listSecurityEventLogs(accessToken, query = {}) {
    const params = new URLSearchParams(query).toString();
    return this.#json('GET', `/v1/security_event_logs?${params}`, { bearer: accessToken });
  }

  #form(path, fields, method = 'POST') {
    return this.#request(method, path, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(fields).toString(),
    });
  }

  #json(method, path, { bearer, body }) {
    return this.#request(method, path, {
      headers: {
        Authorization: `Bearer ${bearer}`,
        ...(body ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
  }

  async #request(method, path, { headers, body }) {
    const response = await fetch(`${this.apiUrl}${path}`, {
      method,
      headers: { Accept: 'application/json', ...headers },
      body,
    });
    const text = await response.text();
    const parsed = text ? JSON.parse(text) : null;

    if (!response.ok) throw new MiddeskError(method, path, response.status, parsed);
    return parsed;
  }
}
