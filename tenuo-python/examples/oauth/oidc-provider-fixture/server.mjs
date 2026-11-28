// Local test fixture only: real protocol implementation, development-only login UI.
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import Provider, { errors } from 'oidc-provider';

const issuer = process.env.OIDC_SMOKE_ISSUER;
const callback = process.env.OIDC_SMOKE_CALLBACK;
if (!issuer?.startsWith('http://127.0.0.1:') || !callback?.startsWith('http://127.0.0.1:')) {
  throw new Error('Fixture requires explicit loopback URLs');
}
const resource = 'https://tenuo.example.test/authority';
const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...privateKey.export({ format: 'jwk' }), kid: 'smoke-rsa', alg: 'RS256', use: 'sig' };
const clients = ['support', 'mail-support', 'no-tenant', 'opaque'].map(client_id => ({
  client_id, redirect_uris: [callback], response_types: ['code'],
  grant_types: ['authorization_code', 'refresh_token'], token_endpoint_auth_method: 'none',
}));
const provider = new Provider(issuer, {
  clients,
  jwks: { keys: [jwk] },
  cookies: { keys: [randomBytes(32).toString('hex')] },
  scopes: ['openid', 'offline_access', 'refunds:write', 'mail:send'],
  pkce: { required: () => true },
  features: {
    devInteractions: { enabled: true },
    resourceIndicators: {
      enabled: true,
      defaultResource: () => resource,
      useGrantedResource: () => true,
      getResourceServerInfo(ctx, requested, client) {
        if (![resource, 'https://other.example.test/api'].includes(requested)) throw new errors.InvalidTarget();
        return {
          audience: requested === resource ? 'tenuo-authority' : 'other-api',
          scope: client.clientId === 'mail-support' ? 'mail:send' : 'refunds:write',
          accessTokenTTL: 180,
          accessTokenFormat: client.clientId === 'opaque' ? 'opaque' : 'jwt',
          jwt: { sign: { alg: 'RS256' } },
        };
      },
    },
  },
  async findAccount(ctx, id) {
    if (!['alice', 'bob'].includes(id)) return undefined;
    return { accountId: id, async claims() { return { sub: id }; } };
  },
  async extraTokenClaims(ctx, token) {
    if (token.clientId === 'no-tenant') return {};
    return { tenant_id: token.accountId === 'alice' ? 'acme' : 'other' };
  },
});
provider.listen(Number(new URL(issuer).port), '127.0.0.1');
