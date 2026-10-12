import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

export type OAuthSignedClaims = Record<string, unknown> & {
  typ: string;
  iat: number;
  exp: number;
};

const VERSION = 'v1';
const MAX_TOKEN_LENGTH = 32768;

function signingKey(): Buffer {
  const githubSecret = process.env.GITHUB_OAUTH_CLIENT_SECRET || '';
  const proxySecret = process.env.PROXY_SECRET || '';
  if (!githubSecret || !proxySecret) {
    throw new Error('OAuth token signing is not configured.');
  }
  return createHash('sha256')
    .update('mcp-on-vercel/oauth-signed-claims/v1\0')
    .update(githubSecret)
    .update('\0')
    .update(proxySecret)
    .digest();
}

export function signOAuthClaims(claims: OAuthSignedClaims): string {
  const payload = Buffer.from(JSON.stringify(claims), 'utf8').toString('base64url');
  const unsigned = VERSION + '.' + payload;
  const signature = createHmac('sha256', signingKey()).update(unsigned).digest('base64url');
  return unsigned + '.' + signature;
}

export function issueOAuthClaims(
  claims: Record<string, unknown> & { typ: string },
  lifetimeSeconds: number
): string {
  const now = Math.floor(Date.now() / 1000);
  return signOAuthClaims({ ...claims, iat: now, exp: now + lifetimeSeconds } as OAuthSignedClaims);
}

export function verifyOAuthClaims(token: unknown, expectedType?: string): OAuthSignedClaims | null {
  if (typeof token !== 'string' || token.length < 32 || token.length > MAX_TOKEN_LENGTH) return null;
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== VERSION) return null;

  let expectedSignature: Buffer;
  let actualSignature: Buffer;
  try {
    const unsigned = parts[0] + '.' + parts[1];
    expectedSignature = createHmac('sha256', signingKey()).update(unsigned).digest();
    actualSignature = Buffer.from(parts[2], 'base64url');
  } catch {
    return null;
  }
  if (actualSignature.length !== expectedSignature.length || !timingSafeEqual(actualSignature, expectedSignature)) return null;

  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  const claims = parsed as Record<string, unknown>;
  if (typeof claims.typ !== 'string' || (expectedType && claims.typ !== expectedType)) return null;
  if (!Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp)) return null;

  const now = Math.floor(Date.now() / 1000);
  if ((claims.exp as number) <= now || (claims.iat as number) > now + 60 || (claims.exp as number) <= (claims.iat as number)) return null;
  return claims as OAuthSignedClaims;
}
