const BASE_URL = (process.env.MCP_PUBLIC_BASE_URL || 'https://mcp-on-vercel-msaiful0404-5024s-projects.vercel.app').replace(/\/+$/, '');
const RESOURCE = process.env.MCP_RESOURCE_URL || `${BASE_URL}/mcp`;
const METADATA_URL = `${BASE_URL}/.well-known/oauth-protected-resource/mcp`;

async function redisGet(key: string): Promise<any | null> {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) throw new Error('OAuth storage is not configured.');
  const r = await fetch(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(['GET', key]),
    cache: 'no-store',
  });
  const j = await r.json() as { result?: unknown; error?: string };
  if (!r.ok || j.error) throw new Error('OAuth storage request failed.');
  if (typeof j.result !== 'string') return null;
  try { return JSON.parse(j.result); } catch { return null; }
}

function challenge(error?: string): Response {
  return new Response('Unauthorized', {
    status: 401,
    headers: {
      'WWW-Authenticate': `Bearer resource_metadata="${METADATA_URL}", scope="github"${error ? ', error="invalid_token"' : ''}`,
      'Cache-Control': 'no-store',
    },
  });
}

async function handler(request: Request): Promise<Response> {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204 });

  const match = /^Bearer\s+([A-Za-z0-9_-]{32,})$/i.exec(request.headers.get('authorization') || '');
  if (!match) return challenge();

  if (!process.env.UPSTASH_REDIS_REST_URL || !process.env.UPSTASH_REDIS_REST_TOKEN || !process.env.PROXY_SECRET) {
    return new Response('MCP authentication is not configured.', { status: 503 });
  }

  try {
    const record = await redisGet(`mcp_access_token:${match[1]}`);
    const allowed = (process.env.GITHUB_ALLOWED_LOGIN || '').trim().toLowerCase();
    if (!record || record.resource !== RESOURCE || record.scope !== 'github' ||
        typeof record.login !== 'string' || record.login.toLowerCase() !== allowed) {
      return challenge('invalid_token');
    }
  } catch {
    return new Response('Authentication storage is temporarily unavailable.', { status: 503 });
  }

  const upstream = new URL(`${BASE_URL}/api/server`);
  upstream.searchParams.set('key', process.env.PROXY_SECRET);

  const headers = new Headers(request.headers);
  headers.delete('host');
  headers.delete('authorization');

  const upstreamResponse = await fetch(upstream, {
    method: request.method,
    headers,
    body: request.method === 'GET' || request.method === 'HEAD' ? undefined : await request.arrayBuffer(),
    redirect: 'manual',
    cache: 'no-store',
  });

  const responseHeaders = new Headers(upstreamResponse.headers);
  responseHeaders.set('Cache-Control', 'no-store');
  return new Response(upstreamResponse.body, {
    status: upstreamResponse.status,
    statusText: upstreamResponse.statusText,
    headers: responseHeaders,
  });
}

export { handler as GET, handler as POST, handler as DELETE };
