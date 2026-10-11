const BASE_URL = (process.env.MCP_PUBLIC_BASE_URL || 'https://mcp-on-vercel-msaiful0404-5024s-projects.vercel.app').replace(/\/+$/, '');
const CALLBACK = `${BASE_URL}/oauth/github/callback`;
const RESOURCE = process.env.MCP_RESOURCE_URL || `${BASE_URL}/mcp`;

const json = (value: unknown, status = 200) => new Response(JSON.stringify(value, null, 2), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }
});

const safe = (value: unknown) => String(value ?? 'unknown').slice(0, 240);

async function redis(command: string[]) {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) throw new Error(`missing_redis_config:${!url ? 'url' : ''}${!url && !token ? ',' : ''}${!token ? 'token' : ''}`);
  const response = await fetch(url, {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify(command),
    cache: 'no-store'
  });
  const text = await response.text();
  let body: any;
  try { body = JSON.parse(text); } catch { throw new Error(`redis_non_json_http_${response.status}`); }
  if (!response.ok || body?.error) throw new Error(`redis_http_${response.status}:${safe(body?.error || 'unknown_error')}`);
  return body.result;
}

async function check(name: string, fn: () => Promise<any>) {
  const started = Date.now();
  try {
    const result = await fn();
    return { name, ok: true, duration_ms: Date.now() - started, result };
  } catch (error: any) {
    return { name, ok: false, duration_ms: Date.now() - started, error: safe(error?.message || error) };
  }
}

export async function GET() {
  const required = [
    'GITHUB_OAUTH_CLIENT_ID', 'GITHUB_OAUTH_CLIENT_SECRET', 'GITHUB_ALLOWED_LOGIN',
    'GITHUB_PAT', 'PROXY_SECRET', 'UPSTASH_REDIS_REST_URL', 'UPSTASH_REDIS_REST_TOKEN'
  ];

  const checks: any[] = [];
  checks.push(await check('environment_variables', async () => ({
    required: Object.fromEntries(required.map(k => [k, Boolean(process.env[k])])),
    missing: required.filter(k => !process.env[k])
  })));

  checks.push(await check('base_url_and_callback', async () => {
    const base = new URL(BASE_URL);
    const callback = new URL(CALLBACK);
    return {
      base_url: base.origin,
      callback_host: callback.host,
      callback_path: callback.pathname,
      callback_is_https: callback.protocol === 'https:',
      resource: RESOURCE,
      callback_matches_base_host: callback.host === base.host
    };
  }));

  checks.push(await check('redis_ping', async () => await redis(['PING'])));

  const diagnosticKey = `mcp_oauth_diag:${crypto.randomUUID()}`;
  checks.push(await check('redis_set_get_del', async () => {
    await redis(['SET', diagnosticKey, 'ok', 'EX', '60']);
    const value = await redis(['GET', diagnosticKey]);
    const deleted = await redis(['DEL', diagnosticKey]);
    return { get_value: value, del_result: deleted };
  }));

  checks.push(await check('github_authorize_endpoint', async () => {
    if (!process.env.GITHUB_OAUTH_CLIENT_ID) throw new Error('missing_github_oauth_client_id');
    const url = new URL('https://github.com/login/oauth/authorize');
    url.searchParams.set('client_id', process.env.GITHUB_OAUTH_CLIENT_ID);
    url.searchParams.set('redirect_uri', CALLBACK);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', 'read:user');
    url.searchParams.set('state', 'diagnostic-state');
    const response = await fetch(url, { redirect: 'manual', cache: 'no-store' });
    return {
      http_status: response.status,
      location_present: Boolean(response.headers.get('location')),
      location_host: response.headers.get('location') ? new URL(response.headers.get('location')!).host : null,
      content_type: response.headers.get('content-type') || null
    };
  }));

  checks.push(await check('github_pat_user', async () => {
    if (!process.env.GITHUB_PAT) throw new Error('missing_github_pat');
    const response = await fetch('https://api.github.com/user', {
      headers: {
        authorization: `Bearer ${process.env.GITHUB_PAT}`,
        accept: 'application/vnd.github+json',
        'x-github-api-version': '2022-11-28',
        'user-agent': 'mcp-on-vercel-diagnostics'
      },
      cache: 'no-store'
    });
    const text = await response.text();
    let body: any = null;
    try { body = JSON.parse(text); } catch {}
    return {
      http_status: response.status,
      json: Boolean(body),
      login: typeof body?.login === 'string' ? body.login : null,
      allowlist_match: typeof body?.login === 'string' && typeof process.env.GITHUB_ALLOWED_LOGIN === 'string'
        ? body.login.toLowerCase() === process.env.GITHUB_ALLOWED_LOGIN.toLowerCase()
        : false,
      message: typeof body?.message === 'string' ? body.message : null
    };
  }));

  const failed = checks.filter(c => !c.ok);
  return json({
    diagnostic: 'oauth_exhaustive',
    timestamp: new Date().toISOString(),
    public_base_url: BASE_URL,
    callback_url: CALLBACK,
    resource: RESOURCE,
    summary: { total_checks: checks.length, passed: checks.length - failed.length, failed: failed.length },
    checks
  }, failed.length ? 503 : 200);
}
