// app/mcp/route.ts
// Proxies MCP tool calls to GitHub's remote MCP server, injecting a
// server-side GitHub PAT so Claude web never needs to hold the token.
//
// Auth model (deliberately simple — private single-user server):
//   Claude web  --?key=SHARED_SECRET-->  this Vercel route  --PAT-->  GitHub MCP
//
// This is NOT OAuth. It's a shared secret in the URL's query string.
// That's an acceptable tradeoff ONLY if:
//   - this URL is never shared, committed to a public repo, or logged
//     anywhere public
//   - the underlying PAT is scoped to only the repos you actually want
//     Claude touching (never an all-repos token)
//
// Setup (Vercel Project Settings > Environment Variables):
//   GITHUB_PAT     - your fine-grained github_pat_... token
//   PROXY_SECRET   - a long random string you generate yourself
//                    (e.g. run: openssl rand -hex 32)
//
// Claude web custom connector URL:
//   https://<your-project>.vercel.app/mcp?key=<PROXY_SECRET>

const GITHUB_MCP_URL = 'https://api.githubcopilot.com/mcp/';
const GITHUB_PAT = process.env.GITHUB_PAT!;
const PROXY_SECRET = process.env.PROXY_SECRET!;

// Constant-time-ish comparison to avoid trivial timing attacks on the secret.
function secretsMatch(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

async function forwardToGitHub(body: unknown, incoming: Headers): Promise<Response> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${GITHUB_PAT}`,
  };

  // Streamable HTTP servers care about Accept (often needs to include
  // text/event-stream) and about the session id once one's been issued.
  const accept = incoming.get('accept');
  if (accept) headers['Accept'] = accept;

  const sessionId = incoming.get('mcp-session-id');
  if (sessionId) headers['Mcp-Session-Id'] = sessionId;

  return fetch(GITHUB_MCP_URL, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });
}

async function handleRequest(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const providedKey = url.searchParams.get('key');

  if (!PROXY_SECRET || !providedKey || !secretsMatch(providedKey, PROXY_SECRET)) {
    return new Response('Unauthorized', { status: 401 });
  }

  if (req.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return new Response('Invalid JSON', { status: 400 });
  }

  const upstream = await forwardToGitHub(body, req.headers);

  // Stream the body through untouched rather than buffering with .text() —
  // GitHub's MCP server can reply with text/event-stream (SSE), and
  // buffering breaks that.
  const headers = new Headers();
  upstream.headers.forEach((value, key) => {
    if (!['content-encoding', 'content-length', 'connection'].includes(key.toLowerCase())) {
      headers.set(key, value);
    }
  });

  return new Response(upstream.body, {
    status: upstream.status,
    headers,
  });
}

export { handleRequest as GET, handleRequest as POST };
