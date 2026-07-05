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

async function forwardToGitHub(body: unknown): Promise<Response> {
  return fetch(GITHUB_MCP_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${GITHUB_PAT}`,
    },
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

  const upstream = await forwardToGitHub(body);
  const text = await upstream.text();

  return new Response(text, {
    status: upstream.status,
    headers: {
      'Content-Type': upstream.headers.get('Content-Type') ?? 'application/json',
    },
  });
}

export { handleRequest as GET, handleRequest as POST };
