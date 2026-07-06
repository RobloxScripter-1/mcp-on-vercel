// api/server.ts
//
// A real MCP server (not a raw proxy) built with mcp-handler's
// createMcpHandler. Each tool below calls GitHub's REST API directly
// using a server-side Personal Access Token (PAT) — Claude never sees
// the token, only the tool results.
//
// Auth model (deliberately simple — private single-user server):
//   Claude web  --?key=SHARED_SECRET-->  this Vercel route  --PAT-->  GitHub REST API
//
// Setup (Vercel Project Settings > Environment Variables):
//   GITHUB_PAT     - your fine-grained github_pat_... token,
//                    scoped to only the repos you want Claude touching,
//                    with Contents: Read and write (+ Pull requests,
//                    Issues if you want those tools to work)
//   PROXY_SECRET   - a long random string only you know
//
// Claude web custom connector URL:
//   https://<your-project>.vercel.app/mcp?key=<PROXY_SECRET>
//
// package.json needs: mcp-handler, @modelcontextprotocol/sdk (>=1.26.0), zod

import { createMcpHandler } from 'mcp-handler';
import { z } from 'zod';

const GITHUB_PAT = process.env.GITHUB_PAT!;
const PROXY_SECRET = process.env.PROXY_SECRET!;
const GITHUB_API = 'https://api.github.com';

function secretsMatch(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function githubRequest(path: string, init: RequestInit = {}) {
  const res = await fetch(`${GITHUB_API}${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${GITHUB_PAT}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      ...(init.headers as Record<string, string> | undefined),
    },
  });
  const text = await res.text();
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    data = text;
  }
  if (!res.ok) {
    throw new Error(`GitHub API ${res.status}: ${JSON.stringify(data)}`);
  }
  return data;
}

const mcpHandler = createMcpHandler((server) => {
  server.tool(
    'list_files',
    'List files and folders in a GitHub repo path',
    {
      owner: z.string().describe('Repo owner, e.g. "octocat"'),
      repo: z.string().describe('Repo name'),
      path: z.string().default('').describe('Path within repo, empty for root'),
      branch: z.string().optional().describe('Branch name, defaults to repo default branch'),
    },
    async ({ owner, repo, path, branch }) => {
      const q = branch ? `?ref=${encodeURIComponent(branch)}` : '';
      const data = await githubRequest(`/repos/${owner}/${repo}/contents/${path}${q}`);
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'read_file',
    'Read the contents of a single file from a GitHub repo',
    {
      owner: z.string(),
      repo: z.string(),
      path: z.string().describe('Full file path, e.g. "src/index.js"'),
      branch: z.string().optional(),
    },
    async ({ owner, repo, path, branch }) => {
      const q = branch ? `?ref=${encodeURIComponent(branch)}` : '';
      const data: any = await githubRequest(`/repos/${owner}/${repo}/contents/${path}${q}`);
      const content = data.content
        ? Buffer.from(data.content, data.encoding ?? 'base64').toString('utf-8')
        : '';
      return { content: [{ type: 'text', text: content }] };
    }
  );

  server.tool(
    'create_or_update_file',
    'Create a new file or update an existing one in a GitHub repo (commits directly to a branch)',
    {
      owner: z.string(),
      repo: z.string(),
      path: z.string(),
      content: z.string().describe('The full new file content, as plain text'),
      message: z.string().describe('Commit message'),
      branch: z.string().optional().describe('Branch to commit to, defaults to repo default branch'),
    },
    async ({ owner, repo, path, content, message, branch }) => {
      let sha: string | undefined;
      try {
        const existing: any = await githubRequest(
          `/repos/${owner}/${repo}/contents/${path}${branch ? `?ref=${branch}` : ''}`
        );
        sha = existing.sha;
      } catch {
        // File doesn't exist yet — that's fine, we're creating it.
      }

      const body: Record<string, unknown> = {
        message,
        content: Buffer.from(content, 'utf-8').toString('base64'),
      };
      if (sha) body.sha = sha;
      if (branch) body.branch = branch;

      const data = await githubRequest(`/repos/${owner}/${repo}/contents/${path}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'create_pull_request',
    'Open a pull request in a GitHub repo',
    {
      owner: z.string(),
      repo: z.string(),
      title: z.string(),
      head: z.string().describe('Branch containing your changes'),
      base: z.string().describe('Branch you want to merge into, e.g. "main"'),
      body: z.string().optional().describe('PR description'),
    },
    async ({ owner, repo, title, head, base, body }) => {
      const data = await githubRequest(`/repos/${owner}/${repo}/pulls`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title, head, base, body }),
      });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'list_issues',
    'List open issues in a GitHub repo',
    {
      owner: z.string(),
      repo: z.string(),
      state: z.enum(['open', 'closed', 'all']).default('open'),
    },
    async ({ owner, repo, state }) => {
      const data = await githubRequest(`/repos/${owner}/${repo}/issues?state=${state}`);
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
});

async function handler(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const providedKey = url.searchParams.get('key');

  if (!PROXY_SECRET || !providedKey || !secretsMatch(providedKey, PROXY_SECRET)) {
    return new Response('Unauthorized', { status: 401 });
  }

  return mcpHandler(req);
}

export { handler as GET, handler as POST, handler as DELETE };
