import { test, expect } from '@playwright/test';
import { readFileSync, readdirSync, mkdtempSync, rmSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import config from '../playwright.config.js';

const workflowDir = new URL('../../.github/workflows/', import.meta.url);
const stagingWorkflow = readFileSync(new URL('e2e-staging.yml', workflowDir), 'utf8');

// Execute the exact checked-in shell blocks, not a copy of their logic. Only
// dummy inputs enter the child; no ambient credentials or network requests.
function runShell(script: string, env: Record<string, string> = {}, cwd?: string) {
  const scratch = mkdtempSync(join(process.env.PAPERCLIP_RUN_SCRATCH_DIR || tmpdir(), 'workflow-test-'));
  const outputFile = join(scratch, 'github-output');
  try {
    const result = spawnSync('/bin/bash', ['--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', script], {
      encoding: 'utf8',
      timeout: 5_000,
      ...(cwd ? { cwd } : {}),
      env: { PATH: process.env.PATH, GITHUB_OUTPUT: outputFile, ...env },
    });
    expect(result.error).toBeUndefined();
    expect(result.signal).toBeNull();
    let output = result.stdout + result.stderr;
    // Failing preflights intentionally never create a configured output.
    try { output += readFileSync(outputFile, 'utf8'); } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
    return { status: result.status, output };
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

const preflights = [...stagingWorkflow.matchAll(
  /      - name: Check staging configuration\n([\s\S]*?)        run: \|\n((?:          [^\n]*\n)+)/g,
)];

const dummyPair = {
  CF_ACCESS_CLIENT_ID: 'dummy-client-id',
  CF_ACCESS_CLIENT_SECRET: 'dummy-client-secret',
};

test('both staging jobs have tested preflights', () => {
  expect(preflights).toHaveLength(2);
});

for (const [index, preflight] of preflights.entries()) {
  const script = preflight[2]!.replace(/^ {10}/gm, '');
  test.describe(index === 0 ? 'synthetic preflight' : 'journey preflight', () => {
    test('binds both Access secrets into the preflight environment', () => {
      expect(preflight[1]).toContain('CF_ACCESS_CLIENT_ID: ${{ secrets.CF_ACCESS_CLIENT_ID }}');
      expect(preflight[1]).toContain('CF_ACCESS_CLIENT_SECRET: ${{ secrets.CF_ACCESS_CLIENT_SECRET }}');
    });

    test('unconfigured staging skips offline', () => {
      const result = runShell(script);
      expect(result.status).toBe(0);
      expect(result.output).toContain('configured=false');
      expect(result.output).not.toContain('configured=true');
    });

    for (const [name, pair] of [
      ['both missing', {}],
      ['ID only', { CF_ACCESS_CLIENT_ID: dummyPair.CF_ACCESS_CLIENT_ID }],
      ['secret only', { CF_ACCESS_CLIENT_SECRET: dummyPair.CF_ACCESS_CLIENT_SECRET }],
    ] as const) {
      test(`configured staging rejects ${name} with names-only output`, () => {
        const result = runShell(script, { STAGING_BASE_URL: 'https://staging.example', ...pair });
        expect(result.status).not.toBe(0);
        expect(result.output).toContain('CF_ACCESS_CLIENT_ID');
        expect(result.output).toContain('CF_ACCESS_CLIENT_SECRET');
        expect(result.output).not.toContain('configured=true');
        expect(result.output).not.toContain(dummyPair.CF_ACCESS_CLIENT_ID);
        expect(result.output).not.toContain(dummyPair.CF_ACCESS_CLIENT_SECRET);
      });
    }

    test('configured staging with complete dummy pair proceeds', () => {
      const result = runShell(script, { STAGING_BASE_URL: 'https://staging.example', ...dummyPair });
      expect(result.status).toBe(0);
      expect(result.output).toContain('configured=true');
      expect(result.output).not.toContain(dummyPair.CF_ACCESS_CLIENT_ID);
      expect(result.output).not.toContain(dummyPair.CF_ACCESS_CLIENT_SECRET);
    });
  });
}

const ciWorkflow = readFileSync(new URL('ci.yml', workflowDir), 'utf8');
const aggregate = ciWorkflow.split('  ci-ok:\n')[1]?.match(/      - run: \|\n((?:          [^\n]*\n)+)/)?.[1];

test.describe('ci-ok aggregate', () => {
  for (const result of ['success', 'failure', 'cancelled', 'skipped']) {
    test(`e2e-lint ${result} ${result === 'success' ? 'passes' : 'fails'} the aggregate`, () => {
      expect(aggregate).toBeDefined();
      const needs = JSON.stringify({ placeholder: { result: 'success' }, 'e2e-lint': { result } }, null, 2);
      const script = aggregate!.replace(/^ {10}/gm, '');
      const actual = runShell(script, { NEEDS_JSON: needs });
      expect(actual.status).toBe(result === 'success' ? 0 : 1);
    });
  }
});

test('credential-bearing contexts do not record raw traces or screenshots', () => {
  expect(config.use?.trace).toBe('off');
  expect(config.use?.screenshot).toBe('off');
});

test('every workflow Action ref is a full commit SHA', () => {
  for (const name of readdirSync(fileURLToPath(workflowDir)).filter(name => name.endsWith('.yml'))) {
    const workflow = readFileSync(new URL(name, workflowDir), 'utf8');
    for (const match of workflow.matchAll(/uses:\s+[^\s@]+@([^\s#]+)/g)) {
      expect(match[1], `${name}: ${match[0]}`).toMatch(/^[a-f0-9]{40}$/);
    }
  }
});

test.describe('credential scope (static pins)', () => {
  test('no context-level extraHTTPHeaders in the Playwright config', () => {
    // Usage patterns only (colons/parens): explanatory comments may name the
    // APIs to document why they are banned.
    const configSource = readFileSync(new URL('../playwright.config.ts', import.meta.url), 'utf8');
    expect(configSource).not.toContain('extraHTTPHeaders:');
    expect(configSource).not.toContain('setExtraHTTPHeaders(');
  });

  test('browser auth is origin-scoped through a context route', () => {
    const accounts = readFileSync(new URL('../helpers/accounts.ts', import.meta.url), 'utf8');
    expect(accounts).toContain('isStagingOrigin');
    expect(accounts).toContain('context.route');
    expect(accounts).not.toContain('extraHTTPHeaders:');
    expect(accounts).not.toContain('setExtraHTTPHeaders(');
  });

  test('credentialed API calls never follow redirects (maxRedirects: 0)', () => {
    const accounts = readFileSync(new URL('../helpers/accounts.ts', import.meta.url), 'utf8');
    expect(accounts).toContain('maxRedirects: 0');
    expect(accounts).toContain('export async function apiGet');
    expect(accounts).toContain('export async function apiPost');
    expect(accounts).toContain('unexpected redirect');
  });

  // Raw API-context calls follow a staging 302 to another origin WITH the
  // Access pair + bearer (Playwright follows up to 20 redirects by default).
  // Live specs must go through apiGet/apiPost; helpers.spec.ts may use the
  // raw fixture inside its own no-follow proof (it asserts the wrapper, not
  // staging). The pin bans every method (get/post/put/patch/delete/head/fetch
  // on request/page.request/context.request) without a headers condition: the
  // old /request\.(get|post)\([^)]*headers/ stopped at the first ')' so a URL
  // containing a nested call (every API.stream() stream URL) never matched,
  // and request.fetch bypassed it entirely.
  const RAW_API_CALL = /\b(?:request|page\.request|context\.request)\.(?:get|post|put|patch|delete|head|fetch)\s*\(/;
  test('live specs use the no-follow API wrapper, not raw credentialed calls', () => {
    // Raw request.get/post with headers would follow a staging 302 to another
    // origin WITH the Access pair + bearer. Live specs must go through
    // apiGet/apiPost; helpers.spec.ts may use the raw fixture inside its own
    // no-follow proof (it asserts the wrapper, not staging).
    for (const name of ['health.spec.ts', 'ingest-play-meter.spec.ts', 'signup-byop.spec.ts']) {
      const source = readFileSync(new URL(`../tests/${name}`, import.meta.url), 'utf8');
      expect(source, `${name} must not carry credentials on a raw request call`).not.toMatch(
        RAW_API_CALL,
      );
    }
    for (const name of ['health.spec.ts', 'ingest-play-meter.spec.ts']) {
      const source = readFileSync(new URL(`../tests/${name}`, import.meta.url), 'utf8');
      expect(source, `${name} must use the no-follow wrapper`).toContain('apiGet(');
    }
  });

  test('no-follow pin catches nested-paren and fetch mutants', () => {
    // Regression proof for the pin above: the reviewer's bypass mutants must
    // match (fail the pin), while the approved wrapper call must not.
    const nestedStreamCall =
      "await request.get(`${baseURL}${API.stream(trackId as string)}`, " +
      "{ headers: { ...headers, Range: 'bytes=0-8' }, timeout: 30_000 })";
    const fetchCall = 'await request.fetch(libraryUrl, { headers })';
    const pageScoped = 'await page.request.get(`${baseURL}/api/usage`, { headers })';
    expect(nestedStreamCall).toMatch(RAW_API_CALL);
    expect(fetchCall).toMatch(RAW_API_CALL);
    expect(pageScoped).toMatch(RAW_API_CALL);
    expect("await apiGet(request, url, headers, 'range')").not.toMatch(RAW_API_CALL);
  });
});

// Execute the exact checked-in sanitize blocks: Playwright 1.55 writes
// test-results/**/error-context.md (ARIA snapshots rendering filled input
// values, including the BYOP password) and the junit reporter embeds failure
// messages (e.g. toHaveValue Received strings) carrying the same filled
// secrets. CI uses the junit reporter only and uploads test-results/ alone;
// the sanitize step deletes error-context.md plus the whole
// playwright-report/ dir, then scrubs secret values from test-results/.
const sanitizeSections = [...stagingWorkflow.matchAll(
  /      - name: Sanitize failure artifacts([\s\S]*?)run: \|\n((?:          [^\n]*\n)+)/g,
)];
const sanitizeBlocks = sanitizeSections.map((m) => m[2]!);

function listFilesRecursive(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...listFilesRecursive(full));
    else out.push(full);
  }
  return out;
}

// Scan a file for a marker in plain text AND inside base64 blobs (the html
// report embeds its payload as a base64 zip): decode every long base64 run
// and check the decoded bytes too.
function fileContainsMarker(file: string, marker: string): boolean {
  const raw = readFileSync(file, 'utf8');
  if (raw.includes(marker)) return true;
  for (const match of raw.matchAll(/[A-Za-z0-9+/]{200,}={0,2}/g)) {
    try {
      const decoded = Buffer.from(match[0], 'base64').toString('utf8');
      if (decoded.includes(marker)) return true;
    } catch {
      // Not decodable — ignore this run.
    }
  }
  return false;
}

test.describe('failure-artifact sanitization', () => {
  test('both jobs sanitize before uploading', () => {
    expect(sanitizeSections).toHaveLength(2);
    expect(sanitizeBlocks).toHaveLength(2);
    for (const section of sanitizeSections) {
      // The scrub needs the secret VALUES, so each sanitize step must bind
      // them (names only in source; values come from GitHub secrets).
      for (const name of [
        'CF_ACCESS_CLIENT_ID',
        'CF_ACCESS_CLIENT_SECRET',
        'QA_AUTH_TOKEN',
        'SYNTHETIC_NNTP_HOST',
        'SYNTHETIC_NNTP_USER',
        'SYNTHETIC_NNTP_PASS',
      ]) {
        expect(section[1], `sanitize step env binds ${name}`).toContain(name);
      }
    }
    for (const block of sanitizeBlocks) {
      const script = block.replace(/^ {10}/gm, '');
      expect(script).toContain('error-context.md');
      // Whole-dir removal: the old `playwright-report/data`-only strip left
      // index.html (with its embedded base64 zip) behind.
      expect(script).toContain('rm -rf playwright-report');
      expect(script).not.toContain('playwright-report/data');
      // junit.xml embeds failure messages (toHaveValue Received strings) that
      // can carry filled secrets: the block must scrub test-results/.
      expect(script).toContain('***REDACTED***');
      expect(script).toContain('SYNTHETIC_NNTP_PASS');
    }
    // Each sanitize precedes its job's upload: nothing uploads raw first.
    for (const artifact of ['e2e-synthetic-report', 'e2e-journey-report']) {
      const uploadAt = stagingWorkflow.indexOf(artifact);
      const sanitizeAt = stagingWorkflow.lastIndexOf('Sanitize failure artifacts', uploadAt);
      expect(sanitizeAt, `${artifact} uploads before any sanitize`).toBeGreaterThan(-1);
    }
  });

  test('uploads are junit-only (no playwright-report)', () => {
    // Both jobs upload test-results/ only. The html report (index.html with
    // its embedded base64 zip of step fill values) must never be an upload
    // path — the sanitize step may still NAME playwright-report/ to delete it.
    const uploadPaths = [...stagingWorkflow.matchAll(/path: \|\n((?:            [^\n]*\n)+)/g)];
    expect(uploadPaths).toHaveLength(2);
    for (const upload of uploadPaths) {
      expect(upload[1]).toContain('e2e/test-results/');
      expect(upload[1]).not.toContain('playwright-report');
    }
  });

  test('CI reporter is junit-only (html embeds fill values)', () => {
    const configSource = readFileSync(new URL('../playwright.config.ts', import.meta.url), 'utf8');
    expect(configSource).toContain('junit');
    expect(configSource).toContain('test-results/junit.xml');
    expect(configSource).not.toContain("'html'");
    expect(configSource).not.toContain('"html"');
  });

  // Real-browser proof: run a genuinely failing Playwright test that fills a
  // marker password under the CI reporter config (junit, no html,
  // trace/screenshot off). The junit reporter embeds the failure message
  // (toHaveValue Received string), so junit.xml DOES carry the marker before
  // sanitize. Apply the exact checked-in sanitize block with the marker bound
  // as SYNTHETIC_NNTP_PASS (as CI binds the real secret) and assert the
  // marker is absent from every file left under the upload path, including
  // base64-decoded payloads.
  test('real failing fill leaves no marker after the checked-in sanitize', async () => {
    test.setTimeout(120_000);
    const script = sanitizeBlocks[0]!.replace(/^ {10}/gm, '');
    const marker = 'MARKER-NNTP-PASS-9f8e7d6c5b4a';
    // Probe lives under e2e/ so `import '@playwright/test'` in the generated
    // spec resolves via e2e/node_modules (a system-temp dir has no ancestors
    // with the package). Removed in `finally`.
    const e2eDir = fileURLToPath(new URL('..', import.meta.url));
    const probe = mkdtempSync(join(e2eDir, '.real-sanitize-'));
    try {
      writeFileSync(
        join(probe, 'marker.spec.ts'),
        `import { test, expect } from '@playwright/test';\n` +
          `test('fills marker password then fails', async ({ page }) => {\n` +
          `  await page.setContent('<input data-testid="byop-pass" type="password" />');\n` +
          `  await page.getByTestId('byop-pass').fill('${marker}');\n` +
          // Fail on a page assertion so the failure snapshots the filled page.
          `  await expect(page.getByTestId('byop-pass')).toHaveValue('definitely-not-the-marker');\n` +
          `});\n`,
      );
      writeFileSync(
        join(probe, 'playwright.config.ts'),
        `import { defineConfig } from '@playwright/test';\n` +
          `export default defineConfig({\n` +
          `  testDir: '.',\n` +
          `  testMatch: 'marker.spec.ts',\n` +
          `  timeout: 30_000,\n` +
          `  retries: 0,\n` +
          `  reporter: [['list'], ['junit', { outputFile: 'test-results/junit.xml' }]],\n` +
          `  use: { trace: 'off', screenshot: 'off' },\n` +
          `  outputDir: 'test-results',\n` +
          `});\n`,
      );
      const cli = join(e2eDir, 'node_modules', '@playwright', 'test', 'cli.js');
      const run = spawnSync(process.execPath, [cli, 'test', `--config=${join(probe, 'playwright.config.ts')}`], {
        encoding: 'utf8',
        timeout: 90_000,
        cwd: probe,
        env: { ...process.env, CI: '1' },
      });
      const probeOutput = `${run.stdout}\n${run.stderr}`;
      // Minimal containers (no system browser libs) cannot launch Chromium;
      // CI installs --with-deps so the probe runs for real there. Skip here
      // rather than failing the suite on environment, never on assertion.
      if (/cannot open shared object|browser has been closed|browserType\.launch|executable doesn't exist/i.test(probeOutput)) {
        test.skip(true, 'Chromium system libraries unavailable in this container — probe runs in CI with --with-deps.');
        return;
      }
      // The probe must actually fail (otherwise it proved nothing).
      expect(run.status, `probe run output:\n${probeOutput}`).not.toBe(0);
      // The failing run must have produced the leak-prone snapshot with the
      // marker (otherwise the sanitize assertion is vacuous).
      const errorContexts = listFilesRecursive(probe).filter((f) => f.endsWith('error-context.md'));
      expect(errorContexts.length).toBeGreaterThan(0);
      expect(errorContexts.some((f) => readFileSync(f, 'utf8').includes(marker))).toBe(true);
      // junit.xml embeds the failure message (Received string), so it DOES
      // carry the marker before sanitize — this is the leak the scrub fixes.
      const junitBefore = listFilesRecursive(probe).filter((f) => f.endsWith('.xml'));
      expect(junitBefore.length).toBeGreaterThan(0);
      expect(junitBefore.some((f) => readFileSync(f, 'utf8').includes(marker))).toBe(true);

      // CI binds the real secret to the sanitize step; the probe binds the
      // marker the same way so the exact checked-in scrub removes it.
      const sanitized = runShell(script, { SYNTHETIC_NNTP_PASS: marker }, probe);
      expect(sanitized.status).toBe(0);
      expect(listFilesRecursive(probe).filter((f) => f.endsWith('error-context.md'))).toHaveLength(0);
      expect(existsSync(join(probe, 'playwright-report'))).toBe(false);
      // Marker absent from every remaining file under the upload path,
      // including inside base64 payloads.
      for (const file of listFilesRecursive(join(probe, 'test-results'))) {
        expect(fileContainsMarker(file, marker), file).toBe(false);
      }
      // Non-credential evidence survives sanitization.
      expect(existsSync(join(probe, 'test-results', 'junit.xml'))).toBe(true);
    } finally {
      rmSync(probe, { recursive: true, force: true });
    }
  });
});
