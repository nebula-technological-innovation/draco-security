import test from 'node:test';
import assert from 'node:assert/strict';
import { DependencyScanner, SecretScanner } from '../dist/index.js';
import { z } from 'zod';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const lock = {
  name: 'fixture', version: '1.0.0', lockfileVersion: 3,
  packages: {
    '': { name: 'fixture', version: '1.0.0', dependencies: { zod: '^4.6.7' } },
    'node_modules/zod': { version: '4.6.7', integrity: 'sha512-AAA=' },
    'node_modules/parent/node_modules/nested': { version: '1.2.3', integrity: 'sha512-AAA=' },
  },
};

test('unverified package-only fallback refuses false-green result', async () => {
  const scanner = new DependencyScanner();
  const result = await scanner.scanNpm([{ name: 'zod', version: '4.6.7' }]);
  assert.equal(result.summary.high, 1);
  assert.equal(result.findings[0].id, 'dependency-advisory-feed-unavailable');
  assert.match(result.findings[0].description, /incomplete scan/);
  assert.equal(result.findings[0].cve, undefined);
});

const cleanReport = () => JSON.stringify({
  auditReportVersion: 2,
  vulnerabilities: {},
  metadata: { vulnerabilities: { total: 0, info: 0, low: 0, moderate: 0, high: 0, critical: 0 } },
});
const vulnerableReport = () => JSON.stringify({
  auditReportVersion: 2,
  vulnerabilities: {
    zod: {
      name: 'zod', severity: 'high', isDirect: true, range: '<4.6.6',
      via: [{ name:'zod', source: 12345, title:'Resource exhaustion',
        url:'https://github.com/advisories/GHSA-mrhx-c7xc-m3w5',
        range: '<4.6.6', severity: 'high' }],
      fixAvailable: { name:'zod', version:'4.6.7', isSemVerMajor: true },
    },
  },
  metadata: { vulnerabilities: { total: 1, info: 0, low: 0, moderate: 0, high: 1, critical: 0 } },
});

test('verified npm advisory feed supplies timestamp, hashes, source, and clean verdict', async () => {
  const scanner = new DependencyScanner();
  const evidence = await scanner.scanLockfile(JSON.stringify(lock), 'npm', {
    runner: (cwd) => {
      assert.ok(cwd.includes('draco-npm-audit-'));
      assert.equal(JSON.parse(readFileSync(join(cwd,'package-lock.json'), 'utf8')).lockfileVersion, 3);
      return { status: 0, stdout: cleanReport() };
    },
    now: () => Date.UTC(2026,10,12,22,45),
  });
  assert.equal(evidence.summary.total, 0);
  assert.equal(evidence.evidence?.source, 'npm-registry-advisory-audit');
  assert.equal(evidence.evidence?.verified, true);
  assert.match(evidence.evidence?.lockSha256 || '', /^[0-9a-f]{64}$/);
  assert.equal(evidence.evidence?.fetchedAt, '2026-11-12T22:45:00.000Z');
});

test('known high-severity advisory blocks with grounded GHSA identity', async () => {
  const scanner = new DependencyScanner();
  const evidence = await scanner.scanLockfile(JSON.stringify(lock), 'npm', {
    runner: () => ({ status: 1, stdout: vulnerableReport() }),
  });
  assert.equal(evidence.summary.high, 1);
  assert.equal(evidence.findings[0].id,'npm:GHSA-mrhx-c7xc-m3w5');
  assert.match(evidence.findings[0].recommendation,/4\.6\.7/);
});

test('invalid and unsupported lockfiles cannot return zero findings', async () => {
  const scanner = new DependencyScanner();
  await assert.rejects(scanner.scanLockfile('not json', 'npm'), /invalid lockfile JSON/);
  await assert.rejects(scanner.scanLockfile('{"lockfileVersion":1}', 'npm'), /Unsupported npm lockfile/);
  await assert.rejects(scanner.scanLockfile(JSON.stringify(lock), 'pip'), /No verified vulnerability advisory source/);
});

test('incomplete dependency graph fails before consulting advisory provider', async () => {
  const scanner = new DependencyScanner();
  const broken = { ...lock, packages: { '': lock.packages[''] } };
  await assert.rejects(scanner.scanLockfile(JSON.stringify(broken), 'npm'), /missing resolved dependency/);
});

test('missing transitive dependency cannot be verified as clean', async () => {
  const scanner = new DependencyScanner();
  const broken = structuredClone(lock);
  broken.packages['node_modules/zod'].dependencies = { undisclosed: '^1.0.0' };
  await assert.rejects(
    scanner.scanLockfile(JSON.stringify(broken), 'npm'),
    /missing transitive dependency/,
  );
});

test('offline, malformed, unverified, and internally inconsistent npm results fail closed', async () => {
  const scanner = new DependencyScanner();
  for (const response of [
    { status: null, stdout: '' },
    { status: 1, stdout: '{"error":{"code":"ENOAUDIT"}}' },
    { status: 0, stdout: '{"auditReportVersion":2,"vulnerabilities":{}}' },
    { status: 0, stdout: vulnerableReport() },
    { status: 1, stdout: cleanReport() },
    { status: 0, stdout: 'garbled' },
  ]) {
    await assert.rejects(scanner.scanLockfile(JSON.stringify(lock), 'npm', {
      runner: () => response,
    }));
  }
});

test('Zod v4 preserves severity and dependency schema primitives', () => {
  const severity = z.enum(['critical', 'high', 'medium', 'low', 'info']);
  const dependency = z.object({
    name: z.string(),
    version: z.string(),
    vulnerabilities: z.array(z.object({ cve: z.string(), severity })),
  });
  assert.equal(dependency.parse({ name: 'zod', version: '4.6.7', vulnerabilities: [] }).name, 'zod');
  assert.equal(severity.safeParse('critical').success, true);
  assert.equal(severity.safeParse('not-a-severity').success, false);
});

test('security reports never include matched credential bytes', async () => {
  const token = 'ghp_' + 'A'.repeat(36);
  const scanner = new SecretScanner();
  const result = await scanner.scan('const SECRET = "' + token + '";', 'fixture.ts');
  assert.ok(result.findings.length > 0);
  assert.equal(result.findings[0].code, '[REDACTED]');
  assert.equal(JSON.stringify(result).includes(token), false);
});
