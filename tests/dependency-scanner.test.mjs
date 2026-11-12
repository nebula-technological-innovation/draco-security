import test from 'node:test';
import assert from 'node:assert/strict';
import { DependencyScanner, SecretScanner } from '../dist/index.js';
import { z } from 'zod';

const lock = {
  name: 'fixture', version: '1.0.0', lockfileVersion: 3,
  packages: {
    '': { name: 'fixture', version: '1.0.0', dependencies: { zod: '^4.6.7' } },
    'node_modules/zod': { version: '4.6.7', integrity: 'sha512-AAA=' },
    'node_modules/parent/node_modules/nested': { version: '1.2.3', integrity: 'sha512-AAA=' },
  },
};

test('dependency scanner refuses a false-green result without an advisory feed', async () => {
  const scanner = new DependencyScanner();
  const result = await scanner.scanLockfile(JSON.stringify(lock), 'npm');
  assert.equal(result.summary.high, 1);
  assert.equal(result.findings[0].id, 'dependency-advisory-feed-unavailable');
  assert.match(result.findings[0].description, /incomplete scan/);
  assert.equal(result.findings[0].cve, undefined);
});

test('invalid npm lockfile does not yield empty-success', async () => {
  const scanner = new DependencyScanner();
  await assert.rejects(scanner.scanLockfile('not json', 'npm'), /Invalid npm lockfile JSON/);
  await assert.rejects(scanner.scanLockfile('{"lockfileVersion":1}', 'npm'), /Unsupported npm lockfile/);
});

test('lockfile with declared dependencies but no resolved packages is rejected', async () => {
  const scanner = new DependencyScanner();
  const broken = { ...lock, packages: { '': lock.packages[''] } };
  await assert.rejects(scanner.scanLockfile(JSON.stringify(broken), 'npm'), /no resolved package entries/);
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
