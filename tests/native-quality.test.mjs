import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { verify } from '../scripts/native-quality.mjs';

function fixture({ lock = true, badIntegrity = false, dirty = false, mismatch = false } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'nebula-quality-test-'));
  const git = (...args) => { const r = spawnSync('git', args, { cwd: root, encoding: 'utf8' }); assert.equal(r.status, 0, r.stderr); };
  git('init', '-q'); git('config', 'user.email', 'quality@example.invalid'); git('config', 'user.name', 'Native Quality');
  const pkg = { name: 'quality-fixture', version: '1.0.0', devDependencies: { typescript: '5.8.2' } };
  writeFileSync(join(root, 'package.json'), JSON.stringify(pkg));
  if (lock) {
    const l = { name: pkg.name, version: pkg.version, lockfileVersion: 3, packages: {
      '': { name: pkg.name, version: pkg.version, devDependencies: mismatch ? { typescript: '^5.8.2' } : pkg.devDependencies },
      'node_modules/typescript': { version: '5.8.2', integrity: badIntegrity ? undefined : 'sha512-AAA=' }
    } };
    writeFileSync(join(root, 'package-lock.json'), JSON.stringify(l));
  }
  git('add', '-A'); git('commit', '-qm', 'fixture');
  if (dirty) writeFileSync(join(root, 'package.json'), '{}');
  return { root, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

for (const [name, opts, expected] of [
  ['valid lock', {}, true],
  ['missing lock', { lock: false }, false],
  ['invalid integrity', { badIntegrity: true }, false],
  ['out of sync root dependencies', { mismatch: true }, false],
  ['dirty checkout', { dirty: true }, false]
]) {
  test(name, () => { const f = fixture(opts); try { assert.equal(verify(f.root).passed, expected); } finally { f.cleanup(); } });
}
test('incomplete lockfile dependency graph blocks', () => { const f = fixture(); try { const p = join(f.root, 'package-lock.json'); const l = JSON.parse(requireFile(p)); delete l.packages['node_modules/typescript']; writeFileSync(p, JSON.stringify(l)); assert.equal(verify(f.root).passed, false); } finally { f.cleanup(); } });
function requireFile(p) { return readFileSync(p, 'utf8'); }
test('uncommitted package-lock must never pass', () => {
  const f = fixture({ lock: false });
  try {
    const pkg = { name: 'quality-fixture', version: '1.0.0', devDependencies: { typescript: '5.8.2' } };
    const lock = { name: pkg.name, version: pkg.version, lockfileVersion: 3, packages: {
      '': { name: pkg.name, version: pkg.version, devDependencies: pkg.devDependencies },
      'node_modules/typescript': { version: '5.8.2', integrity: 'sha512-AAA=' }
    }};
    writeFileSync(join(f.root, 'package-lock.json'), JSON.stringify(lock));
    const result = verify(f.root);
    assert.equal(result.passed, false);
    assert.match(result.errors.join(' '), /must be committed at exact HEAD/);
  } finally {
    f.cleanup();
  }
});
test('exact SHA mismatch cannot pass', () => { const f = fixture(); try { assert.equal(verify(f.root, { expectedSha: 'a'.repeat(40) }).passed, false); } finally { f.cleanup(); } });
test('typecheck is not invented if compiler missing', () => { const f = fixture(); try { const r = verify(f.root, { typecheck: true }); assert.equal(r.passed, false); assert.match(r.unverified.join(' '), /frozen install/); } finally { f.cleanup(); } });
test('no npm lifecycle or network authority', () => { const f = fixture(); try { const r = verify(f.root); assert.equal(r.authority.npm_install_executed, false); assert.equal(r.authority.network_used, false); assert.equal(r.authority.merge, false); } finally { f.cleanup(); } });
