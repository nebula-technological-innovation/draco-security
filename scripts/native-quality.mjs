#!/usr/bin/env node
/**
 * Nebula/Aether dependency integrity and local TypeScript quality gate.
 * Offline, deterministic, read-only; intentionally fails closed until lockfile and compiler exist.
 * No npm install, lifecycle scripts, network calls, paid tokens, or release authority.
 */
import { readFileSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const sha256 = (b) => createHash('sha256').update(b).digest('hex');
const call = (command, args, root, timeout = 15000) =>
  spawnSync(command, args, { cwd: root, encoding: 'utf8', timeout, shell: false, env: { ...process.env, npm_config_offline: 'true' } });

export function verify(root, { typecheck = false, expectedSha = null } = {}) {
  const errors = [];
  const unverified = [];
  const evidence = {
    schema_version: '1.0',
    system: 'nebula-aether-native-dependency-quality',
    git: { head: null, exact_head: false, clean: false },
    manifests: { package_sha256: null, lock_sha256: null, lock_version: null },
    checks: { lock_root_matches_package: false, lock_integrity_entries: 0, typecheck: 'not_run' },
    errors, unverified,
    authority: { paid_quality_used: false, npm_install_executed: false, network_used: false, merge: false, deploy: false }
  };
  const head = call('git', ['rev-parse', '--verify', 'HEAD'], root);
  const dirty = call('git', ['status', '--porcelain', '--untracked-files=no'], root);
  if (head.status !== 0 || !/^[0-9a-f]{40}\s*$/.test(head.stdout ?? '')) errors.push('git exact HEAD unavailable');
  else evidence.git.head = head.stdout.trim();
  if (dirty.status !== 0 || (dirty.stdout || '').trim()) errors.push('tracked checkout is modified');
  else evidence.git.clean = true;
  if (expectedSha && evidence.git.head !== expectedSha) errors.push('expected SHA mismatch');
  evidence.git.exact_head = Boolean(evidence.git.head && (!expectedSha || evidence.git.head === expectedSha));
  const packagePath = join(root, 'package.json');
  const lockPath = join(root, 'package-lock.json');
  if (!existsSync(packagePath)) errors.push('package.json missing');
  if (!existsSync(lockPath)) errors.push('package-lock.json missing: reproducible install blocked');
  if (existsSync(packagePath) && existsSync(lockPath)) {
    try {
      const pbuf = readFileSync(packagePath), lbuf = readFileSync(lockPath);
      evidence.manifests.package_sha256 = sha256(pbuf);
      evidence.manifests.lock_sha256 = sha256(lbuf);
      const pkg = JSON.parse(pbuf.toString('utf8'));
      const lock = JSON.parse(lbuf.toString('utf8'));
      evidence.manifests.lock_version = lock.lockfileVersion ?? null;
      if (lock.lockfileVersion !== 3 || !lock.packages || !lock.packages['']) {
        errors.push('npm lockfile v3 with root package entry required');
      } else {
        const rootLock = lock.packages[''];
        if (rootLock.name !== pkg.name || rootLock.version !== pkg.version) errors.push('package-lock root name/version differs from package.json');
        const types = ['dependencies', 'devDependencies', 'optionalDependencies'];
        for (const type of types) {
          const a = pkg[type] ?? {}, b = rootLock[type] ?? {};
          if (JSON.stringify(Object.entries(a).sort()) !== JSON.stringify(Object.entries(b).sort())) {
            errors.push(`package-lock root ${type} differs from package.json`);
          }
          for (const dep of Object.keys(a)) {
            if (!lock.packages[`node_modules/${dep}`]) errors.push(`lockfile missing resolved package ${dep}`);
          }
        }
        if (!errors.some(x => x.includes('differs'))) evidence.checks.lock_root_matches_package = true;
        for (const [name, item] of Object.entries(lock.packages)) {
          if (!name || item.link || !name.startsWith('node_modules/')) continue;
          if (!/^(?:sha512|sha1)-[A-Za-z0-9+/=]+$/.test(item.integrity ?? '')) errors.push(`lockfile integrity absent for ${name}`);
          else evidence.checks.lock_integrity_entries++;
        }
      }
    } catch (err) {
      errors.push('manifest or lockfile JSON unreadable');
    }
  }
  if (typecheck) {
    const compiler = join(root, 'node_modules', 'typescript', 'bin', 'tsc');
    if (errors.length) unverified.push('typecheck not run because provenance or lock validation failed');
    else if (!existsSync(compiler)) unverified.push('local TypeScript compiler unavailable; frozen install required');
    else {
      const result = call(process.execPath, [compiler, '--noEmit', '--pretty', 'false', '--project', 'tsconfig.json'], root, 120000);
      evidence.checks.typecheck = result.status === 0 ? 'passed' : 'failed';
      if (result.status !== 0) errors.push('TypeScript project typecheck failed (diagnostics remain local)');
    }
  }
  evidence.passed = errors.length === 0 && unverified.length === 0 && (!typecheck || evidence.checks.typecheck === 'passed');
  evidence.evidence_sha256 = sha256(JSON.stringify(evidence));
  return evidence;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const rootIndex = process.argv.indexOf('--root');
  const shaIndex = process.argv.indexOf('--expected-sha');
  const root = rootIndex < 0 ? process.cwd() : resolve(process.argv[rootIndex + 1]);
  const expectedSha = shaIndex < 0 ? null : process.argv[shaIndex + 1];
  const typecheck = process.argv.includes('--typecheck');
  const result = verify(root, { typecheck, expectedSha });
  console.log(JSON.stringify(result, null, 2));
  process.exitCode = result.passed ? 0 : 1;
}
