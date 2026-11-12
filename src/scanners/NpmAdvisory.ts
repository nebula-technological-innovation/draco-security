/** Nebula-owned npm advisory verification, backed by the public npm registry.
 * No paid GitHub Code Quality, scripts, package install, or repo mutation.
 * A malformed/stale/unavailable advisory response NEVER means zero vulnerabilities.
 */
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import type { ScanResult, Finding } from '../types/index.js';

type AuditResponse = { status: number | null; stdout: string | Buffer | null; error?: Error | undefined };
export type AuditRunner = (cwd: string) => AuditResponse;
export type VerifiedNpmScan = ScanResult & {
  evidence: {
    source: 'npm-registry-advisory-audit';
    registry: 'https://registry.npmjs.org/';
    lockSha256: string;
    responseSha256: string;
    fetchedAt: string;
    advisoryCount: number;
    verified: true;
  };
};

function sha256(data: string): string {
  return createHash('sha256').update(data, 'utf8').digest('hex');
}
function restrictedNpmAudit(cwd: string): AuditResponse {
  // Allowlist environment: never forward host API tokens, npm credentials,
  // Node preload hooks, or arbitrary process settings to a subprocess.
  const env: NodeJS.ProcessEnv = {
    PATH: process.env.PATH,
    HOME: cwd,
    TMPDIR: cwd,
  };
  env.npm_config_registry = 'https://registry.npmjs.org/';
  env.npm_config_userconfig = process.platform === 'win32' ? 'NUL' : '/dev/null';
  env.npm_config_globalconfig = join(cwd, 'empty-global-npmrc');
  writeFileSync(join(cwd, 'empty-global-npmrc'), '', { mode: 0o600 });
  env.npm_config_cache = join(cwd, '.npm-cache');
  env.npm_config_audit = 'true';
  return spawnSync(
    'npm', ['audit', '--json', '--package-lock-only', '--ignore-scripts', '--no-fund'],
    { cwd, env, encoding: 'utf8', timeout: 30_000, maxBuffer: 8 * 1024 * 1024, shell: false },
  );
}

function validateLock(content: string): {
  root: Record<string, unknown>; count: number; lock: Record<string, unknown>;
} {
  if (Buffer.byteLength(content) > 10 * 1024 * 1024) {
    throw new Error('npm dependency verification blocked: lockfile exceeds limit');
  }
  let parsed: unknown;
  try { parsed = JSON.parse(content); }
  catch { throw new Error('npm dependency verification blocked: invalid lockfile JSON'); }
  if (!parsed || typeof parsed !== 'object') throw new Error('Invalid npm lockfile root');
  const lock = parsed as Record<string, unknown>;
  if (![2, 3].includes(lock.lockfileVersion as number)) throw new Error('Unsupported npm lockfile version');
  const entries = lock.packages;
  if (!entries || typeof entries !== 'object' || Array.isArray(entries)) throw new Error('npm lockfile packages missing');
  const packages = entries as Record<string, Record<string, unknown>>;
  const root = packages[''];
  if (!root || typeof root !== 'object' || typeof root.name !== 'string' || typeof root.version !== 'string') {
    throw new Error('npm lockfile root package identity missing');
  }
  const referenced = ['dependencies','devDependencies','optionalDependencies'];
  for (const typ of referenced) {
    const deps = root[typ] ?? {};
    if (!deps || typeof deps !== 'object' || Array.isArray(deps)) throw new Error('Invalid root dependencies');
    for (const dep of Object.keys(deps as object)) {
      if (!packages['node_modules/' + dep]) throw new Error('npm lockfile missing resolved dependency');
    }
  }
  let count=0;
  for (const [path, info] of Object.entries(packages)) {
    if (!path) continue;
    if (!path.startsWith('node_modules/') || !info || typeof info !== 'object') {
      throw new Error('Invalid npm package graph entry');
    }
    if (info.link === true) throw new Error('Linked npm packages need separately verified provenance');
    if (typeof info.version !== 'string' ||
        typeof info.integrity !== 'string' ||
        !/^(sha512|sha384|sha256)-[A-Za-z0-9+/=]+$/.test(info.integrity)) {
      throw new Error('npm package graph contains missing version or integrity');
    }
    count++;
  }
  return {root, count, lock};
}
function severity(s: string): Finding['severity'] {
  return s === 'critical' ? 'critical' : s === 'high' ? 'high' :
    s === 'moderate' ? 'medium' : s === 'low' ? 'low' : 'info';
}
function parseAudit(stdout: string): { findings: Finding[], advisoryCount: number } {
  let data: unknown;
  try { data = JSON.parse(stdout); }
  catch { throw new Error('npm advisory verification blocked: malformed response'); }
  if (!data || typeof data !== 'object') throw new Error('npm audit response invalid');
  const record = data as Record<string, unknown>;
  if (record.error || record.auditReportVersion !== 2 ||
      !record.metadata || !record.vulnerabilities || typeof record.vulnerabilities !== 'object') {
    throw new Error('npm advisory verification unavailable or incomplete');
  }
  const metadata = record.metadata as Record<string, unknown>;
  const counts = metadata.vulnerabilities as Record<string, unknown> | undefined;
  if (!counts || !Number.isSafeInteger(counts.total) || Number(counts.total) < 0) {
    throw new Error('npm advisory result lacks verified vulnerability counts');
  }
  const vulnerabilities = record.vulnerabilities as Record<string, Record<string, unknown>>;
  if (Number(counts.total) !== Object.keys(vulnerabilities).length) {
    throw new Error('npm advisory total and vulnerability records disagree');
  }
  const findings: Finding[] = [];
  for (const [name, item] of Object.entries(vulnerabilities)) {
    if (!item || typeof item !== 'object') throw new Error('npm advisory item invalid');
    const state=String(item.severity ?? '');
    if (!['info','low','moderate','high','critical'].includes(state) || !Array.isArray(item.via) || item.via.length===0) {
      throw new Error('npm advisory evidence incomplete for an affected package');
    }
    const direct = item.via.find((a: unknown) => !!a && typeof a === 'object' && 'url' in a) as Record<string, unknown> | undefined;
    const url=direct && typeof direct.url==='string' && /^https:\/\/(github\.com\/advisories\/|npmjs\.com\/advisories\/)/.test(direct.url) ? direct.url : null;
    const id = url ? url.split('/').at(-1) : null;
    const fix = item.fixAvailable && typeof item.fixAvailable==='object'
      ? String((item.fixAvailable as Record<string, unknown>).version ?? '') : '';
    findings.push({
      id: id ? 'npm:' + id : 'npm:transitive:' + name,
      scanner: 'dependencies',
      severity: severity(state),
      title: 'npm advisory affecting ' + name,
      description: 'Public npm registry reports a ' + state + ' dependency advisory' + (url ? ' (' + url + ')' : ''),
      recommendation: fix ? 'Review upgrade to ' + name + '@' + fix : 'Review dependency chain and npm audit output',
    });
  }
  return { findings, advisoryCount: Number(counts.total) };
}

export function auditNpmLockfile(
  content: string, options: { runner?: AuditRunner; now?: () => number } = {},
): VerifiedNpmScan {
  const { root } = validateLock(content);
  const tmp=mkdtempSync(join(tmpdir(), 'draco-npm-audit-'));
  const start = (options.now ?? Date.now)();
  try {
    const manifest: Record<string, unknown> = {
      name: root.name, version: root.version, private: true,
      dependencies: root.dependencies ?? {}, devDependencies: root.devDependencies ?? {},
      optionalDependencies: root.optionalDependencies ?? {},
    };
    writeFileSync(join(tmp, 'package-lock.json'), content, { mode: 0o600 });
    writeFileSync(join(tmp, 'package.json'), JSON.stringify(manifest), { mode: 0o600 });
    const runner=options.runner ?? restrictedNpmAudit;
    const response=runner(tmp);
    if (![0,1].includes(response.status as number) || response.error || typeof response.stdout!=='string') {
      throw new Error('npm advisory service or command unavailable: verification blocked');
    }
    const parsed=parseAudit(response.stdout);
    if (parsed.advisoryCount>0 && response.status===0) {
      throw new Error('npm advisory exit status conflicts with reported findings');
    }
    if (parsed.advisoryCount===0 && response.status!==0) {
      throw new Error('npm advisory exit status conflicts with zero findings');
    }
    const findings=parsed.findings;
    const summary={total:findings.length,critical:0,high:0,medium:0,low:0,info:0};
    for (const f of findings) summary[f.severity]++;
    return {
      scanner:'dependencies',
      target:'npm-lockfile',
      findings, summary,
      durationMs: Math.max(0,(options.now ?? Date.now)()-start), timestamp: start,
      evidence:{
        source:'npm-registry-advisory-audit',
        registry:'https://registry.npmjs.org/',
        lockSha256:sha256(content),
        responseSha256:sha256(response.stdout),
        fetchedAt: new Date(start).toISOString(),
        advisoryCount: parsed.advisoryCount,
        verified:true,
      },
    };
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}
