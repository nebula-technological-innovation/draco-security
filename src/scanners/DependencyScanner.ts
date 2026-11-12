import type { ScanResult, ScannerType, Finding } from '../types/index.js';

const NPM_ADVISORY_DB: Record<
  string,
  Array<{
    cve: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    title: string;
    patched: string;
  }>
> = {};

export class DependencyScanner {
  readonly type: ScannerType = 'dependencies';

  async scanNpm(packages: Array<{ name: string; version: string }>): Promise<ScanResult> {
    const startTime = Date.now();
    const findings: Finding[] = [];

    // No advisory intelligence is shipped in this module. An empty database
    // must never be represented as a clean vulnerability assessment.
    if (packages.length > 0 && Object.keys(NPM_ADVISORY_DB).length === 0) {
      findings.push({
        id: 'dependency-advisory-feed-unavailable',
        scanner: 'dependencies',
        severity: 'high',
        title: 'Dependency advisory feed unavailable (verification blocked)',
        description:
          'No trusted vulnerability intelligence is configured. This is an incomplete scan, not an assertion of a known CVE.',
        recommendation:
          'Run an independently validated lockfile-based dependency audit or configure a trustworthy current advisory source.',
      });
    }

    for (const pkg of packages) {
      const advisories = NPM_ADVISORY_DB[pkg.name] ?? [];
      for (const adv of advisories) {
        findings.push({
          id: `dep-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
          scanner: 'dependencies',
          severity: adv.severity,
          title: `${pkg.name}: ${adv.title}`,
          description: `Vulnerability in ${pkg.name}@${pkg.version}: ${adv.title}`,
          cve: adv.cve,
          recommendation: `Upgrade ${pkg.name} to ${adv.patched}`,
        });
      }
    }

    const critical = findings.filter((f) => f.severity === 'critical').length;
    const high = findings.filter((f) => f.severity === 'high').length;
    const medium = findings.filter((f) => f.severity === 'medium').length;
    const low = findings.filter((f) => f.severity === 'low').length;

    return {
      scanner: 'dependencies',
      target: 'npm-packages',
      findings,
      summary: { total: findings.length, critical, high, medium, low, info: 0 },
      durationMs: Date.now() - startTime,
      timestamp: Date.now(),
    };
  }

  async scan(
    packages: Array<{ name: string; version: string; ecosystem: string }>,
  ): Promise<ScanResult> {
    if (packages.length === 0) {
      return {
        scanner: 'dependencies',
        target: 'packages',
        findings: [],
        summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        durationMs: 0,
        timestamp: Date.now(),
      };
    }

    return this.scanNpm(
      packages
        .filter((p) => p.ecosystem === 'npm')
        .map((p) => ({ name: p.name, version: p.version })),
    );
  }

  async scanLockfile(
    content: string,
    ecosystem: 'npm' | 'pip' | 'cargo' | 'go' | 'maven',
  ): Promise<ScanResult> {
    const packages = this.parseLockfile(content, ecosystem);
    return this.scan(packages);
  }

  private parseLockfile(
    content: string,
    ecosystem: string,
  ): Array<{ name: string; version: string; ecosystem: string }> {
    const result: Array<{ name: string; version: string; ecosystem: string }> = [];

    if (ecosystem === 'npm') {
      let parsed: unknown;
      try {
        parsed = JSON.parse(content);
      } catch {
        throw new Error('Invalid npm lockfile JSON: dependency scan unavailable');
      }
      if (!parsed || typeof parsed !== 'object') {
        throw new Error('Npm lockfile root is invalid');
      }
      const lock = parsed as {
        lockfileVersion?: number;
        packages?: Record<string, { version?: unknown; dependencies?: unknown; devDependencies?: unknown } | undefined>;
      };
      if (![2, 3].includes(lock.lockfileVersion ?? 0) || !lock.packages) {
        throw new Error('Unsupported npm lockfile: dependency scan unavailable');
      }
      for (const [path, entry] of Object.entries(lock.packages)) {
        if (!path.startsWith('node_modules/') || !entry || typeof entry.version !== 'string') {
          continue;
        }
        const marker = 'node_modules/';
        const name = path.slice(path.lastIndexOf(marker) + marker.length);
        if (name) {
          result.push({ name, version: entry.version, ecosystem: 'npm' });
        }
      }
      const root = lock.packages[''];
      if (result.length === 0 && root && (
        Object.keys((root.dependencies as object) ?? {}).length > 0 ||
        Object.keys((root.devDependencies as object) ?? {}).length > 0
      )) {
        throw new Error('Npm lockfile has dependencies but no resolved package entries');
      }
    }
    return result;
  }
}
