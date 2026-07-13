import type { Dependency, ScanResult, ScannerType, Finding } from '../types/index.js';

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
      const pkgMatch = content.match(/"name":\s*"([^"]+)"/);
      if (pkgMatch) {
        const depRegex = /"([^"]+)":\s*\{\s*"version":\s*"([^"]+)"/g;
        let m;
        while ((m = depRegex.exec(content)) !== null) {
          result.push({ name: m[1], version: m[2], ecosystem: 'npm' });
        }
      }
    }

    return result;
  }
}
