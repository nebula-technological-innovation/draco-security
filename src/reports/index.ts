import type { ScanResult, SecurityReport, ThreatModel } from '../types/index.js';

const SEVERITY_WEIGHTS: Record<string, number> = {
  critical: 10,
  high: 7,
  medium: 4,
  low: 1,
  info: 0,
};

export function generateReport(
  scans: ScanResult[],
  title = 'Security Audit Report',
): SecurityReport {
  const allFindings = scans.flatMap((s) => s.findings);
  const critical = allFindings.filter((f) => f.severity === 'critical').length;
  const high = allFindings.filter((f) => f.severity === 'high').length;
  const medium = allFindings.filter((f) => f.severity === 'medium').length;
  const low = allFindings.filter((f) => f.severity === 'low').length;
  const info = allFindings.filter((f) => f.severity === 'info').length;

  const maxScore = allFindings.length * 10;
  const actualScore = allFindings.reduce((s, f) => s + SEVERITY_WEIGHTS[f.severity], 0);
  const score = maxScore > 0 ? Math.round((1 - actualScore / maxScore) * 100) : 100;

  return {
    id: `report-${Date.now()}`,
    title,
    scans,
    overall: { totalFindings: allFindings.length, critical, high, medium, low, info, score },
    generatedAt: Date.now(),
  };
}

export function formatReport(report: SecurityReport): string {
  const lines: string[] = [
    `# ${report.title}`,
    `Generated: ${new Date(report.generatedAt).toISOString()}`,
    `Security Score: ${report.overall.score}/100`,
    '',
    '## Summary',
    `Total Findings: ${report.overall.totalFindings}`,
    `  Critical: ${report.overall.critical}`,
    `  High:     ${report.overall.high}`,
    `  Medium:   ${report.overall.medium}`,
    `  Low:      ${report.overall.low}`,
    `  Info:     ${report.overall.info}`,
    '',
  ];

  for (const scan of report.scans) {
    lines.push(`## ${scan.scanner} Scan — ${scan.target}`);
    lines.push(`Duration: ${scan.durationMs}ms`);
    lines.push(`Findings: ${scan.summary.total}`);
    lines.push('');

    for (const f of scan.findings) {
      const tag =
        f.severity === 'critical'
          ? '🔴'
          : f.severity === 'high'
            ? '🟠'
            : f.severity === 'medium'
              ? '🟡'
              : '⚪';
      lines.push(`### ${tag} [${f.severity.toUpperCase()}] ${f.title}`);
      lines.push(`${f.description}`);
      if (f.file) lines.push(`File: ${f.file}${f.line ? `:${f.line}` : ''}`);
      if (f.cve) lines.push(`CVE: ${f.cve}`);
      lines.push(`Recommendation: ${f.recommendation}`);
      lines.push('');
    }
  }

  return lines.join('\n');
}

export function generateThreatModel(system: string, assets: string[]): ThreatModel {
  return {
    id: `tm-${Date.now()}`,
    system,
    assets,
    threats: [
      {
        id: 'STR-01',
        name: 'Identity Spoofing',
        category: 'spoofing',
        risk: 'high',
        description: 'Attacker impersonates a legitimate user or service',
        mitigation: 'Implement strong authentication and mutual TLS',
      },
      {
        id: 'STR-02',
        name: 'Data Tampering',
        category: 'tampering',
        risk: 'high',
        description: 'Attacker modifies data in transit or at rest',
        mitigation: 'Use TLS, signing, and integrity checks',
      },
      {
        id: 'STR-03',
        name: 'Repudiation',
        category: 'repudiation',
        risk: 'medium',
        description: 'User denies performing an action without proof',
        mitigation: 'Implement audit logging with non-repudiation',
      },
      {
        id: 'STR-04',
        name: 'Information Disclosure',
        category: 'information-disclosure',
        risk: 'critical',
        description: 'Sensitive data exposed to unauthorized parties',
        mitigation: 'Encrypt data at rest and in transit, implement least privilege',
      },
      {
        id: 'STR-05',
        name: 'Denial of Service',
        category: 'denial-of-service',
        risk: 'high',
        description: 'System becomes unavailable due to resource exhaustion',
        mitigation: 'Rate limiting, auto-scaling, DDoS protection',
      },
      {
        id: 'STR-06',
        name: 'Privilege Escalation',
        category: 'elevation-of-privilege',
        risk: 'critical',
        description: 'User gains unauthorized elevated access',
        mitigation: 'RBAC, principle of least privilege, regular access reviews',
      },
    ],
  };
}
