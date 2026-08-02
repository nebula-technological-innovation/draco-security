import type { Severity, Finding } from '../types/index.js';
import type { SecurityAgent, SecurityContext, SecurityResult } from './types.js';

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 10,
  high: 7,
  medium: 4,
  low: 1,
  info: 0,
};

/**
 * DracoSecurityAgent — the flagship Aether Draco reasoning agent.
 *
 * Responsibilities (per platform spec):
 *  - classify findings
 *  - determine impact
 *  - recommend remediation
 *  - generate security reasoning
 */
export class DracoSecurityAgent implements SecurityAgent {
  name = 'draco';

  async analyze(input: SecurityContext): Promise<SecurityResult> {
    const findings: Finding[] = input.findings ?? [];

    const riskScore = Math.min(
      100,
      findings.reduce((acc, f) => acc + (SEVERITY_WEIGHT[f.severity] ?? 1), 0) * 3,
    );

    const ranked = [...findings].sort(
      (a, b) => (SEVERITY_WEIGHT[b.severity] ?? 1) - (SEVERITY_WEIGHT[a.severity] ?? 1),
    );
    const top = ranked[0];
    const severity: Severity = top?.severity ?? 'low';

    const classification = top ? `${top.scanner} finding` : 'no findings';
    const impact = top
      ? `Potential ${severity} business impact via ${top.scanner} weakness.`
      : 'No significant impact detected.';
    const remediation = top?.recommendation ?? 'No remediation required at this time.';
    const reasoning =
      `Analyzed ${findings.length} finding(s) for asset ` +
      `${input.assetId ?? 'unknown'}. Highest observed severity: ${severity}.`;

    return {
      agent: this.name,
      classification,
      impact,
      remediation,
      reasoning,
      riskScore,
      severity,
      recommendations: findings.map((f) => `${f.title}: ${f.recommendation}`),
    };
  }
}
