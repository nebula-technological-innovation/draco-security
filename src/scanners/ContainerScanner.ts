import type { ScanResult, ScannerType, Finding } from '../types/index.js';

const DOCKERFILE_RULES: Array<{
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  pattern: RegExp;
  recommendation: string;
}> = [
  {
    id: 'DOCK-001',
    severity: 'high',
    description: 'Using latest tag',
    pattern: /FROM\s+\S+:latest/,
    recommendation: 'Pin to a specific version tag',
  },
  {
    id: 'DOCK-002',
    severity: 'critical',
    description: 'Running as root',
    pattern: /^USER (?!\d+)(?!nobody)(?!www-data)(?!node)/m,
    recommendation: 'Use a non-root user',
  },
  {
    id: 'DOCK-003',
    severity: 'medium',
    description: 'No HEALTHCHECK instruction',
    pattern: /^(?!.*HEALTHCHECK)/s,
    recommendation: 'Add HEALTHCHECK for container orchestration',
  },
  {
    id: 'DOCK-004',
    severity: 'medium',
    description: 'Exposed port without EXPOSE',
    pattern: /CMD.*\d{4,5}|ENTRYPOINT.*\d{4,5}/,
    recommendation: 'Explicitly EXPOSE the port',
  },
  {
    id: 'DOCK-005',
    severity: 'low',
    description: 'No .dockerignore',
    pattern: /./,
    recommendation: 'Create .dockerignore to reduce build context',
  },
  {
    id: 'DOCK-006',
    severity: 'high',
    description: 'Sensitive data in build args',
    pattern: /ARG\s+(API_KEY|SECRET|PASSWORD|TOKEN)/i,
    recommendation: 'Use build secrets instead of ARG for sensitive data',
  },
  {
    id: 'DOCK-007',
    severity: 'medium',
    description: 'apt-get without --no-install-recommends',
    pattern: /apt-get\s+install(?!.*--no-install-recommends)/,
    recommendation: 'Add --no-install-recommends to reduce image size',
  },
  {
    id: 'DOCK-008',
    severity: 'low',
    description: 'Multiple RUN statements',
    pattern: /RUN.*&&.*&&.*&&.*&&/,
    recommendation: 'Combine RUN statements to reduce layers',
  },
  {
    id: 'DOCK-009',
    severity: 'info',
    description: 'Can use multi-stage build',
    pattern: /FROM\s+\S+\s+AS\s+\w+/,
    recommendation: 'Multi-stage builds reduce final image size',
  },
  {
    id: 'DOCK-010',
    severity: 'high',
    description: 'COPY instead of ADD recommended',
    pattern: /ADD\s+/s,
    recommendation: 'Use COPY instead of ADD when not extracting archives',
  },
];

export class ContainerScanner {
  readonly type: ScannerType = 'containers';

  scanDockerfile(content: string, filePath?: string): ScanResult {
    const startTime = Date.now();
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (const rule of DOCKERFILE_RULES) {
      if (rule.id === 'DOCK-003') {
        if (!content.match(/HEALTHCHECK/)) {
          findings.push({
            id: `${rule.id}-${Date.now()}`,
            scanner: 'containers',
            severity: rule.severity,
            title: `Dockerfile: ${rule.description}`,
            description: rule.description,
            file: filePath,
            line: 1,
            recommendation: rule.recommendation,
          });
        }
        continue;
      }

      for (let i = 0; i < lines.length; i++) {
        if (rule.pattern.test(lines[i])) {
          findings.push({
            id: `${rule.id}-${Date.now()}-${i}`,
            scanner: 'containers',
            severity: rule.severity,
            title: `Dockerfile: ${rule.description}`,
            description: rule.description,
            file: filePath,
            line: i + 1,
            code: lines[i].trim(),
            recommendation: rule.recommendation,
          });
        }
      }
    }

    const critical = findings.filter((f) => f.severity === 'critical').length;
    const high = findings.filter((f) => f.severity === 'high').length;
    const medium = findings.filter((f) => f.severity === 'medium').length;
    const low = findings.filter((f) => f.severity === 'low').length;
    const info = findings.filter((f) => f.severity === 'info').length;

    return {
      scanner: 'containers',
      target: filePath ?? 'Dockerfile',
      findings,
      summary: { total: findings.length, critical, high, medium, low, info },
      durationMs: Date.now() - startTime,
      timestamp: Date.now(),
    };
  }

  scanHelmChart(content: string, filePath?: string): ScanResult {
    const startTime = Date.now();
    const findings: Finding[] = [];

    if (content.includes('privileged: true')) {
      findings.push({
        id: `helm-priv-${Date.now()}`,
        scanner: 'containers',
        severity: 'critical',
        title: 'Helm: privileged container',
        description: 'Container runs with privileged security context',
        file: filePath,
        recommendation: 'Remove privileged: true from securityContext',
      });
    }

    return {
      scanner: 'containers',
      target: filePath ?? 'helm-chart',
      findings,
      summary: {
        total: findings.length,
        critical: findings.filter((f) => f.severity === 'critical').length,
        high: findings.filter((f) => f.severity === 'high').length,
        medium: findings.filter((f) => f.severity === 'medium').length,
        low: findings.filter((f) => f.severity === 'low').length,
        info: findings.filter((f) => f.severity === 'info').length,
      },
      durationMs: Date.now() - startTime,
      timestamp: Date.now(),
    };
  }
}
