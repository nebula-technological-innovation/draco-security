import type { IaCIssue, ScanResult, ScannerType, Finding } from '../types/index.js';

interface IaCRule {
  id: string;
  provider: string;
  resource: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  pattern: RegExp;
  recommendation: string;
}

const IAC_RULES: IaCRule[] = [
  {
    id: 'S3-001',
    provider: 'aws',
    resource: 'aws_s3_bucket',
    severity: 'high',
    description: 'S3 bucket without encryption',
    pattern:
      /resource\s+"aws_s3_bucket"\s+[^{]*\{[^}]*"(?!.*server_side_encryption_configuration)/gs,
    recommendation: 'Enable default encryption on S3 buckets',
  },
  {
    id: 'S3-002',
    provider: 'aws',
    resource: 'aws_s3_bucket',
    severity: 'critical',
    description: 'S3 bucket with public access',
    pattern: /acl\s*=\s*"public-read"/,
    recommendation: 'Remove public read ACL from S3 bucket',
  },
  {
    id: 'IAM-001',
    provider: 'aws',
    resource: 'aws_iam_role',
    severity: 'high',
    description: 'IAM role with wildcard action',
    pattern: /Action\s*=\s*\[?\s*"\*"/,
    recommendation: 'Restrict IAM actions to least privilege',
  },
  {
    id: 'SG-001',
    provider: 'aws',
    resource: 'aws_security_group',
    severity: 'critical',
    description: 'Security group allows 0.0.0.0/0 ingress',
    pattern: /cidr_blocks\s*=\s*\[?\s*"0\.0\.0\.0\/0"/,
    recommendation: 'Restrict security group ingress to specific IP ranges',
  },
  {
    id: 'KMS-001',
    provider: 'aws',
    resource: 'aws_kms_key',
    severity: 'medium',
    description: 'KMS key with rotation disabled',
    pattern: /enable_key_rotation\s*=\s*false/,
    recommendation: 'Enable automatic key rotation',
  },
  {
    id: 'CON-001',
    provider: 'docker',
    resource: 'container',
    severity: 'high',
    description: 'Container running as root',
    pattern: /USER\s+root/i,
    recommendation: 'Use a non-root user in container',
  },
  {
    id: 'CON-002',
    provider: 'docker',
    resource: 'container',
    severity: 'medium',
    description: 'Container using latest tag',
    pattern: /:\s*"?latest"?$/,
    recommendation: 'Pin container image to a specific version',
  },
  {
    id: 'K8S-001',
    provider: 'kubernetes',
    resource: 'Pod',
    severity: 'critical',
    description: 'Privileged container',
    pattern: /privileged\s*:\s*true/,
    recommendation: 'Remove privileged: true from container security context',
  },
  {
    id: 'K8S-002',
    provider: 'kubernetes',
    resource: 'Pod',
    severity: 'high',
    description: 'Container with host network access',
    pattern: /hostNetwork\s*:\s*true/,
    recommendation: 'Remove hostNetwork: true unless absolutely necessary',
  },
];

export class IaCScanner {
  readonly type: ScannerType = 'iac';

  scan(content: string, filePath?: string): ScanResult {
    const startTime = Date.now();
    const findings: Finding[] = [];

    for (const rule of IAC_RULES) {
      if (rule.pattern.test(content)) {
        rule.pattern.lastIndex = 0;
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          if (rule.pattern.test(lines[i])) {
            rule.pattern.lastIndex = 0;
            findings.push({
              id: `${rule.id}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
              scanner: 'iac',
              severity: rule.severity,
              title: `${rule.provider.toUpperCase()}: ${rule.resource} — ${rule.description}`,
              description: rule.description,
              file: filePath,
              line: i + 1,
              code: lines[i].trim(),
              recommendation: rule.recommendation,
            });
          }
        }
      }
    }

    const critical = findings.filter((f) => f.severity === 'critical').length;
    const high = findings.filter((f) => f.severity === 'high').length;
    const medium = findings.filter((f) => f.severity === 'medium').length;

    return {
      scanner: 'iac',
      target: filePath ?? 'unknown',
      findings,
      summary: { total: findings.length, critical, high, medium, low: 0, info: 0 },
      durationMs: Date.now() - startTime,
      timestamp: Date.now(),
    };
  }
}
