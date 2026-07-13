import { z } from 'zod';

export const SeveritySchema = z.enum(['critical', 'high', 'medium', 'low', 'info']);
export type Severity = z.infer<typeof SeveritySchema>;

export const ScannerTypeSchema = z.enum([
  'secrets',
  'dependencies',
  'containers',
  'iac',
  'sast',
  'dast',
  'threat-model',
]);
export type ScannerType = z.infer<typeof ScannerTypeSchema>;

export interface Finding {
  id: string;
  scanner: ScannerType;
  severity: Severity;
  title: string;
  description: string;
  file?: string;
  line?: number;
  code?: string;
  recommendation: string;
  cve?: string;
  cvss?: number;
}

export interface ScanResult {
  scanner: ScannerType;
  target: string;
  findings: Finding[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  durationMs: number;
  timestamp: number;
}

export interface SecurityReport {
  id: string;
  title: string;
  scans: ScanResult[];
  overall: {
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    score: number;
  };
  generatedAt: number;
}

export interface ThreatModel {
  id: string;
  system: string;
  assets: string[];
  threats: Array<{
    id: string;
    name: string;
    category:
      | 'spoofing'
      | 'tampering'
      | 'repudiation'
      | 'information-disclosure'
      | 'denial-of-service'
      | 'elevation-of-privilege';
    risk: Severity;
    description: string;
    mitigation: string;
  }>;
}

export const DependencySchema = z.object({
  name: z.string(),
  version: z.string(),
  latest: z.string().optional(),
  vulnerabilities: z.array(
    z.object({
      cve: z.string(),
      severity: SeveritySchema,
      title: z.string(),
      fixVersion: z.string().optional(),
    }),
  ),
  licenses: z.array(z.string()).optional(),
});

export type Dependency = z.infer<typeof DependencySchema>;

export interface SecretMatch {
  type: string;
  value: string;
  file: string;
  line: number;
  entropy: number;
  isVerified: boolean;
}

export interface IaCIssue {
  resource: string;
  provider: string;
  severity: Severity;
  rule: string;
  description: string;
  recommendation: string;
}
