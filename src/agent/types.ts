import type { Severity, Finding } from '../types/index.js';

export type MissionStatus = 'queued' | 'running' | 'completed';

export interface SecurityContext {
  assetId?: string;
  organizationId?: string;
  findings: Finding[];
  source?: string;
  metadata?: Record<string, unknown>;
}

export interface SecurityResult {
  agent: string;
  classification: string;
  impact: string;
  remediation: string;
  reasoning: string;
  riskScore: number;
  severity: Severity;
  recommendations: string[];
}

export interface SecurityAgent {
  name: string;
  analyze(input: SecurityContext): Promise<SecurityResult>;
}
