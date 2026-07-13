import type { SecretMatch, ScanResult, ScannerType } from '../types/index.js';

const SECRET_PATTERNS: Array<{ type: string; pattern: RegExp; flags?: string }> = [
  { type: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/ },
  { type: 'AWS Secret Key', pattern: /aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]/, flags: 'i' },
  { type: 'GitHub Token', pattern: /ghp_[0-9a-zA-Z]{36}/ },
  { type: 'GitHub PAT', pattern: /github_pat_[0-9a-zA-Z]{22,}/ },
  { type: 'Stripe Key', pattern: /sk_live_[0-9a-zA-Z]{24,}/ },
  { type: 'Stripe Publishable', pattern: /pk_live_[0-9a-zA-Z]{24,}/ },
  { type: 'Cloudflare Token', pattern: /cfat_[0-9a-zA-Z]{40,}/ },
  { type: 'JWT Secret', pattern: /jwt.{0,20}['\"][0-9a-zA-Z]{32,}['\"]/, flags: 'i' },
  { type: 'Private Key', pattern: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/ },
  { type: 'Slack Token', pattern: /xox[baprs]-[0-9a-zA-Z\-]{10,}/ },
  { type: 'Google API Key', pattern: /AIza[0-9A-Za-z\-_]{35}/ },
  {
    type: 'Heroku API Key',
    pattern: /heroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/,
    flags: 'i',
  },
  {
    type: 'Generic API Key',
    pattern: /(api[_-]?key|apikey|secret[_-]?key).{0,20}['\"][0-9a-zA-Z]{16,}['\"]/,
    flags: 'i',
  },
  {
    type: 'Password in Code',
    pattern: /(password|passwd|pwd).{0,20}=.{0,20}['\"][^'\"\s]{8,}['\"]/,
    flags: 'i',
  },
  { type: 'Connection String', pattern: /mongodb(\+srv)?:\/\/[^\s]+/ },
  { type: 'Redis URL', pattern: /redis:\/\/[^\s]+/ },
  { type: 'PostgreSQL URL', pattern: /postgresql:\/\/[^\s]+/ },
];

export class SecretScanner {
  readonly type: ScannerType = 'secrets';

  async scan(content: string, filePath?: string): Promise<ScanResult> {
    const startTime = Date.now();
    const findings: any[] = [];

    for (const { type, pattern, flags } of SECRET_PATTERNS) {
      const re = flags ? new RegExp(pattern.source, flags) : pattern;
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const match = lines[i].match(re);
        if (match) {
          findings.push({
            type,
            value: match[0].slice(0, 40) + '...',
            file: filePath ?? 'unknown',
            line: i + 1,
            entropy: this.calcEntropy(match[0]),
            isVerified: false,
          });
        }
      }
    }

    const critical = findings.filter((f) => this.isCritical(f.type)).length;
    const high = findings.filter((f) => this.isHigh(f.type)).length;
    const medium = findings.filter((f) => !this.isCritical(f.type) && !this.isHigh(f.type)).length;

    return {
      scanner: 'secrets',
      target: filePath ?? 'string-content',
      findings: findings.map((f) => ({
        id: `secret-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        scanner: 'secrets' as const,
        severity: this.classify(f.type),
        title: `Secret detected: ${f.type}`,
        description: `Found ${f.type} at line ${f.line}${f.file !== 'unknown' ? ` in ${f.file}` : ''}`,
        file: f.file,
        line: f.line,
        code: f.value,
        recommendation: `Remove this ${f.type} from source code. Use environment variables or a secrets manager.`,
      })),
      summary: { total: findings.length, critical, high, medium, low: 0, info: 0 },
      durationMs: Date.now() - startTime,
      timestamp: Date.now(),
    };
  }

  private calcEntropy(s: string): number {
    const freq: Record<string, number> = {};
    for (const ch of s) freq[ch] = (freq[ch] ?? 0) + 1;
    let entropy = 0;
    for (const ch in freq) {
      const p = freq[ch] / s.length;
      entropy -= p * Math.log2(p);
    }
    return Math.round(entropy * 100) / 100;
  }

  private isCritical(type: string): boolean {
    return ['Private Key', 'AWS Secret Key', 'Stripe Key'].includes(type);
  }

  private isHigh(type: string): boolean {
    return [
      'AWS Access Key',
      'GitHub Token',
      'GitHub PAT',
      'Cloudflare Token',
      'JWT Secret',
    ].includes(type);
  }

  private classify(type: string): 'critical' | 'high' | 'medium' {
    if (this.isCritical(type)) return 'critical';
    if (this.isHigh(type)) return 'high';
    return 'medium';
  }
}
