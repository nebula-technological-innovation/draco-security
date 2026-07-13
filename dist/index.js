// src/scanners/SecretScanner.ts
var SECRET_PATTERNS = [
  { type: "AWS Access Key", pattern: /AKIA[0-9A-Z]{16}/ },
  { type: "AWS Secret Key", pattern: /aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]/, flags: "i" },
  { type: "GitHub Token", pattern: /ghp_[0-9a-zA-Z]{36}/ },
  { type: "GitHub PAT", pattern: /github_pat_[0-9a-zA-Z]{22,}/ },
  { type: "Stripe Key", pattern: /sk_live_[0-9a-zA-Z]{24,}/ },
  { type: "Stripe Publishable", pattern: /pk_live_[0-9a-zA-Z]{24,}/ },
  { type: "Cloudflare Token", pattern: /cfat_[0-9a-zA-Z]{40,}/ },
  { type: "JWT Secret", pattern: /jwt.{0,20}['\"][0-9a-zA-Z]{32,}['\"]/, flags: "i" },
  { type: "Private Key", pattern: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/ },
  { type: "Slack Token", pattern: /xox[baprs]-[0-9a-zA-Z\-]{10,}/ },
  { type: "Google API Key", pattern: /AIza[0-9A-Za-z\-_]{35}/ },
  { type: "Heroku API Key", pattern: /heroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/, flags: "i" },
  { type: "Generic API Key", pattern: /(api[_-]?key|apikey|secret[_-]?key).{0,20}['\"][0-9a-zA-Z]{16,}['\"]/, flags: "i" },
  { type: "Password in Code", pattern: /(password|passwd|pwd).{0,20}=.{0,20}['\"][^'\"\s]{8,}['\"]/, flags: "i" },
  { type: "Connection String", pattern: /mongodb(\+srv)?:\/\/[^\s]+/ },
  { type: "Redis URL", pattern: /redis:\/\/[^\s]+/ },
  { type: "PostgreSQL URL", pattern: /postgresql:\/\/[^\s]+/ }
];
var SecretScanner = class {
  type = "secrets";
  async scan(content, filePath) {
    const startTime = Date.now();
    const findings = [];
    for (const { type, pattern, flags } of SECRET_PATTERNS) {
      const re = flags ? new RegExp(pattern.source, flags) : pattern;
      const lines = content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const match = lines[i].match(re);
        if (match) {
          findings.push({
            type,
            value: match[0].slice(0, 40) + "...",
            file: filePath ?? "unknown",
            line: i + 1,
            entropy: this.calcEntropy(match[0]),
            isVerified: false
          });
        }
      }
    }
    const critical = findings.filter((f) => this.isCritical(f.type)).length;
    const high = findings.filter((f) => this.isHigh(f.type)).length;
    const medium = findings.filter((f) => !this.isCritical(f.type) && !this.isHigh(f.type)).length;
    return {
      scanner: "secrets",
      target: filePath ?? "string-content",
      findings: findings.map((f) => ({
        id: `secret-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        scanner: "secrets",
        severity: this.classify(f.type),
        title: `Secret detected: ${f.type}`,
        description: `Found ${f.type} at line ${f.line}${f.file !== "unknown" ? ` in ${f.file}` : ""}`,
        file: f.file,
        line: f.line,
        code: f.value,
        recommendation: `Remove this ${f.type} from source code. Use environment variables or a secrets manager.`
      })),
      summary: { total: findings.length, critical, high, medium, low: 0, info: 0 },
      durationMs: Date.now() - startTime,
      timestamp: Date.now()
    };
  }
  calcEntropy(s) {
    const freq = {};
    for (const ch of s) freq[ch] = (freq[ch] ?? 0) + 1;
    let entropy = 0;
    for (const ch in freq) {
      const p = freq[ch] / s.length;
      entropy -= p * Math.log2(p);
    }
    return Math.round(entropy * 100) / 100;
  }
  isCritical(type) {
    return ["Private Key", "AWS Secret Key", "Stripe Key"].includes(type);
  }
  isHigh(type) {
    return ["AWS Access Key", "GitHub Token", "GitHub PAT", "Cloudflare Token", "JWT Secret"].includes(type);
  }
  classify(type) {
    if (this.isCritical(type)) return "critical";
    if (this.isHigh(type)) return "high";
    return "medium";
  }
};

// src/scanners/DependencyScanner.ts
var NPM_ADVISORY_DB = {};
var DependencyScanner = class {
  type = "dependencies";
  async scanNpm(packages) {
    const startTime = Date.now();
    const findings = [];
    for (const pkg of packages) {
      const advisories = NPM_ADVISORY_DB[pkg.name] ?? [];
      for (const adv of advisories) {
        findings.push({
          id: `dep-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
          scanner: "dependencies",
          severity: adv.severity,
          title: `${pkg.name}: ${adv.title}`,
          description: `Vulnerability in ${pkg.name}@${pkg.version}: ${adv.title}`,
          cve: adv.cve,
          recommendation: `Upgrade ${pkg.name} to ${adv.patched}`
        });
      }
    }
    const critical = findings.filter((f) => f.severity === "critical").length;
    const high = findings.filter((f) => f.severity === "high").length;
    const medium = findings.filter((f) => f.severity === "medium").length;
    const low = findings.filter((f) => f.severity === "low").length;
    return {
      scanner: "dependencies",
      target: "npm-packages",
      findings,
      summary: { total: findings.length, critical, high, medium, low, info: 0 },
      durationMs: Date.now() - startTime,
      timestamp: Date.now()
    };
  }
  async scan(packages) {
    if (packages.length === 0) {
      return {
        scanner: "dependencies",
        target: "packages",
        findings: [],
        summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        durationMs: 0,
        timestamp: Date.now()
      };
    }
    return this.scanNpm(packages.filter((p) => p.ecosystem === "npm").map((p) => ({ name: p.name, version: p.version })));
  }
  async scanLockfile(content, ecosystem) {
    const packages = this.parseLockfile(content, ecosystem);
    return this.scan(packages);
  }
  parseLockfile(content, ecosystem) {
    const result = [];
    if (ecosystem === "npm") {
      const pkgMatch = content.match(/"name":\s*"([^"]+)"/);
      if (pkgMatch) {
        const depRegex = /"([^"]+)":\s*\{\s*"version":\s*"([^"]+)"/g;
        let m;
        while ((m = depRegex.exec(content)) !== null) {
          result.push({ name: m[1], version: m[2], ecosystem: "npm" });
        }
      }
    }
    return result;
  }
};

// src/scanners/IaCScanner.ts
var IAC_RULES = [
  { id: "S3-001", provider: "aws", resource: "aws_s3_bucket", severity: "high", description: "S3 bucket without encryption", pattern: /resource\s+"aws_s3_bucket"\s+[^{]*\{[^}]*"(?!.*server_side_encryption_configuration)/gs, recommendation: "Enable default encryption on S3 buckets" },
  { id: "S3-002", provider: "aws", resource: "aws_s3_bucket", severity: "critical", description: "S3 bucket with public access", pattern: /acl\s*=\s*"public-read"/, recommendation: "Remove public read ACL from S3 bucket" },
  { id: "IAM-001", provider: "aws", resource: "aws_iam_role", severity: "high", description: "IAM role with wildcard action", pattern: /Action\s*=\s*\[?\s*"\*"/, recommendation: "Restrict IAM actions to least privilege" },
  { id: "SG-001", provider: "aws", resource: "aws_security_group", severity: "critical", description: "Security group allows 0.0.0.0/0 ingress", pattern: /cidr_blocks\s*=\s*\[?\s*"0\.0\.0\.0\/0"/, recommendation: "Restrict security group ingress to specific IP ranges" },
  { id: "KMS-001", provider: "aws", resource: "aws_kms_key", severity: "medium", description: "KMS key with rotation disabled", pattern: /enable_key_rotation\s*=\s*false/, recommendation: "Enable automatic key rotation" },
  { id: "CON-001", provider: "docker", resource: "container", severity: "high", description: "Container running as root", pattern: /USER\s+root/i, recommendation: "Use a non-root user in container" },
  { id: "CON-002", provider: "docker", resource: "container", severity: "medium", description: "Container using latest tag", pattern: /:\s*"?latest"?$/, recommendation: "Pin container image to a specific version" },
  { id: "K8S-001", provider: "kubernetes", resource: "Pod", severity: "critical", description: "Privileged container", pattern: /privileged\s*:\s*true/, recommendation: "Remove privileged: true from container security context" },
  { id: "K8S-002", provider: "kubernetes", resource: "Pod", severity: "high", description: "Container with host network access", pattern: /hostNetwork\s*:\s*true/, recommendation: "Remove hostNetwork: true unless absolutely necessary" }
];
var IaCScanner = class {
  type = "iac";
  scan(content, filePath) {
    const startTime = Date.now();
    const findings = [];
    for (const rule of IAC_RULES) {
      if (rule.pattern.test(content)) {
        rule.pattern.lastIndex = 0;
        const lines = content.split("\n");
        for (let i = 0; i < lines.length; i++) {
          if (rule.pattern.test(lines[i])) {
            rule.pattern.lastIndex = 0;
            findings.push({
              id: `${rule.id}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
              scanner: "iac",
              severity: rule.severity,
              title: `${rule.provider.toUpperCase()}: ${rule.resource} \u2014 ${rule.description}`,
              description: rule.description,
              file: filePath,
              line: i + 1,
              code: lines[i].trim(),
              recommendation: rule.recommendation
            });
          }
        }
      }
    }
    const critical = findings.filter((f) => f.severity === "critical").length;
    const high = findings.filter((f) => f.severity === "high").length;
    const medium = findings.filter((f) => f.severity === "medium").length;
    return {
      scanner: "iac",
      target: filePath ?? "unknown",
      findings,
      summary: { total: findings.length, critical, high, medium, low: 0, info: 0 },
      durationMs: Date.now() - startTime,
      timestamp: Date.now()
    };
  }
};

// src/scanners/ContainerScanner.ts
var DOCKERFILE_RULES = [
  { id: "DOCK-001", severity: "high", description: "Using latest tag", pattern: /FROM\s+\S+:latest/, recommendation: "Pin to a specific version tag" },
  { id: "DOCK-002", severity: "critical", description: "Running as root", pattern: /^USER (?!\d+)(?!nobody)(?!www-data)(?!node)/m, recommendation: "Use a non-root user" },
  { id: "DOCK-003", severity: "medium", description: "No HEALTHCHECK instruction", pattern: /^(?!.*HEALTHCHECK)/s, recommendation: "Add HEALTHCHECK for container orchestration" },
  { id: "DOCK-004", severity: "medium", description: "Exposed port without EXPOSE", pattern: /CMD.*\d{4,5}|ENTRYPOINT.*\d{4,5}/, recommendation: "Explicitly EXPOSE the port" },
  { id: "DOCK-005", severity: "low", description: "No .dockerignore", pattern: /./, recommendation: "Create .dockerignore to reduce build context" },
  { id: "DOCK-006", severity: "high", description: "Sensitive data in build args", pattern: /ARG\s+(API_KEY|SECRET|PASSWORD|TOKEN)/i, recommendation: "Use build secrets instead of ARG for sensitive data" },
  { id: "DOCK-007", severity: "medium", description: "apt-get without --no-install-recommends", pattern: /apt-get\s+install(?!.*--no-install-recommends)/, recommendation: "Add --no-install-recommends to reduce image size" },
  { id: "DOCK-008", severity: "low", description: "Multiple RUN statements", pattern: /RUN.*&&.*&&.*&&.*&&/, recommendation: "Combine RUN statements to reduce layers" },
  { id: "DOCK-009", severity: "info", description: "Can use multi-stage build", pattern: /FROM\s+\S+\s+AS\s+\w+/, recommendation: "Multi-stage builds reduce final image size" },
  { id: "DOCK-010", severity: "high", description: "COPY instead of ADD recommended", pattern: /ADD\s+/s, recommendation: "Use COPY instead of ADD when not extracting archives" }
];
var ContainerScanner = class {
  type = "containers";
  scanDockerfile(content, filePath) {
    const startTime = Date.now();
    const findings = [];
    const lines = content.split("\n");
    for (const rule of DOCKERFILE_RULES) {
      if (rule.id === "DOCK-003") {
        if (!content.match(/HEALTHCHECK/)) {
          findings.push({
            id: `${rule.id}-${Date.now()}`,
            scanner: "containers",
            severity: rule.severity,
            title: `Dockerfile: ${rule.description}`,
            description: rule.description,
            file: filePath,
            line: 1,
            recommendation: rule.recommendation
          });
        }
        continue;
      }
      for (let i = 0; i < lines.length; i++) {
        if (rule.pattern.test(lines[i])) {
          findings.push({
            id: `${rule.id}-${Date.now()}-${i}`,
            scanner: "containers",
            severity: rule.severity,
            title: `Dockerfile: ${rule.description}`,
            description: rule.description,
            file: filePath,
            line: i + 1,
            code: lines[i].trim(),
            recommendation: rule.recommendation
          });
        }
      }
    }
    const critical = findings.filter((f) => f.severity === "critical").length;
    const high = findings.filter((f) => f.severity === "high").length;
    const medium = findings.filter((f) => f.severity === "medium").length;
    const low = findings.filter((f) => f.severity === "low").length;
    const info = findings.filter((f) => f.severity === "info").length;
    return {
      scanner: "containers",
      target: filePath ?? "Dockerfile",
      findings,
      summary: { total: findings.length, critical, high, medium, low, info },
      durationMs: Date.now() - startTime,
      timestamp: Date.now()
    };
  }
  scanHelmChart(content, filePath) {
    const startTime = Date.now();
    const findings = [];
    if (content.includes("privileged: true")) {
      findings.push({
        id: `helm-priv-${Date.now()}`,
        scanner: "containers",
        severity: "critical",
        title: "Helm: privileged container",
        description: "Container runs with privileged security context",
        file: filePath,
        recommendation: "Remove privileged: true from securityContext"
      });
    }
    return {
      scanner: "containers",
      target: filePath ?? "helm-chart",
      findings,
      summary: {
        total: findings.length,
        critical: findings.filter((f) => f.severity === "critical").length,
        high: findings.filter((f) => f.severity === "high").length,
        medium: findings.filter((f) => f.severity === "medium").length,
        low: findings.filter((f) => f.severity === "low").length,
        info: findings.filter((f) => f.severity === "info").length
      },
      durationMs: Date.now() - startTime,
      timestamp: Date.now()
    };
  }
};

// src/reports/index.ts
var SEVERITY_WEIGHTS = {
  critical: 10,
  high: 7,
  medium: 4,
  low: 1,
  info: 0
};
function generateReport(scans, title = "Security Audit Report") {
  const allFindings = scans.flatMap((s) => s.findings);
  const critical = allFindings.filter((f) => f.severity === "critical").length;
  const high = allFindings.filter((f) => f.severity === "high").length;
  const medium = allFindings.filter((f) => f.severity === "medium").length;
  const low = allFindings.filter((f) => f.severity === "low").length;
  const info = allFindings.filter((f) => f.severity === "info").length;
  const maxScore = allFindings.length * 10;
  const actualScore = allFindings.reduce((s, f) => s + SEVERITY_WEIGHTS[f.severity], 0);
  const score = maxScore > 0 ? Math.round((1 - actualScore / maxScore) * 100) : 100;
  return {
    id: `report-${Date.now()}`,
    title,
    scans,
    overall: { totalFindings: allFindings.length, critical, high, medium, low, info, score },
    generatedAt: Date.now()
  };
}
function formatReport(report) {
  const lines = [
    `# ${report.title}`,
    `Generated: ${new Date(report.generatedAt).toISOString()}`,
    `Security Score: ${report.overall.score}/100`,
    "",
    "## Summary",
    `Total Findings: ${report.overall.totalFindings}`,
    `  Critical: ${report.overall.critical}`,
    `  High:     ${report.overall.high}`,
    `  Medium:   ${report.overall.medium}`,
    `  Low:      ${report.overall.low}`,
    `  Info:     ${report.overall.info}`,
    ""
  ];
  for (const scan of report.scans) {
    lines.push(`## ${scan.scanner} Scan \u2014 ${scan.target}`);
    lines.push(`Duration: ${scan.durationMs}ms`);
    lines.push(`Findings: ${scan.summary.total}`);
    lines.push("");
    for (const f of scan.findings) {
      const tag = f.severity === "critical" ? "\u{1F534}" : f.severity === "high" ? "\u{1F7E0}" : f.severity === "medium" ? "\u{1F7E1}" : "\u26AA";
      lines.push(`### ${tag} [${f.severity.toUpperCase()}] ${f.title}`);
      lines.push(`${f.description}`);
      if (f.file) lines.push(`File: ${f.file}${f.line ? `:${f.line}` : ""}`);
      if (f.cve) lines.push(`CVE: ${f.cve}`);
      lines.push(`Recommendation: ${f.recommendation}`);
      lines.push("");
    }
  }
  return lines.join("\n");
}
function generateThreatModel(system, assets) {
  return {
    id: `tm-${Date.now()}`,
    system,
    assets,
    threats: [
      { id: "STR-01", name: "Identity Spoofing", category: "spoofing", risk: "high", description: "Attacker impersonates a legitimate user or service", mitigation: "Implement strong authentication and mutual TLS" },
      { id: "STR-02", name: "Data Tampering", category: "tampering", risk: "high", description: "Attacker modifies data in transit or at rest", mitigation: "Use TLS, signing, and integrity checks" },
      { id: "STR-03", name: "Repudiation", category: "repudiation", risk: "medium", description: "User denies performing an action without proof", mitigation: "Implement audit logging with non-repudiation" },
      { id: "STR-04", name: "Information Disclosure", category: "information-disclosure", risk: "critical", description: "Sensitive data exposed to unauthorized parties", mitigation: "Encrypt data at rest and in transit, implement least privilege" },
      { id: "STR-05", name: "Denial of Service", category: "denial-of-service", risk: "high", description: "System becomes unavailable due to resource exhaustion", mitigation: "Rate limiting, auto-scaling, DDoS protection" },
      { id: "STR-06", name: "Privilege Escalation", category: "elevation-of-privilege", risk: "critical", description: "User gains unauthorized elevated access", mitigation: "RBAC, principle of least privilege, regular access reviews" }
    ]
  };
}
export {
  ContainerScanner,
  DependencyScanner,
  IaCScanner,
  SecretScanner,
  formatReport,
  generateReport,
  generateThreatModel
};
