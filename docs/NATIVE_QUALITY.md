# Draco Security — first-party dependency and source quality

**Review-only changes.** The release/merge hold remains even when individual
checks pass.

## Verified improvements

- npm v3 `package-lock.json` with real registry-resolved dependency integrity.
- Zod migrated from vulnerable v3 to **v4**. The esbuild resolution is
  overridden to a patched **0.28.x** release within the reviewed local lock.
- Frozen `npm ci --ignore-scripts --no-audit --no-fund`, TypeScript
  `tsc --noEmit`, tsup ESM/type-declaration build and strict pinned
  open-source Biome lint all passed on the isolated Mac worktree.
- **15/15** native and source scanner tests passed (including lockfile
  provenance, Zod schema compatibility, fail-closed advisory feed, and secret
  output redaction).
- A public npm advisory audit returned **0 known findings** in the tested
  dependency graph. This does not guarantee absence of vulnerabilities.

## Critical limitation — advisory authority

The embedded `DependencyScanner` does not include an authoritative advisory
database. It now emits a **high-severity verification blocker**, rather than
incorrectly reporting a clean vulnerability scan, whenever packages are
supplied without configured intelligence. Invalid/unresolved npm lockfiles also
fail closed. The independent npm audit is separate and must run for actual
known-vulnerability verification. Do not treat the embedded scanner's
verification blocker as a discovered CVE.

The `SecretScanner` reports `[REDACTED]` rather than preserving credential
bytes in finding output. A regression test checks this boundary.

## Operator validation

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run typecheck
npm run build
npm run lint
npm run test
npm audit --audit-level=high --no-fund
node scripts/native-quality.mjs --typecheck --expected-sha "$(git rev-parse HEAD)"
```

This native control uses no paid GitHub Code Quality, paid tokens, merge,
deployment, or repository-setting changes. Keep the Zod major-version
migration, esbuild override, and dependency scanner behavior under code review;
test consumers and other runtime integration surfaces before production
promotion. Full security SAST/DAST, runtime integration, SBOM and license
provenance remain independent release gates.

Portfolio tracking: https://github.com/nebula-technological-innovation/nebula-monorepo/issues/1236
