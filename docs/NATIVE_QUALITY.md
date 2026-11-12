# Nebula/Aether first-party dependency and TypeScript quality gate

This repository is migrating away from paid GitHub Code Quality. This **draft-only**
preflight is a reproducibility and evidence control, not a release authorization.

## Verified scope

- Uses Node.js built-ins and `git`; does **not** call GitHub Actions, npm install,
  external code-quality services, model APIs, or a network service.
- Validates exact checked-out Git SHA (optionally an expected SHA), tracked-tree
  cleanliness, npm lockfile v3, the root dependency spec, and package-integrity entries.
- Optional `--typecheck` invokes only the already installed, local
  `node_modules/typescript/bin/tsc` with `--noEmit` and no shell.
- Emits JSON with SHA-256 manifest digests and fail-closed status. It does not
  publish credentials, merge code, deploy, or grant any production permission.
- All nine synthetic contract tests passed in an isolated Node.js 22 environment,
  but real repo build and installed dependency checks are **not verified**.

## Current blocker

**No root `package-lock.json` is committed.** The verifier intentionally
returns a nonzero exit until a legitimate npm-generated lockfile is reviewed
and installed. Do not fabricate package integrity hashes or bypass the gate.

## Reproducible recovery procedure (requires an approved, clean worktree and a working registry)

```sh
# In an isolated branch, check free disk and use the approved npm registry.
npm install --package-lock-only --ignore-scripts --no-audit --no-fund

# Inspect package-lock.json and package.json before committing.
git diff --check
git diff -- package.json package-lock.json

# Commit and verify the exact SHA; use this after the lockfile exists.
node --test tests/native-quality.test.mjs
npm ci --ignore-scripts --no-audit --no-fund
node scripts/native-quality.mjs --typecheck --expected-sha "$(git rev-parse HEAD)"
```

For fully offline operation use `npm ci --offline --ignore-scripts` **only if all
locked tarballs are already cached**. Missing dependencies are a blocker, not a
passing result. Follow the existing TypeScript `typecheck` command, then
run project tests, dependency and license checks, and the broader Nebula native
security policy independently. Do not automatically merge or promote builds.

Related tracking: https://github.com/nebula-technological-innovation/nebula-monorepo/issues/1236
