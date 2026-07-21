# Phase 1 normal review

## Scope

This is the single focused review/fix pass requested for Phase 1. It covers the
production foundation: monorepo boundaries, web and worker runtimes, PostgreSQL,
Temporal, telemetry, infrastructure definitions, CI, and the synthetic durable path.

Reviewed candidate before this report:

- Base: `8a4b325e20d0f606196f632c91ea970651900736`
- Snapshot: `4eba815da35b5e4b445059ea64016a8436355763faa1cc2cda4f033a4f2c3048`
- Files: 206 tracked and untracked nonignored files

## Findings and resolutions

| Severity | Finding | Resolution |
|---:|---|---|
| P1 | A repeated delivery ID with a changed body digest could be treated as an ordinary duplicate | Duplicate acceptance now requires the original digest; a changed payload fails closed |
| P1 | An outbox row abandoned in `publishing` could never be reclaimed | Claims now include expired publishing leases under a fresh fencing token; the real integration test forces this state |
| P1 | The web role could update outbox rows even though ingress only needs insert and read | The upsert became insert-then-select and the migration grants only `SELECT` and `INSERT` |
| P1 | Temporal TLS was inferred from the hostname, so an internal non-loopback development address was incorrectly forced to TLS | TLS is now explicit, production requires it, mTLS credentials require it, and local container networking can safely disable it |
| P1 | The slim production image lacked a usable CA trust store and the Temporal native client exited at startup | The runtime installs `ca-certificates`; the rebuilt image connects and reaches readiness |
| P2 | The Coolify worker had no liveness/readiness contract or image health check | Added `/livez`, `/readyz`, drain-aware readiness, a Docker health check, and unit tests |
| P2 | Broad OpenTelemetry auto-instrumentation inflated the runtime dependency set | Replaced it with explicit HTTP, PostgreSQL, and Undici instrumentation |
| P2 | pnpm could skip required native build scripts in clean container installs | Added a narrow build-script allowlist for SWC, esbuild, protobufjs, and sharp |
| P2 | Generated Terraform plugin files were accidentally included in the whitespace walk | The repository gate now excludes `.terraform` just like other generated directories |

No unresolved P0 or P1 finding remains in the reviewed Phase 1 scope.

## Verification

- Full repository CI: 18 of 18 Turbo tasks passed; 12 unit tests passed.
- Phase 0 regression gate: 40 schemas, 321 adversarial mutations, three replay
  bundles, whitespace, and Markdown passed.
- Real foundation integration: duplicate ingress converged, a changed digest was
  rejected, an expired relay lease was reclaimed, two forced activity failures
  retried, and one result persisted on activity attempt three.
- PostgreSQL isolation: tenant RLS hid the second tenant and the web role was unable
  to update outbox state.
- Terraform 1.14.0: format and validation passed for development, staging, and
  production with read-only provider locks.
- Worker image: `sha256:edd7f13986e0825ed5ceb0006ab5e780f354caa912922bccb46e76a8ffe9c8c3`
  built on the local ARM64 environment, connected to the containerized dependencies,
  returned ready, and drained with exit code 0.
- Final diff whitespace check passed.

## Result

Phase 1 is approved. Its exit gate is satisfied: a synthetic delivery travels
idempotently from ingress through the durable outbox and Temporal workflow to one
persisted result under forced retries. Phase 2 may build the GitHub App lifecycle on
this foundation.
