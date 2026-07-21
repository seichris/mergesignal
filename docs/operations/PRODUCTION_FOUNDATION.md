# Production foundation operations

## Service boundary

The Vercel control plane accepts short requests and commits durable database work.
It does not connect to Temporal from an ingress handler. The Coolify worker owns
the outbox relay, Temporal workflows, and side-effecting activities.

The synthetic foundation path is deliberately the same shape as the future GitHub
path:

1. The authenticated route validates a bounded request.
2. One PostgreSQL transaction inserts the idempotent delivery and deduplicated
   outbox event.
3. The relay claims events with `FOR UPDATE SKIP LOCKED` and a fencing lease.
4. Temporal starts the deterministic workflow under a delivery-derived workflow ID.
5. An idempotent activity persists the result. Forced test failures commit their
   attempt before raising a retryable Temporal failure.
6. Duplicate ingress, relay retries, and activity retries converge on one delivery,
   one outbox event, one workflow, and one result.

## Local environment

Required versions are Node 22.17.0 and pnpm 10.34.5. Start PostgreSQL and Temporal:

~~~bash
docker compose up -d
cp .env.example .env
set -a
source .env
set +a
pnpm db:migrate
pnpm build
pnpm test:phase1:integration
~~~

The integration test creates isolated tenants, verifies RLS through the web role,
submits the same synthetic delivery twice, reclaims an expired relay lease, forces
two activity failures, and waits for exactly one persisted result on attempt three.

## Managed PostgreSQL

The provider is a deployment choice, but it must support PostgreSQL 17, TLS,
point-in-time recovery, connection pooling, role management, and tested restores.
Use separate login credentials that inherit these migration-created NOLOGIN roles:

- `mergesignal_web`: tenant-scoped ingress and dashboard access.
- `mergesignal_worker`: tenant-scoped workflow data plus the cross-tenant outbox
  relay envelope.
- `mergesignal_support`: tenant-scoped read-only access activated only through the
  later just-in-time support flow.

The migration principal is not an application credential. Run migrations as a
separate release step before promoting compatible web and worker artifacts.
Applied SQL is checksum-protected; changing an applied file fails closed.

## Temporal Cloud and Coolify

Terraform provisions one API-key-authenticated, deletion-protected Temporal Cloud
namespace per environment. Configure Coolify from `.env.example`; production must
enable Temporal TLS and Worker Deployment Versioning, and use the immutable signed
image digest as `WORKER_BUILD_ID`.

During rollout, keep the old and candidate Coolify services alive together. Set the
candidate as a bounded ramping Worker Deployment Version, inspect replay and
reachability, then promote. Rollback changes Temporal's current/ramping assignment;
it never rebuilds an older image.

Coolify probes `GET /readyz` on `WORKER_HEALTH_PORT` (8080 by default). The worker
returns ready only after PostgreSQL and Temporal clients, workflow bundling, and the
relay process have initialized; it returns unavailable as soon as draining begins.

## Vercel Kontext project

Terraform configures `apps/web` as the Next.js project root and enables affected
monorepo deployments. Configure secrets outside Terraform state:

- `DATABASE_URL` for the pooled `mergesignal_web` login.
- `INTERNAL_INGRESS_TOKEN`, at least 32 random bytes.
- `MERGESIGNAL_ENV` and `DEPLOYMENT_ID`.
- `OTEL_EXPORTER_OTLP_ENDPOINT` when an authenticated collector is available.

Builds initialize database and service clients lazily, so preview builds never need
production secrets. Vercel Git integration creates previews; production promotion
must reuse the already-tested artifact.

## Telemetry contract

Both runtimes emit OpenTelemetry traces and metrics through OTLP/HTTP. Structured
logs inherit active trace and span IDs. The logging helper rejects attribute names
that commonly carry authorization, tokens, bodies, content, private data, or raw
payloads.

Minimum alerts for Phase 1 are outbox age, outbox retry rate, workflow/activity
failure rate, database pool saturation, and web error/latency. Later phases add
GitHub, evidence, model, and publication-specific SLOs.
