# ADR 0001: Temporal for durable workflows

- Status: Accepted
- Date: July 21, 2026

## Context

Contributor history backfills can span many paginated GitHub requests, wait through rate limits, retry publication, and outlive a web request or worker restart. Pull-request updates can arrive out of order, and a newer head SHA must supersede older work.

## Decision

Use Temporal Cloud for durable orchestration and TypeScript workers on the Coolify server. PostgreSQL inbox/outbox records make webhook acceptance independent of Temporal availability.

Workflow definitions contain deterministic orchestration only. GitHub, OpenAI, database side effects, clocks, and identifiers live in idempotent activities.

Production uses Temporal Worker Versioning. Every signed worker image maps to one
immutable Worker Deployment Version/build identity. A candidate version must replay
the retained production-history corpus before it becomes eligible. New workflows
move first to a bounded ramping version; existing workflows remain pinned according
to their versioning behavior. Rollback changes the current/ramping assignment rather
than rebuilding an old image.

Coolify runs old and new worker deployments concurrently during a rollout. The old
deployment is drained only after Temporal reachability shows that no pinned or
otherwise reachable workflow can still require it, in-flight activities have
completed or heartbeated safely, and the rollback window has closed. Version
identity, current/ramping percentages, pinning state, reachability, replay result,
image digest, and retirement approval are release evidence.

## Consequences

- Backfills and retries resume after worker failure.
- Workflow versioning and replay safety become required engineering disciplines.
- Secrets and large payloads must not enter workflow histories.
- Temporal Cloud is an operational dependency, with a documented self-hosting escape path.
- A local Temporal server is required for development and CI.

## Rejected alternatives

- Long work in Vercel request handlers: timeout and retry behavior are unsuitable.
- Ad hoc database job polling: would recreate workflow history, retry, cancellation, and recovery logic.
- Queue-only tasks: insufficient for multi-step state, supersession, and resumable backfills without another orchestration layer.
