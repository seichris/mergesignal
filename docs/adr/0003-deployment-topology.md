# ADR 0003: Vercel Kontext control plane and Coolify workers

- Status: Accepted
- Date: July 21, 2026

## Context

The team has the Kontext team on Vercel and an existing Coolify server. The Next.js dashboard benefits from Vercel, while long-lived Temporal workers and outbox relays require persistent container processes.

## Decision

- Deploy the Next.js web/control plane to the Kontext team on Vercel.
- Deploy containerized Temporal workers and the PostgreSQL outbox relay to the Coolify server.
- Use Temporal Cloud for orchestration.
- Use managed PostgreSQL with backups, point-in-time recovery, pooling, and encryption.
- Keep stateful services in compatible regions and connect them through authenticated TLS.
- Define repeatable infrastructure and environment configuration in Terraform where provider support permits.

## Consequences

- Web request handlers remain stateless and short-lived.
- Vercel and Coolify need separate, least-privilege deployment credentials.
- Cross-provider latency, egress, and incident ownership must be observed.
- Coolify health checks, rolling deploys, resource limits, and worker drain behavior become release requirements.
- Coolify worker services are named by immutable Worker Deployment Version and image
  digest. Deployments overlap during Temporal current/ramping transitions; an old
  service is never stopped merely because a new container is healthy.
- Development, staging, and production use separate GitHub Apps, OpenAI projects, databases, and Temporal namespaces.
- Each environment's signed product-policy artifact contains that deployment's
  positive numeric GitHub App ID and slug. Startup and promotion query the
  authenticated GitHub App identity and fail closed unless it matches the artifact;
  schemas do not embed a fixture App ID as a universal constant.

## Rejected alternatives

- Run workers in Vercel functions: incompatible with persistent polling and graceful activity execution.
- Run the dashboard on Coolify immediately: gives up the existing Vercel team workflow without a demonstrated need.
- Self-host Temporal initially: adds substantial stateful operational risk.
