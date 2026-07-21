# ADR 0002: PostgreSQL as system of record with row-level security

- Status: Accepted
- Date: July 21, 2026

## Context

MergeSignal stores tenant state, public and private evidence, immutable assessment
snapshots, append-only GitHub publication events, workflow coordination,
corrections, and audit records. Private evidence must not cross tenant or
repository boundaries.

## Decision

Use managed PostgreSQL as the system of record. Apply row-level security with default-deny policies to tenant-owned data. Keep public-global evidence and target-repository-private evidence in separate schemas, and use distinct application roles for web, worker, migration, and support operations.

Use a transactional inbox/outbox for webhook durability. Object storage holds only short-lived raw payloads and export artifacts.

Keep the immutable calculation record separate from PR-scoped publication
generations, comment IDs, Check IDs, retry state, supersession, and an append-only
assessment-retention lifecycle. Retention events have a monotonic per-assessment
revision, unique `(assessment_id, lifecycle_revision)`, and database-enforced
compare-and-swap transition constraint. `subject_deleted` and
`expired` are terminal; compare-and-swap writes reject reversal or stale retained
updates. Retain the minimized calculation material referenced by an assessment for
the assessment's retention period. A lawful deletion erases or cryptographically
destroys the subject, assessment, and calculation content; the content-free
lifecycle reaches `subject_deleted`, forbids publication, and intentionally ends
exact reproduction.

Snapshot manifests use the exact I-JSON envelope `{schemaVersion, snapshotId,
capturedAt, items}`. Items are sorted by evidence ID, the complete envelope is serialized with
a pinned and tested RFC 8785 JSON Canonicalization Scheme implementation, and the
resulting UTF-8 bytes are hashed with SHA-256. Append-only publication events bind
installation, repository, immutable PR node, PR number, assessment, head SHA,
latest observed generation, typed pre/post source-visibility records, and pre/post
retention revisions independently from that immutable hash. Unique logical keys
allow one publication aggregate per installation/repository/PR/generation and one
comment-removal aggregate per terminal-retention/publication/comment target.

## Consequences

- Tenant isolation is enforced below application code and requires dedicated integration tests.
- Migrations use expand/deploy/contract sequencing.
- Assessment snapshots are immutable; corrections create new records.
- Publication generations are append-only operational event streams and never rewrite an assessment.
- Target-repository-private evidence is keyed and authorized to the exact repository, not merely to its tenant.
- Managed backups, point-in-time recovery, encryption, and restoration testing are required.
- The exact managed provider remains a deploy-time choice but must satisfy the production controls.

## Rejected alternatives

- Tenant filtering only in application queries: too easy to bypass.
- Document database as primary storage: weaker fit for evidence provenance, version joins, and RLS.
- One database per repository: operationally excessive and poor for organization-level workflows.
