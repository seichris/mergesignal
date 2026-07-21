# ADR 0006: One PR comment is the primary reputation surface

- Status: Accepted
- Date: July 21, 2026

## Context

Maintainers and contributors already collaborate in the pull-request conversation. The product owner confirmed that reputation information should appear there. A GitHub Check remains useful for asynchronous lifecycle and integrations but is not the primary explanation surface.

## Decision

After an assessment completes, create one MergeSignal PR conversation comment and update it in place on reruns. Show descriptive dimensions and confidence, not raw numeric scores. Link to the authenticated detailed view for authorized maintainers.

Use Pull requests read/write permission to create and update the app's own issue-style PR comment. The renderer accepts only the template-only PR-comment contract. It has no numeric-score field, free-form public copy, arbitrary detailed-report URL, or private link. Registered reason and caveat templates own public prose; the renderer builds the authenticated detail URL from trusted application configuration. Direct evidence links are limited to three currently `PUBLIC_GLOBAL` GitHub sources.

The trusted render target includes installation ID, repository node ID, immutable
PR node ID, PR number, visibility, head SHA, generation, and marker version. The
hidden marker uses installation, repository, immutable PR, generation, and version.
Persist the GitHub comment ID and
verify current app authorship before any update.

Serialize monotonic publication generations per PR and persist the latest observed
generation. Publication state is an append-only event stream with unique transition
IDs, monotonic revisions, explicit previous states, nondecreasing attempts, and
database compare-and-swap writes. Revision one is queued, and a unique logical key
allows only one aggregate for an installation/repository/PR/generation. Immediately
before a write, recheck the head SHA and latest append-only
retention revision, then persist a typed visibility observation for the complete
assessment source/provenance set. Every item binds expected and current revisions,
visibility, repository scope, and observation time. Persist explicit provider-write
start and completion timestamps. Require the pre-write record and every underlying
source observation to remain inside the registered freshness fence relative to the
actual write start. After the GitHub write, repeat those reads with a
distinct validation ID and fresh per-source observations after completion, then
bind the publication to both visibility-validation IDs, both retention revisions,
and the post-write visibility-state digest. Database compare-and-swap constraints
prevent a stale retained event from authorizing publication after terminal deletion.
Any mismatch marks the write stale and queues repair. The comment visibly names its
assessed SHA because GitHub cannot atomically compare a PR head and update an issue
comment.

Terminal deletion and expiry use a separate append-only comment-removal state
machine bound to the exact retention transition, publication, comment ID, attempts,
and provider deletion receipt digest. A unique logical key prevents competing
removal aggregates; `removed` is terminal. Exact PR/comment
linkage expires within 30 days; the persistent retention tombstone contains no
request prose or provider response. Normal publication never accepts terminal
retention.

Before retrying an ambiguous create, recover by exact marker and verified app authorship. A reconciler removes only duplicate comments proven to be owned by the same installation. Assessment, render, and publication records are cross-validated for repository, PR, assessment, and head before a write.

The operational Check state machine permits `none` only for non-terminal work,
`success`, `action_required`, or `failure` for completed work, and `cancelled` for
supersession. Success requires the primary comment to be published for the latest
observed generation with matching pre/post retention revisions, typed publishable
source observations, and persisted GitHub IDs. Limited evidence and disabled
priority guidance are successful analyses; they are not action-required or failure.

Keep an operational GitHub Check for queued, complete, failed, and superseded states.

## Consequences

- Public-repository comments are public, so comment evidence is restricted to public GitHub sources and current PR facts.
- The app needs Pull requests write permission; code and tests must prove it never modifies other PR fields or comments.
- Reruns must not spam notifications; ambiguous writes and duplicate comments require verified recovery and reconciliation.
- Comment publication is independently retryable after assessment completion.
- Stale-head fencing and post-write repair apply to both comment and Check lifecycle state.
- Raw numeric scores remain in the authorized detailed view only.

## Rejected alternatives

- Maintainer-only dashboard as the default: hides the result from the PR workflow.
- Check-only output: too compressed for evidence and caveats.
- New comment on every update: noisy and harmful under high PR volume.
- Raw numeric score in GitHub: encourages overconfidence and gaming.
