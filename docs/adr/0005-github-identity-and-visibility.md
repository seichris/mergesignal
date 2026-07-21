# ADR 0005: GitHub node identity and explicit evidence visibility

- Status: Accepted
- Date: July 21, 2026

## Context

GitHub logins can change. Public histories are incomplete, and an installation can expose private repository data that must not become a global contributor profile or leak into another repository's PR comment.

## Decision

Identify GitHub accounts and repositories by immutable node ID and record logins as aliases. Do not link off-GitHub identities.

Classify every evidence item as:

- PUBLIC_GLOBAL.
- PUBLIC_DERIVED.
- TARGET_REPOSITORY_PRIVATE.
- SUBJECT_VISIBLE.
- INTERNAL_OPERATIONAL.

`PUBLIC_GLOBAL` is a source fact directly verifiable at a public GitHub URL.
`PUBLIC_DERIVED` is a labeled MergeSignal inference or system collection summary and
must not be presented as GitHub-authored data. Every true derivation records all
input evidence IDs, minimum input cardinalities, and its registry-declared version
and recomputation predicate; public derivations must have an acyclic, entirely
public provenance graph. `PUBLIC_COVERAGE_SUMMARY` is the one authoritative
collection-run result, not a derivation from actor facts. Its typed partitions bind
exact windows, totals, page completion, candidate IDs and digests, and same-run
gaps; freshness is recomputed against the hashed snapshot capture time. Every snapshot item is attributed to the assessed
immutable actor node ID and carries stable relationship endpoints. PR-related facts
use a complete relationship key: PR node, repository node, PR number, author or
subject where applicable, and provider event ID. Every changed path and target fact
also matches the exact assessment PR node and head. Provider-event natural keys are
unique inside a snapshot, and every derivation consumes the complete deterministic
candidate set rather than a cherry-picked subset. Public evidence may be cached
across tenants, but its
snapshot attribution is still subject-bound. Target-private evidence must carry and
match the exact target repository and cannot enter a public-target assessment.
GitHub `internal` repositories use the same restricted boundary. Subject-only
evidence cannot enter a maintainer assessment, and internal operational evidence
cannot directly drive reputation. Private or internal evidence from another
repository cannot influence the assessment or appear in its PR comment, even when
both repositories belong to the same tenant.

A private-target relevance derivation is the narrow visibility-lattice exception:
it may combine public-global history with restricted facts from the exact target
repository, and the result remains target-private. This supports both prior work in
other public repositories and prior work on another PR in the target repository.

Repository relevance is never inferred from internally consistent historical facts
alone. A versioned comparison record must bind historical sources to typed language,
domain, and changed-path facts from the actual target repository and target PR.
Historical and target paths bind explicit complete filesets and exact head SHAs.
Public source URLs are generated from provider-observed logins or `nameWithOwner`
values returned with their stable node IDs. Exact paths are type-specific; query
strings, fragments, and caller-selected slugs are forbidden.

Preserve the GitHub GraphQL actor implementation type. `User` is initially supported for history scoring; `Bot`, `Mannequin`, `Organization`, `EnterpriseUserAccount`, and unknown available actor implementations receive a visible unsupported-history coverage state until explicitly supported. A deleted or unavailable author is represented with null provider identity and a separate `AUTHOR_UNAVAILABLE` reason; the system never fabricates a node ID.

Missing or inaccessible evidence affects coverage and confidence only.

## Consequences

- Account renames preserve one history.
- Unsupported actors are not misattributed to user records.
- Renderers require a visibility-aware input type.
- Private cross-repository organization insights need a future explicit authorization design; they are not inferred from tenant membership.
- Deleted or privatized sources are tombstoned.
- No public global contributor directory or leaderboard is created.

## Rejected alternatives

- Use login as identity: breaks on rename and risks misattribution.
- Treat all installation data as tenant-wide: leaks across repository collaborator boundaries.
- Count private contribution totals as public reputation: unverifiable and potentially disclosive.
