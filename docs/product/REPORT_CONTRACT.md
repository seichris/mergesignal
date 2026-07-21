# Reputation report contract

> Status: Phase 0 contract
>
> Immutable assessment: [reputation-assessment.schema.json](../../contracts/reputation-assessment.schema.json)
>
> Template-only comment input: [pr-comment-render.schema.json](../../contracts/pr-comment-render.schema.json)
>
> Append-only publication lifecycle: [publication-state.schema.json](../../contracts/publication-state.schema.json)
>
> Append-only retention lifecycle: [assessment-retention-state.schema.json](../../contracts/assessment-retention-state.schema.json)
>
> Source-visibility fence: [source-visibility-validation.schema.json](../../contracts/source-visibility-validation.schema.json)
>
> Authoritative PR cursor and high-water record: [pr-output-cursor.schema.json](../../contracts/pr-output-cursor.schema.json), [pr-output-cursor-head.schema.json](../../contracts/pr-output-cursor-head.schema.json)
>
> Provider-observed comment ownership: [comment-ownership-observation.schema.json](../../contracts/comment-ownership-observation.schema.json)
>
> Database lifecycle high-water record: [lifecycle-stream-head.schema.json](../../contracts/lifecycle-stream-head.schema.json)

## Purpose

One completed assessment supports three consumers without changing meaning:

1. The PR comment for maintainers and contributors.
2. The operational GitHub Check.
3. The authenticated detailed dashboard.

The persisted assessment is immutable. A visibility-aware domain service projects it into a template-only render model after current authorization and source-visibility checks. The Markdown renderer receives no numeric reputation field, free-form public copy, private source link, arbitrary destination URL, credential, or unrestricted evidence object.

## Internal assessment

The internal contract contains:

- Contributor availability, immutable GitHub actor ID when available, actor implementation type, and history-support state.
- Exact GitHub App installation ID, repository node ID, visibility, immutable PR node ID, PR number, and head SHA.
- Summary state, stored overall confidence, review priority or `not_enabled`, and the
  controlled priority basis (`reputation_and_patch`, `patch_only`, standard,
  inspection, or disabled).
- Six deterministic dimensions with nullable internal score, confidence, state, reason codes, and evidence IDs. A score is null when evidence is insufficient rather than fabricated as zero; strong and moderate states require a number.
- Separate normalized patch facts.
- Coverage and freshness.
- An immutable evidence-snapshot ID, hashed capture time, canonicalization algorithm, canonical hash, and bounded evidence set.
- Contextual claims represented individually with one deterministic reason type and supporting evidence IDs per claim.
- Policy, engine, evidence, feature, scoring, prompt, and model versions plus registry-resolved artifact digests. The engine content-addresses both assessment and publication decisions.
- A provider-observed repository-visibility evidence ID. The target visibility is
  derived from that installation- and repository-bound fact rather than accepted as
  a caller label.

Publication, Check, retry, supersession, and fencing state lives in a separate
append-only event stream. Every publication event carries a unique transition ID,
monotonic lifecycle revision, previous state, nondecreasing attempt count, and
immutable creation identity. PostgreSQL accepts the next revision only through a
compare-and-swap constraint; stale generations and terminal events cannot be
overwritten. Revision one is always `queued`, and one logical aggregate owns each
installation/repository/PR/generation tuple.
Retention, expiry, and lawful-deletion state lives in a second, content-free,
append-only lifecycle. Every event has a transition ID, monotonic revision, prior
state, and effective time. Deletion and expiry are terminal. PostgreSQL transition
constraints, unique `(assessment_id, lifecycle_revision)`, and compare-and-swap
workflow writes prevent a stale `retained` read
from replacing a terminal tombstone. A deleted or expired event forbids dashboard,
comment, and Check publication; the immutable subject and calculation records are
erased or cryptographically destroyed rather than mutated into a misleading
deleted assessment.

Every publication read also carries a database-issued lifecycle high-water record:
aggregate ID, terminal revision, event count, canonical stream digest, serializable
snapshot token, and read time. A prefix with a valid local transition chain is still
rejected when it omits an event below that high-water mark. The same rule covers
publication, retention, and comment-removal streams.

## Template-only PR comment

The template-only render model contains only:

- Structured descriptive states.
- Registered reason codes rendered through repository-owned copy templates.
- Controlled caveat keys.
- Normalized coverage and patch facts copied from the assessment.
- Up to three unique, currently public GitHub source links generated from provider-observed node-bound locators. Query strings and fragments are forbidden.
- Trusted marker context: installation ID, repository node ID, immutable PR node ID, PR number, head SHA, and marker version.
- The immutable assessment/publication generation for that head.
- A SHA-256 digest of the complete rendered evidence and recursive provenance set.

It has no headline, summary, risk-label, evidence-label, detailed URL, or other free-form copy field. The model can only select exact structured claim tuples from the assessment's content-addressed deterministic candidate packet. Both the authenticated detailed view and the PR comment render repository-owned reason and caveat templates. The renderer constructs the detailed assessment URL from the configured canonical application origin and `assessmentId`.

Every comment projection must match its assessment exactly for target, summary, confidence, priority, six dimension states and reasons, coverage, patch facts and reasons, explanation status, caveats, and scoring version. A selected contextual claim must exist in the assessment. Every evidence link must belong to the assessment section it claims to support.

The fixed renderer always includes a neutral caveat that public history cannot prove the current patch correct. Sparse evidence may legitimately produce no source link; the renderer never invents links to satisfy a cardinality target.

A deterministic fallback contains no model claims or `MODEL_INTERPRETATION`
caveat and fits the same three-caveat maximum as the comment. It requires a non-complete
contextualizer-status fact, `MODEL_EXPLANATION_UNAVAILABLE`, and the controlled
`CONTEXTUALIZATION_UNAVAILABLE` caveat. A complete explanation cannot carry that
reason or caveat. Both states retain the neutral patch-correctness caveat, so every
valid assessment has a valid template-only comment projection.

## Hidden marker

The hidden marker is generated from trusted render-target fields and includes:

- Marker schema version.
- GitHub App installation ID.
- Repository node ID.
- Immutable PR node ID.
- PR number.
- Assessment generation.

It contains no login, score, evidence, credential, or user-authored text. Before
update, deduplication, or deletion, the app persists a provider-observed ownership
record binding the exact comment, marker digest, current GitHub App, and installation.
The observation also records the source-set digest currently encoded by that marker,
so an old deletion task cannot erase a canonical comment that now renders a newer
assessment.
Installation ID plus verified app authorship establishes the duplicate-recovery
ownership boundary.

## Comment lifecycle

1. Persist the immutable assessment.
2. Under a serializable database read, load the PR-scoped output cursor and its
   independent high-water record. They bind the active generation/head and canonical
   comment/Check IDs. Append the next monotonic publication generation and lifecycle
   revision only if the cursor revision and digest still match.
   A new head advances the generation exactly once, preserves the canonical comment,
   and resets the generation-scoped Check ID before the next Check is assigned.
3. Signal the single PR-scoped output workflow, which serializes GitHub writes.
4. Read the complete retention stream plus its database high-water record under
   compare-and-swap fencing. Recheck the
   current head SHA and active generation. Persist a typed pre-write visibility
   record for every assessment source and recursive provenance item, including its
   expected record revision, freshly observed revision, current visibility and
   repository scope, expected source-set digest, and canonical visibility-state
   digest. The record and every underlying source observation must remain inside the
   registered freshness fence relative to the actual provider-write start.
5. Build and validate the exact template-only projection.
6. Create the first comment only after analysis completes.
7. Re-observe exact marker and App-installation ownership, update only the canonical
   stored comment for the active cursor generation, and persist explicit provider-write
   start and completion timestamps.
8. Re-read the generation, head, complete retention stream, and complete
   source/provenance set after the GitHub write. Persist a second typed visibility
   record and bind the publication to both validation IDs, both retention revisions,
   and the post-write visibility-state digest. The two validation IDs are distinct,
   every post-write source observation follows write completion, and the record is
   bounded by the publication update time.
9. If the comment completed after deletion or expiry became effective, persist the
   non-publishable post-write fence, mark the output stale or repair queued, and
   commit a generic cleanup outbox command with terminal retention. After that
   transaction is durable, acquire a PR-scoped mutation lease that blocks
   publication, then re-read the cursor, marker inventory, and ownership. The
   deletion authority binds that lease/fencing token and those post-lease reads
   before a per-comment removal aggregate is CAS-enqueued in a new transaction.
   A completed provider write is representable without treating it as current.
10. Start the operational Check only after the comment and publishable post-write
   fence complete. Persist explicit Check write-start and completion times.
11. After Check completion, re-read head, generation, the latest event from the full
   retention stream, and every source into a third, distinct post-Check visibility
   record. A publishable record authorizes a current `success`. If GitHub already
   accepted success but the post-Check record is non-publishable, persist that exact
   completed success under `repair_queued`; terminal retention also atomically queues
   removal of the visible comment.
12. Append the final publication event. If the head, generation, retention revision, source visibility, source revision,
   repository scope, or source-set identity changed, mark the write stale and queue
   the newest generation immediately.
13. Retry publication independently from evidence collection and scoring.

Before retrying an ambiguous create, the publisher searches the exact marker and verifies app authorship. A reconciler removes only extra comments with the exact marker and the same verified installation, retaining the oldest as canonical.

GitHub has no atomic compare-head-and-update-comment operation. Every comment therefore visibly names its assessed short SHA. Serialization, explicit latest-observed generation, head and source digests, post-write checks, and repair ensure an older or newly restricted write cannot remain the final current result. Later source privatization, deletion, or retention changes are reconciled within the publication-removal SLO; Phase 8 must set and monitor that bound before broad availability.

Deletion and expiry use the separate content-free
[`comment-removal-state`](../../contracts/comment-removal-state.schema.json)
machine. It binds the terminal retention transition ID and revision, exact app
comment ID, retry count, provider deletion completion time, and a SHA-256 receipt
digest. Each removal attempt is an append-only event with a unique transition ID,
monotonic revision, explicit previous state, legal transition table, and
nondecreasing attempt count; `removed` and `superseded` are terminal. Terminal
retention atomically persists only the generic cleanup command. The first
per-comment event is inserted after a fresh authority read in a new transaction and
retains immutable links to that terminal origin. Every event has its own truthful
database commit and outbox identity. Every retry acquires a higher fencing token,
re-reads the complete population, and binds a new authority. If a newer assessment
has replaced the marker, the aggregate ends as `superseded` without deleting it. Each terminal
retention/publication/comment identity has exactly one removal aggregate. Terminal
retention cannot pass through the normal publication path or be reversed; a
successful removal has auditable provider confirmation without retaining free-form
provider or deletion-request content. Exact publication, PR, and comment linkage is
kept for at most 30 days for security, deletion verification, and dispute handling,
then erased; only the opaque terminal retention tombstone remains.

## Operational Check state machine

Internal state and GitHub conclusion use these valid terminal combinations:

| Internal Check state | Conclusion | Meaning |
|---|---|---|
| `queued`, `in_progress`, or `retrying` | `none` | Work is non-terminal |
| `completed` | `success` | Provider accepted success; current only with publishable post-Check fences, otherwise durably `repair_queued` |
| `completed` | `action_required` | Configuration or maintainer input is required |
| `completed` | `failure` | The system exhausted its completion or publication policy |
| `superseded` | `cancelled` | A newer head or generation replaced this one |

Current `success` requires the latest observed generation, a current head, a published
app-owned comment ID, a non-null Check ID, ordered Check write timestamps, and
matching typed pre-write, post-write, and post-Check visibility records. The final
record must bind the latest event in the complete retention stream and remain
publishable. `action_required` is only
configuration or maintainer input; ordinary limited evidence and a disabled
optional priority policy still succeed. `failure` is only exhausted system policy;
resumable source collection remains non-terminal. `superseded` requires a stale
head or older generation, stale comment state, and a cancelled Check. Reputation
never appears as a failing CI conclusion.

Validated examples cover [success](../../contracts/examples/publication-state.json), [failure](../../contracts/examples/publication-state.failure.json), [supersession](../../contracts/examples/publication-state.superseded.json), [repair](../../contracts/examples/publication-state.repair.json), [queued removal](../../contracts/examples/comment-removal-state.queued.json), [active removal](../../contracts/examples/comment-removal-state.removing.json), and [terminal comment removal](../../contracts/examples/comment-removal-state.json).

## Detailed view

The detailed view may show raw scores only to an authorized maintainer. It also shows:

- Full dimension definitions and confidence factors.
- Evidence coverage by year and source.
- Authorized evidence links and visibility badges.
- Deterministic facts separately from model-selected exact claim tuples.
- Per-claim citations and reason type.
- Engine and policy versions.
- Publication, supersession, refresh, feedback, and correction state.

Authorization is checked at request time against current GitHub access. A historical
session claim is insufficient. A trusted internal authority receipt binds the
viewer, installation, repository, browser session and single-use nonce to a fresh
GitHub permission response and an independent serializable dashboard-policy
high-water read. The short-lived authorization references those exact observation,
revision, snapshot, and digest values. Validation receives a trusted current request
time, requires `authorizedAt <= now < expiresAt`, and atomically consumes the
session/nonce through a serializable PostgreSQL insert protected by unique
`(session_id, request_nonce)`. The authorization binds the trusted commit receipt.
Object digests detect corruption; they are never treated as caller
authentication. The response is constructed from the closed detailed-report
projection schema; handlers never serialize the assessment object directly.

## Invariants

- Assessment, comment, publication, retention, and visibility records bind to the same installation, repository node, immutable PR node, PR number, assessment, generation, and head where applicable.
- The publication and every visibility fence bind the same database-high-water PR cursor revision and digest; a self-consistent older generation is insufficient.
- The PR cursor itself is protected by unique `(installation_id, repository_node_id, pull_request_node_id)` ownership and cannot fork into a second aggregate.
- Publication, retention, and removal event arrays must equal their database-issued high-water revision, count, and digest rather than relying on a caller's claim that an array is complete.
- Comment update, reconciliation, and deletion require a fresh provider-observed ownership record for the exact App installation, marker, and comment ID.
- Terminal deletion holds the PR publication fence and re-reads the complete marker inventory and current PR cursor after acquiring it;
  it removes only comments whose current source-set marker still identifies the
  terminal assessment and preserves a canonical comment already updated by a newer
  assessment.
- Publication is forbidden when the latest append-only retention event is deleted or expired.
- Snapshot capture, assessment creation, retention read, pre-write fence, comment
  write, post-write fence, Check write, post-Check fence, publication update, and later removal follow one enforced
  causal order.
- PR comment copy is rendered only from controlled reason and caveat templates.
- No comment input can represent a numeric reputation score, arbitrary public prose, private source link, or external report origin.
- Every contextual claim has its own deterministic reason type and sufficient supporting evidence group.
- Every assessment source and recursive provenance item has an exact expected and
  freshly observed revision, visibility, and repository scope in typed records
  before and after the comment and after a successful Check; opaque digest equality
  alone is insufficient.
- The post-write record uses fresh per-source observations after the recorded
  provider write completion; changing only a wrapper timestamp cannot pass.
- A stale in-flight generation is detected after its write and repaired.
- A rerun updates one verified app-owned comment.
- Contributor reputation cannot cancel patch-context risk.
