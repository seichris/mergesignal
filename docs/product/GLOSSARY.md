# MergeSignal product glossary

> Status: Phase 0 contract
>
> Last updated: July 21, 2026

This glossary defines product language used in code, schemas, user interfaces, tests, and operations. New terms that affect a user-visible judgment require a contract version and review.

## Core terms

### Assessment

An immutable, versioned result for one GitHub actor, target repository, immutable
pull-request node ID, pull-request number, and exact head SHA. An assessment
also carries its monotonic PR-scoped generation and contains evidence coverage,
deterministic dimensions, contextual explanation, and
patch context. Publication and supersession live in a separate append-only,
revisioned PR-scoped event stream.

### Contributor

The GitHub actor that authored the target pull request. When available, MergeSignal identifies the actor by immutable GitHub node ID and records the login only as a time-bound alias. Full history assessment initially supports User actors. Unsupported Bot, Mannequin, Organization, or EnterpriseUserAccount actors receive `UNSUPPORTED_ACTOR_TYPE`. A deleted or unavailable author has null provider identity and receives `AUTHOR_UNAVAILABLE`; MergeSignal never fabricates a node ID. Both paths produce explicit limited evidence. A GitHub account does not prove real-world identity.

### Contributor reputation

Repository-specific evidence about the contributor's public GitHub history: continuity, independent open-source validation, merge follow-through, collaboration, relevant experience, and integrity confidence. It is not a universal rating of the person.

### Evidence

A normalized, typed fact with subject attribution, stable relationship keys,
type-specific natural identity, provenance, visibility, event time, observation
time, source identifier, collection run, and collector version. A model statement
is not evidence.

### Evidence snapshot

The immutable, minimized canonical evidence and feature material used by one
assessment. The exact hashed envelope is
`{schemaVersion, snapshotId, capturedAt, items}`, with
items sorted by evidence ID before serialization. It must be I-JSON, is serialized
by a tested RFC 8785 JSON Canonicalization Scheme implementation, and is hashed with
SHA-256. Retention lives in a separate append-only, monotonically revised lifecycle.
A lawful deletion erases or cryptographically destroys the assessment and
calculation material, leaves only that content-free terminal tombstone, forbids
republication, and explicitly ends exact reproduction.

### Coverage

What MergeSignal attempted to collect, what it successfully observed, what was
partial or inaccessible, how attributable it is, and how fresh it is. The coverage
summary is a versioned collection-run result, not a derivation from unrelated actor
facts. Coverage limits confidence; missing coverage never becomes negative
evidence.

The authoritative result contains run-bound query partitions with exact boundaries,
provider totals, page completion, candidate IDs, and candidate digests. Freshness
and confidence are recomputed by registered policies against the hashed snapshot
capture time.

### Relevance comparison

A deterministic, versioned record that compares one historical contribution with
typed language, domain, ecosystem, and changed-path facts from the actual target
repository and target PR. Historical evidence alone cannot satisfy a relevance
reason. Historical and target paths are bound to explicit complete filesets and
their exact head SHAs.

### Source-visibility validation

An immutable pre-write or post-write publication-fence record covering every
assessment source and recursive provenance item. It records expected and freshly
observed revisions, visibility, repository scope, source-set identity, publication
generation, and a canonical visibility-state digest.
Pre/post records are distinct, and every post-write source observation occurs after
the recorded provider write completion.

### PR output cursor

The authoritative database row for one installation/repository/PR. It identifies
the active generation and head plus canonical comment and Check IDs. Publication
and visibility fences bind its revision and digest. An independent cursor
high-water record proves the row is not a self-consistent stale generation.

### Lifecycle stream head

A database-issued proof of a complete publication, retention, or comment-removal
prefix: aggregate ID, high-water revision, event count, canonical digest,
serializable snapshot token, and read time. It rejects a caller-supplied event array
that omits a persisted transition.

### Comment ownership observation

A provider-observed record binding an exact comment and marker digest to the current
MergeSignal App and installation. It is required before update, duplicate cleanup,
or deletion; the hidden marker alone never proves ownership.

### Comment inventory observation

A complete, provider-observed population of comments matching the configured
MergeSignal App and marker on one pull request. It includes provider totals,
pagination completion, a canonical digest, and an ownership proof for each match.
An empty pre-write inventory authorizes initial creation; the post-write inventory
must contain the one canonical comment. Terminal retention queues removal for the
complete owned population.

### Detailed-report authorization

A short-lived authorization record binding one maintainer permission observation,
installation, repository, exact assessment digest, and independent dashboard-policy
high-water state. It authorizes only the allowlisted detailed projection; it is not
a reusable session claim and never authorizes raw assessment serialization.

### Request-local population commitment

An HMAC over the request alias, nonce, claim ID, and complete local evidence
population. It changes for every provider request and prevents disclosure of the
stable local population digest. Provider eligibility still evaluates the complete
population, including members outside bounded exemplars and witnesses.

### Comment removal

An append-only operational state machine that removes one verified app-owned PR
comment after terminal deletion or expiry. Each event has a monotonic revision,
previous state, unique transition ID, and nondecreasing attempt count; `removed` is
terminal. It binds the exact retention transition, publication, comment ID, and a
digest of the provider receipt. Exact PR/comment linkage expires within 30 days and
is not the permanent retention tombstone.

### Dimension

One independently explainable part of contributor reputation:

- Tenure and continuity.
- Independent open-source record.
- Merge and follow-through.
- Collaboration.
- Relevant experience.
- Integrity and gaming resistance.

### Confidence

A separate 0–1 internal measure of evidence volume, time coverage, accessibility, attribution quality, freshness, and consistency. GitHub renders confidence descriptively. It is never silently folded into a reputation score.

### Summary state

One of four descriptive results:

- Established evidence.
- Developing evidence.
- Limited evidence.
- Needs manual inspection.

Limited evidence means the product cannot reach a strong conclusion. It does not mean low reputation.

### Review priority

An optional, advisory repository-policy result: not enabled, prioritize, standard review, or inspect first. It is visible and auditable and cannot merge, close, or reject a pull request. A prioritize result also exposes its controlled basis: established reputation plus patch readiness, or patch readiness alone while history remains limited. When priority is not enabled, the GitHub comment omits priority guidance.

### Patch context

Objective facts about the current pull request, including CI state, scope, linked
issues, changed tests, and configured sensitive paths. Path-derived facts are
`unknown` when the head-bound changed-file inventory is incomplete. Patch context
remains separate from contributor reputation.

### Independent validation

Evidence that a maintainer without a known control or affiliation relationship to the contributor reviewed or merged the contributor's work. Unknown relationships reduce confidence instead of being guessed.

### Integrity reason code

A neutral, evidence-backed explanation that independence or recent behavior needs human inspection. It is not an allegation of spam, fraud, collusion, account theft, or AI authorship.

### PR report comment

The single GitHub conversation comment authored by the MergeSignal App for a pull request. It is created after an assessment completes and updated in place on reruns. Public copy comes only from controlled reason and caveat templates. The comment contains descriptive states and never raw numeric scores, model-authored prose, or private source links.

### Operational Check

The GitHub Check run that exposes queued, completed, failed, and superseded analysis lifecycle. A reputation state never becomes a failing CI conclusion.

### Detailed view

The authenticated dashboard view. Authorized maintainers can inspect raw numeric dimensions, evidence coverage, policy and engine versions, and source links they are permitted to access.

## Visibility terms

### PUBLIC_GLOBAL

Evidence already public on GitHub and reusable across tenants. It may appear in a public PR comment when the source remains public.

### PUBLIC_DERIVED

A versioned MergeSignal inference derived only from public evidence, or a labeled
system collection result such as coverage. True derivations are reusable with
their complete provenance. Neither form may be presented as a GitHub-provided fact.

### TARGET_REPOSITORY_PRIVATE

Evidence from the target private repository or a derivation whose visibility ceiling is that repository. It may be used only within that same repository's assessment and authorized output.

GitHub `private` and `internal` repository visibility both use this restricted evidence boundary. `internal` is never treated as `PUBLIC_GLOBAL`.

### SUBJECT_VISIBLE

Evidence GitHub exposes to the account subject but not generally to maintainers or the public. It may inform coverage but cannot be disclosed to unauthorized viewers.

### INTERNAL_OPERATIONAL

Delivery, rate-limit, billing, security, or debugging data. It never becomes reputation evidence.

## Prohibited terms in automated conclusions

Automated output must not label a contributor:

- Trusted or untrusted as an absolute claim.
- Good or bad.
- Safe to merge.
- Spam, fraudulent, fake, colluding, or hacked.
- Junior, senior, qualified, or unqualified.

The product reports observed evidence, uncertainty, and a review recommendation.
