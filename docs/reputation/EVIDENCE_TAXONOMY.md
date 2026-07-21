# Evidence taxonomy and data dictionary

> Status: Phase 0 contract
>
> Registry: [evidence-types.json](../../contracts/evidence-types.json)
>
> Reason codes: [reason-codes.json](../../contracts/reason-codes.json)

## Evidence record

Every normalized evidence item has:

| Field | Meaning |
|---|---|
| evidence_id | MergeSignal immutable identifier |
| evidence_type | Registry key |
| provider | Source provider, initially GitHub |
| provider_node_id | Immutable source identifier when available |
| provider_locator | Provider-observed actor login or repository nameWithOwner bound to its stable node ID |
| subject_github_node_id | Contributor account node ID |
| repository_node_id | Source repository when applicable |
| source_url | Authorized source URL when available |
| event_at | When the source event happened |
| observed_at | When MergeSignal observed it |
| visibility | PUBLIC_GLOBAL, PUBLIC_DERIVED, TARGET_REPOSITORY_PRIVATE, SUBJECT_VISIBLE, or INTERNAL_OPERATIONAL |
| canonical_payload | Closed, type-specific normalized fields needed by features |
| canonical_hash | Hash used to detect source changes |
| derivation_version | Required versioned function for derived evidence |
| input_evidence_ids | Complete input set for derived evidence |
| collector_version | Adapter and normalization version |
| collection_run_id | Provenance for pagination and coverage |
| tombstoned_at | When a source became unavailable or was deleted |

Raw API payloads are short-lived operational material, not the evidence contract.
Every evidence registry key has exactly one matching payload contract. Payload
objects reject undeclared fields, including profile proxies such as email, and a
payload valid for one evidence type cannot be attached to another type.

The immutable snapshot manifest hashes its own capture time and materializes the
decision-critical subset of this record: subject GitHub node ID, repository scope when applicable, event and
observation times, provider node ID when available, collector version, collection
run ID, closed canonical payload, source URL, and derivation provenance. Stable PR,
review, repository, actor, issue, path, and head identifiers live in the typed
payloads so a reason cannot join unrelated events merely because their types match.
Within one snapshot, type-specific natural keys are unique: retries and pagination
duplicates cannot become separate contributions merely by receiving new
`evidence_id` values. A public source stores a provider-observed actor or repository
locator in the same adapter result as its stable node ID. The URL is generated from
that locator with exact path cardinality for profiles, repositories, PRs, files,
checks, commits, and issues. Query strings, fragments, caller-supplied slugs, and a
valid GitHub URL to another entity are not acceptable evidence.

## Reason evidence rules

Every reason code declares:

- `requiredAll`: evidence types that must all be present.
- `requiredAny`: alternative evidence types of which at least one must be present.
- `predicate`: the versioned deterministic relationship or threshold function that must also pass.

Phase 0 dispatches every registered predicate identifier to one deterministic
implementation and rejects an unimplemented or extra predicate. The executable
contract probes threshold and relationship semantics, including multi-month
continuity, repeated merge follow-through, requested-changes follow-through,
target-bound relevance, coverage limitations, integrity triggers, and patch facts.
Phase 4 moves these same versioned functions into the production engine and expands
their property and calibration suites; it does not get to weaken the Phase 0
meaning. Type groups prevent a merged-PR fact alone from becoming “independent
merges”; the predicate then proves that the merge actor and repository relationship
meet the versioned independence rule. Coverage reasons may qualify a dimension,
but patch, integrity, and reputation reasons cannot be attached to unrelated
owners.

Every derived evidence type separately declares its version, required-all,
required-any, and optional input types, minimum input cardinalities, and
deterministic predicate.
A manifest item must use that exact version and input shape. Phase 0 has an exact
recomputation implementation for every registered derivation, including active
months, ownership, dependency ecosystem, burst and baseline features, template
similarity, reciprocal relationships, target relevance, patch scope, tests, and
sensitive paths. Arbitrary derived payloads are rejected even when their type list
looks plausible.

The input set is also closed, not cherry-picked. A versioned selector recomputes
the exact candidate IDs from the frozen snapshot for the subject, time window,
repository, PR, and head involved. Incomplete coverage forces the corresponding
coverage reasons and a partial assessment. Derived observations must occur after
every input observation. Repeated-history predicates count distinct immutable
provider events, never record rows. Relevance paths additionally name complete
historical and target fileset records and both immutable head SHAs; paths from an
older target head cannot enter the current comparison.

`patch-scope-v1` classifies at most 3 files and 20 changed lines as small, at most
20 files and 500 changed lines as medium, and larger complete patches as large.
Unknown is reserved for incomplete collection. Repository policy may add a separate
sensitive-path reason but cannot silently rewrite these versioned size thresholds.
Every changed path carries the immutable head SHA. The fileset record carries the
provider total, collected count, pagination completion, and collection state.
When no first page is available, patch scope, test-path state, and sensitive-path
state are `unknown`; the system never fabricates a check-suite ID or renders
"unchanged" from missing paths.

## Source hierarchy

### Primary GitHub sources

- GraphQL User.createdAt for account creation.
- GraphQL contributionYears and explicit one-year contributionsCollection windows.
- Pull-request, review, merge actor, repository, language, topic, and changed-path data.
- REST check runs, repository contents, installation state, and PR comment publication.

### Derived evidence

Derived evidence must:

- Name every input evidence ID.
- Record the derivation version.
- Be reproducible without a model.
- Preserve the applicable visibility ceiling.
- Never convert missing input into a negative fact.

The machine-readable snapshot manifest requires `derivation.version` and a nonempty `inputEvidenceIds` array for every derived type. Validation rejects missing inputs, cycles, cross-repository provenance, and a `PUBLIC_DERIVED` item whose dependency graph contains restricted evidence. Publication-time visibility refresh traverses that graph before rendering an inference.

Examples include active months, ownership relationships, activity bursts,
dependency ecosystems, reciprocal merge edges, and patch scope. Pull-request
metadata fingerprints are recomputed from bounded normalized structural fields.
Repository-owned pull-request-template structure is subtracted before comparison;
only sufficiently informative adjusted fingerprints from distinct independently
maintained repositories can satisfy the template-pattern rule.
Follow-up commits and resolved threads record the action actor; a contributor
follow-through judgment requires that actor to be the assessed subject. PR
lifecycle validation rejects mutually exclusive terminal outcomes, events before
opening, activity after a terminal outcome, and a review node represented in both
directions.

`PUBLIC_COVERAGE_SUMMARY` is a versioned system collection result rather than a
derivation from unrelated actor facts. Exactly one authoritative summary exists in
a snapshot. Its collection run owns typed query partitions, requested and completed
boundaries, provider totals, pagination completion, exact candidate IDs and digests,
partial-source labels, freshness policy, attribution, and confidence policy.
The partition set must exactly equal the feature artifact's singleton and
year-granular query plan; an omitted partition or a complete partition hiding a
same-run candidate is invalid. Complete years, attribution, freshness, and confidence
are derived from typed records and partition observations.
Same-run operational gaps must appear in the partition limitations. Freshness is
recomputed against the hashed snapshot capture time, and confidence is recomputed
from completed years, complete partitions, attribution, and freshness.
It remains labeled `PUBLIC_DERIVED` on output because it is a MergeSignal summary,
not a GitHub-authored fact.

### Model selection

Model outputs are exact structured selections, not evidence or prose. A selected relevance claim can cite only registered evidence IDs already in the assessment snapshot; repository-owned templates render every surface.

## Visibility and output

| Visibility | Cross-tenant reuse | Public PR comment | Private target PR comment | Detailed view |
|---|---:|---:|---:|---:|
| PUBLIC_GLOBAL | Yes | Yes, after publication-time visibility recheck | Yes | Yes |
| PUBLIC_DERIVED | Yes, with provenance | As a labeled inference, never as a source link | Yes | Yes |
| TARGET_REPOSITORY_PRIVATE | No | No | Same target only | Authorized target viewers |
| SUBJECT_VISIBLE | No | No | No | Subject-authorized flow only |
| INTERNAL_OPERATIONAL | No | No | No | Restricted operations only |

Private evidence from another repository never influences or renders in a target
assessment, even when both repositories belong to the same organization.
Every manifest item is also bound to the assessed subject. Target-private evidence
must name the exact target repository and cannot enter a public-target assessment.
A private-target relevance comparison may additionally consume public-global
historical evidence from any repository, including earlier work in the target
repository; its target facts remain private and the derived output inherits the
private ceiling. Subject-only evidence is excluded from maintainer assessments.
Internal operational evidence may explain coverage or contextualizer availability
but cannot directly drive a reputation dimension. Every such item is still scoped to
the exact target repository, even when no dimension or explanation cites it.

## Attribution limitations

GitHub history is incomplete by construction:

- Public APIs may omit private work.
- Contribution graphs depend on GitHub attribution rules.
- Accounts can change login while retaining a node ID.
- Repositories or contributions can be deleted or made private.
- Detailed queries can be interrupted or limited.
- A merge outcome does not prove code quality.
- A closed-unmerged PR does not prove poor quality.
- The merge actor can be missing or ambiguous.

Every collection run records requested scope, completed scope, pagination cursors, source limits, and reason codes. The product must state partial coverage rather than infer the missing history.

## Independence classification

Each relevant contribution receives one of:

- self controlled.
- affiliated or maintainer controlled.
- independently maintained.
- unknown.

The Phase 0 classifier is mutually exclusive. Ownership, owner association, or a
self merge is `self_controlled`; `MEMBER` and `COLLABORATOR` are `affiliated`;
external contributor associations plus a different merge actor are
`independently_maintained`; everything else is `unknown`. Organization and
permission evidence may refine a later version only through a new versioned rule.
The classifier does not use employer claims, profile biography, location, or
outside data brokers. Unknown and affiliated relationships carry an independence
caveat. Affiliation alone is not a self-merge: self-merge concentration requires the
canonical merge actor to be the assessed subject.

## Data minimization

The core reputation engine excludes:

- Followers and following.
- Stars as a direct contributor-quality feature.
- Employer and organization biography claims.
- Name, avatar, location, pronouns, email, and social links.
- Comment sentiment or personality inference.
- AI-authorship guesses.
- Off-GitHub identity enrichment.

Repository popularity may be used only as a capped contextual feature during future calibration and cannot dominate a dimension.

## Evidence lifecycle

1. Collect within a documented GitHub rate budget.
2. Normalize and classify visibility at ingress.
3. Validate required fields and provenance.
4. Bind every PR-related fact to the complete immutable relationship key: PR node
   ID, repository node ID, PR number, subject/author where applicable, and provider
   event ID. Every changed path and target fact additionally binds to the assessed
   PR node ID and head SHA.
5. Append or update mutable source state without rewriting historical snapshots.
6. Build the I-JSON envelope `{schemaVersion, snapshotId, capturedAt, items}`, sort items by
   evidence ID, serialize the complete envelope with a tested RFC 8785 JSON
   Canonicalization Scheme implementation, compute its SHA-256 hash, and freeze the
   minimized evidence and feature inputs for the assessment retention period.
7. Refresh recent mutable outcomes.
8. Before and after publication, persist a typed visibility-validation record for
   the complete assessment source and recursive provenance set. Each observation
   binds the expected record revision, freshly observed revision, visibility,
   repository scope, publication generation, observation time, and canonical
   visibility-state digest. Pre/post records are distinct; every post-write source
   observation occurs after the completed GitHub write and inside the publication
   interval.
9. Tombstone inaccessible sources.
10. Expire reusable caches according to retention policy without deleting calculation
   material still referenced by a retained assessment.
11. On lawful deletion, erase or cryptographically destroy the immutable assessment
   and protected calculation material, append a monotonically versioned,
   content-free terminal retention event, forbid publication, and mark exact
   reproduction unavailable. Database constraints reject reversal to a publishable
   state.
12. Recompute only under a new version; never rewrite the original assessment.
