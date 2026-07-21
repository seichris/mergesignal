# Reputation scoring methodology

> Status: Phase 0 hypothesis
>
> The production engine starts in Phase 4 and must be calibrated before broad availability. Phase 0 already owns an executable, versioned reference policy so schemas and fixtures cannot accept arbitrary values.

## Objective

The engine summarizes evidence useful for repository-specific review triage. It does not estimate a person's intrinsic quality, prove control of an account, or determine whether the current patch is correct.

An internal dimension score may be null when evidence is insufficient or actor
history is unsupported. Null is not zero and is shown as unavailable in the
detailed view. A strong or moderate dimension always has a numeric score, at least
one deterministic reason, and only evidence types registered to that dimension.
Absence of an integrity trigger is not positive integrity evidence.

The machine-readable retired [`scoring-v1`](../../contracts/dimension-scoring-policy.json)
and active [`scoring-v2`](../../contracts/version-artifacts/scoring-v2.json) policies
map every registered supporting reason to a dimension weight, order the `moderate`
and `strong` thresholds, and define exact confidence caps. The validator loads each
content-addressed version independently and replays an assessment with the version
that was effective when it was created. A stored value is not authoritative merely
because it fits the JSON Schema.

## Pipeline

1. Normalize GitHub facts into versioned evidence.
2. Extract deterministic features.
3. Calculate six dimension results and separate confidence.
4. Apply explicit integrity reason codes and confidence modifiers.
5. Derive a descriptive history summary independent of technical relevance.
6. Apply the repository's opt-in review-priority policy.
7. Let the contextual model rank and select registered structured claims without changing facts, renderer copy, scores, states, or confidence.

## Dimensions

### Tenure and continuity

Inputs include account creation time, contribution years, active months across bounded windows, and recent activity relative to the account's own baseline.

- Account age is a capped input within this dimension, not a trust shortcut.
- Age without sustained activity cannot produce a strong state.
- An old dormant account is not assumed trustworthy.

### Independent open-source record

Inputs include merged PRs, merge actors, repository ownership relationships, and distinct independent repositories and maintainers.

- Self-owned and self-merged work has little independent-validation weight.
- Unknown and affiliated relationships lower independence confidence, but
  affiliation is not called a self-merge unless the canonical merge actor is the
  assessed subject.
- Raw volume is capped and transformed sublinearly.

### Merge and follow-through

Inputs include submitted, open, closed-unmerged, and merged PRs plus the action sequence around reviews and follow-up commits. Small-sample rates use Bayesian shrinkage:

$$
\hat{p} = \frac{m + \alpha}{n + \alpha + \beta}
$$

The prior is calibrated from a versioned cohort. The dashboard always shows sample size. A closed-unmerged PR is not a failure without supporting context.

### Collaboration

Inputs include structured reviews received and given, follow-up commits after reviews, and resolved review threads. The engine does not score tone, politeness, writing ability, personality, or response prose.

### Relevant experience

Deterministic retrieval and scoring compare each historical candidate with typed
facts from the actual target repository and target PR. A versioned relevance record
names both repository IDs, both PR identities where applicable, the comparison
version, and exact language, domain, and path-family matches. Language matches come
from the exact changed paths bound to both complete head-specific filesets;
repository-wide language metadata cannot be attributed to the contributor.
Historical facts that
are internally consistent but unrelated to the target cannot satisfy a relevance
reason. Code owns the candidate set, score, state, confidence, and renderer copy.
The contextual model may select only exact registered claim-ID, reason-code, and
evidence-ID tuples from that closed candidate set.
Prior accepted work in the same repository is eligible when it is a different PR.
For a private target, the comparison may combine public-global history with exact
target-private facts; no private fact from another repository can enter the cohort.

Relevance remains a separate dimension. An established contributor with unrelated experience remains `established_evidence`, while relevance can be `limited` and review priority can remain `standard`.

### Integrity and gaming resistance

Inputs include self-merge concentration, activity bursts, template similarity,
reciprocal relationships, and changes from the account's own baseline. Merge
relationship events must reconcile with the canonical merged outcome and merge actor.
Template similarity removes repository-owned PR-template boilerplate and requires at
least five informative contributions across five distinct independently maintained
repositories, so repeated activity in one project cannot inflate the signal.

Integrity is not an additive punishment score. Evidence-backed patterns lower confidence or produce `needs_manual_inspection` with neutral reason codes. They never allege intent or wrongdoing.

## Time weighting

Evidence uses a dimension-specific exponential decay:

$$
w(t) = 2^{-t/h}
$$

where $t$ is evidence age and $h$ is a versioned half-life. Technical relevance decays faster than sustained collaboration. Original timestamps remain inspectable.

## Initial composite hypothesis

The five additive dimensions use one explicit starting allocation:

| Dimension | Weight |
|---|---:|
| Independent open-source record | 30% |
| Merge and follow-through | 20% |
| Collaboration | 15% |
| Relevant experience | 20% |
| Tenure and continuity | 15% |

These weights total 100 percent. Integrity and gaming resistance is a non-additive confidence modifier and manual-inspection trigger. Repository policies may choose supported presets and thresholds, but cannot make age dominant or introduce excluded proxy features. GitHub never displays the composite number.

## Confidence

Dimension confidence considers accessible sample size, completed time windows,
pagination completeness, freshness, attribution, independence-classification
coverage, and conflicting evidence. `coverage-confidence-v1` is calculated, not
declared: completed-window share, complete-partition share, attribution factor, and
freshness factor are multiplied and rounded to two decimals. Dimension confidence
then follows the registered scoring policy and cannot exceed coverage confidence.
Integrity confidence requires the complete closed merge-relationship evidence set,
not a selected subset.

Overall confidence is stored alongside the assessment and deterministically labeled:

- `low`: $0 \le c < 0.40$
- `medium`: $0.40 \le c < 0.75$
- `high`: $0.75 \le c \le 1$

For both registered scoring versions, overall confidence is the two-decimal mean of the three core
dimension confidences, capped by calculated coverage confidence. Rate-limit
interruption, source inaccessibility, unsupported actors,
stale evidence, attribution uncertainty, and incomplete requested windows produce
their exact mandatory coverage reasons and a partial assessment; omitting a caveat
cannot preserve an established result. This cap applies independently of whether
review-priority guidance is enabled.

## Summary states

Classification is total and ordered, so one canonical assessment cannot validate
as two states. The engine applies this precedence exactly: an evidence-backed manual
trigger yields `needs_manual_inspection`; otherwise all established prerequisites
yield `established_evidence`; otherwise any explicit coverage limitation, partial
assessment, fewer than two complete years, low overall confidence, or absence of a
supported dimension yields `limited_evidence`; the remaining complete supported
cases yield `developing_evidence`.

The established-history threshold is engine-versioned. Retired `engine-v1`
requires two complete years so retained assessments created during its effective
interval replay exactly. Active `engine-v2` requires three complete years. In both
engines, fewer than two complete years remains an explicit limited-evidence
condition; a complete two-year `engine-v2` history may therefore be developing but
cannot be established.

### Established evidence

Under active `engine-v2`, requires a complete collection, a supported User actor
with full history support, at least three complete years, coverage confidence of at
least 0.75, high overall confidence, repeated independent validation across at
least two repositories, supported core dimensions, and no unresolved
manual-inspection trigger. Historical `engine-v1` replay preserves its two-year
threshold. Low repository relevance does not rewrite this history summary.

### Developing evidence

Used only for a complete, supported User assessment where accessible history
supports at least one dimension, at least two complete years are present, no
limiting condition applies, the result does not meet established thresholds, and
no manual-inspection trigger exists.

### Limited evidence

Used when accessible history is sparse, stale, partial, attribution-limited,
low-confidence, unsupported, covers fewer than two complete years, or supports no
dimension. It describes the system's knowledge, not the contributor.

### Needs manual inspection

Used if and only if at least one evidence-backed integrity reason or manual-inspection dimension is present. The report describes the observed pattern without alleging intent. Any such trigger forbids `prioritize`.

## GitHub actor support

`User` is the initially supported contributor-history actor. `Bot`, `Mannequin`, `Organization`, `EnterpriseUserAccount`, and unknown available actor implementations are preserved by type and receive `limited_evidence` with `UNSUPPORTED_ACTOR_TYPE` unless a later version explicitly supports them. A deleted or unavailable author is represented with null provider identity and `AUTHOR_UNAVAILABLE`; no synthetic node ID is created. Unsupported and unavailable actors cannot receive `prioritize`.

## Review-priority policy

- `not_enabled` is emitted when the repository has not enabled priority guidance, and no priority copy is rendered.
- `prioritize` is opt-in and has two explicit, rendered bases. The
  `reputation_and_patch` path requires established evidence, high confidence, a
  supported User actor, the assessment engine's established-history threshold,
  coverage confidence of at least 0.75, and safe complete patch facts. The
  `patch_only` path allows a supported User
  with limited or developing history when the current patch has passing CI, small
  scope, changed tests, unchanged sensitive paths, and no forbidden patch or
  integrity reason. GitHub states that contributor history remains limited.
- `standard` is the safe default when neither registered prioritize path nor an
  inspect-first trigger applies, including for established but unrelated contributors.
- `inspect_first` requires an explicit integrity or patch-risk reason. Sparse history alone cannot cause it.
- No priority automatically merges, closes, labels, rejects, or deprioritizes a PR.

## Versioning and calibration

Every assessment records policy, evidence, feature, scoring, prompt, and model
versions plus their immutable artifact digests. The version registry resolves each
reference, verifies repository-owned artifact bytes, and enforces its effective
interval. A new scoring version:

1. Runs in shadow mode against retained snapshots.
2. Produces score and state diffs.
3. Passes property, fairness, and adversarial fixtures.
4. Receives documented approval.
5. Applies only to new or explicitly recomputed assessments.

Historical assessments remain reproducible while their minimized calculation
material is retained. Retention is an append-only, monotonically revised lifecycle
rather than a field on the immutable assessment. Deletion and expiry are terminal
states enforced by transition validation and database constraints. Publication
binds both its pre-write and post-write reads to the latest retention revision. A
lawful deletion erases or cryptographically destroys subject and calculation
content, forbids republication, intentionally ends exact reproduction, and leaves
only the non-content lifecycle tombstone.
Retiring a version removes it from new-assessment selection but does not invalidate a
historical assessment created inside that version's effective interval and bound to
the retained artifact digest.

## Required invariants

- Missing evidence cannot lower reputation.
- Account age alone cannot create established evidence.
- Sparse history defaults to standard review, not inspect first.
- Self-merges cannot dominate independent validation.
- One repository cannot dominate the assessment.
- Raw event volume has diminishing returns.
- Technical relevance cannot erase an established history summary.
- Model output cannot alter deterministic facts, candidates, scores, states, or confidence.
- GitHub comments contain no numeric score, free-form public claim, arbitrary report URL, or private source link; controlled templates render registered reasons and caveats.
- Equivalent evidence under a renamed login produces the same result.
- Reputation cannot override failing CI or sensitive patch context.
