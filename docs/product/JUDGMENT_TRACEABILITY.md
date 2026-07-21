# User-visible judgment traceability

> Status: Phase 0 contract
>
> Machine-readable mapping: [judgment-traceability.json](../../contracts/judgment-traceability.json)

Every contributor or patch judgment must have:

1. An owning package.
2. One or more allowed evidence types.
3. A concrete confidence rule.
4. Versioned reason codes.
5. At least one proving fixture.

Operational Check outcomes are lifecycle facts rather than reputation judgments.
They instead map every permitted state/conclusion pair to an owning package, an
explicit contract-state set, a lifecycle rule, and a proving fixture. They cannot
borrow contributor evidence or reason codes to make an operational state appear
proved.

The Phase 0 validator fails when a dimension, summary state, rendered review
priority, reason code, or permitted operational Check state lacks this mapping. It
also verifies that each judgment's evidence set satisfies every mapped reason's
required-all and required-any groups, every registered reason predicate is
implemented, and every fixture declares one exact Check state/conclusion pair that
is cited by the matching operational judgment. `not_enabled` is a non-rendered
repository-policy control state, so it deliberately carries no contributor evidence
or judgment entry; a valid assessment with priority disabled still has a successful
operational Check.

## Ownership

| Judgment | Owner | Primary proof |
|---|---|---|
| Tenure and continuity | packages/reputation | Clock-controlled continuity and newcomer fixtures |
| Independent open-source record | packages/reputation | Merge-actor and ownership relationship fixtures |
| Merge and follow-through | packages/reputation | Resolved outcome and review lifecycle fixtures |
| Collaboration | packages/reputation | Structured review-action fixtures |
| Relevant experience | packages/reputation | Deterministic similarity and citation-valid explanation fixtures |
| Integrity and gaming resistance | packages/reputation | Burst, self-merge, reciprocal, and behavior-change fixtures |
| Summary state | packages/reputation | Cross-dimension policy fixtures |
| Review priority | packages/policy | Explicit repository-policy fixtures |
| Patch context | packages/github-output | Current-head CI, scope, issue, test, and risk-path fixtures |
| Contextual explanation status | packages/contextualizer | Timeout, schema, and citation fallback fixtures |
| Operational Check lifecycle | packages/github-output | Pending, success, action-required, failure, and superseded contract-state mappings |

## Review rule

A pull request cannot claim a judgment is implemented unless its entry path reaches the owning package, its reason's required evidence groups and implemented versioned predicate are satisfied, the result conforms to the report schema, the corresponding executable fixture asserts the distinguishing outcome, and the rendered GitHub output obeys the template-only and visibility rules.

Build success alone is not evidence that a judgment is implemented.

Phase 0 fixtures are explicitly `specification_only`. Their copy expectations become executable behavioral gates only when the owning engine and renderer exist in later phases; Phase 0 validates their schema, traceability, safety invariants, and absence of orphan expectations without claiming to have executed a nonexistent product.
