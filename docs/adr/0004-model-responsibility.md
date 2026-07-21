# ADR 0004: Models contextualize but do not own reputation facts or scores

- Status: Accepted
- Date: July 21, 2026

## Context

Repository relevance can benefit from language understanding. Account age, merge actors, rates, independence, coverage, explanations, and numeric dimensions must remain reproducible and auditable.

## Decision

Use deterministic code for evidence normalization, feature extraction, confidence, reason codes, candidate retrieval, relevance scores and states, renderer copy, and all other scores. Use the OpenAI Responses API with GPT-5.6 only to rank and select from a closed deterministic set of registered claims.

The model receives a closed, minimized public-evidence packet, has no tools or
browsing, and must return strict Structured Output containing only claim IDs,
registered reason codes, and request-local evidence aliases. The provider payload
contains a per-request HMAC target alias, independently HMAC-aliased evidence IDs,
a request-local HMAC commitment to each complete candidate population, and a
separate pseudonymous safety identifier. Stable population digests, exact targets,
and internal evidence mappings stay in a local content-digested envelope. Provider
eligibility is evaluated against every member of the complete population, not just
the at-most-64 deterministic exemplars and witnesses. Bounded technical context is
NFKC-normalized, allowlisted, and replaced by an opaque digest token when it
contains instruction-like or active-content syntax.

The invocation binds the exact prompt bytes, request and response schemas, resolved
model parameters, and provider request digest. A single-use append-only request
ledger CAS-binds the sent invocation to exactly one accepted response. A second
content-digested envelope binds that response to the assessment and exact output;
replay or reassignment is rejected. Validation still requires the evidence groups
declared by each reason, so an allowed but irrelevant citation cannot justify a
claim. Candidates depending on target-repository-private evidence are excluded and
use deterministic fallback rendering. Timeout, invalid schema, unknown citation,
or insufficient evidence also falls back to the deterministic assessment.

Model-authored prose is not accepted on any surface. Both the authenticated detailed view and the public PR comment render controlled repository-owned templates from validated structured claims.

Use Promptfoo for repository-owned evaluations. Promote a model or prompt version only after citation, injection, newcomer, relevance, latency, and cost gates pass.

## Consequences

- Deterministic output remains available during OpenAI outages.
- Model prompts and schemas are versioned product contracts.
- Provider request and response receipts are replay-resistant, and no stable target or internal evidence identifier crosses the provider boundary.
- Private-dependent candidates are excluded by default; any future opt-in mode requires a new reviewed policy and provider data-control review.
- Explanations are renderer-owned and cannot make uncited claims or alter candidates, scores, states, or confidence.
- Additional engineering is required for candidate retrieval and citation validation.

## Rejected alternatives

- Ask a model for one reputation score: opaque, unstable, difficult to calibrate, and unsafe.
- Avoid models entirely: loses useful semantic ranking among already-safe deterministic candidates.
- Give the model GitHub tools: expands prompt-injection and data-access risk without a core-product need.
