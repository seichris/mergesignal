# MergeSignal threat model

> Status: Phase 0 baseline
>
> Review cadence: every architecture change and at least quarterly

## Scope

This model covers:

- GitHub webhook ingress and API access.
- Vercel web/control plane.
- Coolify-hosted Temporal workers and outbox relay.
- Temporal Cloud.
- Managed PostgreSQL and object storage.
- OpenAI Responses API.
- PR comments, GitHub Checks, and the authenticated dashboard.

## Assets

1. GitHub App private key and installation tokens.
2. GitHub user authorization refresh credentials.
3. Public and private normalized evidence.
4. Assessment snapshots and raw numeric scores.
5. Tenant membership and repository authorization.
6. Webhook delivery and audit records.
7. OpenAI credentials, prompts, inputs, and outputs.
8. Integrity of PR comments and Checks.
9. Availability under burst traffic and upstream rate limits.
10. The reputation and privacy of evaluated contributors.

## Trust boundaries

~~~mermaid
flowchart LR
    U["Maintainer or contributor"] --> GH["GitHub"]
    GH --> V["Vercel ingress and dashboard"]
    V --> PG[("Managed PostgreSQL")]
    PG --> C["Coolify workers"]
    C --> T["Temporal Cloud"]
    C --> GH
    C --> O["OpenAI"]
    V --> U
~~~

Everything received from GitHub content fields is untrusted. A valid GitHub webhook proves delivery authenticity, not the truth or safety of user-authored text.

## Threat actors

- Unauthenticated internet attacker.
- Malicious or compromised contributor account.
- Malicious repository content attempting prompt injection.
- Tenant member trying to access another repository or tenant.
- Compromised dependency or CI runner.
- Compromised Vercel, Coolify, database, workflow, or model credential.
- Over-privileged support operator.
- Benign maintainer who over-interprets a concise reputation result.

## Threats and controls

### Webhook forgery and replay

Threat:

- An attacker submits fabricated or repeated pull-request events.

Controls:

- Verify the HMAC against the exact raw request body.
- Enforce body size, event type, action, and content type.
- Uniquely persist X-GitHub-Delivery before acknowledging.
- Return success for an already accepted delivery without duplicating work.
- Store an outbox record in the same transaction.
- Reconcile outbox state independently.

Verification:

- Invalid signature, modified body, duplicate ID, and out-of-order delivery tests.

### Installation-token or private-key theft

Threat:

- An attacker uses app credentials to read private repositories or write comments.

Controls:

- KMS or secrets-manager storage and restricted signing boundary.
- Memory-only installation tokens with scoped repositories and expiry.
- No tokens in logs, traces, errors, workflow histories, or model requests.
- Separate development, staging, and production apps.
- Zero-downtime private-key rotation and revocation runbook.
- Egress restrictions for worker containers where practical.

Verification:

- Secret scanning, log-redaction tests, key-rotation exercise, and scoped-token integration tests.

### Unauthorized PR comment mutation

Threat:

- The app edits another user's comment, duplicates comments, or publishes stale results.

Controls:

- Persist the exact comment ID.
- Use a versioned hidden marker only for recovery.
- Persist a fresh provider-observed ownership record binding exact marker digest,
  comment ID, App identity, and installation before update, deduplication, or removal.
- Serialize monotonic publication generations per repository and PR. Persist every
  publication change as an append-only event with a unique transition ID,
  lifecycle revision, previous state, nondecreasing attempt count, and database
  compare-and-swap constraint. Require `queued` as the initial event and one
  publication aggregate per
  `(installation_id, repository_node_id, pull_request_node_id, generation)`.
- Recheck the current head SHA, active generation, latest append-only retention
  revision, and every assessment source/provenance node immediately before
  publication. Persist a typed observation with expected and current source
  revisions, visibility, repository scope, and its canonical visibility-state
  digest.
- Read a PR-scoped output cursor and independent cursor high-water record in the
  serializable publication transaction. Bind publication plus every visibility
  fence to its revision and digest; reject a self-consistent older generation below
  the high-water revision.
- Require database-issued high-water revision, event count, stream digest, snapshot
  token, and read time for publication, retention, and comment-removal prefixes. A
  locally valid truncated stream cannot authorize a write.
- Record provider-write start and completion. Require distinct pre/post validation
  IDs and require every post-write source observation after completion and before
  the publication update; a fresh wrapper around cached observations is rejected.
  Cap both the pre-write validation record and every underlying source observation
  relative to the actual provider-write start.
- Render through a template-only type that cannot represent numeric scores, model-authored public prose, private source links, or arbitrary report origins.
- Key publication by repository, PR, head SHA, assessment version, and generation, and store the latest observed generation explicitly.
- Re-read the active generation, head, latest retention revision, and complete
  source/provenance set after each GitHub write. Persist the typed post-write
  validation ID and digest; if any fence changed, mark the write stale and queue
  repair immediately.
- Bind the assessment, render target, publication, visibility validations, and
  retention lifecycle to the same installation, repository node ID, immutable PR
  node ID, PR number, assessment ID, generation, and head SHA.
- Enforce monotonic retention revisions with database compare-and-swap constraints;
  a unique `(assessment_id, lifecycle_revision)` rejects competing branches, and
  deletion and expiry are terminal and cannot be overwritten by a stale workflow.
- Remove known app comments through a separate append-only workflow bound to the
  terminal retention transition and verified provider deletion receipt digest.
  Enforce legal transitions, make `removed` terminal, and purge exact PR/comment
  linkage within 30 days. A unique terminal-retention/publication/comment key
  prevents competing removal aggregates.
- If GitHub accepted a successful Check before the post-Check fence became invalid,
  persist the completed success as `repair_queued`; terminal retention must also
  durably enqueue removal of the exact visible comment.
- Include the assessed head SHA visibly in the comment because GitHub cannot atomically compare the head and update a comment.
- Before retrying an ambiguous create, search the exact marker and verify app authorship; remove only verified duplicates owned by the same installation.
- Never delete or edit a comment the app cannot prove it owns.

Repository policy provenance uses the same fail-closed rule. Dashboard policy
activation requires one atomic admin-authorization snapshot binding nonce,
revision sequence, repository policy high-water revision, and snapshot token.
Default-branch policy requires one provider observation bundle resolving the actual
default ref, tip commit, path, and blob; the exact canonical UTF-8 bytes must
recompute both the Git blob SHA-1 and normalized policy SHA-256.

Verification:

- Missing database record, forged marker, ambiguous create, duplicate recovery,
  deleted comment, reused or stale per-source visibility observations, same-head
  rerun, terminal comment removal, retention deletion, and superseded-head race
  tests.

### Dashboard authentication and browser session compromise

Threat:

- An attacker forges an OAuth callback, fixes or steals a session, performs a cross-site request, injects script into rendered GitHub content, or abuses a redirect to gain dashboard access.

Controls:

- Bind every OAuth attempt to a short-lived, single-use state value and the initiating browser session; use PKCE when the selected GitHub authorization flow supports it.
- Allowlist exact callback and post-login destinations; never redirect to an arbitrary user-supplied URL.
- Rotate the application session after login and privilege changes.
- Use encrypted, `HttpOnly`, `Secure`, `SameSite=Lax` or stricter cookies with bounded idle and absolute expiry.
- Protect mutations with same-origin checks and CSRF tokens where cookie semantics alone are insufficient.
- Reauthorize tenant, installation, and repository access on every request; never trust client-provided membership.
- Contextually encode all GitHub-derived output, prohibit unsafe HTML, and deploy a restrictive Content Security Policy.
- Keep refresh credentials encrypted at rest, out of browser-readable storage, and revocable.

Verification:

- OAuth state replay, login CSRF, session rotation, open redirect, repository IDOR, stored XSS, CSP, cookie, and cross-origin mutation tests.

### Cross-tenant or cross-repository disclosure

Threat:

- Private evidence appears in another tenant, repository, PR comment, trace, or export.

Controls:

- Visibility classification at evidence ingestion.
- Separate public-global and private schemas.
- PostgreSQL row-level security with default deny.
- Tenant and repository identifiers in keys and indexes.
- Viewer authorization at request time.
- PR comments restricted to public source links plus target-repository facts.
- Generate every public GitHub link from a provider-observed login or
  `nameWithOwner` bound to the stable actor/repository node ID. Reject query strings,
  fragments, conflicting node locators, and caller-supplied destination slugs.
- Target-repository-private evidence can influence only an assessment for that same repository, regardless of tenant membership.
- Every snapshot item is bound to the assessed immutable actor node ID; target-private and internal items require an exact repository scope, and subject-only items cannot enter maintainer assessment surfaces.
- The complete PR relationship key—PR node, repository node, PR number,
  subject/author, and provider event ID—is validated before evidence types can
  jointly satisfy a reason. Target patch facts additionally match the assessed PR
  node and head.
- Relevance reasons require a versioned comparison to typed language, domain, or
  path facts from the actual target repository and PR. Historical and target paths
  require explicit complete filesets and their exact head SHAs; historical
  self-consistency or a stale target head is insufficient.
- Require one authoritative coverage summary whose typed source partitions bind
  the collection run and exactly implement the registered singleton/year-granular
  query plan with exact boundaries, totals, pagination, observations, candidate
  digests, and same-run gaps. Recompute complete years, attribution, freshness, and
  confidence, and reject an omitted partition, hidden same-run candidate, or stale
  candidate inside a declared-current snapshot.
- Derived public inferences are labeled `PUBLIC_DERIVED`, carry complete acyclic source provenance, and are not presented as raw GitHub facts.
- GitHub `internal` repositories use the restricted target-repository boundary and are never treated as public-global.
- Typed render models that cannot contain disallowed evidence classes.
- Lawful deletion or expiry is represented by a separate content-free, append-only
  terminal retention event; subject and calculation content is erased or
  cryptographically destroyed and republication is forbidden.

Verification:

- RLS, wrong-subject joins, unscoped and cross-repository private evidence, subject-only/internal misuse, deletion republication, IDOR, export, comment-rendering, and trace-redaction tests.

### Prompt injection

Threat:

- Repository descriptions, issues, commit messages, or comments instruct the model to ignore policy, disclose secrets, or invent reputation.

Controls:

- Closed model packet with no browsing, tools, secrets, or network capability.
- Per-request HMAC target aliases and independently request/nonce-bound evidence
  aliases with a local-only exact-target and alias-map envelope; stable GitHub and
  internal evidence identifiers never enter the provider payload.
- Stable population digests remain local. The provider receives a request-local HMAC
  commitment and count with at most 64 deterministic exemplars and witnesses;
  eligibility is checked against the complete population so private evidence hidden
  outside the sample still excludes the candidate.
- Prompt, request schema, response schema, resolved model parameters, and request
  digest form one invocation digest. A single-use CAS ledger binds one sent
  invocation to one accepted response, and a content-digested receipt binds the
  exact output to assessment provenance; cross-request replay is rejected.
- Default-deny exclusion of every candidate depending on target-repository-private evidence.
- Untrusted GitHub topic and path text never reaches the provider as a normalized
  free-form token. Languages and domains resolve only through fixed allowlists;
  everything else becomes `opaque`, while paths become one fixed structural class
  such as `tests`, `documentation`, `dependencies`, or `source`. The versioned
  prompt separately states that every dynamic field is untrusted data and can never
  supply instructions.
- Strict Structured Output schema with one deterministic reason type and evidence-ID set per claim.
- Evidence-ID allowlist validation.
- Evidence-rule validation rejects valid but irrelevant citations that do not satisfy the claim's required evidence groups.
- Neutral-copy validation applies NFKC normalization, rejects unsafe format and bidi
  controls, then rejects ratings, accusations, Markdown links and images, URLs,
  autolinks, user mentions, unsafe HTML or script schemes, and prohibited
  contributor labels from detailed-view and public renderer templates.
- Model cannot modify deterministic facts or scores.
- Model-authored text is rejected on every surface; the authenticated detailed view and public PR comment both use controlled templates for validated structured selections.
- Deterministic fallback on timeout or invalid output.

Verification:

- Injection corpus across repository, issue, PR, commit, comment, guidance, Unicode, Markdown/HTML, and truncation boundaries, including valid-but-irrelevant citations.

### Evidence manipulation and cheap reputation gaming

Threat:

- Self-merges, reciprocal merge rings, templated mass PRs, or warmed-up accounts create misleading validation.

Controls:

- Merge-actor and ownership relationship evidence.
- Diminishing returns for volume.
- Independence weighting.
- Activity-baseline, burst, template, and reciprocal-pattern features. Template
  matching removes repository boilerplate and requires distinct independently
  maintained repositories; merge-relationship events reconcile with canonical merge
  actors and outcomes.
- Neutral manual-inspection states rather than accusations.
- Versioned methodology and adversarial replay.

Verification:

- Self-merge, reciprocal ring, burst, template, and behavior-shift fixtures.

### Account takeover

Threat:

- A reputable old GitHub account is compromised and behaves differently.

Controls:

- Account age is weak and capped.
- Recent behavior compared with the account's own baseline.
- New merge-actor and domain concentrations lower confidence.
- No automatic trust or merge based on history.

Verification:

- Account-takeover-shift fixture.

### Rate-limit and resource exhaustion

Threat:

- Large installations, high-history contributors, webhook bursts, or API abuse exhaust GitHub, database, workflow, model, or worker capacity.

Controls:

- Fast durable ingress and backpressure.
- Per-installation rate and concurrency budgets.
- Fair workflow queues.
- Resumable cursors and cached immutable evidence.
- Request, payload, pagination, model-token, and workflow limits.
- Circuit breakers and degraded deterministic output.

Verification:

- Burst load, large-history, partial-pagination, and upstream-outage tests.

### Supply-chain compromise

Threat:

- A dependency, build action, container, or artifact injects malicious code.

Controls:

- Locked dependencies and reviewed update automation.
- Dependency, source, secret, IaC, and container scanning.
- Minimal CI permissions and pinned third-party actions.
- Reproducible builds, SBOMs, signed artifacts, and promotion between environments.
- Separate deploy credentials per environment.

Verification:

- CI policy tests and periodic dependency provenance review.

### Support and operational overreach

Threat:

- An operator accesses private evidence or changes outcomes without authorization.

Controls:

- No shared production accounts.
- Just-in-time, time-bound access.
- Read-only support tools by default.
- Immutable audit log.
- No silent assessment edit; corrections create a new version.
- Alerts for privileged access and bulk export.

Verification:

- Quarterly access review and audited incident drill.

### Reputational harm and automation bias

Threat:

- Maintainers interpret a score as fact about a person or automatically reject newcomers.

Controls:

- Descriptive GitHub states, no raw scores.
- Limited evidence is not negative.
- Neutral language and visible caveats.
- No public leaderboard or blacklist.
- Correction and refresh flow.
- Review priority advisory only.
- Published methodology and limitations.

Verification:

- Copy tests, newcomer fixtures, pilot interviews, and override/appeal monitoring.

## Security invariants

- No secret is placed in Temporal workflow arguments or histories.
- No output renderer receives evidence it is not authorized to display.
- No PR renderer accepts free-form public copy or a caller-provided detailed-report origin.
- No publication is marked current when its assessment SHA differs from the latest observed head SHA.
- No publication is marked current when it is older than the latest observed
  generation or a stale/terminal retention lifecycle revision forbids publication.
- Every published comment visibly identifies its assessed SHA, and every detected stale head, generation, retention, or source write enters the repair queue.
- Every assessment source and its complete provenance graph has typed pre-write and
  post-write observations whose expected/current revisions, visibility, repository
  scopes, source-set identity, and generation match. Digest equality without those
  typed observations is not authorization.
- No model output bypasses schema and evidence-citation validation.
- No installation token is persisted.
- No historical assessment is silently rewritten.
- No automated reputation state creates a failing CI result.

## Residual risks

- Public GitHub evidence can still be incomplete or misleading.
- Relationship inference can miss affiliations that are not public.
- A compromised established account may resemble legitimate behavior.
- Public PR comments create reputational exposure even with neutral wording.
- Infrastructure vendors remain trust dependencies.

These risks require transparent limitations, correction paths, monitoring, and human decision authority; they cannot be fully eliminated in code.
