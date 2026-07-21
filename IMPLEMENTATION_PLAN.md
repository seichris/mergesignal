# MergeSignal — Production Implementation Plan

> Status: Phases 0-1 complete; Phase 2 in progress
> Planning date: July 21, 2026
> Product: MergeSignal — Trust for Every Pull Request
> Scope: the complete long-term product, not a disposable MVP

## 1. Executive summary

MergeSignal is a GitHub App that helps maintainers decide which pull requests deserve scarce human review time. Its primary product is an evidence-backed, repository-specific view of the contributor:

- How long has the GitHub account existed?
- Has the contributor participated in open source over time, or only in a recent burst?
- Have independent maintainers merged their pull requests before?
- Do they collaborate constructively through reviews and revisions?
- Is their prior experience relevant to this repository?
- How complete and trustworthy is the available evidence?

MergeSignal will keep this contributor-reputation analysis separate from a smaller patch-context layer. The patch layer will report objective facts such as CI state, scope, linked issues, tests, and sensitive paths; it will not try to replace the repository's existing linters, security tools, code-review agents, or maintainers.

The system will never treat account age, popularity, or a single opaque score as proof that code is safe. It will produce versioned dimensions, confidence, caveats, and links to evidence. A newcomer with little history is “limited evidence,” not “low trust.” A highly established contributor still receives no exemption from code review.

## 2. Product objective

### Primary objective

For each pull request, answer:

> Based on public GitHub history and this repository's context, what evidence helps a maintainer decide whether to invest review time in this contribution?

### Success criteria

MergeSignal succeeds when it:

1. Reduces the time maintainers spend opening and investigating low-context submissions.
2. Surfaces credible contributors and relevant prior work without disadvantaging newcomers.
3. Makes every conclusion traceable to GitHub evidence.
4. Remains useful under high PR volume, GitHub rate limits, partial history, and service failures.
5. Is difficult to game cheaply and honest when it cannot reach a confident conclusion.
6. Keeps private repository information isolated to the installation that granted access.
7. Gives maintainers control without turning reputation into automatic merge authority.

### Non-goals

MergeSignal is not:

- An AI-authorship detector.
- A universal social-credit score for developers.
- A public leaderboard of “good” and “bad” contributors.
- Proof of identity, employment, or code ownership.
- A replacement for CI, security scanning, or human review.
- An automatic merge or rejection system.
- A sentiment analyzer for GitHub comments.
- A system that infers protected, demographic, geographic, or socioeconomic attributes.

## 3. Product invariants

These rules are architectural constraints, not optional product copy:

1. **Unknown is not negative.** Missing, private, inaccessible, or sparse evidence lowers confidence; it does not lower reputation by itself.
2. **External validation matters more than self-activity.** A pull request merged by an independent maintainer is stronger evidence than activity in a repository controlled by the contributor.
3. **Account age is a weak signal.** It is capped and cannot outweigh sustained contribution quality.
4. **Private evidence stays repository-scoped.** Evidence from an installed private repository may influence only an assessment for that exact repository. It never enters another repository's assessment or a public profile, even inside the same tenant.
5. **Facts and judgments are deterministic.** GitHub-derived facts, relevance candidates, states, confidence, numeric dimensions, and explanatory copy are computed or rendered in code. A language model may select exact claim tuples from a closed candidate set but cannot change or author the result.
6. **Contributor and patch signals remain separate.** A strong history cannot make a risky patch safe; a sparse history cannot make a sound patch bad.
7. **Every result is reproducible.** Each assessment records its evidence snapshot, data coverage, policy version, feature version, scoring version, prompt version, and model version.
8. **No silent adverse action.** MergeSignal does not close, reject, merge, or deprioritize a PR invisibly. Repository automation based on its output must be explicit, configurable, and auditable.
9. **Evidence is contestable.** Maintainers and contributors can report incorrect attribution, request refreshes, and see why a result was produced.
10. **Popularity is not competence.** Followers, employer, profile text, location, social links, and raw star totals are excluded from the core score.

## 4. Complete user experience

### 4.1 Installation and onboarding

1. An organization owner installs the GitHub App on selected repositories.
2. MergeSignal verifies installation permissions and repository access.
3. The owner selects a versioned policy preset and may adjust supported thresholds.
4. MergeSignal validates repository configuration from the dashboard and, optionally, from .github/mergesignal.yml on the default branch.
5. A test assessment runs without publishing a conclusion.
6. The owner reviews the exact PR comment and operational GitHub Check that future pull requests will receive.
7. The installation moves from shadow mode to active mode.

Dashboard revisions are accepted only from an atomic authorization snapshot that
binds actor, admin permission, nonce, revision sequence, repository policy
high-water revision, and database snapshot token. Default-branch configuration is
accepted only from one provider observation bundle that resolves the actual default
ref to a commit and `.github/mergesignal.yml` blob; MergeSignal recomputes the Git
blob SHA-1 from the exact canonical UTF-8 bytes and the normalized policy SHA-256.
Stale dashboard revisions, cherry-picked proof fragments, and caller-asserted blob
digests are rejected.

### 4.2 Pull-request assessment

1. GitHub sends a pull_request webhook.
2. MergeSignal verifies its signature, records the delivery idempotently, and acknowledges it immediately.
3. A queued GitHub Check makes the asynchronous state visible without posting an incomplete comment.
4. A durable workflow resolves the current PR head SHA and repository policy.
5. The system collects or refreshes contributor evidence within a defined rate budget.
6. Deterministic feature extraction and scoring run against an immutable evidence snapshot; insufficient evidence produces a null internal dimension score rather than a fabricated zero.
7. The contextual model selects exact cited claim tuples from the closed deterministic relevance-candidate set; repository-owned templates render them.
8. The result is persisted before the PR comment is created or updated and the GitHub Check is completed.
9. If a newer commit arrives, the older assessment is marked superseded and cannot overwrite the newer result.

### 4.3 Maintainer review

The PR comment shows:

- Contributor signal by dimension.
- Evidence coverage and freshness.
- Strongest positive evidence.
- Important caveats or integrity concerns.
- Relevant prior contributions with direct links.
- A separate patch-context summary.
- The exact policy and assessment versions.
- A link to a detailed dashboard view where authorized maintainers can inspect raw numeric scores.

Maintainers can:

- Mark the result useful, incomplete, or incorrect.
- Identify a bad evidence link or attribution.
- Rerun the current version.
- Compare an assessment with earlier versions.
- Inspect raw normalized facts without seeing another tenant's private data.

### 4.4 Contributor experience

Because the reputation summary is posted as a PR comment, the contributor can:

- See the evidence used for their PR.
- Learn that sparse history means limited evidence rather than a negative judgment.
- Report identity mismatches, renamed accounts, deleted sources, or incorrect facts.
- Request a refresh after public data changes.
- See the resolution status of a correction request.

On a public repository, the PR comment and the public evidence linked from it are public. On a private repository, the comment is visible to repository-authorized users. On a GitHub Enterprise internal repository, it is visible according to GitHub's enterprise authorization and all target facts remain restricted rather than public-global. MergeSignal will not expose a separate public global profile or searchable contributor leaderboard.

### 4.5 Organization operations

Organization owners can:

- Monitor the review queue across repositories.
- Filter by evidence coverage, relevance, confidence, and patch state.
- Compare policy behavior in shadow mode.
- Audit policy changes and maintainer overrides.
- Export assessments and evidence links.
- Set retention, visibility, and repository-specific policies.
- Disable analysis immediately and request data deletion.

## 5. Assessment contract

### 5.1 Contributor dimensions

| Dimension | Question | Representative evidence | Important limitation |
|---|---|---|---|
| Tenure and continuity | Is this an established account with activity over time? | Account creation date, active months, contribution years, recent continuity | Age alone is weak and capped |
| Independent open-source record | Has work been accepted outside repositories the contributor controls? | PRs merged by others, distinct repositories and maintainers | Public data can be incomplete |
| Merge and follow-through | Do submitted changes reach an accepted outcome? | Merged PRs, review-to-merge flow, revisions after requested changes | A closed PR is not automatically poor work |
| Collaboration | Does the contributor participate in review and revision? | Review states, follow-up commits, resolved threads, response cadence | No sentiment or personality scoring |
| Relevant experience | Does prior work resemble the target repository's domain and stack? | Languages, topics, dependency ecosystems, changed paths, issue themes | Contextual similarity is not proof of quality |
| Integrity and gaming resistance | Does the evidence appear organic and independently validated? | Burst patterns, self-merges, reciprocal clusters, template repetition | Flags indicate uncertainty, not misconduct |

### 5.2 Confidence is separate

Every dimension and the overall assessment include confidence based on:

- Evidence volume.
- Time coverage.
- Source accessibility.
- Successful pagination and rate-limit completion.
- Attribution quality.
- Freshness.
- Agreement or conflict among signals.

Confidence must never be folded invisibly into the score. The report may say “strong evidence, high confidence,” “promising evidence, medium confidence,” or “limited evidence,” but never convert missing history into a low score.

### 5.3 Output states

The default maintainer-facing output uses descriptive states:

- **Established evidence**
- **Developing evidence**
- **Limited evidence**
- **Needs manual inspection**

A repository may additionally enable a review-priority recommendation:

- **Prioritize**
- **Standard review**
- **Inspect first**

These are triage suggestions, not merge or rejection decisions. GitHub receives descriptive states and confidence only. Raw 0–100 values remain available to authorized maintainers in the detailed evidence view for calibration and debugging.

### 5.4 Versioned report schema

The canonical contracts are:

- [Immutable assessment schema](contracts/reputation-assessment.schema.json)
- [Template-only PR-comment render schema](contracts/pr-comment-render.schema.json)
- [Append-only publication-event schema](contracts/publication-state.schema.json)
- [Validated assessment example](contracts/examples/reputation-assessment.json)
- [Public PR-comment example](contracts/examples/pr-comment-render.public.json)
- [Private-repository PR-comment example](contracts/examples/pr-comment-render.private.json)
- [Evidence snapshot manifest](contracts/examples/evidence-snapshot.json)

The assessment, schemas, reason-code registry, and examples are checked together.
Publication lifecycle and supersession never mutate an assessment. Application-level
validation requires every dimension, patch, coverage, and explanation evidence ID to
belong to the assessment's immutable snapshot.

## 6. Reputation methodology

### 6.1 Deterministic evidence pipeline

The reputation engine has four explicit stages:

1. **Normalize:** Convert GitHub objects into typed, immutable evidence records.
2. **Extract:** Produce a versioned feature vector from those records.
3. **Score:** Convert features into dimension values through deterministic, tested functions.
4. **Select:** Ask the contextual model to return exact individually cited claim tuples from the closed candidate set, each bound to one deterministic reason type and its required evidence groups.

The provider request uses only per-request opaque target and evidence aliases,
request-local HMAC population commitments, and a pseudonymous safety identifier;
exact targets, stable population digests, and internal mappings stay in a local
content-digested envelope. Full populations, not only bounded exemplars, determine
provider eligibility. Candidates that depend on target-repository-private evidence
are excluded by default and use deterministic fallback rendering. No model output
can modify raw GitHub facts or author prose. A model failure yields a deterministic
report with a controlled contextualization-unavailable message.

### 6.2 Time windows

Use several windows rather than a lifetime total:

- 90 days for recent activity and anomalous bursts.
- 365 days for current consistency and collaboration.
- 3 years for sustained open-source work.
- Up to 5 complete contribution years for long-term context.
- Lifetime account age as a capped, low-weight feature.

Historical evidence uses dimension-specific exponential decay:

$$
w(t) = 2^{-t / h}
$$

where $t$ is age and $h$ is a configurable half-life. Relevant technical experience should decay faster than evidence of sustained collaboration. Original event dates remain visible so maintainers can interpret the weighting.

### 6.3 Independent validation

For each contribution, compute an independence class:

- Contributor-owned or contributor-administered repository.
- Organization closely affiliated with the contributor.
- Repository where the contributor is a maintainer.
- Independent repository with a distinct merger or reviewer.
- Unknown relationship.

Independent merges receive the greatest weight. Self-owned work remains useful evidence of activity and domain experience but contributes little to external validation. Unknown relationships lower confidence instead of being guessed.

### 6.4 Merge record

Merge history is descriptive evidence, not a simplistic acceptance percentage. The engine will track:

- Submitted, open, closed-unmerged, and merged PRs.
- Who merged the PR when public data permits.
- Time from opening to first review and merge.
- Requested changes followed by later commits.
- Repeated success across independent repositories.
- Whether apparent merges are self-merges or reciprocal patterns.

Rates with small samples use Bayesian shrinkage:

$$
\hat{p} = \frac{m + \alpha}{n + \alpha + \beta}
$$

where $m$ is merged PRs, $n$ is resolved PRs, and the prior is calibrated from an appropriate reference cohort. The interface always shows the sample size. Closed or abandoned PRs are not treated as evidence of poor quality without context.

### 6.5 Consistency

Consistency features include:

- Active months per year.
- Longest active and inactive periods.
- Distribution of contributions over time.
- Number of distinct repositories and maintainers.
- Ratio of recent activity to historical baseline.
- Concentrated bursts immediately before the assessed PR.

High volume alone is not rewarded. The design favors sustained, independently validated work over raw event counts.

### 6.6 Collaboration

Collaboration is derived from structured GitHub actions:

- Reviews received and review outcomes.
- Follow-up commits after requested changes.
- Resolution of review conversations when accessible.
- Maintainer participation before merge.
- Reviews the contributor has provided to others.
- Repeated collaboration across independent projects.

MergeSignal does not infer politeness, personality, intent, or emotional tone.

### 6.7 Repository relevance

The target repository and current PR receive a deterministic, typed fingerprint:

- Languages derived from the exact changed paths at the historical and target head
  SHAs; repository-wide language metadata is context, never proof that the
  contributor worked in that language.
- Dependency ecosystems and key packages.
- Repository topics and bounded normalized domain features.
- Architectural areas derived from paths.
- Contribution guidelines and declared project domains.

Prior evidence receives the same fingerprint where data is available. Every
relevance match names the historical PR/repository, target PR/repository, comparison
version, typed target inputs, and exact matched values. Internally consistent
historical evidence is not relevant unless the comparison to the actual target also
passes. Deterministic similarity owns the relevant-experience score, state, and
confidence and generates a bounded candidate set. GPT-5.6 may select from those
candidates for presentation and returns:

- Selected registered claim IDs in deterministic candidate order.
- The unchanged reason code and exact evidence IDs attached to each candidate.

The selected claim tuples are validated as an ordered subset of the
content-addressed candidate packet. All visible rationale, uncertainty, and missing
context copy comes from repository-owned renderer templates.

The model cannot change the deterministic relevant-experience result and is not asked whether the contributor is “good” or “trustworthy.”

### 6.8 Initial weighting hypothesis

Weights are a calibration starting point, not product truth:

| Dimension | Initial hypothesis |
|---|---:|
| Independent open-source record | 30% |
| Merge and follow-through | 20% |
| Collaboration | 15% |
| Repository-relevant experience | 20% |
| Tenure and continuity | 15% |

These five additive weights total 100%. Integrity and gaming resistance is not additive: it acts as a confidence modifier and manual-inspection trigger, not a negative point bucket. Account age is capped inside tenure and continuity. Repository policies may select supported presets and thresholds, but may not enable protected-attribute proxies or make account age dominant.

### 6.9 Anti-gaming analysis

The engine will identify evidence patterns that deserve more scrutiny:

- Large bursts from a new or previously dormant account.
- Many near-identical PRs across unrelated repositories.
- High apparent merge success dominated by self-merges.
- Small reciprocal groups repeatedly merging one another's work.
- Repositories created primarily to manufacture activity.
- Sudden topic switching paired with templated contributions.
- Contribution counts unsupported by accessible underlying events.
- An established account whose recent behavior changes sharply from its baseline.

These patterns produce reason codes such as INDEPENDENCE_UNCLEAR or RECENT_ACTIVITY_ANOMALY. They never produce accusations such as “spam,” “fraud,” or “fake contributor.” Maintainers see the evidence and make the judgment.

### 6.10 Fairness and calibration constraints

Automated tests and offline evaluation must enforce:

- Adding inaccessible history cannot reduce a result.
- Increasing account age alone cannot move a contributor from limited to established evidence.
- A newcomer with a strong current patch remains eligible for standard or prioritized review.
- Self-merges cannot dominate independent-validation dimensions.
- A single popular repository cannot dominate the complete assessment.
- Followers, employer, location, avatar, name, and profile prose do not enter features.
- Equivalent evidence produces equivalent output across renamed GitHub logins.
- Model selections cannot cite evidence absent from the snapshot.
- Changing a scoring version never silently rewrites a historical result.

Calibration will use consented or public, manually adjudicated cases across sparse, new, established, high-volume, and adversarial histories. Reviewers label evidence sufficiency and relevance—not a person's intrinsic worth.

## 7. Secondary patch-context layer

Patch context remains intentionally narrow:

- Current CI/check conclusion.
- Changed file and line counts.
- Test files added or changed.
- Linked issue or discussion.
- Compliance with repository-provided contribution instructions.
- Sensitive areas such as authentication, billing, permissions, workflows, generated files, lockfiles, and migrations.
- Binary or minified content.
- Draft state, mergeability, and stale base state.

It produces facts and risk flags, not a second general-purpose code review. Repositories may link their existing security scanners, linters, or LLM reviewers alongside MergeSignal.

Contributor reputation and patch context are displayed in separate cards and separate JSON fields. There is no formula in which strong reputation cancels a failing test or security warning.

## 8. GitHub data strategy

### 8.1 Sources

Use the GitHub GraphQL API as the primary history interface:

- User.createdAt for account tenure.
- User.contributionYears to plan bounded historical collection.
- User.contributionsCollection with explicit from and to dates for each year.
- Pull-request, issue, commit, and review contribution connections.
- User pull-request and review connections for accessible detailed history.
- Repository, organization, actor, review, merge, language, topic, and file metadata.

Use REST where it is the authoritative or more practical endpoint:

- GitHub App installations and access tokens.
- Check runs.
- Repository contents and configuration.
- Webhook redelivery and operational recovery.
- Conditional requests where ETags are useful.

Do not use the public Events API as historical truth: GitHub documents that it exposes only recent events and caps the result set. A contribution-calendar count is also not treated as a complete history because GitHub attribution and visibility rules can omit work.

### 8.2 Evidence collection plan

For a first-seen contributor:

1. Fetch account metadata and contribution years.
2. Build a rate-budgeted query plan for up to five complete years.
3. Fetch yearly contribution collections with explicit boundaries.
4. Fetch detailed recent pull requests, reviews, and repository metadata.
5. Continue pagination until complete or a documented source limit is reached.
6. Stratify older detailed evidence by time, repository, and outcome if complete retrieval is impractical.
7. Record requested, observed, missing, and truncated coverage separately.
8. Normalize records by immutable GitHub node ID and retain the login as historical display data.

For subsequent assessments:

- Reuse immutable evidence and refresh mutable outcomes.
- Refresh recent activity aggressively and older windows lazily.
- Invalidate affected features on relevant webhooks.
- Run a scheduled reconciliation for missed GitHub deliveries and changed visibility.
- Use stale-but-labeled evidence during temporary GitHub failure when policy permits.

### 8.3 Rate-limit control

A central GitHub client layer will:

- Pin the supported REST API version and expose upgrades through an ADR and regression suite.
- Estimate GraphQL query cost before broad backfills.
- Track primary and secondary limits by installation and credential.
- Schedule fair per-installation work instead of allowing one large account to starve others.
- Honor Retry-After and reset headers.
- Apply exponential backoff with jitter.
- Bound concurrency for mutating and expensive endpoints.
- Prefer GraphQL batching, conditional REST requests, and cached immutable metadata.
- Persist collection cursors and coverage so a backfill resumes rather than restarts.

No code will assume token length, permanent numeric rate limits, or a fixed response shape outside the typed GitHub adapter.

### 8.4 Visibility boundaries

Evidence is classified at ingestion:

- PUBLIC_GLOBAL: public GitHub evidence reusable across tenants.
- PUBLIC_DERIVED: a MergeSignal derivation with an acyclic, entirely public input-evidence graph and versioned derivation; reusable only with that provenance and labeled as an inference.
- TARGET_REPOSITORY_PRIVATE: source or derived evidence usable only for the same target repository.
- SUBJECT_VISIBLE: evidence visible to the contributor but not generally public.
- INTERNAL_OPERATIONAL: delivery, billing, security, and debugging metadata.

The scoring engine receives an explicit visibility scope. It cannot query storage directly or allow private evidence from one repository to influence another repository's assessment, even inside the same tenant.

## 9. System architecture

### 9.1 Architecture decision

Use a TypeScript monorepo with a stateless Next.js control plane, durable Temporal workflows, PostgreSQL as the system of record, and separately deployable workers.

This avoids two long-term failure modes: performing slow history analysis inside a webhook request, and building retry/backfill logic from ad hoc queue jobs. Temporal provides durable workflow state across retries and outages; the database inbox/outbox ensures webhook acceptance does not depend on Temporal being available at that instant.

### 9.2 Component flow

~~~mermaid
flowchart LR
    GH["GitHub App<br/>webhooks and APIs"] --> IN["Webhook ingress<br/>signature verification"]
    IN --> DB[("PostgreSQL<br/>inbox, evidence, assessments")]
    IN --> OUT["Transactional outbox"]
    OUT --> WF["Temporal workflows"]
    WF --> GW["GitHub gateway<br/>rate and token control"]
    GW --> GH
    WF --> FE["Feature and scoring engine"]
    FE --> DB
    WF --> AI["OpenAI Responses API<br/>relevance and explanation"]
    AI --> WF
    WF --> DB
    WF --> OUTPUT["GitHub output publisher<br/>PR comment and operational Check"]
    OUTPUT --> GH
    UI["Next.js dashboard"] --> DB
    OBS["OpenTelemetry pipeline"] --- IN
    OBS --- WF
    OBS --- UI
~~~

### 9.3 Deployment topology

Recommended production topology:

- **Web/control plane:** Next.js App Router in the Kontext team on Vercel.
- **Durable orchestration:** Temporal Cloud, with a documented self-hosting escape path.
- **Workers:** containerized Node.js Temporal workers and the outbox relay on the existing Coolify server.
- **Database:** managed PostgreSQL with high availability, point-in-time recovery, encrypted backups, and connection pooling.
- **Object storage:** encrypted S3-compatible storage for short-lived raw payloads and export artifacts.
- **Secrets and signing keys:** cloud KMS or a secrets manager; GitHub private-key operations should use a non-exportable signing boundary where supported.
- **Observability:** OpenTelemetry with configurable trace, metric, log, error, and alert backends.
- **Edge protection:** managed WAF, rate limiting, and DDoS protection for public endpoints.

Keep all stateful services in compatible regions. Development and CI use local PostgreSQL, a local Temporal server, and recorded GitHub fixtures.

### 9.4 Monorepo structure

~~~text
apps/
  web/                 Next.js dashboard, auth, API, webhook ingress
  worker/              Temporal workers and activities
  admin-cli/           Audited backfills, reprocessing, and incident tools
packages/
  domain/              Entities, value objects, reason codes, invariants
  db/                  Schema, migrations, repositories, RLS tests
  github/              Auth, API adapters, pagination, rate budgeting
  evidence/            Normalization, provenance, coverage
  reputation/          Feature extraction, scoring, calibration
  contextualizer/      OpenAI schemas, prompts, model routing
  policy/              Policy schema, presets, validation, versioning
  github-output/       PR comment and GitHub Check rendering/publishing
  workflows/           Temporal workflow definitions
  observability/       Logging, tracing, metrics, redaction
  security/            Webhook verification, encryption, audit helpers
  test-kit/            Factories, fixtures, fake clocks, contract harnesses
  ui/                  Shared accessible components
infra/
  terraform/           Environments, networking, database, storage, secrets
evals/
  promptfoo/           Contextual-model and adversarial evaluation suites
docs/
  adr/                  Architecture decisions
  operations/           Runbooks, SLOs, incident and recovery procedures
~~~

Enforce package boundaries so web handlers cannot import database tables directly, scoring cannot call GitHub, and model code cannot mutate evidence.

### 9.5 Durable workflows

Core workflows:

- ProcessWebhookDelivery
- AssessPullRequest
- BackfillContributorEvidence
- RefreshContributorEvidence
- ReconcileInstallation
- RepublishCheck
- RecomputeScoringVersion
- DeleteTenantData
- CorrectContributorEvidence

AssessPullRequest uses this sequence:

1. Resolve delivery, installation, repository, PR, and current head SHA.
2. Create or reuse an assessment idempotency key.
3. Publish queued state.
4. Ensure contributor evidence meets the registered freshness and coverage
   policies. Materialize every partition in the registered query plan for the exact
   collection run and calendar window, including query version, evidence types,
   provider totals, pagination completion, limitations, candidate IDs, observation
   time, and candidate-set digest. Derive complete years, attribution, freshness, and
   confidence from those partitions rather than accepting collector claims.
5. Freeze an evidence snapshot.
   Reject duplicate provider-event natural keys, bind changed paths to the exact
   historical and target head SHAs and complete filesets, select exactly one active
   repository risk policy at capture time, and prove closed derivation candidate
   sets from provider-backed coverage, totals, and pagination state.
6. Extract the versioned feature vector.
7. Run deterministic dimensions and integrity rules.
8. Run bounded contextual claim selection without changing deterministic results or renderer-owned copy.
9. Validate all cited evidence IDs and schema constraints.
10. Persist the immutable completed assessment atomically.
11. Signal the single PR-scoped output workflow with a new monotonic publication generation.
12. Revalidate the current head SHA and latest generation; read the latest monotonic
    retention revision under compare-and-swap fencing; persist a typed pre-write
    observation for every assessment source/provenance node with expected/current
    revisions, visibility, repository scope, and canonical state digest.
13. Publish through the template-only comment model and the head-specific operational Check.
14. Re-read the active generation, head, complete retention stream, and complete
    source set after the write; persist the typed post-write validation ID and state
    digest. Every source observation must follow the recorded provider write
    completion and precede the publication update; queue repair immediately if any
    fence changed.
15. Start the GitHub Check only after the comment and publishable post-write fence
    complete. After the Check completes, re-read head, generation, latest retention
    revision, and every source into a distinct post-Check record. Only that final
    publishable fence can authorize `success`. A deletion or expiry racing either
    write produces stale/repair state and removal work, never success.

Activities are retryable and idempotent. Non-deterministic operations—including API calls, clocks, random identifiers, and model calls—live in activities, not workflow definitions.

### 9.6 Webhook durability

The ingress route must:

1. Enforce body-size and content-type limits.
2. Verify the GitHub HMAC against the exact raw body.
3. Validate the event type and action.
4. Insert X-GitHub-Delivery into a unique delivery ledger.
5. Persist the minimal payload and an outbox record in one transaction.
6. Return a 2xx response with no analysis work in the request path.

An outbox relay starts the Temporal workflow. A reconciliation process catches unsent outbox rows. Duplicate deliveries return success without duplicate analysis.

## 10. GitHub App design

### 10.1 Repository permissions

| Permission | Access | Purpose |
|---|---|---|
| Metadata | Read | Required repository identity and installation metadata |
| Pull requests | Read and write | Read PR metadata and create/update the app's single reputation comment |
| Checks | Read and write | Queued and completed MergeSignal Check runs |
| Contents | Read | Base-branch policy, contribution guidance, language and path context |
| Issues | Read | Linked-issue context when enabled |
| Actions | Read, optional | Workflow details only when a repository enables deeper CI context |

No write permission to contents, issues, actions, administration, or members is required. Pull-request write access is used only for the app's own PR comment; the app never edits PR titles, bodies, branches, labels, reviewers, or merge state. Optional permissions must be feature-gated and omitted until enabled.

### 10.2 Webhook subscriptions

Required:

- pull_request
- installation
- installation_repositories
- check_run for requested reruns

Optional for fresh tenant-local collaboration evidence:

- pull_request_review
- pull_request_review_comment
- issue_comment
- workflow_run

Only subscribed events and relevant actions are accepted.

### 10.3 Authentication

- App-level JWTs are created only in the GitHub gateway.
- Installation access tokens are scoped to selected repositories, cached in memory, refreshed before expiry, and never logged.
- Dashboard login uses the GitHub App user authorization flow with expiring user tokens and encrypted refresh credentials.
- Authorization is recomputed from current GitHub organization and repository access, not trusted from old session claims.
- GitHub App private keys support zero-downtime rotation and immediate revocation.
- All credential formats are treated as opaque strings.

### 10.4 PR comment and Check behavior

The reputation report is one persistent PR conversation comment. A single PR-scoped output workflow serializes publication generations. MergeSignal stores its GitHub comment ID and embeds a versioned hidden marker containing installation ID, repository node ID, PR number, and marker version. A rerun updates that comment in place instead of adding another notification. It may only update a comment authored by the current GitHub App installation.

The comment contains:

- Descriptive evidence state and confidence.
- Controlled reason-template summaries for all six dimensions without raw numeric scores or model prose.
- Up to three unique public evidence links when available and controlled caveat templates.
- Secondary patch-context facts.
- Assessment freshness and version.
- A link built by the renderer from the configured canonical application origin and assessment ID.

PR-comment evidence links contain only currently public GitHub sources. Public copy
has no free-form input field: the renderer owns reason and caveat templates. Private
or internal repository comments may additionally summarize facts already visible
in the target PR, but never disclose restricted evidence from another repository.
Source visibility and the complete provenance graph behind every assessment state
are revalidated before and after the GitHub write. Each typed validation records the
expected and current source revisions, visibility and repository scope for every
item, the complete source-set identity digest, publication generation, and canonical
visibility-state digest. Publication is an append-only transition stream; every
event has a globally unique transition ID, a per-publication lifecycle revision,
the prior state, and the latest source and retention fences. A database
compare-and-swap appends the next revision only if the expected revision remains
current. Every stream begins at `queued`, and a unique logical key
`(installation_id, repository_node_id, pull_request_node_id, generation)` prevents
two publication aggregates from owning the same PR generation. If publishing is
temporarily blocked, the completed assessment remains
immutable and a later publication transition retries without rerunning the
assessment.

The publisher also reads one authoritative PR output cursor and an independent
database high-water record in the same serializable transaction. The cursor binds
the latest generation/head plus canonical comment and Check IDs; publication and
every visibility fence bind its revision and digest. Publication, retention, and
comment-removal arrays are accepted only when database-issued high-water metadata
matches their terminal revision, count, canonical digest, snapshot token, and read
time. Before any comment update, duplicate reconciliation, or deletion, a typed
provider observation must prove that the exact marker/comment was authored by the
current App installation.

Changed-file facts are head-bound and provider-total-backed. A missing first page
or incomplete pagination yields `unknown` scope/test/sensitive states plus
`PATCH_INVENTORY_INCOMPLETE`; it never fabricates a check-suite identifier or
turns missing paths into an "unchanged" claim.

Before retrying a create after an ambiguous network result, the publisher searches for the exact hidden marker and verifies app authorship. A reconciler retains the oldest verified app-owned marker comment and removes only verified duplicate comments created by the same installation. Assessment, render target, and publication state are cross-validated for installation, repository, PR, assessment, and head before every write.

One check run is keyed by repository, PR, head SHA, and analysis type. Updates are idempotent. Conclusions are limited to operational outcomes:

- success: the assessment and primary comment for the latest observed generation
  are current, typed pre/post source observations are publishable, identical latest
  retention revisions permit publication, and both GitHub IDs are persisted,
  regardless of reputation state.
- action_required: configuration or maintainer input required.
- cancelled: superseded by a newer head SHA.
- failure: system could not complete the assessment.

A contributor reputation state is never disguised as a failing CI conclusion. The Check reports analysis lifecycle and machine-readable status; the PR comment is the primary human-facing reputation report.

## 11. Data model

### 11.1 Core identity and tenancy

- tenants
- tenant_memberships
- github_app_installations
- installation_repositories
- repositories
- repository_policies
- github_actors
- github_actor_aliases

GitHub node IDs are canonical when an author is available. Actor implementation type is preserved, and logins are versioned aliases so renames do not split a contributor's history. `User` history is initially supported; unsupported actor implementations remain typed and produce explicit limited coverage. An unavailable author has null provider identity and a distinct coverage reason; no synthetic node ID is created.

### 11.2 Evidence and scoring

- contribution_items
- contribution_relationships
- evidence_items
- evidence_collection_runs
- evidence_source_partitions
- evidence_coverage
- evidence_snapshots
- feature_vectors
- scoring_policies
- version_registry_entries
- version_artifacts
- reputation_assessments
- assessment_dimensions
- assessment_evidence_links
- model_runs
- prompt_versions

Evidence records contain:

- Source provider and immutable source ID.
- Typed provider locator and stable provider node identity. Public GitHub URLs are
  rendered from the locator only after authorization and contain no query or
  fragment; stored URLs must equal that deterministic rendering.
- Subject and relevant actors.
- Event and observation timestamps.
- Visibility class plus tenant and exact repository boundary when restricted.
- Closed, type-specific normalized payload; undeclared source fields and profile
  proxies are rejected at ingress.
- Hash of canonical source fields.
- Derivation version, complete input-evidence IDs, minimum input cardinalities, and
  exact recomputation rule for every derived record.
- Registry-declared derivation input groups and deterministic predicate; stable relation endpoints prevent cross-event joins.
- Collection run and adapter version.
- Snapshot capture time inside the canonical hashed envelope.
- Tombstone state if the source disappears or becomes private.

### 11.3 Pull-request and operational state

- pull_requests
- pull_request_heads
- check_runs
- pull_request_report_comments
- publication_generations
- publication_events
- assessment_retention_events
- source_visibility_validations
- pull_request_output_cursors
- pull_request_output_cursor_heads
- pr_output_mutation_leases
- lifecycle_stream_heads
- contextualization_request_ledger
- detailed_report_nonce_consumptions
- comment_ownership_observations
- comment_removal_events
- webhook_deliveries
- outbox_events
- workflow_runs
- maintainer_feedback
- correction_requests
- audit_log
- deletion_requests

### 11.4 Database isolation

- Tenant-owned tables include tenant_id in keys and indexes.
- PostgreSQL row-level security is enabled with default-deny policies.
- Application roles separate web reads, worker writes, migrations, and support access.
- Public-global evidence lives in a distinct schema from target-repository-private evidence.
- Cross-tenant and cross-repository joins occur only through audited domain services that exclude private evidence.
- RLS and data-export boundaries have automated integration tests.
- Append-only publication, retention, and removal streams have unique transition IDs
  and unique aggregate revisions: `(publication_id, lifecycle_revision)`,
  `(assessment_id, lifecycle_revision)`, and `(removal_id, lifecycle_revision)`.
  Publication additionally has one aggregate per
  `(installation_id, repository_node_id, pull_request_node_id, generation)`, and
  the authoritative PR output cursor has exactly one row per
  `(installation_id, repository_node_id, pull_request_node_id)`.
  comment removal has one aggregate per terminal-retention/publication/comment
  target. The append transaction compares the current revision and prior state,
  rejects competing branches plus illegal or terminal transitions, and records the
  outbox event atomically.
- Contextualization requests have database `UNIQUE` constraints on request alias,
  request nonce, and non-null provider response ID. Provider acceptance advances
  the request stream in the same transaction that commits the response-ID receipt.
- Detailed-report access atomically inserts one
  `(session_id, request_nonce)` consumption row before returning numeric data.

### 11.5 Retention defaults

Recommended defaults, configurable where legally and operationally appropriate:

| Data | Default |
|---|---:|
| Raw webhook bodies | 7 days |
| Normalized public evidence cache | 90 days after last use, refreshable |
| Target-repository-private cache | 90 days |
| Minimized calculation material referenced by an assessment | Same retention as the assessment |
| Completed assessment snapshots | 13 months |
| Model inputs and outputs | 30 days internally; OpenAI request uses store false |
| Security audit events | 13 months |
| Minimized comment-removal audit event | At most 30 days after removal-workflow creation |
| Installation tokens | Memory only |

Deletion workflows remove or cryptographically destroy subject identity, immutable
assessments, target-repository-private data, model material, exports, and referenced
calculation content; revoke credentials; remove or neutralize known app-owned
comments where possible; append a separate content-free `subject_deleted` retention
event; forbid republication; and verify object-storage and backup-expiry deletion.
Retention events use a per-assessment monotonic revision, unique
`(assessment_id, lifecycle_revision)` constraint, and compare-and-swap transition
fence. `subject_deleted` and `expired` are terminal, and publication
must compare-and-swap the latest revision before and after a GitHub write. Exact
reproduction is intentionally unavailable after a lawful deletion. Legal holds, if
ever supported, must be explicit and audited.

Comment removal is a separate minimized, short-lived append-only state machine
keyed to the terminal retention transition ID and revision, exact
publication/comment identity, attempts, provider completion time, and a receipt
digest. Deletion request identifiers are UUIDs; receipts are digests, never raw
provider payloads. Exact comment and publication linkage expires no later than 30
  days after removal-workflow creation, leaving only an unlinkable aggregate audit
outcome if policy requires it. Removal cannot reuse publication state or reverse
terminal retention.

## 12. Internal APIs and contracts

### 12.1 Boundary contracts

All service boundaries use versioned Zod schemas:

- GitHubWebhookEnvelope
- EvidenceCollectionRequest and Result
- EvidenceItem
- EvidenceCoverage
- FeatureVector
- ScoringPolicy
- ReputationAssessment
- ContextualizationRequest and Result
- PrCommentRenderModel
- TrustedMarkerContext
- PublicationState
- CheckRenderModel
- CorrectionRequest

Unknown external fields are ignored safely; missing required fields fail at the adapter boundary with a typed reason code.

### 12.2 Public endpoints

- POST /api/github/webhooks
- GET /api/auth/github/callback
- GET /api/v1/installations/:id/repositories
- GET /api/v1/repositories/:id/pull-requests/:number/assessment
- POST /api/v1/assessments/:id/rerun
- POST /api/v1/assessments/:id/feedback
- POST /api/v1/evidence/:id/corrections
- GET and PUT /api/v1/repositories/:id/policy
- POST /api/v1/tenants/:id/export
- DELETE /api/v1/installations/:id/data

The public API is OpenAPI-documented, uses cursor pagination, enforces resource-scoped authorization, and records mutating actions in the audit log.

## 13. OpenAI integration

### 13.1 Model responsibility

OpenAI is used for:

- Comparing prior contribution evidence with the target repository's technical context.
- Ranking and selecting registered claim IDs from deterministic candidates.

OpenAI is not used to:

- Fetch GitHub facts.
- Calculate account age, counts, rates, independence, or numeric dimensions.
- Infer identity, protected traits, intent, personality, or AI authorship.
- Make merge, rejection, or access-control decisions.

### 13.2 Runtime design

- Use the Responses API.
- Start with GPT-5.6 Sol for quality-critical relevance selection.
- Evaluate GPT-5.6 Terra for routine high-volume assessments and Luna only for bounded extraction tasks.
- Pin promoted model snapshots after evaluation and record the resolved model returned by the API.
- Set reasoning effort explicitly by task and tune it with measured quality, latency, and cost.
- Require strict Structured Outputs against a versioned JSON Schema.
- Send a closed public-evidence packet with opaque evidence IDs and a per-request
  HMAC target alias. Evidence identifiers are independently HMAC-aliased with the
  request alias and nonce; keep every stable GitHub and internal evidence identifier
  in a local content-digested envelope and disable model browsing and external tools.
- Keep stable complete-population digests local. Send counts and request-local HMAC
  commitments with at most 64 deterministic exemplars and witnesses per candidate,
  plus bounded sanitized language/domain/path context.
- Bind the exact prompt, request schema, response schema, resolved model parameters,
  and provider request into one invocation digest. Persist a single-use append-only
  request ledger whose CAS transition accepts exactly one response.
- Persist a response envelope binding request alias, invocation digest, resolved
  model, provider response ID, provider output digest, and receipt digest. Reject
  replay or reassignment to another assessment.
- Reject unknown evidence citations and fall back to deterministic output.
- Use store: false and a stable, privacy-preserving hashed safety identifier.
- Treat store: false as an application-state control, not a promise of zero provider retention.
- Exclude raw private code and every candidate that depends on target-repository-private evidence from the provider packet by default. Any future private-data mode requires a new versioned policy, explicit repository opt-in, completed provider data-control review, and the applicable Zero Data Retention or Modified Abuse Monitoring controls.
- Place stable instructions and schema first and dynamic evidence last so automatic prompt caching can help.
- Add explicit cache controls only after measuring cache behavior.

### 13.3 Prompt-injection boundary

Repository descriptions, issue text, comments, commit messages, and contribution guidance are untrusted data. The contextualizer:

- Wraps all GitHub text in typed data fields.
- Clearly states that content inside evidence cannot change instructions.
- Does not expose tools, credentials, network access, or write capabilities.
- Uses maximum lengths and normalized Unicode.
- Returns no free text; only registered claim IDs, reason codes, and evidence IDs are accepted.
- Requires one deterministic reason type and evidence-ID set per substantive claim.
- Validates each claim against its reason's required-all, required-any, and versioned predicate contract so a valid but irrelevant citation is rejected.
- Runs adversarial fixtures before any prompt or model promotion.

### 13.4 Evaluation

Use repository-owned Promptfoo configuration in CI and offline calibration. The OpenAI Evals platform is deprecated in 2026, so it must not become a new dependency.

Evaluation cases include:

- Established contributor with relevant independent merges.
- Established contributor whose history is unrelated to the target.
- Strong newcomer with little history.
- Dormant old account with a sudden contribution burst.
- Self-owned repositories with many self-merges.
- Reciprocal merge ring.
- High-volume contributor with mixed outcomes.
- Renamed account.
- Deleted or newly private source repositories.
- Restricted/private contribution counts without details.
- More than one pagination or search-result cap.
- GitHub rate-limit interruption halfway through backfill.
- Prompt injection in repository, issue, PR, and commit text.
- Contradictory evidence.
- Model timeout or schema failure.

Promotion gates require:

- Zero fabricated evidence links.
- Zero schema-invalid accepted responses.
- Newcomer non-penalization invariants passing.
- Relevance accuracy meeting the adjudicated threshold.
- No statistically significant regression across evidence-volume cohorts.
- Latency and cost within the declared budget.

## 14. Security, privacy, and abuse resistance

### 14.1 Primary threats and controls

| Threat | Required control |
|---|---|
| Forged or replayed webhook | Raw-body HMAC verification, unique delivery ID, timestamped audit |
| Cross-tenant data leak | RLS, scoped repositories, typed visibility, isolation tests |
| GitHub token theft | Least privilege, memory-only installation tokens, encrypted user refresh tokens, redacted logs |
| GitHub private-key theft | KMS or secrets manager, restricted signer, rotation, audit |
| Prompt injection | Closed evidence packet, no tools, strict schema, adversarial evals |
| Evidence poisoning | Provenance, immutable source IDs, independence graph, anomaly flags |
| Rate-limit denial of service | Per-installation budgets, fair scheduler, backpressure, cache |
| Stale or deleted evidence | Freshness labels, reconciliation, tombstones, correction flow |
| Account takeover | Recent-behavior anomaly and confidence reduction; never assume age proves control |
| Support-agent overreach | Just-in-time access, audited impersonation ban, field-level redaction |
| Supply-chain compromise | Lockfile policy, provenance, dependency scanning, signed build artifacts |

### 14.2 Privacy rules

- Collect only data needed for a documented assessment feature.
- Never enrich GitHub data with data-broker, social-network, employment, or inferred demographic data.
- Do not store rendered GitHub pages when normalized API facts are enough.
- Redact PR content and tokens from logs, traces, error reports, and model metadata.
- Expose source links only when the viewer is authorized for the underlying repository.
- Support tenant export and deletion.
- Publish a plain-language data dictionary and scoring methodology.
- Complete a privacy review and a data-protection impact assessment before broad availability.

### 14.3 Reputational safety

User-visible text reports evidence, not allegations. Integrity flags use neutral language and a manual-review recommendation. No public global score, contributor blacklist, or cross-customer private signal is permitted. Material methodology changes require versioning, shadow evaluation, release notes, and the ability to reproduce prior results.

## 15. Dashboard and GitHub UI

### 15.1 PR comment

The single, app-authored PR comment should fit the maintainer's immediate decision:

1. Evidence state and confidence.
2. Controlled reason templates for all six dimensions.
3. Key controlled caveat.
4. Patch-context facts.
5. Up to three unique public source links when evidence is available.
6. A trusted-origin link to full evidence.

The comment is created once and updated in place. Its structured input has no numeric score, free-form public copy, private link, or caller-provided report origin. A trusted marker context and stored comment ID prevent duplicates, and the renderer must stay within GitHub's content limits. The operational Check is also updated in place and links to the same detailed assessment.

### 15.2 Detailed assessment

The dashboard contains:

- Dimension cards with definitions and confidence.
- Evidence timeline.
- Relevant prior PRs and reviews.
- Independence and merge-attribution explanation.
- Coverage map by year and source.
- Patch-context card.
- Individually cited structured claims selected by the model from the immutable candidate packet and rendered with repository-owned copy in the authenticated detailed view.
- Version, freshness, and superseded-state metadata.
- Feedback and correction actions.

### 15.3 Policy editor

The policy editor supports:

- Publication mode: shadow mode publishes nothing; active mode always publishes the single PR comment and operational Check.
- History window and freshness requirements.
- Supported weighting presets.
- Review-priority thresholds.
- Patch-context risk paths.
- Optional event and permission features.
- Optional advisory review-priority thresholds, independent of the mandatory active-mode comment and operational Check.

Every change produces a new immutable policy version, validation preview, audit record, and estimated effect on recent assessments. Unsafe combinations are rejected.

### 15.4 Accessibility and localization

- Meet WCAG 2.2 AA.
- Full keyboard navigation and visible focus.
- Do not encode assessment states through color alone.
- Human-readable dates with exact UTC timestamps available.
- External evidence links announce repository visibility and destination.
- Keep system reason codes localization-safe from the start.

## 16. Reliability and observability

### 16.1 Initial service objectives

| Objective | Target |
|---|---:|
| Valid webhook acknowledgement | p95 under 2 seconds |
| Queued check visible after accepted webhook | p95 under 10 seconds |
| Reputation PR comment published after completed assessment | p95 under 15 seconds |
| Cached-evidence assessment completion | p95 under 60 seconds |
| Cold history assessment completion | p95 under 10 minutes |
| Assessment workflow success, excluding upstream outage | 99.9% |
| Completed comment visibly identifies its assessed head SHA | 100% |
| Detected stale publication generation reaches the repair queue | 100% |
| Cross-tenant or cross-repository private evidence incidents | 0 |
| Fabricated evidence citations accepted | 0 |

These targets become formal SLOs after load testing validates realistic baselines.

### 16.2 Telemetry

Collect:

- Webhook latency, validation failures, duplicates, and event lag.
- Outbox age and workflow queue depth.
- Workflow and activity retries by reason.
- GitHub request cost, remaining budget, secondary limits, and cache hit rate.
- Evidence coverage, freshness, truncation, and tombstones.
- Assessment latency by stage.
- Model latency, tokens, cost, cache behavior, schema failures, and fallback rate.
- PR-comment and Check publication lag, deduplication, and stale-head prevention.
- Feedback, corrections, overrides, and score drift.
- Tenant-isolation denials and privileged support access.

Use correlation IDs spanning GitHub delivery, workflow, assessment, model request, PR comment, and check run. Logs are structured and redacted.

### 16.3 Degraded modes

- **OpenAI unavailable:** publish deterministic dimensions and mark contextual explanation unavailable.
- **GitHub partially rate-limited:** continue from cached evidence with visible freshness, or keep the check queued according to policy.
- **Temporal unavailable at ingress:** retain the database outbox and reconcile later.
- **Database read-only incident:** acknowledge only if delivery durability is preserved; otherwise return a retryable error.
- **Incomplete history:** publish limited coverage, never fabricate completeness.
- **New head SHA:** advance the PR publication generation, mark the existing comment as refreshing, cancel or supersede old work, and repair any in-flight stale write.

Runbooks cover each mode, replay, key rotation, data restoration, and GitHub webhook redelivery.

## 17. Testing strategy

### 17.1 Test layers

- **Unit:** feature functions, time decay, Bayesian rates, policy validation, reason codes.
- **Property-based:** score invariants, time boundaries, missing-data behavior, idempotency.
- **Contract:** recorded GitHub GraphQL/REST fixtures and OpenAI schema responses.
- **Integration:** PostgreSQL RLS, migrations, outbox, Temporal activities, token refresh.
- **End-to-end:** dedicated GitHub organization, test app, PR lifecycle, reruns, superseding commits.
- **Load:** webhook bursts, high-history contributors, large installations, rate-limit pressure.
- **Security:** HMAC, replay, authz, IDOR, SSRF, injection, secret leakage, dependency and container scans.
- **Resilience:** GitHub, OpenAI, database, worker, and workflow fault injection.
- **Evaluation:** relevance, citation fidelity, newcomer treatment, anti-gaming, and explanation quality.
- **Accessibility:** automated checks plus keyboard and screen-reader review.

### 17.2 Test data

- Synthetic fixture generator for all scoring edge cases.
- Recorded, redacted GitHub responses with schema-version metadata.
- Public examples only when license and retention allow.
- Consented real-world calibration set.
- No production private-repository payloads in development or model evaluation.

### 17.3 Release gates

No production promotion unless:

- Formatting, linting, type checking, unit, integration, and contract tests pass.
- Database migration runs forward and rollback/recovery is documented.
- RLS isolation and authorization suites pass.
- Promptfoo quality and injection thresholds pass.
- A staging PR lifecycle completes against the real GitHub App.
- No critical or high unresolved security finding exists.
- Observability dashboards and rollback are ready.
- Feature and scoring versions are documented.
- Every shipped artifact has a verified SBOM, signature, and build provenance, and
  production promotion reuses those exact bytes.
- Temporal workflow histories replay against the candidate worker build before task
  queues are shifted.
- The signed worker image has an immutable Worker Deployment Version/build identity;
  staging records current and ramping assignments, pinning behavior, reachability,
  and the exact rollback target.
- Workers prove graceful drain under rolling deployment, forced termination, and
  Coolify host loss without duplicate GitHub writes or lost outbox work.

## 18. Delivery and CI/CD

### 18.1 Environments

- Local: fixture-first, local PostgreSQL and Temporal.
- Development: disposable preview deployments and synthetic GitHub payloads.
- Staging: separate GitHub App, OpenAI project, secrets, database, and test organization.
- Production: isolated accounts/projects, protected changes, backups, alerting, and least privilege.

Production data never flows down to lower environments.

### 18.2 Pipeline

For each pull request:

1. Verify generated schemas and migrations are committed.
2. Format, lint, and type-check.
3. Run unit, property, contract, integration, and RLS tests.
4. Run Promptfoo quality and injection suites.
5. Scan secrets, dependencies, source, IaC, and container images.
6. Build reproducible web and worker artifacts with an SBOM.
7. Deploy a preview where safe.

For a production release:

1. Apply backward-compatible schema expansion.
2. Deploy workers and web code in compatibility mode.
3. Run smoke and synthetic GitHub-App assessments.
4. Register the candidate Worker Deployment Version, replay retained histories, and
   move only a bounded percentage of new workflows to the ramping version.
5. Verify pinned workflows, reachability, activity heartbeats, and rollback by
   restoring the previous current/ramping assignment.
6. Drain the previous Coolify worker only when it is no longer reachable and the
   rollback window has closed.
7. Exercise host-loss recovery and outbox reconciliation before full promotion.
8. Monitor SLOs, score drift, model failures, and GitHub limits.
9. Complete data migration and later contract old schemas.

Infrastructure is defined in Terraform. Artifacts are immutable, signed, and promoted between environments rather than rebuilt.

## 19. Implementation phases

These phases deliver the final architecture incrementally. They are not permission to create throwaway shortcuts.

### Phase 0 — Product and architecture specification

Deliver:

- Product glossary and report contract.
- Data dictionary and visibility model.
- Scoring methodology draft.
- Threat model and privacy impact assessment.
- ADRs for workflow engine, database, deployment, model responsibilities, and identity.
- Immutable installation- and PR-node-bound assessment, template-only PR comment,
  typed provenance manifest, authoritative source partitions, typed pre/post/post-Check
  source-visibility validation, append-only publication and comment-removal event
  streams, a separate append-only terminal retention/deletion lifecycle, PR-scoped
  database-unique output cursor plus high-water record, PR output mutation leases,
  complete app-owned comment inventories,
  provider-observed comment ownership, terminal cleanup origin linkage, and
  database high-water records proving complete lifecycle prefixes.
- Executable dimension-scoring and coverage-confidence policies plus a registry of
  content-addressed policy, assessment/publication engine, evidence,
  feature-evaluator, scoring, prompt, model, schema, and self-contained replay-bundle
  artifacts, including the exact Node/V8/ICU runtime and the required OCI manifest
  and signature-bundle identities. Phase 1 promotion must replace the specification's
  `promotion_required` state with verified build provenance before deployment.
  Historical engines never import mutable root dependencies. Repository
  configuration is parsed as strict, alias-free YAML.
- Historical assessments resolve versions by effective interval and immutable
  artifact digest; retiring a version prevents new selection but does not invalidate
  a retained historical assessment.
- Provider requests use request-local commitments and aliases, bind exact invocation
  artifacts, and accept a response only through PostgreSQL-enforced unique
  request-alias, nonce, and response-ID receipts bound to its CAS ledger.
- Authenticated detailed reports use a trusted provider permission receipt,
  independent serializable dashboard-policy high-water proof, explicit trusted
  request time, a durable database-consumed session nonce, and an allowlisted projection; raw
  scores never enter the GitHub comment contract.
- Synthetic evaluation specifications plus negative contract mutations; copy expectations remain explicitly non-executed until their owning engine and renderer phases.

Exit gate:

- Every contributor judgment maps to named evidence, confidence, reason, owner, and
  test contracts; every operational Check outcome maps to an explicit
  state/conclusion contract; deterministic scores, states, confidence, coverage,
  version digests, transition legality, causal chronology, and fixture semantics
  are recomputed from the frozen examples; every schema and cross-field invariant
  passes the named positive and adversarial mutation suite.

### Phase 1 — Production foundation

Deliver:

- pnpm monorepo and package-boundary enforcement.
- Next.js control plane and containerized worker.
- PostgreSQL migrations, RLS, outbox, and audit primitives.
- Temporal development and production connectivity.
- OpenTelemetry instrumentation.
- Terraform environments and CI pipeline.

Exit gate:

- A synthetic delivery travels idempotently from ingress through a durable workflow to a persisted result under forced retries.

### Phase 2 — GitHub App and lifecycle

Deliver:

- GitHub App manifest and least-privilege permissions.
- Installation, repository, webhook, and token lifecycle.
- HMAC validation, delivery ledger, outbox relay, and reconciliation.
- Serialized single-comment create/update/recovery behavior, typed pre/post-write
  source and recursive-provenance revalidation, latest-generation and monotonic
  retention-revision fencing, authoritative PR cursor/high-water reads, exact comment
  ownership observations, complete-stream head validation, post-write race repair,
  completed-success/post-Check repair, bounded later-privatization
  reconciliation, and queued, completed, failed, rerun, and superseded Check
  behavior.
- Dedicated staging organization and fixture repositories.

Exit gate:

- Repeated, ambiguous, racing, and out-of-order GitHub deliveries converge to exactly one app-owned comment and one current Check for the correct head SHA.

### Phase 3 — Evidence platform

Deliver:

- GraphQL and REST adapters with versioned schemas.
- Per-installation rate scheduler.
- Multi-year collection and resumable pagination.
- Typed GitHub actors plus normalized evidence, coverage, provenance, visibility, and tombstones.
- Public cache and target-repository-private boundary.
- Refresh, reconciliation, correction, export, and deletion workflows.

Exit gate:

- Sparse, renamed, unsupported-actor, high-volume, private, truncated, and rate-limited accounts all produce honest coverage reports with no cross-tenant or cross-repository leakage.

### Phase 4 — Deterministic reputation engine

Deliver:

- Versioned feature vectors.
- Tenure, consistency, independence, merge, collaboration, and integrity functions.
- Implementations and property tests for every registered reason predicate.
- Confidence model and missing-data behavior.
- Policy presets and repository overrides.
- Historical replay and score-diff tooling.

Exit gate:

- All product invariants pass as property tests, and a scoring version can be replayed without changing historical snapshots.

### Phase 5 — Contextual relevance and claim selection

Deliver:

- Repository and contribution fingerprints.
- Candidate retrieval and evidence-packet builder.
- GPT-5.6 model router, strict tuple-selection schema, citation validator, and fallback.
- Prompt registry and Promptfoo evaluation suite.
- Cost, latency, and cache observability.

Exit gate:

- Promotion thresholds pass with zero accepted fabricated citations and no instruction-following from untrusted GitHub content.

### Phase 6 — Maintainer and contributor product

Deliver:

- Template-only PR-comment renderer, trusted marker and URL context, and explicit operational Check state machine.
- Dashboard authentication and GitHub authorization.
- Assessment detail, evidence timeline, coverage, policy editor, and audit log.
- Feedback, correction, refresh, and contributor-visibility flows.
- Accessible responsive interface.

Exit gate:

- Maintainers can trace every displayed conclusion to authorized evidence; contributors can challenge an incorrect fact without seeing private maintainer data.

### Phase 7 — Anti-gaming and calibration

Deliver:

- Independence graph and self-merge attribution.
- Burst, repetition, reciprocal-cluster, and behavior-change features.
- Human adjudication tools and documented labeling guide.
- Threshold calibration, cohort analysis, score-drift monitoring, and shadow comparisons.

Exit gate:

- Known gaming fixtures trigger manual-inspection reason codes without falsely converting sparse or newcomer evidence into a negative judgment.

### Phase 8 — Enterprise privacy and operations

Deliver:

- SSO-ready tenant model and role administration.
- Configurable retention, export, deletion, and legal workflows.
- KMS-backed keys, rotation, just-in-time support access, and security alerts.
- Backup restoration, regional recovery, incident runbooks, and SLO dashboards.
- Penetration test and external privacy/security review.

Exit gate:

- Restore, deletion, key rotation, tenant isolation, and upstream-outage exercises pass in staging.

### Phase 9 — Organization-scale workflows

Deliver:

- Cross-repository review queue.
- Policy inheritance and exceptions.
- Preflight assessment for contributors before submission.
- Supported exports and API/webhook integrations.
- Installation-wide backfill and policy-impact simulation.

Exit gate:

- A large synthetic organization can operate within bounded GitHub and OpenAI budgets without starving small installations.

### Phase 10 — Broad-availability readiness

Deliver:

- Shadow pilots with diverse open-source maintainers.
- Published methodology, data dictionary, limitations, and status page.
- Support, incident, correction, and abuse-response procedures.
- Capacity model, cost controls, billing hooks, and service limits.
- Final security, reliability, accessibility, and legal reviews.

Exit gate:

- Pilot evidence shows meaningful review-time improvement without unacceptable newcomer, privacy, citation, or reliability regressions.

## 20. Critical path

~~~mermaid
flowchart LR
    A["Contracts, privacy, and threat model"] --> B["Durable platform foundation"]
    B --> C["GitHub App lifecycle"]
    C --> D["Evidence platform"]
    D --> E["Deterministic reputation engine"]
    E --> F["Contextual relevance"]
    E --> G["PR comment, GitHub Check, and dashboard"]
    F --> G
    G --> H["Anti-gaming and calibration"]
    H --> I["Enterprise operations"]
    I --> J["Organization workflows and broad availability"]
~~~

The UI can progress against stable fixtures while evidence collection is built, and evaluation cases can be written alongside every feature. Scoring must not be finalized before real coverage behavior is understood.

## 21. Requirement traceability for review

| Product requirement | Owning modules | Required evidence |
|---|---|---|
| Account age without age-based trust | github, evidence, reputation | Capped tenure tests and newcomer invariants |
| Open-source contribution history | github, evidence | Multi-year fixtures and coverage reports |
| Regularity over time | reputation | Clock-controlled feature and property tests |
| Successfully merged PRs | github, evidence, reputation | Merge actor and independence fixtures |
| Collaboration history | evidence, reputation | Review-and-revision lifecycle tests |
| Repository relevance | evidence, contextualizer | Adjudicated Promptfoo cases with citations |
| Gaming resistance | reputation | Self-merge, burst, reciprocal, and takeover fixtures |
| Explainability | domain, github-output, web | Evidence-link validation and UI trace |
| Newcomer protection | reputation, policy | Sparse-history regression suite |
| Private-repository isolation | db, domain, github | RLS and cross-tenant integration tests |
| Unsupported GitHub actors | github, evidence, reputation | Actor-interface fixtures and explicit limited-coverage output |
| Template-only public PR comment | github-output, domain | Rejection of numeric/free-form fields, private links, projection drift, target mismatch, and stale sources |
| Secondary code context | github, github-output | CI, scope, linked-issue, and risk-path fixtures |
| Correct current PR result | workflows, github-output | Out-of-order, duplicate-comment, and stale-head end-to-end tests |

Codex reviews should use this table to connect a submission's claims to code, tests, and observable behavior. A feature is not complete because a UI element exists; its evidence path, failure behavior, and acceptance gate must also exist.

## 22. Definition of done

The long-term implementation is complete when:

- A production GitHub App handles installation, revocation, repository selection, permissions, webhook replay, and key rotation safely.
- Contributor history collection is resumable, rate-aware, visibility-aware, and explicit about coverage.
- Reputation dimensions are deterministic, documented, versioned, calibrated, and reproducible.
- Sparse evidence never becomes a negative score by default.
- Independent validation, self-merges, and gaming patterns are distinguishable.
- GPT-5.6 contextual output contains exact structured claim tuples only, is evidence-group-valid and injection-tested, and is optional during failure; it cannot contain prose.
- PR comments visibly name the assessed SHA; head, latest-generation, retention, and pre/post-write source-set fencing detect stale writes and deterministically repair them, while Checks converge to the current head.
- The dashboard supports authorized evidence inspection, policy versioning, feedback, correction, export, and deletion.
- Target-repository-private evidence cannot cross repository or tenant boundaries in application or database tests.
- CI, staging, observability, backups, recovery, incident response, and security review meet release gates.
- Documentation accurately separates shipped behavior from planned behavior.
- Pilot maintainers demonstrate reduced triage time without unacceptable newcomer or false-confidence regressions.

## 23. Confirmed product and deployment decisions

These decisions were confirmed on July 21, 2026. A later change requires an ADR and migration plan.

| Decision | Confirmed choice | Rationale |
|---|---|---|
| GitHub reputation surface | One app-authored PR comment, updated in place | Puts the evidence where maintainers and contributors already collaborate |
| Public contributor profile | Disabled | Avoids creating a global ranking product |
| GitHub presentation | Descriptive dimensions plus confidence; no raw numeric scores | More honest than one opaque number |
| Detailed presentation | Raw numeric scores available to authorized maintainers | Supports calibration and debugging without making the number the product |
| Review-priority tier | Advisory and opt-in | Keeps maintainers in control |
| Private repository support | Architect and test from the start | Retrofitting tenant boundaries is unsafe |
| Private evidence reuse | Same target repository only | Prevents cross-repository collaborator leakage |
| Model role | Exact relevance-claim selection only | Keeps facts, copy, and scoring reproducible |
| Workflow platform | Temporal | Durable retries, long backfills, and recovery |
| Web deployment | Kontext team on Vercel | Uses the existing team and keeps the Next.js control plane stateless |
| Worker deployment | Existing Coolify server | Keeps Temporal workers and the outbox relay off request handlers |
| Initial history window | Up to five years with explicit coverage | Balances relevance, completeness, and API cost |
| Raw webhook retention | Seven days | Supports incident recovery while limiting sensitive data |

## 24. Principal risks

| Risk | Mitigation |
|---|---|
| Public GitHub history is incomplete or attribution is wrong | Coverage model, source links, correction flow, confidence separation |
| Reputation disadvantages new contributors | Limited-evidence state, patch separation, invariants, cohort evaluation |
| Maintainers over-trust a concise PR comment | Dimensions first, explicit caveats, no merge authority, policy education |
| Scores become a game target | Versioned multidimensional evidence, independence graph, capped volume, anomaly monitoring |
| API limits make deep history slow | Resumable collection, caches, fair scheduling, bounded windows, visible partial results |
| LLM selects an invalid claim | Closed packet, exact-tuple schema, evidence validation, deterministic fallback |
| Private data leaks between customers | Visibility types, separate schemas, RLS, authz and isolation tests |
| Methodology drifts without accountability | Immutable versions, shadow mode, replay, release notes, historical preservation |
| Architecture becomes too complex early | Modular monolith plus one worker deployment; split services only at measured boundaries |
| Legal or reputational harm | Neutral evidence language, no public leaderboard, appeal/correction, privacy and legal review |

## 25. Authoritative references

GitHub:

- [Registering a GitHub App](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app)
- [Choosing permissions for a GitHub App](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app)
- [GitHub GraphQL User reference](https://docs.github.com/en/graphql/reference/users)
- [GitHub GraphQL Actor interface](https://docs.github.com/en/graphql/reference/interfaces#actor)
- [GitHub Checks API](https://docs.github.com/en/rest/checks/runs)
- [GitHub issue and pull-request comments API](https://docs.github.com/en/rest/issues/comments)
- [Webhook best practices](https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks)
- [GraphQL rate and query limits](https://docs.github.com/en/graphql/overview/rate-limits-and-query-limits-for-the-graphql-api)
- [REST Events API limitations](https://docs.github.com/en/rest/activity/events)
- [Managing GitHub App private keys](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/managing-private-keys-for-github-apps)

OpenAI:

- [GPT-5.6 model guidance](https://developers.openai.com/api/docs/guides/model-guidance?model=gpt-5.6)
- [Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs)
- [Prompt caching](https://developers.openai.com/api/docs/guides/prompt-caching)
- [Data controls](https://developers.openai.com/api/docs/guides/your-data)
- [Safety checks](https://developers.openai.com/api/docs/guides/safety-checks)
- [Evals platform deprecation](https://developers.openai.com/api/docs/deprecations#2026-06-03-evals-platform)
- [Moving from OpenAI Evals to Promptfoo](https://developers.openai.com/cookbook/examples/evaluation/moving-from-openai-evals-to-promptfoo)

Platform:

- [Next.js App Router](https://nextjs.org/docs/app)
- [Next.js backend-for-frontend guidance](https://nextjs.org/docs/app/guides/backend-for-frontend)
- [Temporal documentation](https://docs.temporal.io/)
- [PostgreSQL row security policies](https://www.postgresql.org/docs/17/ddl-rowsecurity.html)

## 26. Immediate starting sequence

1. Record the confirmed product and deployment decisions as ADRs.
2. Create the product glossary, report JSON Schema, evidence taxonomy, and reason-code registry.
3. Create synthetic cases for newcomers, established contributors, self-merges, reciprocal activity, sparse data, and prompt injection.
4. Scaffold the monorepo and enforce package boundaries.
5. Implement the database inbox/outbox, RLS skeleton, and durable synthetic workflow.
6. Register separate development and staging GitHub Apps with the minimum permissions.
7. Build the typed GitHub adapter and evidence coverage model before implementing scoring.
8. Implement deterministic dimensions with property tests before adding GPT-5.6 explanations.
9. Run the complete staging PR lifecycle and expose evidence traceability in the first usable PR comment and operational GitHub Check.

This ordering makes the hardest long-term properties—evidence provenance, missing-data honesty, tenant isolation, idempotency, and reproducibility—part of the foundation rather than later retrofits.
