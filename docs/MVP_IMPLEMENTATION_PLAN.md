# MergeSignal MVP implementation plan

> Status: implemented and verified locally; live release gate pending
>
> Goal: when a human GitHub user opens a pull request, MergeSignal posts one
> app-owned PR comment containing a transparent score derived from that user's
> observable public GitHub history.

## 1. MVP outcome

For every supported pull request, MergeSignal will:

1. identify the GitHub account that opened the pull request;
2. collect a bounded snapshot of its public GitHub history;
3. calculate a deterministic `0-100` GitHub history score;
4. explain the score with the underlying public metrics;
5. create one PR comment, then update that same comment on reruns; and
6. complete an operational GitHub Check without blocking merge.

This MVP answers one question:

> How much verifiable public GitHub history does this contributor have?

It does **not** decide whether the code is correct, safe, or appropriate. A low
score can mean that little public history is available. It must never be described
as evidence that the contributor is malicious or that the pull request is bad.

## 2. Scope

### Included

- Human GitHub accounts that open pull requests.
- Account age.
- Public contribution volume over the previous 24 months.
- Activity regularity over the previous 24 months.
- Public pull requests merged into repositories not owned by the contributor.
- Observed merge ratio for external, closed pull requests.
- Breadth across public repositories.
- A deterministic numeric score, descriptive band, and evidence-confidence label.
- One persistent PR comment owned by the GitHub App.
- Refresh on relevant pull-request events and a six-hour contributor-snapshot cache.
- Existing webhook verification, durable Temporal processing, PostgreSQL storage,
  comment reconciliation, head-SHA fencing, and operational Checks.

### Explicitly excluded

- Code review, code-quality scoring, vulnerability analysis, or merge decisions.
- LLM calls or OpenAI integration.
- A dashboard, login flow, policy editor, billing, or organization-wide queue.
- Private contribution history outside the repository receiving the pull request.
- Followers, stars, employer, profile text, location, social accounts, or popularity.
- A public contributor leaderboard or searchable reputation profile.
- Automatic labels, reviewer assignment, PR closure, rejection, or prioritization.
- Complex anti-gaming detection and statistical calibration.

The long-term architecture remains documented in `IMPLEMENTATION_PLAN.md`. This
file is the implementation authority for the MVP.

## 3. Product contract

### 3.1 Supported actors

The MVP scores only a webhook author whose GitHub actor type is `User`.

- `Bot`, `Organization`, deleted, or missing authors receive a short
  "not evaluated" comment instead of a numeric score.
- If GitHub returns no public user record, the comment reports that the score is
  unavailable and does not substitute a zero.
- A username change must not create a new identity. Cache and persistence keys use
  the stable GitHub node ID; the current login is display data.

### 3.2 Trigger behavior

Run or refresh the assessment for these `pull_request` actions:

- `opened`
- `reopened`
- `ready_for_review`
- `synchronize`

For `synchronize`, reuse a snapshot collected within the previous six hours. The
existing publication generation still advances so the comment and Check remain
bound to the current head SHA. Ignore closed PRs and unsupported actions.

### 3.3 PR comment

The completed comment should look like this:

```markdown
## MergeSignal contributor history

**@octocat — 72/100 · Substantial public history**

| Signal | Public history observed |
| --- | ---: |
| Account age | 6 years |
| Contributions | 684 in the last 24 months |
| Active weeks | 71 of 104 |
| External pull requests | 24 merged of 31 closed observed |
| Repository breadth | 12 public repositories |

**Evidence confidence:** High

This score summarizes observable public GitHub history. It is not a code-quality,
security, identity, or trust verdict, and it should not replace review of this PR.

Scoring version `mvp-v1` · Assessed for `abc1234`
```

The existing hidden ownership marker follows the visible body. The app creates at
most one marker comment per PR and updates it in place. The comment contains no
private evidence and no link to an unfinished dashboard.

### 3.4 Descriptive bands

| Score | Display band |
| ---: | --- |
| 80-100 | Extensive public history |
| 60-79 | Substantial public history |
| 40-59 | Moderate public history |
| 20-39 | Emerging public history |
| 0-19 | Limited observable public history |

These bands describe the amount and strength of observable history, not personal
trustworthiness.

### 3.5 Evidence confidence

Confidence describes coverage separately from the score:

- **High:** at least 26 active weeks, at least 10 observed external closed PRs,
  and no pagination truncation.
- **Medium:** at least 8 active weeks, at least 3 observed external closed PRs,
  and no pagination truncation.
- **Limited:** everything else, including young or mostly private accounts.

API errors, inaccessible data, or an invalid response produce `unavailable`, never
a fabricated score.

## 4. Data collection

### 4.1 Provider query

Use the existing GitHub App installation token with GitHub's GraphQL API. Before
building the adapter, run one real-installation probe proving that the token can
read a pull-request author's public `User` record and contribution collection.
This is the first gate because an installation token is scoped by the App's granted
access and permissions.

Query the contributor by the webhook's stable node ID. Require the returned node
to be a `User`; treat its current login as display data. Collect:

- `id`, `login`, and `createdAt`;
- two adjacent contribution windows of at most 12 months each;
- bounded public commit-contribution days and public pull-request dates for
  active-week calculation;
- total public commit, issue, pull-request, and pull-request-review contributions;
- public pull-request contribution nodes, including repository owner, state,
  `merged`, and merge time; and
- enough repository identity to count distinct public repositories.

GitHub's contribution collection is queried in two windows because the MVP covers
24 months while each request remains bounded to one year. Page pull-request
contributions up to 200 nodes total and commit days from the ten most active public
repositories. If either source exceeds its MVP cap, set `truncated = true`, retain
the observed values, and lower confidence to `Limited`.

Only public, attributable facts enter the score. Restricted/private contribution
counts may be recorded as an aggregate coverage caveat but must not increase or
decrease the score.

### 4.2 Normalized metrics

The provider adapter returns this conceptual shape:

```ts
interface PublicContributorHistory {
  actorNodeId: string;
  login: string;
  accountCreatedAt: string;
  observedFrom: string;
  observedUntil: string;
  accountAgeDays: number;
  commits: number;
  issues: number;
  pullRequests: number;
  pullRequestReviews: number;
  activeWeeks: number;
  externalPullRequestsObserved: number;
  externalClosedPullRequests: number;
  externalMergedPullRequests: number;
  distinctPublicRepositories: number;
  restrictedContributions: number;
  truncated: boolean;
}
```

The adapter validates all responses with Zod, rejects identity mismatches, clamps
impossible provider counts, and never passes repository text, bios, issue bodies,
PR bodies, or commit messages into the scoring package.

### 4.3 Rate limits and cache

- Cache normalized contributor snapshots per tenant and actor node ID for six hours.
- Reuse the cache across PRs and repositories within the same installation tenant.
- Store the provider observation time and rate-limit metadata.
- Respect primary and secondary rate-limit responses using Temporal retries and the
  provider's reset or retry-after value.
- Do not retry permanent `NOT_FOUND`, actor-type, identity, or schema failures.

## 5. Deterministic scoring version `mvp-v1`

All inputs are the normalized metrics above. Each component is independently
clamped to its maximum and the final result is rounded to the nearest integer.

### 5.1 Components

#### Account maturity: 15 points

```text
15 × min(account_age_days / 1095, 1)
```

The component reaches its cap after three years. Age is deliberately a small
component and cannot outweigh contribution history.

#### Public contribution activity: 20 points

```text
weighted_activity = commits + issues + (3 × pull_requests) + (2 × reviews)
20 × min(log1p(weighted_activity) / log1p(500), 1)
```

The logarithm prevents extremely active accounts from dominating the result.

#### Regularity: 20 points

```text
20 × min(active_weeks / 52, 1)
```

`active_weeks` is counted across the 104-week observation window. Scattered bursts
therefore contribute less than sustained activity.

#### Independently merged pull requests: 35 points

```text
merge_volume = 25 × min(log1p(external_merged_prs) / log1p(25), 1)
sample_weight = min(external_closed_prs / 5, 1)
merge_ratio = external_merged_prs / max(external_closed_prs, 1)
merge_quality = 10 × merge_ratio × sample_weight
merged_pr_score = merge_volume + merge_quality
```

Only public PRs into repositories whose owner login differs from the contributor
login count here. The sample weight prevents one merged PR from appearing equivalent
to a long record. An unmerged PR is not labeled a failure; it only affects the
aggregate observed ratio.

#### Repository breadth: 10 points

```text
10 × min(distinct_public_repositories / 5, 1)
```

### 5.2 Required properties

The scoring package must prove with unit and property tests that:

- identical normalized inputs always produce identical output;
- every component and final score remain within their documented bounds;
- increasing a positive metric cannot lower the score;
- private/restricted contribution counts never change the score;
- followers, stars, names, employers, and profile text are not accepted inputs;
- missing or invalid required metrics return `unavailable`, not zero; and
- scoring version `mvp-v1` is stored with every assessment and shown in the comment.

## 6. Persistence

Add migration `0003_mvp_reputation.sql` with two tenant-isolated tables.

### `app.contributor_history_snapshots`

- immutable snapshot ID and tenant ID;
- stable actor node ID and observed login;
- observation window and collection time;
- normalized public metrics as typed columns;
- truncation and coverage status;
- provider response digest, not the raw provider response;
- cache expiry; and
- uniqueness suitable for safe concurrent cache insertion.

### `app.pr_reputation_assessments`

- immutable assessment ID and tenant ID;
- pull request, publication generation, head SHA, and author identity;
- source snapshot ID;
- component scores, final score, band, and confidence;
- scoring version and calculation time; and
- a unique constraint on the GitHub publication so retries converge on one result.

Apply RLS and the existing worker/support grants. Do not persist access tokens, raw
GraphQL responses, profile text, or private contribution details.

## 7. Code changes

### 7.1 `packages/github`

- Add a validated GraphQL request method to `GitHubAppClient`.
- Add the public-contributor-history query and bounded pagination.
- Capture the webhook author's actor type.
- Surface typed rate-limit, unavailable-user, and identity-mismatch errors.
- Add fixture tests for normal, sparse, renamed, truncated, bot, missing, malformed,
  rate-limited, and restricted-contribution responses.

### 7.2 New `packages/reputation`

- Define the normalized metric and result schemas.
- Implement the pure `mvp-v1` component functions and final score.
- Implement band and confidence derivation.
- Render no Markdown and perform no network or database access.

### 7.3 `packages/database`

- Add migration `0003_mvp_reputation.sql` and Kysely table types.
- Add cache lookup/insertion helpers.
- Add idempotent assessment persistence bound to publication, generation, head SHA,
  and author node ID.
- Include the immutable assessment in the publication claim.

### 7.4 `packages/workflows` and `apps/worker`

Insert one durable activity before publication:

```text
accept delivery
  -> apply PR lifecycle event
  -> load cached history or collect public history
  -> calculate and persist assessment
  -> publish/update PR comment and Check
  -> complete delivery
```

The collection activity may retry. The deterministic calculation and idempotent
database write must safely repeat. Publication must never run without either a
completed assessment or an explicit `not_evaluated`/`unavailable` result.

### 7.5 `packages/github-output`

- Replace the Phase 2 placeholder renderer with a typed reputation renderer.
- Escape the login and every rendered value.
- Show score, band, metrics, confidence, disclaimer, scoring version, and short head
  SHA.
- Remove the dead detailed-report link.
- Preserve existing marker ownership, single-comment reconciliation, Check behavior,
  and head-race repair.

## 8. Implementation sequence

### Block A — Lock the provider and score contract

- [ ] Run the real-installation GraphQL access probe.
- [x] Add normalized input/output schemas and frozen fixtures.
- [x] Implement and test `mvp-v1` scoring.
- [x] Freeze the exact Markdown output with snapshot tests.

Gate: representative accounts produce explainable, reproducible results locally.

### Block B — Collect and persist public history

- [x] Add GraphQL support and contributor-history adapter.
- [x] Add migration `0003_mvp_reputation.sql` and database helpers.
- [x] Implement six-hour cache and bounded pagination.
- [x] Cover sparse, renamed, bot, missing, truncated, and rate-limited accounts.

Gate: a worker activity can persist one normalized contributor snapshot and one
idempotent PR assessment using a real GitHub installation token.

### Block C — Publish the reputation comment

- [x] Add the assessment activity to the Temporal workflow.
- [x] Join the assessment into the publication claim.
- [x] Replace the placeholder with the completed MVP comment.
- [x] Preserve one-comment behavior across retries, reruns, and head changes.
- [x] Ensure unsupported/unavailable actors get honest non-numeric output.

Gate: the Phase 2 integration test is extended so duplicate and racing deliveries
still converge on one current comment containing the expected score.

### Block D — Verify and ship

- [x] Add an end-to-end fixture covering webhook to persisted assessment to comment.
- [x] Run full typecheck, unit tests, integration tests, build, and worker image smoke.
- [x] Perform one normal review/fix loop; do not run a deep review loop.
- [ ] Deploy the web app, database migration, and worker.
- [ ] Open a PR from a test contributor in the staging repository.
- [ ] Verify the live comment, current-head Check, rerun behavior, and logs.
- [x] Update `README.md` with the shipped MVP behavior and limitations.

Gate: a real PR receives exactly one accurate reputation comment without any manual
database or GitHub intervention.

## 9. MVP acceptance criteria

The MVP is complete only when all of the following are true:

1. A real human-authored PR receives one comment containing a `0-100` score.
2. The comment displays account age, contribution volume, active weeks, external
   merged/closed PRs, repository breadth, confidence, and the safety disclaimer.
3. A duplicate webhook or Temporal retry does not create another assessment or
   comment.
4. A new head updates the existing comment and completes the Check for that head.
5. Bot, missing, inaccessible, and malformed accounts never receive a fabricated
   numeric score.
6. Restricted/private contribution counts do not affect the score or leak details.
7. Score calculation is deterministic, versioned, bounded, and fully unit-tested.
8. GitHub rate limiting causes a durable retry or an honest unavailable result.
9. Full repository CI and the production worker image pass.
10. The behavior is verified on a real staging pull request.

## 10. Deferred immediately after MVP

Once the MVP is live and producing real examples, use observed data to decide
whether the score formula needs calibration. The first follow-ups should be:

1. gather maintainer feedback on whether each displayed signal is useful;
2. test the score against a hand-labeled set of established contributors and
   newcomers;
3. add same-repository and language relevance only if it materially improves review;
4. add contributor correction/refresh controls; and
5. decide whether the numeric score should remain public after real-world feedback.

None of these follow-ups blocks shipping the MVP defined above.
