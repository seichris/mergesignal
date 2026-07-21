# MergeSignal

**Contributor reputation for every pull request.**

AI agents can create plausible pull requests much faster than maintainers can verify them. The scarce resource is no longer code generation; it is informed human review. MergeSignal helps a maintainer answer a narrower question before spending that time:

> What does the submitting GitHub actor's history tell us, how complete is that evidence, and which parts are relevant here?

## Product direction

MergeSignal is a GitHub App centered on contributor reputation, not another general code-review bot. It evaluates:

- Sustained public open-source activity over time.
- Pull requests merged by independent maintainers.
- Follow-through after reviews and contributions to other people's reviews.
- Experience relevant to the target repository.
- Evidence coverage, attribution quality, freshness, and possible gaming patterns.

Patch context stays separate and deliberately small: current-head CI, scope, linked issues, changed tests, and configured sensitive paths. Existing CI, security tools, repository review agents, and maintainers continue to own code correctness.

## GitHub experience

After analysis completes, the MVP creates one PR conversation comment and updates
it in place. The comment shows a deterministic `0-100` public GitHub history score,
its descriptive band, evidence confidence, account age, 24-month contribution
volume, active weeks, independently merged PR history, and repository breadth.
It contains no private evidence and clearly states that reputation is not a code,
security, identity, or trust verdict.

An operational GitHub Check shows queued, successful, failed, or superseded lifecycle state. Reputation itself never becomes a failing CI conclusion.

## Principles

- Limited history means limited evidence, not low trust.
- Account age is weak and cannot outweigh sustained independent validation.
- Private evidence is restricted to the exact target repository.
- GitHub facts, relevance candidates, scores, states, and confidence are deterministic.
- A model may select exact structured claim tuples only from a closed public-evidence packet. Stable GitHub target and evidence identifiers stay local behind per-request HMAC aliases, provider output is bound to an exact request/response receipt, private-dependent candidates fall back deterministically, and repository-owned renderers supply all explanatory prose.
- Reputation cannot make failing CI or a sensitive patch safe.
- MergeSignal never merges, rejects, closes, or silently deprioritizes a PR.

## Reference architecture

- TypeScript pnpm monorepo with Next.js on the Kontext Vercel team.
- Long-lived Temporal workers and outbox relay on the existing Coolify server.
- Temporal Cloud and managed PostgreSQL with row-level security.
- GitHub App webhooks, GraphQL/REST evidence adapters, PR comments, and Checks.
- A future OpenAI integration remains outside the MVP; current scoring and copy are
  fully deterministic.

The immediately shippable product is defined in
[docs/MVP_IMPLEMENTATION_PLAN.md](docs/MVP_IMPLEMENTATION_PLAN.md). The complete
long-term design, phase gates, contracts, threat model, privacy analysis, and review
traceability remain in [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md).

## Current status

The MVP reputation path is implemented locally. It includes validated public-history
GraphQL collection, versioned deterministic scoring, six-hour snapshot caching,
immutable tenant-isolated assessments, durable Temporal retries, one app-owned PR
comment, operational Checks, and head-race repair. Unit, contract, build, fresh
PostgreSQL/Temporal integration, and production worker-image gates pass. A real
GitHub App installation and staging pull request remain the final live-release gate.
