# MergeSignal

**Trust for every pull request.**

MergeSignal is a GitHub-native contributor and pull-request rating system for maintainers. It uses evidence from the current patch, repository context, and public contribution history to help maintainers prioritize credible work and filter low-quality, mass-produced PR spam.

## Why

AI coding agents have made it dramatically easier to submit a pull request, but they have not reduced the cost of reviewing one. Maintainers increasingly receive polished-looking changes that ignore project architecture, duplicate existing work, fail basic tests, or show little understanding of the repository.

Existing reputation signals such as follower counts, account age, and total contributions are too shallow. MergeSignal is designed to answer a narrower and more useful question:

> Should a maintainer spend time reviewing this contributor's pull request for this repository?

## What it will evaluate

MergeSignal keeps the patch and the contributor separate:

- **Patch quality:** test results, scope, issue alignment, repository conventions, risk, and demonstrated understanding.
- **Contributor fit:** relevant public contributions, review behavior, responsiveness, and experience related to the repository.
- **Confidence:** how much evidence is available and where the system remains uncertain.

The result is an evidence-backed signal with concise reasoning and links to its sources—not an unexplained global reputation score.

## Principles

- **Evaluate quality, not AI authorship.** Responsible AI-assisted work should be judged by the same standards as any other contribution.
- **Do not punish newcomers.** Limited history means insufficient evidence, not low trust; a strong current patch can still earn a strong signal.
- **Keep maintainers in control.** MergeSignal assists triage and never makes merge decisions.
- **Make every signal inspectable.** Findings should include confidence, reasoning, and supporting evidence.
- **Use only appropriate GitHub data.** The initial version focuses on repository context and public contribution evidence.

## Planned workflow

1. A GitHub App receives a pull-request webhook.
2. Deterministic checks inspect the diff, tests, linked issue, and repository instructions.
3. Relevant public contribution evidence is collected from GitHub.
4. GPT-5.6 evaluates the evidence against a repository-specific rubric.
5. MergeSignal publishes an explainable GitHub Check for maintainers.

## Planned stack

- TypeScript, Next.js, and React
- GitHub Apps, webhooks, Checks, and Octokit
- OpenAI Responses API with GPT-5.6
- PostgreSQL, Drizzle ORM, and Zod
- Vercel, Vitest, and Playwright
- Codex for implementation, testing, review, and iteration

## Project timeline

- **July 15, 2026:** Initial idea and product direction developed during OpenAI Build Week.
- **July 21, 2026:** Public repository created and implementation started.

## Status

MergeSignal is an early OpenAI Build Week prototype. The first milestone is an end-to-end GitHub App that analyzes a real pull request and publishes a transparent, evidence-linked Check.

