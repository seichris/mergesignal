# Data protection impact assessment

> Status: Phase 0 engineering draft
>
> This document requires qualified legal and privacy review before broad availability.

## Processing purpose

MergeSignal processes GitHub activity to help repository maintainers prioritize pull-request review. The purpose is narrow: present evidence about the submitting account's public contribution history and the current repository context.

The product must not repurpose this data for employment screening, public ranking, advertising, identity enrichment, or unrelated profiling.

## Data subjects

- Pull-request contributors.
- Maintainers and reviewers.
- GitHub App installers and dashboard users.
- Public actors who reviewed or merged cited contributions.

## Data categories

### Public GitHub evidence

- GitHub node ID and login aliases.
- GitHub actor implementation type; unsupported actors are not coerced into user identities.
- Account creation date.
- Public pull requests and outcomes.
- Public review and merge actors.
- Public repository languages, topics, paths, and dependency ecosystems. Contributor
  language relevance is derived only from head-bound changed paths; repository-wide
  language metadata is not attributed to the person.
- Public contribution timestamps.

### Public derived evidence

- Activity continuity and recent-baseline comparisons.
- Independence and repository-relationship classifications.
- Technical similarity, template similarity, and reciprocal-relationship features.
- Coverage summaries emitted as versioned collection-run results over accessible
  public sources.

These are MergeSignal results, not GitHub-authored facts. True derivations are
versioned and linked to complete source provenance. Coverage summaries instead bind
to a versioned collection run that owns typed query partitions, exact boundaries,
provider totals, page completion, candidate IDs and digests, partial-source labels,
and calculated complete years, freshness, attribution, and confidence. The partition
set must exactly implement the registered singleton and year-granular query plan.
Both are labeled `PUBLIC_DERIVED`
at the product surface and are subject to correction and deletion handling.

### Target-repository evidence

- Current PR metadata, changed paths, CI state, linked issue, and review lifecycle.
- Private target-repository facts only when the app is installed and authorized.

### Operational data

- Installation, repository, delivery, workflow, audit, rate-limit, and error metadata.
- Encrypted GitHub user refresh credentials for dashboard authorization.
- Model request metadata with redaction.

### Deliberately excluded

- Followers as reputation.
- Employer, biography, location, avatar, email, and social links.
- Protected or demographic attributes and proxies.
- Comment sentiment, personality, or writing quality.
- Off-GitHub enrichment and data-broker information.
- AI-authorship inference.

## Necessity and proportionality

| Processing | Necessity | Minimization |
|---|---|---|
| Account creation date | Weak tenure context | Capped low-weight feature |
| Public PR outcomes | Evidence of independent acceptance | Store normalized facts and source IDs |
| Review actions | Evidence of follow-through | Use structured actions, not prose sentiment |
| Repository metadata | Repository-specific relevance | Retrieve bounded candidate set |
| Model contextualization | Exact relevance-claim tuple selection | Closed normalized packet, no raw private code or prose |
| PR comment | Puts evidence in the review workflow | Descriptive states, no raw scores |
| Detailed dashboard | Supports audit and correction | Current GitHub authorization required |

## Visibility impact

The confirmed default posts the reputation summary as a PR comment:

- On a public repository, the comment is public and indexed according to GitHub behavior.
- On a private repository, repository-authorized users can see it.
- On an internal repository, GitHub-authorized enterprise members may see it; MergeSignal treats all target facts as restricted rather than public-global.
- The comment contains only public evidence plus facts from the target private repository.
- Private evidence from another repository never appears in the comment.
- Target-repository-private evidence can influence only an assessment for that exact repository, even when another repository belongs to the same tenant.
- Provider model requests contain no stable GitHub installation, repository, PR,
  PR-number, head, or internal evidence identifiers. Those bindings and the exact
  alias map remain in a local digested envelope. Stable population digests also stay
  local; the provider sees only request/nonce-bound aliases, request-local HMAC
  population commitments, bounded sanitized technical context, and a pseudonymous
  safety identifier. Provider output is accepted only through a single-use CAS
  ledger and a digested receipt binding the exact invocation, response ID, and
  output.
- Candidates that depend on target-repository-private evidence are excluded from
  provider model requests by default and use deterministic fallback rendering.
- Direct evidence links in comments must still point to currently public GitHub sources; target-private facts are summarized without private source links.
- Raw numeric scores are restricted to authorized maintainers in the detailed view.
- Detailed reports require a fresh provider permission check, the independent
  repository-policy high-water state, a short authorization interval, and an
  allowlisted projection. The raw assessment is never serialized directly.

Because public comments can affect reputation, wording is factual, neutral, and contestable. There is no separate global profile, leaderboard, or blacklist.
All explanation prose comes from reviewed reason and caveat templates. For public-only candidates, the model can only select individually cited structured claims from a content-addressed deterministic candidate packet; it cannot author text on the public or authenticated surface.

## Lawful basis and notice

The appropriate lawful basis depends on operator jurisdiction, customer type, and deployment. It must be confirmed by counsel before broad availability.

The short-lived comment-removal audit is limited to security, deletion
verification, and dispute handling. The operator must document the applicable
basis and balancing test before production; the contract does not treat a request
identifier or provider response as permission to retain free-form content.

Required notices:

- GitHub App privacy policy.
- Plain-language explanation in every PR comment.
- Public data dictionary and methodology.
- Retention and deletion policy.
- Contact and correction process.
- List of subprocessors and international transfer mechanisms where applicable.

## Data-subject controls

The product will support:

- Viewing evidence used in a PR comment.
- Reporting an incorrect source, attribution, or identity alias.
- Requesting a refresh after public data changes.
- Requesting deletion where applicable.
- Receiving a resolution state for a correction.
- Preserving an audit record without preserving deleted private content.

A correction creates a new evidence or assessment version; it does not silently alter history.
When a correction or applicable deletion changes a published result, MergeSignal updates its own known PR comments when technically and lawfully possible. GitHub may retain audit logs, notifications, caches, forks, exports, or copies controlled by GitHub or third parties; MergeSignal cannot guarantee deletion of data outside its control and must state that limitation in the notice.

## Automated decision-making

MergeSignal does not make merge, rejection, employment, access, or legal decisions. Review priority is advisory and visible. Repository automation must not silently convert reputation into an adverse action.

Before broad availability, counsel must determine whether any configured customer workflow could qualify as solely automated decision-making and what additional safeguards would be required.

## Retention

| Data | Initial default |
|---|---:|
| Raw webhook body | 7 days |
| Public normalized evidence cache | 90 days after last use |
| Target private evidence not referenced by an assessment | 90 days |
| Assessment snapshot and minimized calculation material | 13 months |
| Internal model input/output | 30 days |
| Security audit events | 13 months |
| Exact comment-removal linkage and receipt digest | At most 30 days after removal workflow creation |
| Installation token | Memory only |

Retention settings require technical enforcement, deletion verification, backup-expiry documentation, and tenant-visible policy.

Minimized calculation material referenced by an assessment is retained for the same
period as that assessment so the result remains reproducible. Retention is
represented by a separate content-free, append-only lifecycle rather than mutable
fields on the immutable assessment. Each event is monotonically revised; deletion
and expiry are terminal, competing events at one `(assessment_id,
lifecycle_revision)` are rejected, and publication records bind database-issued
high-water revision/count/digest proofs rather than trusting caller-supplied stream
arrays. A PR-scoped output cursor and independent high-water record prevent an older
generation from becoming current through a self-consistent stale read. Publication
records bind the latest revisions observed before and after a GitHub write. A lawful deletion overrides reproducibility:
subject identity, assessment content, evidence, model material, exports, and cache
copies are erased or cryptographically destroyed; known app-owned GitHub comments
are removed or neutralized only after a provider observation proves exact App and
installation ownership, through append-only removal events bound to the exact
terminal retention transition, comment ID, retry attempts, and a bounded provider
receipt digest where technically and lawfully possible. Deletion-request IDs are
opaque UUIDs, not request text. Exact repository, PR, publication, and comment
linkage is erased within 30 days of removal-workflow creation. The retention
lifecycle reaches `subject_deleted`, forbids publication, and its opaque terminal
event is the only persistent non-content tombstone. Backup expiry and deletion
verification remain mandatory.

OpenAI requests use store false. This controls API application state, not necessarily all provider abuse-monitoring retention. Private evidence requires a documented provider data-control review and Zero Data Retention or Modified Abuse Monitoring when policy requires and the account is eligible.

## Subprocessors and transfers

Initial infrastructure roles:

- GitHub: source platform and publication surface.
- Vercel Kontext team: web/control plane.
- Coolify server hosting provider: worker compute.
- Temporal Cloud: durable orchestration.
- Managed PostgreSQL provider: system of record.
- Object-storage and KMS provider: encrypted payload and key services.
- OpenAI: bounded selection of exact contextual relevance claim tuples.
- Observability provider: redacted telemetry.

Exact legal entities, regions, agreements, and transfer mechanisms must be recorded before production data is processed.

## Security measures

- Least-privilege GitHub App.
- HMAC verification and idempotent delivery ledger.
- Encryption in transit and at rest.
- KMS or secrets-manager credentials and rotation.
- PostgreSQL row-level security.
- Typed evidence visibility and renderer boundaries.
- Current authorization checks.
- Redacted logs and traces.
- Strict model schemas and injection testing.
- Backups, restoration tests, incident response, and audited access.

## Risk assessment

| Risk | Likelihood before controls | Impact | Principal controls | Residual |
|---|---:|---:|---|---:|
| Incorrect reputation inference | Medium | High | Coverage, confidence, evidence links, corrections | Medium |
| Newcomer disadvantage | High | High | Limited-evidence state, standard default, cohort tests | Medium |
| Public disclosure of private evidence | Medium | Critical | Visibility types, RLS, renderer allowlist, tests | Low |
| Cross-tenant access | Medium | Critical | RLS, authz, scoped exports, isolation tests | Low |
| Model fabrication | Medium | High | Closed packet, strict schema, citation validation | Low |
| Account gaming or takeover | High | High | Independence and behavior-change evidence, human review | Medium |
| Excessive retention | Medium | Medium | TTLs, deletion workflow, backup expiry | Low |
| Maintainer automation bias | High | High | No scores in GitHub, advisory only, neutral language | Medium |

## Approval gates

Before private-repository pilot:

- Confirm provider regions and data controls.
- Complete RLS and renderer-isolation tests.
- Test export, deletion, and correction workflows.
- Publish privacy notice and data dictionary.

Before broad availability:

- Qualified legal review.
- External privacy and security review.
- Documented subprocessor agreements.
- Pilot evidence on newcomer and false-confidence outcomes.
- Incident and data-subject request runbooks.
