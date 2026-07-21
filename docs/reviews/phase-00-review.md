# Phase 0 deep-review ledger

> Mode: fix-local
>
> Profile: deep
>
> Severity gate: P0, P1, and P2
>
> Status: iteration 14 findings resolved; iteration 15 confirming pass pending

## Scope

This ledger covers the Phase 0 product contract, evidence and reason registries, assessment and publication schemas, adversarial fixtures, validator, methodology, threat model, privacy analysis, and architecture decisions.

## Iteration 1 snapshot

- Base and head: `8a4b325e20d0f606196f632c91ea970651900736`
- Working-tree snapshot hash: `26be938d78e9c763c33f70098ac56b6da4b1fabe51a2c998e6b26a590e1e8153`
- Lenses: repository policy, specification and data flow, security and privacy, and tests and operations.
- Result: changes requested.

## Deduplicated findings and resolutions

| Finding family | Highest severity | Resolution in confirming snapshot |
|---|---:|---|
| Private evidence was tenant-scoped in some documents and repository-scoped in others | P1 | Standardized on exact target-repository scope across contracts, plan, ADRs, security, privacy, and fixtures |
| PR renderer could receive full assessment scores or private evidence | P1 | Added a template-only render schema with no numeric field and public-source links only |
| Immutable assessment mixed calculation and publication lifecycle state | P1 | Split immutable assessment from mutable PR-scoped publication generations |
| Optional review priority had no `not_enabled` value | P1 | Added `not_enabled` to schemas, traceability, fixtures, glossary, and policy rules |
| Original validator could pass invalid registries and unsafe cross-field states | P1 | Compiles every JSON Schema with Ajv, checks semantic invariants, and runs negative mutations |
| Duplicate dimensions, unknown reason codes, and out-of-snapshot citations were representable | P1 | Closed the dimension object, bound reason enums, and validate every evidence reference against the snapshot |
| Deterministic and model ownership of relevance conflicted | P1 | Deterministic code owns candidates, score, state, confidence, and copy; the model only selects exact registered tuples |
| Rename, patch-only, high-volume, and relevance fixtures encoded unfair or contradictory expectations | P1 | Replaced the corpus with explicit controls, stable node-ID equivalence, independent patch context, and complete-versus-truncated cases |
| Publication could lose a head-update race or duplicate an ambiguous comment create | P1 | Added generation serialization, pre-write fences, post-write repair, exact-marker recovery, and verified duplicate cleanup |
| Operational evidence or derived inference could become a public source claim | P1 | Added `PUBLIC_DERIVED`, public coverage summaries, operational-only types, and publication-time visibility checks |
| Unsupported GitHub actor implementations were undefined | P1 | Preserved actor type and added an explicit unsupported limited-coverage path |
| Browser authentication threats were absent | P1 | Added OAuth state, session rotation, cookie, CSRF, XSS, CSP, redirect, and repository-IDOR controls and tests |
| Check conclusions could imply reputation failure or limited evidence | P1 | Restricted Checks to operational lifecycle; a completed assessment is success regardless of reputation state |
| Weighting and confidence rules were inconsistent or incomplete | P1 | Defined one 100-percent additive allocation, a non-additive integrity modifier, and stored confidence thresholds |
| Assessment retention could outlive calculation material without disclosure | P1 | Aligned minimized calculation material with assessment retention and documented the lawful-deletion exception |
| Public and private examples and race/visibility fixtures were missing | P2 | Added template-only examples, an evidence manifest, unsupported-actor, cross-repository, and visibility-race cases |
| Traceability mappings could claim tests that did not exercise their reasons | P2 | Validator now checks every judgment-reason-fixture edge and rejects orphan fixtures or expectations |

## Iteration 2 snapshot

- Base and head: `8a4b325e20d0f606196f632c91ea970651900736`
- Working-tree snapshot hash: `a2a4209b8be4194bad96cbc8b1aace6b720df99ae73baa61bd65dfc62209477a`
- Result: changes requested; no P0, with deduplicated P1 and P2 findings across all four lenses.

## Iteration 2 resolutions

| Finding family | Highest severity | Resolution for the next snapshot |
|---|---:|---|
| Free-form comment fields could leak scores, accusations, or model prose | P1 | Replaced them with a template-only model containing structured states, registered reasons, controlled caveats, and at most three source links |
| Comment data could contradict the immutable assessment | P1 | Exact projection checks now bind all six dimensions, coverage, patch facts, explanation state, caveats, target, and scoring version |
| Assessment, comment, and publication could refer to different repositories or PRs | P1 | Added installation, repository, PR, marker, assessment, and head cross-contract validation |
| A reason passed with any one evidence type or the wrong owner | P1 | Added required-all, required-any, unique versioned predicates, owner rules, and incomplete-evidence mutations |
| Unsupported or unavailable actor combinations could validate as established | P1 | Added availability semantics, null missing-author identity, supported-type rules, reasons, fixtures, and actor mutations |
| Model claims used flat citations and could cite valid but irrelevant evidence | P1 | Split explanations into per-claim reason types and evidence sets validated against reason evidence groups; public output never renders claim prose |
| Priority rules trusted omitted reason codes instead of normalized facts | P1 | Prioritize now checks summary, confidence, actor support, coverage, CI, size, and sensitive-path facts directly |
| A deletion tombstone could retain calculation material | P1 | Added schema and semantic conditionals plus a negative deletion mutation |
| A successful Check did not require the primary comment | P1 | Defined and tested terminal Check combinations; success requires current fence, published comment ID, and Check ID |
| Check failure and supersession state were contradictory | P2 | Added explicit success, failure, supersession, and repair transition examples and validation |
| Snapshot ID and placeholder hash were unbound to calculation material | P2 | Bound manifest ID and exact members; sorted, RFC 8785-canonicalized, SHA-256 hashed, and mutation-tested the manifest |
| Generic canonical payloads could retain undeclared or mismatched source fields | P1 | Added closed payload schemas for every evidence type, exact registry coverage validation, and proxy/type-confusion mutations |
| Derived evidence omitted provenance and privacy-ceiling checks | P2 | Added derivation version, complete input IDs, acyclic graph, repository, and recursive visibility validation |
| `not_enabled` falsely claimed contributor evidence | P2 | Removed it from user-visible judgment traceability and retained it as a non-rendered policy control state |
| Fixture copy arrays looked executable before an engine or renderer existed | P2 | Marked the corpus `specification_only`, closed optional fields, and documented the later behavioral gate |
| Injection coverage used one generic text field | P2 | Added typed repository, issue, PR, commit, comment, guidance, Unicode, Markdown/HTML, truncation, and valid-irrelevant-citation cases |
| README and package test entry point described or exercised stale behavior | P1 | Rewrote the product surface and made `npm test` self-contained with pinned contract, whitespace, and Markdown gates |
| Internal repositories and untracked whitespace were not handled | P3 | Added internal visibility as restricted and an explicit project-file whitespace/conflict-marker gate |

## Confirming-pass gates

- `npm test`
- `node --check scripts/validate-phase0.mjs`
- Parse every JSON contract, example, and fixture with `jq`.
- `git diff --check` for tracked changes plus the explicit whitespace gate for the current untracked submission set.
- Fresh repository-policy, specification/data-flow, security/privacy, and tests/operations review lenses on one frozen snapshot.

Phase 0 is clean only when the fresh snapshot has no active P0, P1, or P2 finding. Any confirmed finding reopens the loop and requires another fresh pass.

## Iteration 3 snapshot

- Base and head: `8a4b325e20d0f606196f632c91ea970651900736`
- Complete tracked-and-untracked nonignored snapshot hash: `e8d28427b5780c264f8f10447aed721eae5bca00b76cd87ec569165309748c00`
- Result: changes requested; no P0, with deduplicated P1, P2, and P3 findings across all four lenses.
- Scope correction: earlier hashes covered only untracked files and therefore omitted the modified tracked README. Iteration 3 used the complete inventory; subsequent passes use `npm run review:snapshot`, whose repository-owned algorithm inventories `git ls-files -co --exclude-standard -z` and hashes path, object type, mode, symlink target, and file content.

## Iteration 3 resolutions

| Finding family | Highest severity | Resolution for the next snapshot |
|---|---:|---|
| Evidence could belong to another actor, repository, PR, review, or relationship | P1 | Added subject attribution, required restricted repository scope, stable join keys, canonical repository checks, recursive provenance boundaries, and wrong-subject/cross-event mutations |
| Derived outputs could claim unrelated inputs | P1 | Added registry-owned derivation versions, input groups, predicates, materialized derivation recomputation, direct follow-up commit source facts, and mismatch mutations |
| Patch and coverage claims could contradict canonical payloads | P1 | Bound CI, head, scope, tests, issue, sensitive paths, coverage, subject, repository, and derived values before reasons or priority validate |
| Established, partial, confidence, manual-inspection, and priority states were one-directional | P1 | Added bidirectional summary/manual rules, coverage confidence cap, complete/support thresholds, core-dimension requirements, and priority prohibitions |
| Deletion state lived inside and retained the immutable profile | P1 | Removed mutable retention from the assessment; added a content-free overlay that forbids publication after deletion/expiry and requires erasure or cryptographic destruction of content |
| Assessment lacked GitHub App installation identity | P1 | Added installation ID to the immutable target and exact assessment/comment/publication binding |
| Fallback could retain model claims or omit its reason and caveat | P2 | Made fallback discriminated: zero claims, required contextualizer status evidence, unavailable reason, and controlled caveat |
| Same-head older generations and source-visibility write races could remain current | P2 | Added latest-observed generation, rendered/post-write source digests, post-write timestamp, retention fence, immediate repair, and later-change reconciliation requirement |
| Operational Checks were falsely traced through reputation evidence | P2 | Added explicit lifecycle state/conclusion traceability and required-evidence validation for every contributor judgment/reason edge |
| Snapshot hash was hand-rolled and excluded envelope identity | P2 | Pinned an RFC 8785 implementation, hashes the complete I-JSON manifest envelope, rejects invalid Unicode, and verifies an interoperability serialization/hash vector |
| Terminal attempts, duplicate URLs, README status, and review hash reproducibility were incomplete | P3 | Added timestamp interval rules and mutations, normalized URL uniqueness, accurate machine-validated wording, and a repository-owned complete snapshot command |

## Iteration 4 snapshot

- Base and head: `8a4b325e20d0f606196f632c91ea970651900736`
- Complete tracked-and-untracked nonignored snapshot hash: `ca5c8465a9c6cd9547d9af9e344b4d55d2a875d8be343a2032fb4ae85cb07e25`
- Result: changes requested; no P0, with deduplicated P1 and P2 findings across specification, security/privacy, and tests/operations lenses.

## Iteration 4 resolutions

| Finding family | Highest severity | Resolution for the next snapshot |
|---|---:|---|
| Historical facts could claim relevance without comparison to the actual target | P1 | Added a versioned relevance-comparison evidence type that binds historical and target repository/PR identities and exactly recomputes language, domain, and path-family matches; added unrelated-target mutations |
| Several derivations could not reproduce their declared outputs | P1 | Added minimum input cardinalities and exact recomputation for every registered derivation; changed coverage to a versioned system collection result; added file-inventory and risk-policy inputs plus focused mutations |
| Registered reason predicates could fall through or implement weaker claims | P1 | Removed the permissive fallback, implemented and exercised every registered predicate, and enforced multi-month continuity, repeated merges, requested-changes follow-through, and explicit integrity thresholds |
| Repository members and collaborators could be labeled independent | P1 | Made ownership classification mutually exclusive and exactly recomputed from ownership, author association, and merge actor |
| Developing and limited summary states overlapped | P1 | Added one total ordered classifier and exact equality validation so one canonical fact set has one summary state |
| Target patch and cross-event facts lacked a complete immutable PR identity | P1 | Bound PR node, repository node, PR number, author/subject, provider event, and target head where applicable; added global consistency, provider-binding, same-repository-other-PR, and timestamp mutations |
| Deletion and expiry could be reversed or bypassed by stale publication reads | P1 | Replaced the mutable overlay with append-only monotonic retention events, terminal transition validation, pre/post publication revision bindings, compare-and-swap requirements, and a separate content-free comment-removal contract |
| Publication source freshness was self-asserted digest equality | P2 | Added typed pre/post visibility-validation records covering every assessment source and recursive provenance item with expected/current revisions, visibility, repository scopes, generation, and canonical state digest |
| Deterministic fallback could exceed the public projection or claim model interpretation | P1 | Capped fallback at three caveats, prohibited `MODEL_INTERPRETATION`, and added schema rejection coverage |
| Operational Check traceability cited fixtures without Check expectations and misused valid cases for failure | P2 | Every fixture now declares an exact Check state/conclusion; every pair is traced to a matching operational judgment; dedicated configuration, retry exhaustion, retrying, in-progress, and supersession cases replace reputation proxies |
| Subject facts depended on example-specific evidence IDs | P2 | Selected exactly one target-bound author-availability and actor-type fact by typed relationship identity and proved equivalent arbitrary evidence IDs validate |

## Iteration 5 snapshot

- Base and head: `8a4b325e20d0f606196f632c91ea970651900736`
- Complete tracked-and-untracked nonignored snapshot hash: `57cfd9b215285ba5a6dc1278d79a29d1966008335f29d3a654d28486f9c39c01`
- Result: changes requested; no P0, with deduplicated P1, P2, and P3 findings across specification/data-flow, security/privacy, and tests/operations lenses.

## Iteration 5 resolutions

| Finding family | Highest severity | Resolution for the next snapshot |
|---|---:|---|
| Duplicate rows and cherry-picked derived inputs could manufacture repeated history | P1 | Added type-specific natural-key uniqueness, distinct immutable-event counting, exact snapshot candidate selectors, complete-population eligibility, and duplicate/cherry-pick mutations |
| Missing baselines and incomplete coverage could create anomaly or established outcomes | P1 | Removed the invented baseline denominator, require a nonzero observed baseline for ratio features, derive exact mandatory coverage reasons/status, and reject history-wide patterns without complete attributable collection |
| Strong dimensions could lack reasons or cite evidence from another dimension | P1 | Strong/moderate states now require a numeric score, deterministic reason, and only evidence types registered to that dimension; absence of an integrity trigger remains uncertain rather than strong |
| Private relevance was contradictory and same-repository history was forbidden | P1 | Added a visibility-lattice exception for public-global history plus exact target-private facts, allow a different historical PR in the target repository, and validate a complete private assessment/comment projection |
| Changed paths and fileset completeness were not bound to the assessed head and provider results | P1 | Every path now carries a head SHA; filesets carry provider totals, collected counts, pagination, and collection state; all patch derivations join the exact PR/head and closed path inventory |
| Missing CI or a zero-path incomplete files response could not be represented honestly | P1 | Missing CI uses a null suite ID; scope, test paths, and sensitive paths expose explicit unknown states, backed by `PATCH_INVENTORY_INCOMPLETE` and a zero-path unavailable-fileset positive fixture |
| Post-write visibility could reuse cached observations or the same record | P1 | Added explicit pre/post phases, distinct validation IDs, provider write start/completion, per-source materialization/freshness bounds, post-write observation ordering, and timestamp-inclusive state digests |
| Terminal retention had no enforceable app-comment removal flow | P1 | Added a separate content-free removal schema and validator bound to transition ID/revision, publication/comment identity, retry state, provider completion, and receipt; deletion and expiry positive paths are covered |
| Contribution-year and public reason predicates could overclaim activity or collaboration | P1 | Bind active months to their declared year and observation time, require activity in two distinct years, exclude self-review from work-by-others, and make “most” strictly greater than one half |
| Public GitHub URLs were not bound to their evidence entity | P2 | Validate canonical GitHub repository, PR, files, checks, commits, issue, and subject-profile components with stable node-to-slug consistency |
| Generation and causal timestamps had upper-bound gaps | P2 | Bind assessment, comment, publication, and visibility generation; cap every fence by latest observed generation; require derived-after-input and coverage-at-or-before-snapshot ordering |
| JSON, fixture, neutral-copy, mutation-count, and review-snapshot gates had portability gaps | P3 | Reject duplicate raw JSON members, use explicit UTF-8 comparators outside JCS, type fixture inputs/dimensions, NFKC-normalize and reject format controls, pin named mutation counts, and hash file type/mode/symlink target metadata |

## Iteration 6 snapshot

- Base and head: `8a4b325e20d0f606196f632c91ea970651900736`
- Complete tracked-and-untracked nonignored snapshot hash: `f662e662d38e6aa190da7d56b1ce35a36aece037fafb6dc7633dc10de2879923`
- Result: changes requested; no P0, with deduplicated P1 and P2 findings across specification/data-flow, security/privacy, and tests/operations lenses.

## Iteration 6 resolutions

| Finding family | Highest severity | Resolution for the next snapshot |
|---|---:|---|
| Coverage and freshness could be self-asserted | P1 | Added run-bound authoritative source partitions with exact query versions, windows, evidence types, totals, pagination, limitations, candidate IDs and digests; freshness and confidence are recomputed from policy |
| Dimension values and version labels were not executable or resolvable | P1 | Added an executable six-dimension scoring policy, exact state/confidence recomputation, and a content-addressed registry for every assessment version kind |
| Relevance and sensitive-path claims were not bound to the exact context | P1 | Relevance now binds historical and target heads plus complete filesets; sensitive-path state and assessment target bind the single risk policy active at capture |
| PR lifecycle and collaboration facts could be causally impossible or misattributed | P1 | Added event chronology and mutually exclusive terminal-outcome checks, subject-bound follow-through actors, and reproducible PR metadata fingerprints |
| Publication and removal records could be overwritten or linked out of order | P1 | Converted both lifecycles to append-only revisioned transitions with legal-transition, monotonic-attempt, terminal-state, provider-write, retention, and cross-contract chronology validation |
| Public source links could leak query data or point to a different object | P2 | Added typed actor/repository locators and require source URLs to be exact query-free and fragment-free renderings of those locators |
| Terminal removal audit data was overbroad or indefinite | P2 | Restrict identifiers to UUIDs and receipt digests, impose a 30-day maximum audit expiry, and document erasure of exact comment/publication linkage afterward |
| Fixtures, integers, ordering, and snapshot modes allowed nonportable or contradictory inputs | P2 | Added I-JSON safe-integer rejection, typed fixture enums/ranges, a semantic fixture oracle, deterministic UTF-8 ordering, and Git-compatible normalized mode hashing |

## Iteration 7 snapshot

- Base and head: `8a4b325e20d0f606196f632c91ea970651900736`
- Complete tracked-and-untracked nonignored snapshot hash: `289fb2e05b4fba9b20e8da5c34160e382c2afb3c006fba6764a89e2d29cdc04a`
- Files: 63
- Result: changes requested; no P0, with deduplicated P1 and P2 findings across specification/data-flow, security/privacy, and tests/operations lenses.

## Iteration 7 resolutions

| Finding family | Highest severity | Resolution for the next snapshot |
|---|---:|---|
| Coverage partitions and derived coverage fields could omit registered source classes or reuse stale candidates | P1 | Added an exact singleton/year-granular feature query plan, mandatory partition equality, complete same-run candidate binding, derived complete years/attribution/freshness/confidence, resource ceilings, and omission, hidden-candidate, and stale-candidate mutations |
| Version labels and model placeholders did not content-address all behavior, and retirement could invalidate history | P1 | Added schema-validated product, feature, evidence, and resolved-model artifacts; bound the exact reference-validator digest; mutation-tested behavior bytes; and permitted historical replay inside a retired version's effective interval |
| Lifecycle records could begin terminally or split into competing publication, retention, and removal aggregates | P1 | Require queued initial publication/removal events, validate every adjacent example transition, enforce globally unique transition and aggregate-revision identities, add logical stream ownership, and mutation-test competing branches |
| A visibility fence or internal item could be stale or scoped outside the exact target repository | P1 | Bound every internal item to the target repository whether cited or not, capped pre-write records and per-source observations at the actual provider-write start, enforced visibility resource ceilings, and added focused mutations |
| Newcomer fairness policy conflicted with the implementation's established-only priority rule | P1 | Added explicit `reputation_and_patch` and `patch_only` bases; a supported newcomer may be prioritized only by controlled passing-CI, small-scope, tests-changed, non-sensitive patch facts, with limited history stated in GitHub |
| Repository-wide language could be attributed to contributor work | P1 | Derive language matches only from changed paths bound to the exact historical and target heads plus complete filesets; repository metadata remains contextual and is covered by an adversarial mismatch test |
| Integrity features could count repository boilerplate, repeated repositories, affiliation, or contradictory merge events as stronger evidence | P1 | Subtract repository PR-template structure, require five informative distinct independently maintained repositories, separate affiliation caveats from actual self-merges, and reconcile relationship events with canonical merged outcomes and actors |
| Fixture expectations were partly hand-authored and semantic mutations could pass through unrelated exceptions | P2 | Recompute dimension states from scoring weights, correct contradictory fixtures, type semantic assertion failures, require intended-invariant messages on critical probes, and grow the named mutation suite from 164 to 181 |
| Generator drift and authoritative prose were outside the normal test gate | P2 | Added a byte-exact non-writing refresh check to `npm test` and aligned publication, snapshot-envelope, relevance, priority, retention, and versioning documentation with executable contracts |

## Iteration 8 snapshot

- Base and head: `8a4b325e20d0f606196f632c91ea970651900736`
- Complete tracked-and-untracked nonignored snapshot hash: `1511950b6389c1a927dc845ff888ab6a7543b7e832ee04fdb1707cdc3ed3bb7b`
- Files: 74
- Result: changes requested; no P0, with deduplicated P1 and P2 findings across specification/data-flow, security/privacy, and tests/operations lenses.

## Iteration 8 resolutions

| Finding family | Highest severity | Resolution for the next snapshot |
|---|---:|---|
| Assessments could omit applicable reputation or integrity reasons and then self-select a stronger state | P1 | Evaluate every registered predicate against the complete authoritative evidence population, require the exact applicable reason set, and mutation-test omitted tenure and template-pattern reasons |
| Historical version replay validated every assessment against one current in-memory artifact | P1 | Load, digest, schema-validate, and retain every registry artifact by kind and version; replay assessments with their selected bundle; cover retired `scoring-v1` and materially different active `scoring-v2` on both sides of the effective boundary |
| Review priority was not repository-policy-bound and established reputation bypassed patch readiness | P1 | Bind the active repository opt-in flag and policy digest into the target; require passing CI, allowed scope, complete test and sensitive-path facts for reputation priority; keep the stricter newcomer patch-only path; cover opt-out, pending CI, unchanged tests, and incomplete inventory |
| Template-pattern evidence was unreachable through the full validator | P1 | Include ownership relationships in the exact selector and add a five-repository positive manifest, assessment, and omission mutation |
| Model routing and output contracts were symbolic, and structured claims could carry unrelated prose | P1 | Content-address and validate the routing policy and response schema; restrict model output and stored claims to claim IDs, registered reasons, and evidence IDs; make all prose renderer-owned |
| Coverage candidates could influence confidence without entering the publication visibility fence | P1 | Include every coverage candidate and recursive derivation input in the source-set digest and typed pre/post visibility records; align source and canonical-byte ceilings and mutation-test an omitted uncited candidate |
| Publication aggregates could migrate across generations or claim multiple logical streams | P1 | Make generation immutable across transitions, enforce bidirectional logical-stream ownership and contiguous revisions, and add advance, collision, and gap mutations |
| Repository-wide language metadata remained attributable and path language labels were trusted | P1 | Require complete head-bound filesets and changed paths for language relevance; recompute each path label from a content-addressed extension map; remove repository-language citations from the public comment |
| Coverage time, freshness, fixture empty states, and derivation lookup had correctness or scale gaps | P2 | Add explicit fileset revision timestamps and query temporal bases, compare freshness instants rather than strings, compute every fixture dimension including empty states, and pre-index derivation candidates by subject, run, PR, head, repository, and type |

## Iteration 9 snapshot

- Base and head: `8a4b325e20d0f606196f632c91ea970651900736`
- Complete tracked-and-untracked nonignored snapshot hash: `3ed5c20594d616a3d388995e22188a9f152df952ccf7c43a5814864dc5d4df79`
- Files: 78
- Result: changes requested; no P0, with deduplicated P1 and P2 findings across specification/data-flow, security/privacy, and tests/operations lenses.

## Iteration 9 resolutions

| Finding family | Highest severity | Resolution for the next snapshot |
|---|---:|---|
| Review priority permitted qualifying assessments to self-select weaker states | P1 | Derive one exact state and basis with fixed precedence for opt-out, inspection, reputation-plus-patch, patch-only, and standard outcomes; add downgrade mutations for established, inspection, and newcomer paths |
| Historical replay still consumed current evidence, reason, feature, and model dependencies | P1 | Build immutable evidence and model dependency bundles from content-addressed registry members, select them per assessment, permit generic future artifact versions, and exercise material retired/active evidence, feature, and scoring generations |
| Model output was not bound to deterministic candidates | P1 | Store a content-addressed deterministic candidate packet, require every selected claim to be an exact ordered subset, cap the path at three claims end to end, and reject invented IDs, substituted evidence, digest changes, and reordering |
| Non-public target facts could claim public visibility | P1 | Add the inverse target visibility ceiling and mutation-test a private target fact relabeled as public-global |
| Repository opt-in and sensitive-path policy could be self-attested | P1 | Bind policy evidence to the GitHub App installation and a digest-covered dashboard admin revision or default-branch commit; reject another installation and any configuration sourced from the PR head |
| Publication fences consumed the current global feature policy | P2 | Resolve the assessment-selected feature artifact for every visibility and cross-contract fence and prove a timestamp accepted by retired v1 is rejected by active v2 |
| Overall-confidence limitations were not the exact coverage limitation set | P2 | Require set equality and reject both omitted and invented limitation reasons |
| Append-only checks did not validate every adjacent state transition | P2 | Validate each sorted adjacent revision with its lifecycle transition function, use canonical composite keys, reject disconnected state chains, and align retention stream identity to `assessmentId` |
| Derivation indexing copied growing buckets and authoritative prose still allowed model text | P2 | Append index members in place and align the implementation plan, report contract, DPIA, and threat model with structured model selection plus renderer-owned prose only |

## Iteration 10 snapshot

- Base and head: `8a4b325e20d0f606196f632c91ea970651900736`
- Complete tracked-and-untracked nonignored snapshot hash: `a9bd3a8ca0f0b362cf2b9d8e76c79bd3ee2ff978d2966b5a8fd7caf85c3122c3`
- Files: 81
- Result: changes requested; no P0, with deduplicated P1 and P2 findings across specification/data-flow, security/privacy, and tests/operations lenses.

## Iteration 10 resolutions

| Finding family | Highest severity | Resolution for the next snapshot |
|---|---:|---|
| Assessment-driving history could bypass the authoritative run and window | P1 | Restrict every reputation dimension, reason derivation, contextualization candidate, and closed-population anomaly to the selected coverage candidate set plus recursively derived facts; add cross-run and out-of-window positive-history mutations and cache coverage validation per summary |
| Registered versions were mutable and historical replay consumed global dependencies | P1 | Make registered bundles write-once, add a Git-history immutability gate, select evidence components generically, remove global reason-schema references, use the assessment-selected feature and policy artifacts, and content-address model request/response dependencies |
| Repository policy provenance was self-attested | P1 | Derive policies only from an exact provider-observed default-branch tip/blob/config digest or an exact dashboard revision paired with installation/repository-scoped GitHub admin permission evidence |
| Contextualization candidates were copied from selected claims | P1 | Deterministically reconstruct the complete ordered candidate population from dimension reasons and eligible evidence, require a content-addressed strict superset, and accept only exact ordered tuple selections |
| Publication provider identities and output fences could drift after a write | P1 | Freeze rendered source identity and assigned GitHub IDs, bind same-generation observations to one head, add typed pre/post head, generation, retention-transition, and visibility observations, and require post-write fencing after every completed comment write including later Check failure |
| `completed:action_required` was unreachable | P1 | Add a first-class recoverable `action_required` publication state, selected-policy transitions, and a positive publishing-to-action-required-to-retrying chain |
| Versioned reason-message overrides bypassed neutral-copy checks | P1 | Validate the fully materialized reason registry after every bundled override and mutation-test unsafe override wording |
| Model input had no executable privacy or resource boundary | P2 | Add a content-addressed contextualization-request schema containing only target/version identities, the closed candidate packet, and exact public normalized evidence descriptors, with item/cardinality and 64 KiB canonical-byte limits |
| Evidence surfaces and review priority accepted contradictory inputs | P2 | Require evidence types to declare their cited surface, make explanation evidence exactly selected claims plus operational facts, and require moderate or strong target relevance before reputation-based priority |
| Edge-case and scale gates were incomplete | P2 | Accept exactly complete 25,000-item partitions, reject only unresolved ceilings, use effective payload repository identity for private-target inversion, and add focused performance, descriptor, provider-ID, post-write, and source-drift probes |

## Iteration 11 snapshot

- Base and head: `8a4b325e20d0f606196f632c91ea970651900736`
- Complete tracked-and-untracked nonignored snapshot hash: `f66c3b2a2bc9a78dd7f752ca861d9e80d9e224e272fb3a686bbea7eefe473d3a`
- Files: 84
- Result: changes requested; no P0, with deduplicated P1 and P2 findings across specification/data-flow, security/privacy, and tests/operations lenses.

## Iteration 11 resolutions

| Finding family | Highest severity | Resolution for the next snapshot |
|---|---:|---|
| Git-history immutability compared a committed registry to the same checkout | P1 | Compare the working registry with every reachable committed registry snapshot, validate every registered artifact and nested evaluator digest, prohibit removal/reactivation/closed-interval drift, and run a built-in same-version rewrite regression before any baseline exists |
| Historical assessments still executed an unversioned feature evaluator | P1 | Content-address an executable `feature-evaluator-v1` module from each feature artifact and dispatch selected path-language, coverage, and reason-predicate behavior through the assessment-selected evaluator bytes |
| Private target facts and integrity closure could escape the authoritative collection run/window | P1 | Require private facts to match the coverage run, exact repository/PR/head, and freshness window; derive integrity closure from authoritative IDs only; add cross-run private and cross-run/out-of-window integrity probes |
| Dashboard authorization could be stale or revoked | P1 | Bind granted admin permission to the exact dashboard revision, actor, installation, repository, provider timestamp, nonce, and a versioned 300-second window; reject stale and revoked observations |
| Repository visibility was caller supplied | P1 | Add a provider-observed installation/repository visibility snapshot, require the assessment target and every downstream projection to derive from it, and reject self-attested flips |
| Default-branch policy provenance was opaque | P1 | Replace the composite assertion with provider-observed default-branch, ref-to-tip, and commit/path-to-blob records; bind all three exact IDs and reject wrong ref, tip, blob, digest, and PR-head substitutions |
| Publication did not prove the latest retention revision or represent deletion during a write | P1 | Validate the complete append-only retention stream, select exact pre/post events and its latest event, allow completed writes only as stale/repair when terminal retention races, and cover retained-to-deleted positive and stale-read paths |
| Successful Checks lacked ordered, post-Check fencing | P1 | Record Check write start/completion, require it to begin after comment completion and a publishable post-write fence, and authorize success only after a distinct publishable post-Check head/generation/retention/source observation |
| Coverage timestamp resolution remained quadratic | P2 | Pre-index changed-path revision timestamps and PR-open events in one pass, use constant-time fileset lookups, and exercise 25,000 filesets across a 50,000-item near-ceiling operation-count probe |
| Provider model requests exposed stable GitHub target identifiers | P2 | Move exact installation/repository/PR/number/head/generation binding into a local digested envelope; send only per-request HMAC aliases plus a pseudonymous safety identifier and mutation-test stable-ID leakage |
| Private-repository contextualization had no reachable safe policy | P2 | Exclude every private-dependent candidate from provider packets by default, reject private-dependent selected claims, validate a complete private-repository public-only request, and document deterministic fallback plus future opt-in requirements |
| Candidate completeness depended on dimension-selected citations | P2 | Build reason candidates from the authoritative population and exact relevance provenance, separately require dimensions to cite every authoritative supporting fact, and reject citation omission while the packet remains complete |
| Neutral renderer copy could contain links or mentions | P2 | Reject Markdown links/images, HTTP URLs, bare URLs, angle-bracket autolinks, and user mentions in addition to prior control, HTML, accusation, label, and numeric-rating bans |

## Iteration 12 snapshot

- Base and head: `8a4b325e20d0f606196f632c91ea970651900736`
- Complete tracked-and-untracked nonignored snapshot hash: `34c57e…` (the frozen review record retained only this prefix)
- Files: 88
- Result: changes requested; no P0, with deduplicated P1 and P2 findings across specification/data-flow, security/privacy, performance, and tests/operations lenses.

## Iteration 12 resolutions

| Finding family | Highest severity | Resolution for the next snapshot |
|---|---:|---|
| Historical assessment and publication decisions still executed unversioned code | P1 | Added retired/active content-addressed assessment engines, bound engine version/digest into manifests, assessments, requests, and publication events, dispatch scoring/summary/evidence/contextualization/publication/repair/removal behavior through exact evaluator bytes, and proved material v1/v2 replay behavior |
| Registry immutability skipped non-registry commits and merge topology | P2 | Traverse every reachable commit and actual parent edge, validate artifacts from each exact Git tree, compare registry transitions across the full DAG, and run rewrite plus synthetic diamond regressions |
| Dashboard authorization and default-branch policy proof admitted stale or assembled evidence | P1 | Bind dashboard actor/permission/revision to nonce, revision/head sequence, exact observation time, and database snapshot token; bind default branch/ref/blob to one observation bundle and recompute Git blob SHA-1 plus normalized policy SHA-256 from canonical bytes |
| Provider requests exposed reusable evidence identity and lacked useful bounded context | P1 | Replace evidence IDs with request/nonce-bound HMAC aliases, keep the exact map local, separate abuse-safety identity, and add bounded language/domain/path context without raw code or private facts |
| Model output was not bound to its exact request and provider receipt | P2 | Added a content-digested response envelope binding request/candidate digests, resolved model, response ID, output digest, and assessment model-run provenance; replay and post-receipt mutation probes reject |
| Candidate transport failed histories with more than 64 supporting facts | P1 | Bind complete-population count/digest and transmit at most 64 deterministic exemplars; validate a 4,096-item population without losing the complete identity |
| PR publication had no independent authoritative output cursor | P1 | Added a PR-scoped cursor for active generation/head and canonical GitHub IDs plus an independent database high-water record; publication and all visibility fences bind cursor revision/digest |
| Lifecycle arrays trusted the caller's assertion that they were complete | P1 | Added database-issued high-water revision, count, digest, snapshot token, and serializable read time for publication, retention, and removal streams; focused truncation probes reject valid-looking prefixes |
| Comment update, deduplication, and deletion ownership was implicit | P1 | Added provider-observed ownership records binding exact comment, marker digest, App, and installation; every mutation/removal validates that record before provider action |
| A successful Check followed by an invalid post-Check observation was unrepresentable | P1 | Permit the exact completed success only under durable `repair_queued`, validate its post-Check fence even though it is non-current, and require terminal retention to atomically queue exact-comment removal |
| Post-write retention chronology and non-success post-Check fields were under-validated | P2 | Require retention effect and durable-write time before every visibility observation, monotonic fence revisions/times, atomic all-or-none post-Check fields, and full validation whenever present |
| Derivation and relevance resolution remained quadratic near the ceiling | P1 | Added repository/path/month/actor/evidence indexes, bounded candidate unions, operation counters, and a 20,000-item/2,500-relevance linear budget gate |
| Neutral-copy URL detection remained TLD-specific | P2 | Reject generic ASCII/punycode domains, IPv4, bracketed IPv6, protocol-relative and arbitrary URI schemes; add uncommon-TLD, punycode, IP, and FTP probes |
| Contract tests lacked direct races and replay probes for the new controls | P2 | Expanded named adversarial mutations from 242 to 265, covering aliases, response receipts, policy bytes/authorization, output cursor staleness, ownership, stream truncation, retention chronology, removal, and partial post-Check state |

## Iteration 13 snapshot

- Base and head: `8a4b325e20d0f606196f632c91ea970651900736`
- Complete tracked-and-untracked nonignored snapshot hash: `53aa6a2cd5bad864cc1fe7cc99b675a48e0fc7153a888a4321218a79a174c06e`
- Files: 106
- Result: changes requested; no P0, with P1 and P2 findings across replay,
  privacy, authorization, publication concurrency, performance, and release
  operations.

## Iteration 13 resolutions

| Finding family | Highest severity | Resolution for Iteration 14 |
|---|---:|---|
| Replay depended on mutable helper code and dependency interpretation | P1 | Added a content-addressed replay runtime and bound its module, package manifest, lockfile, schemas, and evaluator bytes into every engine artifact; effective-interval and YAML behavior now dispatch through the assessment-selected runtime |
| Registry and lifecycle completeness could be defeated by deletion, nested-map mutation, stale cursors, or caller-selected prefixes | P1 | Extended immutability checks to removal and nested members; require true cursor creation paths, independent high-water records, and every publication event's exact persisted prefix digest and revision |
| Provider privacy controls checked exemplars rather than full populations and exposed stable population identity | P1 | Keep stable population digests local, send request-local HMAC commitments, evaluate eligibility over complete populations, and retain only bounded public witnesses and exemplars in provider payloads |
| Provider invocation and response acceptance were not single-use content-addressed operations | P1 | Bind prompt, request schema, response schema, model parameters, provider request, response receipt, and assessment provenance; add an append-only CAS request ledger accepting exactly one response |
| Detailed report authorization and dashboard policy heads were not independently fresh and allowlisted | P1 | Added a fresh maintainer authorization record, independent policy-stream high-water proof, short expiry, exact assessment digest, and closed detailed-report projection schema |
| Comment creation, duplicate cleanup, and terminal removal did not bind a complete App-owned population or one atomic outbox transaction | P1 | Iteration 14 added complete pre/post inventories and origin linkage; Iteration 15 corrected removal execution to use a post-retention PR mutation lease and a new CAS transaction per deletion while preserving immutable origin links |
| Prompt-like repository metadata could enter normalized provider context | P1 | Added a versioned technical-context sanitizer that normalizes Unicode, allowlists safe tokens, and replaces instruction, URL, markup, control, and interpolation syntax with opaque digests |
| Account chronology, engine interval/status, and GitHub App ownership freshness were under-specified | P2 | Require one account-creation fact for available Users, reject all earlier activity, enforce engine effective intervals and status consistency, and verify fresh ownership by the configured App and installation |
| Full semantics and release operations lacked worst-case and host-failure gates | P2 | Added a 20,000-item full semantic validation budget plus signature/provenance, Temporal history replay, graceful drain, rolling deployment, forced termination, and Coolify host-loss release gates |
| Semantic mutations could pass for the wrong reason | P2 | Every semantic mutation now declares the exact expected invariant; misleading fixtures were repaired so timestamp, retention, generation, and transition probes reach their named contract |

## Iteration 14 snapshot

- Base and head: `8a4b325e20d0f606196f632c91ea970651900736`
- Complete tracked-and-untracked nonignored snapshot hash: `653fe8544a4d5cf69782a66c24ba83a491e6eb4a734c93d109fb174bdcd14b76`
- Files: 119
- Result: changes requested; no P0, with deduplicated P1 and P2 findings across
  replay isolation, authorization, publication concurrency, destructive actions,
  provider safety, performance, immutability, and deployment operations.

## Iteration 14 resolutions

| Finding family | Highest severity | Resolution for Iteration 15 |
|---|---:|---|
| Historical replay still depended on mutable validator orchestration and root dependencies | P1 | Moved history closure, reason populations, and bounded witness behavior into the content-addressed engines; generated self-contained evaluator/runtime bundles embed exact dependencies, and historical artifacts no longer bind or import the mutable root package/lock |
| PR output cursors could not advance to a new head | P1 | Added explicit chained transition kinds: generation advances increment exactly once, change head, preserve the canonical comment, and reset the generation-scoped Check; race, skip, and stale-head probes reject |
| Detailed-view authorization was caller-asserted and replayable | P1 | Added a trusted authority receipt for a fresh provider permission observation and independent serializable policy head; authorization binds viewer/session/nonce/snapshot, uses explicit trusted request time, and consumes the session nonce exactly once |
| Contextualization response acceptance was only locally unique | P1 | Added assessment/request-envelope binding, a complete high-water ledger head, global request-alias/nonce/provider-response uniqueness checks, and CAS chronology probes |
| Terminal deletion trusted publication-time inventory and could erase a newer render | P1 | Added a deletion-time authority binding the current PR cursor, complete App/marker inventory, fresh ownership, and source-set marker; newer canonical renders are preserved and late duplicates must be included |
| Removal events falsely reused the terminal-retention transaction | P1 | Preserve immutable origin transaction/commit/outbox fields only; the queued event shares that origin while every later transition has its own truthful commit and outbox identity |
| Registered nested artifacts and shallow history could bypass immutability | P1 | Recursively validate every `*ArtifactPath`/`*ArtifactDigest` pair, reject direct nested rewrites, fail closed for shallow or disconnected history, and retain the full DAG deletion/restore regression |
| Witness minimization was quadratic near maximum history | P1 | Replace full-population greedy deletion with a bounded 64-item predicate witness, deterministic safe fallback, and explicit near-ceiling schema, semantic, time, and predicate-operation gates |
| Prompt injection defenses and replay I-JSON checks were incomplete | P2 | State that all dynamic provider fields are untrusted, collapse broad instruction/role/tool/URL/control syntax to one non-correlatable category, and reject unsafe integers plus unpaired Unicode in the replay runtime |
| Runtime artifact schemas, GitHub App identity, and Temporal rollout operations were fixture-specific or incomplete | P2 | Generalize versioned runtime maps and positive App IDs, fail deployment identity mismatch, and specify Worker Deployment Version identity, replay, ramping, pinning, reachability, rollback, and Coolify drain gates |

Iteration 15 carries 36 compiled schemas, 314 named adversarial mutations, three
byte-checked replay bundles, and a 20,000-item full schema-plus-semantic stress gate.

## Iteration 15 snapshot

- Base and head: `8a4b325e20d0f606196f632c91ea970651900736`
- Complete tracked-and-untracked nonignored snapshot hash: `38ea522080136d5c134057c810860141ed00c9e8c6d81f7ba55a6d67f0fdeabb`
- Files: 134
- Result: changes requested; no P0. Three independent reviews found P1 and P2
  gaps in durable uniqueness, detailed authorization, PR cursor ownership,
  destructive-action fencing, replay closure, runtime identity, scale behavior,
  and Git-history immutability.

## Iteration 15 resolutions

| Finding family | Highest severity | Resolution for the current Phase 0 gate |
|---|---:|---|
| Contextualization alias, nonce, and provider-response uniqueness depended on a caller-supplied population | P1 | Added trusted serializable PostgreSQL uniqueness receipts for all three named constraints; sent and accepted events bind their exact transactions and commits, and concurrent duplicate-key receipts are rejected |
| Detailed-report nonce consumption was optional process-local state and its policy head was not repository scoped | P1 | Added durable unique session/nonce consumption with a commit receipt; policy heads now bind deployment, installation, repository, and logical stream key; cross-repository joins reject |
| The authoritative PR output cursor could fork or regress state | P1 | Added database-unique PR-scope ownership receipts, explicit cursor stream identity, monotonic state transitions, active-only generation advance, and fork/resurrection regressions |
| Terminal cleanup had a publication/deletion race and an impossible shared transaction | P1 | Terminal retention now commits a generic cleanup command; deletion then acquires a PR mutation lease, blocks publication, performs post-lease cursor/marker reads, and CAS-enqueues each removal in a new transaction while preserving origin links |
| Removal retries reused frozen authority, duplicate aggregates could pass, and newer markers had no terminal state | P1 | Retry attempts bind fresh authority, ownership and inventory; complete logical removal populations reject duplicates; later commit/outbox identities are pairwise unique; newer renders terminate as `superseded` without deletion |
| Historical contextualization replay used mutable dimension order and callback wiring | P1 | Versioned engine bundles now own dimension order and feature-predicate wiring; callers supply only versioned facts and policy artifacts |
| Full-population witness fallback could persist 1.2 million IDs | P2 | Added explicit bounded/full-population commitment modes, capped stored witnesses at 64, and gated 50,000 evidence items across 24 fallback candidates under predicate, time, and persistence-size budgets |
| Replay accepted malformed member names, invalid UTF-8, and an unbound ambient runtime | P2 | Validate object member names as I-JSON, decode YAML with fatal UTF-8, and bind exact Node, V8, ICU, OS, architecture, base image, OCI manifest, and signature-bundle identity into each engine |
| Prompt safety was a bypassable keyword blocklist | P2 | Replaced free-form normalized topic/path tokens with closed language/domain allowlists, one opaque fallback, and fixed structural path classes; synonym, split-token, homoglyph, URL, role, and tool probes reject leakage |
| Git immutability missed generic nested paths and divergent same-version siblings | P1 | Validate both generic and named direct artifact bindings and enforce one immutable `(kind, version)` identity across every reachable Git snapshot, including sibling histories |
| Deployment App identity gate copied expected policy values | P2 | Added an authenticated GitHub `/app` observation contract with credential fingerprint and provider request/response provenance; startup validation consumes that trusted observation |

The current Phase 0 candidate has 40 compiled schemas, 321 named adversarial
mutations, three byte-checked replay bundles, a 20,000-item full semantic corpus,
and a separate 50,000-item by 24-candidate worst-case contextualization gate.
Per project direction on 2026-07-21, subsequent phase gates use the normal
review/fix loop rather than independent deep-review rounds.

## Normal closeout review

- Snapshot: `5efb1939d670dc2e8fdea1603ca38a55e065edf8d52d4d81e0f9e6373921e549`
- Files: 142
- Gate: 40 compiled schemas, 321 named adversarial mutations, three byte-checked
  replay bundles, whitespace clean, and Markdown clean.
- Fixes: corrected a stale historical deletion-transaction summary and renamed
  the reference container digests as promotion requirements. The runtime contract
  now explicitly remains `promotion_required` until Phase 1 supplies verified
  build provenance; it no longer implies that the reference image was published.
- Result: approved for Phase 1 under the requested normal review/fix process.
