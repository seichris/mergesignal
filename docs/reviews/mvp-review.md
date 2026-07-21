# MVP normal review

## Scope

This is the single normal review/fix pass requested for the reputation MVP. It
covers public GitHub history collection, deterministic scoring, persistence,
Temporal processing, PR output reconciliation, CI, and the worker image. It is
not a deep review loop.

## Findings and resolutions

| Severity | Finding | Resolution |
|---:|---|---|
| P1 | A head-race repair could publish a new generation without assessing that generation | Every repair publication now runs the durable assessment activity before output |
| P1 | Immutable assessment retries could silently accept a different result for the same publication | Persistence now validates the stored snapshot, recomputes the score, canonicalizes component precision, and rejects conflicting retries |
| P1 | Concurrent history writes in one cache window could silently choose different provider evidence | Cache convergence now requires an identical provider-response digest |
| P1 | Restricted contribution aggregates could influence the activity-regularity signal | Active weeks now come only from explicit public commit and PR dates; restricted counts remain coverage metadata |
| P2 | An inaccessible human account could be described as a bot or non-human actor | Webhook `User` actors with inaccessible provider records now render an honest unavailable result |
| P2 | Commit-date evidence could exceed the per-repository cap without lowering confidence | The query collects connection totals and marks any capped commit or PR evidence as truncated |
| P2 | The six-hour cache expiry was aligned to the bucket boundary and could expire early | Every snapshot now remains reusable for six hours from its actual collection time |
| P2 | Unsupported PR actions returned before their latest lifecycle state was stored | Lifecycle state is applied first; only publication is skipped for unsupported actions |
| P2 | Web build and typecheck raced while rewriting `.next/types` | The web typecheck task now depends on its own completed build |

No unresolved P0 or P1 finding remains in the locally reviewable MVP scope.

## Verification

- Scoring tests prove determinism, bounds, monotonicity, private-evidence
  independence, sample weighting, validation, versioning, and confidence behavior.
- GitHub adapter tests cover two observation windows, sparse and renamed users,
  non-users, inaccessible and malformed actors, identity mismatch, evidence caps,
  private repositories, restricted counts, installation authentication, and rate
  limiting.
- Output tests freeze the completed Markdown and prove one-comment convergence,
  unavailable output, marker ownership, and head-race cancellation.
- The fresh PostgreSQL and real local Temporal integration covers webhook ingress,
  immutable assessments, cache reuse, duplicate and racing deliveries, bot and
  unavailable output, reruns, head repair, and one canonical comment.
- Full repository CI passed all 30 Turbo tasks, the 40-schema contract suite with
  321 negative mutations, workspace boundaries, whitespace, and Markdown.
- The fresh lifecycle run completed five publication generations, four immutable
  assessments, one canonical comment, and a current repaired head through a real
  Temporal worker.
- Production worker image
  `sha256:6bb4eb5fc1616eb4417c16d4e061715a626666a57455cfef6aab2b03c2d73116`
  built from Node 22.17.0, returned `{"status":"ready"}`, and drained with exit
  code 0.

## Result

The implementation is approved for the live-release gate. A real GitHub App
installation probe, deployment, and a staging pull request remain required before
the MVP acceptance criteria are complete.
