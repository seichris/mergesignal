export const evaluatorContractVersion = "feature-evaluator-v1";

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function setEquals(left, right) {
  return left.size === right.size && [...left].every((item) => right.has(item));
}

function pullRequestIdentity(item) {
  const payload = item.canonicalPayload;
  if (!payload.pullRequestNodeId) return null;
  return {
    pullRequestNodeId: payload.pullRequestNodeId,
    repositoryNodeId: payload.repositoryNodeId ?? item.repositoryNodeId ?? null,
    pullRequestNumber: payload.pullRequestNumber ?? null,
    authorNodeId: payload.authorNodeId ?? payload.pullRequestAuthorNodeId ?? null
  };
}

function samePullRequestIdentity(left, right) {
  const a = pullRequestIdentity(left);
  const b = pullRequestIdentity(right);
  if (!a || !b) return false;
  return (
    a.pullRequestNodeId === b.pullRequestNodeId &&
    a.repositoryNodeId === b.repositoryNodeId &&
    a.pullRequestNumber === b.pullRequestNumber &&
    (a.authorNodeId === null || b.authorNodeId === null || a.authorNodeId === b.authorNodeId)
  );
}

export function classifyPathLanguage(path, policy) {
  const normalized = policy.caseSensitive ? path : path.toLowerCase();
  const extensions = Object.keys(policy.extensionMap).sort(
    (left, right) => right.length - left.length || compareUtf8(left, right)
  );
  const extension = extensions.find((candidate) => normalized.endsWith(candidate));
  return extension === undefined ? policy.fallback : policy.extensionMap[extension];
}

export function calculateCoverageFreshness(freshAsOf, capturedAt, policy) {
  return new Date(capturedAt) - new Date(freshAsOf) <= policy.maxAgeSeconds * 1000
    ? "current"
    : "stale";
}

export function calculateCoverageConfidence({ completeYears, requestedWindowYears, completePartitions, totalPartitions, attribution, freshness }, policy) {
  const multiplier = 10 ** policy.precision;
  const value =
    (completeYears / requestedWindowYears) *
    (completePartitions / totalPartitions) *
    policy.attributionFactors[attribution] *
    policy.freshnessFactors[freshness];
  return Math.round((value + Number.EPSILON) * multiplier) / multiplier;
}

export function evaluateReasonPredicate({ predicate, evidenceIds, evidenceById, subjectNodeId, target, features, authoritativeHistoryEvidenceIds }) {
  const items = evidenceIds.map((id) => evidenceById.get(id)).filter(Boolean);
  const ofType = (type) => items.filter((item) => item.type === type);
  const coverage = ofType("PUBLIC_COVERAGE_SUMMARY")[0]?.canonicalPayload;
  const activeMonths = [...new Set(ofType("ACTIVE_MONTH").map((item) => item.canonicalPayload.yearMonth))].sort(compareUtf8);
  const comparisonForTarget = ofType("RELEVANCE_COMPARISON").find(
    (item) =>
      item.canonicalPayload.targetPullRequestNodeId === target.pullRequestNodeId &&
      item.canonicalPayload.targetRepositoryNodeId === target.repositoryNodeId &&
      item.canonicalPayload.targetHeadSha === target.headSha
  )?.canonicalPayload;

  switch (predicate) {
    case "account_tenure_established_v1": {
      const createdAt = ofType("ACCOUNT_CREATED")[0]?.canonicalPayload.createdAt;
      const minimumTenureMs = features.accountTenureMinimumDays * 24 * 60 * 60 * 1000;
      return Boolean(
        createdAt &&
          ofType("CONTRIBUTION_YEAR").some((item) =>
            item.canonicalPayload.activeMonths.some(
              (month) => new Date(`${month}-01T00:00:00Z`) - new Date(createdAt) >= minimumTenureMs
            )
          )
      );
    }
    case "sustained_activity_v1":
      return (
        activeMonths.length >= features.sustainedActivity.minimumActiveMonths &&
        new Date(`${activeMonths.at(-1)}-01T00:00:00Z`) - new Date(`${activeMonths[0]}-01T00:00:00Z`) >=
          features.sustainedActivity.minimumSpanDays * 24 * 60 * 60 * 1000
      );
    case "multi_year_continuity_v1": {
      const years = new Set(ofType("CONTRIBUTION_YEAR").map((item) => item.canonicalPayload.year));
      const activeYears = new Set(activeMonths.map((month) => Number(month.slice(0, 4))));
      return (
        years.size >= features.multiYearContinuity.minimumActiveYears &&
        activeYears.size >= features.multiYearContinuity.minimumActiveYears &&
        activeMonths.every((month) => years.has(Number(month.slice(0, 4))))
      );
    }
    case "limited_public_history_v1":
      return Boolean(
        coverage &&
          (coverage.completeYears < 2 ||
            coverage.confidence < 0.75 ||
            coverage.partialSources.length > 0 ||
            coverage.attribution !== "complete")
      );
    case "history_partially_accessible_v1":
      return Boolean(coverage && coverage.partialSources.length > 0);
    case "history_truncated_v1":
      return Boolean(
        coverage &&
          coverage.partialSources.some((source) => ["rate_limit", "pagination_limit", "source_limit"].includes(source))
      );
    case "evidence_stale_v1":
      return coverage?.freshness === "stale";
    case "attribution_uncertain_v1":
      return coverage?.attribution === "uncertain";
    case "unsupported_actor_type_v1":
      return (
        ofType("AUTHOR_AVAILABILITY").some((item) => item.canonicalPayload.available) &&
        ofType("ACTOR_TYPE").some((item) => item.canonicalPayload.actorType !== "User") &&
        Boolean(coverage)
      );
    case "author_unavailable_v1":
      return (
        ofType("AUTHOR_AVAILABILITY").some(
          (item) => !item.canonicalPayload.available && item.canonicalPayload.authorNodeId === null
        ) && Boolean(coverage)
      );
    case "independent_merges_v1": {
      const merged = ofType("PULL_REQUEST_MERGED");
      const actors = ofType("MERGE_ACTOR");
      const relationships = ofType("REPOSITORY_OWNERSHIP_RELATIONSHIP").filter(
        (item) => item.canonicalPayload.classification === "independently_maintained"
      );
      return relationships.some((relationship) => {
        const pr = relationship.canonicalPayload.pullRequestNodeId;
        return (
          relationship.canonicalPayload.subjectNodeId === subjectNodeId &&
          merged.some(
            (item) => item.canonicalPayload.pullRequestNodeId === pr && item.repositoryNodeId === relationship.repositoryNodeId
          ) &&
          actors.some(
            (item) =>
              item.canonicalPayload.pullRequestNodeId === pr &&
              item.repositoryNodeId === relationship.repositoryNodeId &&
              item.canonicalPayload.githubNodeId !== subjectNodeId
          )
        );
      });
    }
    case "multi_repository_validation_v1":
      return new Set(
        ofType("REPOSITORY_OWNERSHIP_RELATIONSHIP")
          .filter((item) => item.canonicalPayload.classification === "independently_maintained")
          .map((item) => item.repositoryNodeId)
      ).size >= 2;
    case "merge_follow_through_v1": {
      const opened = ofType("PULL_REQUEST_OPENED");
      const merged = ofType("PULL_REQUEST_MERGED");
      return new Set(
        opened
          .filter((item) => merged.some((candidate) => samePullRequestIdentity(item, candidate)))
          .map((item) => item.canonicalPayload.pullRequestNodeId)
      ).size >= 2;
    }
    case "review_follow_through_v1":
      return ofType("REVIEW_RECEIVED").some((review) =>
        review.canonicalPayload.state === "CHANGES_REQUESTED" &&
        [...ofType("FOLLOW_UP_COMMIT"), ...ofType("REVIEW_THREAD_RESOLVED")].some(
          (followUp) =>
            samePullRequestIdentity(review, followUp) &&
            (followUp.canonicalPayload.commitAuthorNodeId ?? followUp.canonicalPayload.resolverNodeId) === subjectNodeId &&
            new Date(followUp.canonicalPayload.committedAt ?? followUp.canonicalPayload.resolvedAt) >
              new Date(review.canonicalPayload.submittedAt)
        )
      );
    case "reviews_contributed_v1":
      return ofType("REVIEW_GIVEN").some(
        (item) => item.canonicalPayload.reviewerNodeId === subjectNodeId && item.canonicalPayload.pullRequestAuthorNodeId !== subjectNodeId
      );
    case "relevant_language_history_v1":
      return Boolean(comparisonForTarget?.languageMatches.length);
    case "relevant_domain_history_v1":
      return Boolean(comparisonForTarget?.domainMatches.length);
    case "relevant_path_history_v1":
      return Boolean(comparisonForTarget?.pathMatches.length);
    case "independence_unclear_v1":
      return ofType("REPOSITORY_OWNERSHIP_RELATIONSHIP").some(
        (item) => ["unknown", "affiliated"].includes(item.canonicalPayload.classification)
      );
    case "self_merge_dominated_v1": {
      const closedTypes = new Set(["PULL_REQUEST_MERGED", "MERGE_ACTOR", "REPOSITORY_OWNERSHIP_RELATIONSHIP"]);
      const authoritativeIds = new Set(
        [...authoritativeHistoryEvidenceIds].filter((id) => closedTypes.has(evidenceById.get(id)?.type))
      );
      const selectedClosedIds = new Set(items.filter((item) => closedTypes.has(item.type)).map((item) => item.evidenceId));
      if (!setEquals(authoritativeIds, selectedClosedIds)) return false;
      const relationships = ofType("REPOSITORY_OWNERSHIP_RELATIONSHIP");
      const actors = ofType("MERGE_ACTOR");
      const merged = ofType("PULL_REQUEST_MERGED");
      const classified = relationships.filter((relationship) =>
        merged.some(
          (item) =>
            item.canonicalPayload.pullRequestNodeId === relationship.canonicalPayload.pullRequestNodeId &&
            item.repositoryNodeId === relationship.repositoryNodeId
        )
      );
      const dominated = classified.filter((relationship) =>
        actors.some(
          (actor) =>
            actor.canonicalPayload.pullRequestNodeId === relationship.canonicalPayload.pullRequestNodeId &&
            actor.repositoryNodeId === relationship.repositoryNodeId &&
            actor.canonicalPayload.githubNodeId === subjectNodeId
        )
      );
      return classified.length >= 2 && dominated.length / classified.length > 0.5;
    }
    case "recent_activity_anomaly_v1":
      return ofType("ACTIVITY_BURST").some(
        (item) => item.canonicalPayload.ratio >= 3 && item.canonicalPayload.recentActiveMonths >= 2
      );
    case "reciprocal_pattern_v1":
      return ofType("RECIPROCAL_MERGE_EDGE").some(
        (item) => item.canonicalPayload.mergeCount >= 3 && item.canonicalPayload.ratio >= 0.8
      );
    case "templated_activity_pattern_v1":
      return ofType("TEMPLATE_SIMILARITY").some(
        (item) => item.canonicalPayload.sampleSize >= 5 && item.canonicalPayload.repositoryCount >= 5 && item.canonicalPayload.similarity >= 0.9
      );
    case "recent_behavior_change_v1":
      return ofType("BEHAVIOR_BASELINE_CHANGE").some(
        (item) => item.canonicalPayload.recentActiveMonths >= 2 && item.canonicalPayload.relativeIncrease >= 2
      );
    case "model_explanation_unavailable_v1":
      return ofType("CONTEXTUALIZER_STATUS").some((item) => item.canonicalPayload.state !== "complete");
    case "ci_passing_v1":
      return ofType("CI_CHECK_STATE").some((item) => item.canonicalPayload.state === "passing");
    case "ci_failing_v1":
      return ofType("CI_CHECK_STATE").some((item) => item.canonicalPayload.state === "failing");
    case "ci_incomplete_v1":
      return ofType("CI_CHECK_STATE").some((item) => ["pending", "missing", "unknown"].includes(item.canonicalPayload.state));
    case "patch_inventory_incomplete_v1":
      return (
        ofType("PATCH_FILESET_STATUS").some((item) => !item.canonicalPayload.complete) &&
        ofType("TEST_PATH_CHANGE").some((item) => item.canonicalPayload.state === "unknown") &&
        ofType("SENSITIVE_PATH_CHANGE").some((item) => item.canonicalPayload.state === "unknown")
      );
    case "tests_changed_v1":
      return ofType("TEST_PATH_CHANGE").some((item) => item.canonicalPayload.state === "changed");
    case "linked_issue_present_v1":
      return ofType("LINKED_ISSUE").length > 0;
    case "sensitive_path_changed_v1":
      return ofType("SENSITIVE_PATH_CHANGE").some((item) => item.canonicalPayload.state === "changed");
    case "large_patch_scope_v1":
      return ofType("PATCH_SCOPE").some((item) => item.canonicalPayload.classification === "large");
    default:
      throw new Error(`Reason predicate has no implementation: ${predicate}`);
  }
}
