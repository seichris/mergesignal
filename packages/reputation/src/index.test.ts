import { describe, expect, it } from "vitest";

import {
  MVP_SCORING_VERSION,
  calculateReputation,
  publicContributorHistorySchema,
  type PublicContributorHistory
} from "./index.js";

function history(overrides: Partial<PublicContributorHistory> = {}): PublicContributorHistory {
  return {
    actorNodeId: "U_kgDOBexample",
    login: "contributor",
    accountCreatedAt: "2020-01-01T00:00:00.000Z",
    observedFrom: "2024-07-22T00:00:00.000Z",
    observedUntil: "2026-07-22T00:00:00.000Z",
    accountAgeDays: 2_394,
    commits: 250,
    issues: 20,
    pullRequests: 40,
    pullRequestReviews: 30,
    activeWeeks: 60,
    externalPullRequestsObserved: 30,
    externalClosedPullRequests: 25,
    externalMergedPullRequests: 20,
    distinctPublicRepositories: 10,
    restrictedContributions: 0,
    truncated: false,
    ...overrides
  };
}

describe("mvp-v1 reputation scoring", () => {
  it("is deterministic, bounded, and versioned", () => {
    const first = calculateReputation(history());
    const second = calculateReputation(history());
    expect(first).toEqual(second);
    expect(first.scoringVersion).toBe(MVP_SCORING_VERSION);
    expect(first.score).toBeGreaterThanOrEqual(0);
    expect(first.score).toBeLessThanOrEqual(100);
    expect(Object.values(first.components).every((value) => value >= 0)).toBe(true);
  });

  it("does not let restricted contributions affect the score", () => {
    expect(calculateReputation(history({ restrictedContributions: 0 }))).toEqual(
      calculateReputation(history({ restrictedContributions: 999_999 }))
    );
  });

  it("uses a sample weight for merge ratio", () => {
    const oneOfOne = calculateReputation(history({
      externalPullRequestsObserved: 1,
      externalClosedPullRequests: 1,
      externalMergedPullRequests: 1
    }));
    const fiveOfFive = calculateReputation(history({
      externalPullRequestsObserved: 5,
      externalClosedPullRequests: 5,
      externalMergedPullRequests: 5
    }));
    expect(fiveOfFive.components.mergedPullRequests).toBeGreaterThan(
      oneOfOne.components.mergedPullRequests
    );
  });

  it("lowers confidence for truncated evidence", () => {
    expect(calculateReputation(history()).confidence).toBe("high");
    expect(calculateReputation(history({ truncated: true })).confidence).toBe("limited");
  });

  it("rejects contradictory and missing metrics instead of scoring them as zero", () => {
    expect(() => calculateReputation(history({
      externalPullRequestsObserved: 1,
      externalClosedPullRequests: 2
    }))).toThrow();
    expect(() => publicContributorHistorySchema.parse({ login: "contributor" })).toThrow();
  });

  it("is monotonic for each positive numeric metric", () => {
    const metrics: Array<keyof PublicContributorHistory> = [
      "accountAgeDays",
      "commits",
      "issues",
      "pullRequests",
      "pullRequestReviews",
      "activeWeeks",
      "externalMergedPullRequests",
      "distinctPublicRepositories"
    ];
    for (const metric of metrics) {
      const baseline = history({
        accountAgeDays: 100,
        commits: 1,
        issues: 1,
        pullRequests: 1,
        pullRequestReviews: 1,
        activeWeeks: 1,
        externalPullRequestsObserved: 10,
        externalClosedPullRequests: 10,
        externalMergedPullRequests: 1,
        distinctPublicRepositories: 1
      });
      const increased = { ...baseline, [metric]: (baseline[metric] as number) + 1 };
      expect(calculateReputation(increased).score).toBeGreaterThanOrEqual(
        calculateReputation(baseline).score
      );
    }
  });

  it("stays bounded over a broad deterministic input grid", () => {
    for (let index = 0; index < 500; index += 1) {
      const closed = index % 201;
      const merged = closed === 0 ? 0 : index % (closed + 1);
      const result = calculateReputation(history({
        accountAgeDays: index * 50,
        commits: index * 1_000,
        issues: index * 2,
        pullRequests: index * 3,
        pullRequestReviews: index * 4,
        activeWeeks: index % 105,
        externalPullRequestsObserved: closed,
        externalClosedPullRequests: closed,
        externalMergedPullRequests: merged,
        distinctPublicRepositories: index * 5
      }));
      expect(result.score).toBeGreaterThanOrEqual(0);
      expect(result.score).toBeLessThanOrEqual(100);
    }
  });
});
