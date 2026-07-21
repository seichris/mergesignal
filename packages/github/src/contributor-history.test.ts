import { describe, expect, it } from "vitest";

import { calculateReputation } from "@mergesignal/reputation";

import {
  ContributorHistoryUnavailableError,
  collectPublicContributorHistory,
  type ContributorHistoryClient
} from "./contributor-history.js";

const actorNodeId = "U_kgDOBexample";

function pullRequest(index: number, overrides: Record<string, unknown> = {}) {
  return {
    occurredAt: "2026-01-01T00:00:00.000Z",
    pullRequest: {
      state: "MERGED",
      merged: true,
      mergedAt: "2026-01-02T00:00:00.000Z",
      repository: {
        nameWithOwner: `community/repository-${index}`,
        isPrivate: false,
        owner: { login: "community" }
      },
      ...overrides
    }
  };
}

function response(options: {
  login?: string;
  typename?: string;
  id?: string;
  pulls?: Array<ReturnType<typeof pullRequest>>;
  hasNextPage?: boolean;
  endCursor?: string | null;
  restricted?: number;
  commitTotalCount?: number;
  commits?: number;
  issues?: number;
  reviews?: number;
  commitNodes?: Array<{ occurredAt: string; isRestricted: boolean }>;
} = {}) {
  const pulls = options.pulls ?? [pullRequest(1), pullRequest(2)];
  const commitNodes = options.commitNodes ?? [
    { occurredAt: "2026-01-01T00:00:00.000Z", isRestricted: false }
  ];
  return {
    node: {
      __typename: options.typename ?? "User",
      id: options.id ?? actorNodeId,
      login: options.login ?? "contributor",
      createdAt: "2020-01-01T00:00:00.000Z",
      contributionsCollection: {
        restrictedContributionsCount: options.restricted ?? 0,
        totalCommitContributions: options.commits ?? 40,
        totalIssueContributions: options.issues ?? 3,
        totalPullRequestContributions: pulls.length,
        totalPullRequestReviewContributions: options.reviews ?? 5,
        totalRepositoriesWithContributedCommits: commitNodes.length === 0 ? 0 : 1,
        contributionCalendar: {
          weeks: [
            {
              firstDay: "2025-12-28",
              contributionDays: [{ date: "2026-01-01", contributionCount: 3 }]
            }
          ]
        },
        commitContributionsByRepository: commitNodes.length === 0
          ? []
          : [{
            repository: {
              nameWithOwner: "community/repository-1",
              isPrivate: false,
              owner: { login: "community" }
            },
            contributions: {
              totalCount: options.commitTotalCount ?? commitNodes.length,
              nodes: commitNodes
            }
          }],
        pullRequestContributions: {
          nodes: pulls,
          pageInfo: {
            hasNextPage: options.hasNextPage ?? false,
            endCursor: options.endCursor ?? null
          },
          totalCount: pulls.length
        }
      }
    }
  };
}

class FakeClient implements ContributorHistoryClient {
  readonly calls: Array<Readonly<Record<string, unknown>>> = [];

  constructor(private readonly responses: unknown[]) {}

  async installationGraphqlRequest<T>(
    _installationId: number,
    _query: string,
    variables: Readonly<Record<string, unknown>>
  ): Promise<T> {
    this.calls.push(variables);
    const next = this.responses.shift();
    if (next === undefined) throw new Error("No fake GraphQL response remains");
    return next as T;
  }
}

describe("collectPublicContributorHistory", () => {
  it("normalizes two public contribution windows", async () => {
    const client = new FakeClient([response(), response()]);
    const history = await collectPublicContributorHistory(client, {
      installationId: 41,
      actorNodeId,
      now: new Date("2026-07-22T00:00:00.000Z")
    });
    expect(client.calls).toHaveLength(2);
    expect(history).toMatchObject({
      actorNodeId,
      login: "contributor",
      commits: 80,
      issues: 6,
      pullRequests: 4,
      pullRequestReviews: 10,
      activeWeeks: 1,
      externalPullRequestsObserved: 4,
      externalClosedPullRequests: 4,
      externalMergedPullRequests: 4,
      distinctPublicRepositories: 2,
      truncated: false
    });
  });

  it("supports sparse and renamed public accounts by stable node ID", async () => {
    const sparse = response({
      login: "renamed-contributor",
      pulls: [],
      commits: 0,
      issues: 0,
      reviews: 0,
      commitNodes: []
    });
    const history = await collectPublicContributorHistory(
      new FakeClient([sparse, sparse]),
      {
        installationId: 41,
        actorNodeId,
        now: new Date("2026-07-22T00:00:00.000Z")
      }
    );
    expect(history).toMatchObject({
      actorNodeId,
      login: "renamed-contributor",
      commits: 0,
      activeWeeks: 0,
      externalPullRequestsObserved: 0
    });
  });

  it("excludes private and contributor-owned repositories from independent PR metrics", async () => {
    const owned = pullRequest(1, {
      repository: {
        nameWithOwner: "Contributor/project",
        isPrivate: false,
        owner: { login: "CONTRIBUTOR" }
      }
    });
    const privatePull = pullRequest(2, {
      repository: {
        nameWithOwner: "private/project",
        isPrivate: true,
        owner: { login: "private" }
      }
    });
    const client = new FakeClient([
      response({ pulls: [owned, privatePull] }),
      response({ pulls: [owned, privatePull] })
    ]);
    const history = await collectPublicContributorHistory(client, {
      installationId: 41,
      actorNodeId,
      now: new Date("2026-07-22T00:00:00.000Z")
    });
    expect(history.externalPullRequestsObserved).toBe(0);
  });

  it("retains restricted counts only as coverage metadata", async () => {
    const client = new FakeClient([response({ restricted: 8 }), response({ restricted: 5 })]);
    const history = await collectPublicContributorHistory(client, {
      installationId: 41,
      actorNodeId,
      now: new Date("2026-07-22T00:00:00.000Z")
    });
    expect(history.restrictedContributions).toBe(13);
  });

  it("does not let restricted contribution counts change score-driving metrics", async () => {
    const withoutRestricted = await collectPublicContributorHistory(
      new FakeClient([response(), response()]),
      {
        installationId: 41,
        actorNodeId,
        now: new Date("2026-07-22T00:00:00.000Z")
      }
    );
    const withRestricted = await collectPublicContributorHistory(
      new FakeClient([response({ restricted: 500 }), response({ restricted: 500 })]),
      {
        installationId: 41,
        actorNodeId,
        now: new Date("2026-07-22T00:00:00.000Z")
      }
    );
    expect(calculateReputation(withRestricted)).toEqual(calculateReputation(withoutRestricted));
  });

  it("marks a capped contribution window as truncated", async () => {
    const pulls = Array.from({ length: 100 }, (_, index) => pullRequest(index));
    const client = new FakeClient([
      response({ pulls, hasNextPage: true, endCursor: "cursor" }),
      response()
    ]);
    const history = await collectPublicContributorHistory(client, {
      installationId: 41,
      actorNodeId,
      now: new Date("2026-07-22T00:00:00.000Z")
    });
    expect(history.truncated).toBe(true);
  });

  it("marks capped commit evidence as truncated", async () => {
    const client = new FakeClient([
      response({ commitTotalCount: 51 }),
      response()
    ]);
    const history = await collectPublicContributorHistory(client, {
      installationId: 41,
      actorNodeId,
      now: new Date("2026-07-22T00:00:00.000Z")
    });
    expect(history.truncated).toBe(true);
  });

  it("distinguishes an inaccessible actor from a non-user actor", async () => {
    await expect(
      collectPublicContributorHistory(new FakeClient([{ node: null }]), {
        installationId: 41,
        actorNodeId,
        now: new Date("2026-07-22T00:00:00.000Z")
      })
    ).rejects.toMatchObject<Partial<ContributorHistoryUnavailableError>>({
      reason: "provider_unavailable"
    });
  });

  it("rejects non-user and mismatched identities", async () => {
    await expect(
      collectPublicContributorHistory(new FakeClient([response({ typename: "Bot" })]), {
        installationId: 41,
        actorNodeId,
        now: new Date("2026-07-22T00:00:00.000Z")
      })
    ).rejects.toMatchObject<Partial<ContributorHistoryUnavailableError>>({
      reason: "actor_not_user"
    });
    await expect(
      collectPublicContributorHistory(new FakeClient([response({ id: "U_other" })]), {
        installationId: 41,
        actorNodeId,
        now: new Date("2026-07-22T00:00:00.000Z")
      })
    ).rejects.toMatchObject<Partial<ContributorHistoryUnavailableError>>({
      reason: "identity_mismatch"
    });
  });

  it("turns malformed provider data into a typed unavailable result", async () => {
    await expect(
      collectPublicContributorHistory(
        new FakeClient([
          response({ login: "not a valid login" }),
          response({ login: "not a valid login" })
        ]),
        {
          installationId: 41,
          actorNodeId,
          now: new Date("2026-07-22T00:00:00.000Z")
        }
      )
    ).rejects.toMatchObject<Partial<ContributorHistoryUnavailableError>>({
      reason: "invalid_provider_data"
    });
  });
});
