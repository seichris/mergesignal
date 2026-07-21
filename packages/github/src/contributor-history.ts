import { z } from "zod";

import {
  publicContributorHistorySchema,
  type PublicContributorHistory
} from "@mergesignal/reputation";

const DAY_MILLISECONDS = 24 * 60 * 60 * 1_000;
const MAX_PULL_REQUESTS = 200;

export type ContributorHistoryUnavailableReason =
  | "actor_not_user"
  | "identity_mismatch"
  | "invalid_provider_data"
  | "provider_unavailable";

export class ContributorHistoryUnavailableError extends Error {
  constructor(readonly reason: ContributorHistoryUnavailableReason, message: string) {
    super(message);
    this.name = "ContributorHistoryUnavailableError";
  }
}

export interface ContributorHistoryClient {
  installationGraphqlRequest<T>(
    installationId: number,
    query: string,
    variables: Readonly<Record<string, unknown>>
  ): Promise<T>;
}

const repositorySchema = z.object({
  nameWithOwner: z.string().min(3),
  isPrivate: z.boolean(),
  owner: z.object({ login: z.string().min(1) })
});

const contributionCollectionSchema = z.object({
  restrictedContributionsCount: z.number().int().min(0),
  totalCommitContributions: z.number().int().min(0),
  totalIssueContributions: z.number().int().min(0),
  totalPullRequestContributions: z.number().int().min(0),
  totalPullRequestReviewContributions: z.number().int().min(0),
  totalRepositoriesWithContributedCommits: z.number().int().min(0),
  commitContributionsByRepository: z.array(z.object({
    repository: repositorySchema,
    contributions: z.object({
      totalCount: z.number().int().min(0),
      nodes: z.array(z.object({
        occurredAt: z.iso.datetime(),
        isRestricted: z.boolean()
      }).nullable())
    })
  })),
  pullRequestContributions: z.object({
    nodes: z.array(z.object({
      occurredAt: z.iso.datetime(),
      pullRequest: z.object({
        state: z.enum(["OPEN", "CLOSED", "MERGED"]),
        merged: z.boolean(),
        mergedAt: z.iso.datetime().nullable(),
        repository: repositorySchema
      })
    }).nullable()),
    pageInfo: z.object({
      hasNextPage: z.boolean(),
      endCursor: z.string().nullable()
    }),
    totalCount: z.number().int().min(0)
  })
});

const responseSchema = z.object({
  node: z
    .object({
      __typename: z.string(),
      id: z.string().optional(),
      login: z.string().optional(),
      createdAt: z.iso.datetime().optional(),
      contributionsCollection: contributionCollectionSchema.optional()
    })
    .nullable()
});

const CONTRIBUTOR_HISTORY_QUERY = `
  query MergeSignalContributorHistory(
    $actorId: ID!
    $from: DateTime!
    $until: DateTime!
    $after: String
    $pageSize: Int!
  ) {
    node(id: $actorId) {
      __typename
      ... on User {
        id
        login
        createdAt
        contributionsCollection(from: $from, to: $until) {
          restrictedContributionsCount
          totalCommitContributions
          totalIssueContributions
          totalPullRequestContributions
          totalPullRequestReviewContributions
          totalRepositoriesWithContributedCommits
          commitContributionsByRepository(maxRepositories: 10) {
            repository { nameWithOwner isPrivate owner { login } }
            contributions(first: 50) {
              totalCount
              nodes { occurredAt isRestricted }
            }
          }
          pullRequestContributions(
            first: $pageSize
            after: $after
            orderBy: { direction: DESC }
          ) {
            totalCount
            nodes {
              occurredAt
              pullRequest {
                state
                merged
                mergedAt
                repository { nameWithOwner isPrivate owner { login } }
              }
            }
            pageInfo { hasNextPage endCursor }
          }
        }
      }
    }
  }
`;

interface WindowResult {
  identity: { id: string; login: string; createdAt: string };
  commits: number;
  issues: number;
  pullRequests: number;
  pullRequestReviews: number;
  restrictedContributions: number;
  activeWeekKeys: Set<string>;
  repositories: Set<string>;
  externalObserved: number;
  externalClosed: number;
  externalMerged: number;
  truncated: boolean;
}

function emptyWindow(identity: WindowResult["identity"]): WindowResult {
  return {
    identity,
    commits: 0,
    issues: 0,
    pullRequests: 0,
    pullRequestReviews: 0,
    restrictedContributions: 0,
    activeWeekKeys: new Set(),
    repositories: new Set(),
    externalObserved: 0,
    externalClosed: 0,
    externalMerged: 0,
    truncated: false
  };
}

function weekKey(dateValue: string): string {
  const date = new Date(`${dateValue.slice(0, 10)}T00:00:00.000Z`);
  if (!Number.isFinite(date.getTime())) {
    throw new ContributorHistoryUnavailableError(
      "invalid_provider_data",
      "GitHub contribution date is invalid"
    );
  }
  date.setUTCDate(date.getUTCDate() - date.getUTCDay());
  return date.toISOString().slice(0, 10);
}

function requireUser(response: z.infer<typeof responseSchema>, actorNodeId: string) {
  const node = response.node;
  if (node === null) {
    throw new ContributorHistoryUnavailableError(
      "provider_unavailable",
      "GitHub actor is not publicly accessible"
    );
  }
  if (node.__typename !== "User") {
    throw new ContributorHistoryUnavailableError(
      "actor_not_user",
      "GitHub actor is not a human user"
    );
  }
  if (
    node.id === undefined ||
    node.login === undefined ||
    node.createdAt === undefined ||
    node.contributionsCollection === undefined
  ) {
    throw new ContributorHistoryUnavailableError(
      "invalid_provider_data",
      "GitHub omitted required contributor history fields"
    );
  }
  if (node.id !== actorNodeId) {
    throw new ContributorHistoryUnavailableError(
      "identity_mismatch",
      "GitHub returned a different actor identity"
    );
  }
  return {
    identity: { id: node.id, login: node.login, createdAt: node.createdAt },
    collection: node.contributionsCollection
  };
}

async function collectWindow(
  client: ContributorHistoryClient,
  input: {
    installationId: number;
    actorNodeId: string;
    from: Date;
    until: Date;
    remainingPullRequests: number;
  }
): Promise<WindowResult> {
  let after: string | null = null;
  let result: WindowResult | null = null;
  let collected = 0;
  do {
    const pageSize = Math.min(100, input.remainingPullRequests - collected);
    if (pageSize <= 0) {
      if (result !== null) result.truncated = true;
      break;
    }
    const raw: unknown = await client.installationGraphqlRequest(
      input.installationId,
      CONTRIBUTOR_HISTORY_QUERY,
      {
        actorId: input.actorNodeId,
        from: input.from.toISOString(),
        until: input.until.toISOString(),
        after,
        pageSize
      }
    );
    let parsed: z.infer<typeof responseSchema>;
    try {
      parsed = responseSchema.parse(raw);
    } catch (error) {
      throw new ContributorHistoryUnavailableError(
        "invalid_provider_data",
        error instanceof Error ? error.message : "GitHub returned invalid contributor history"
      );
    }
    const { identity, collection } = requireUser(parsed, input.actorNodeId);
    result ??= emptyWindow(identity);
    if (result.identity.login !== identity.login || result.identity.createdAt !== identity.createdAt) {
      throw new ContributorHistoryUnavailableError(
        "identity_mismatch",
        "GitHub actor identity changed during pagination"
      );
    }
    if (after === null) {
      result.commits = collection.totalCommitContributions;
      result.issues = collection.totalIssueContributions;
      result.pullRequests = collection.totalPullRequestContributions;
      result.pullRequestReviews = collection.totalPullRequestReviewContributions;
      result.restrictedContributions = collection.restrictedContributionsCount;
      if (
        collection.totalRepositoriesWithContributedCommits >
        collection.commitContributionsByRepository.length
      ) {
        result.truncated = true;
      }
      if (collection.pullRequestContributions.totalCount > input.remainingPullRequests) {
        result.truncated = true;
      }
      for (const contribution of collection.commitContributionsByRepository) {
        if (contribution.contributions.totalCount > contribution.contributions.nodes.length) {
          result.truncated = true;
        }
        if (!contribution.repository.isPrivate) {
          result.repositories.add(contribution.repository.nameWithOwner.toLowerCase());
          for (const commit of contribution.contributions.nodes) {
            if (commit !== null && !commit.isRestricted) {
              result.activeWeekKeys.add(weekKey(commit.occurredAt));
            }
          }
        }
      }
    }
    for (const node of collection.pullRequestContributions.nodes) {
      if (node === null || node.pullRequest.repository.isPrivate) continue;
      result.activeWeekKeys.add(weekKey(node.occurredAt));
      result.repositories.add(node.pullRequest.repository.nameWithOwner.toLowerCase());
      if (node.pullRequest.repository.owner.login.toLowerCase() === identity.login.toLowerCase()) {
        continue;
      }
      result.externalObserved += 1;
      if (node.pullRequest.state !== "OPEN") result.externalClosed += 1;
      if (node.pullRequest.merged) result.externalMerged += 1;
    }
    collected += collection.pullRequestContributions.nodes.length;
    const pageInfo = collection.pullRequestContributions.pageInfo;
    if (!pageInfo.hasNextPage) break;
    if (pageInfo.endCursor === null) {
      throw new ContributorHistoryUnavailableError(
        "invalid_provider_data",
        "GitHub pagination omitted its next cursor"
      );
    }
    after = pageInfo.endCursor;
    if (collected >= input.remainingPullRequests) {
      result.truncated = true;
      break;
    }
  } while (true);
  if (result === null) {
    throw new ContributorHistoryUnavailableError(
      "invalid_provider_data",
      "GitHub contributor history collection was empty"
    );
  }
  return result;
}

export async function collectPublicContributorHistory(
  client: ContributorHistoryClient,
  input: { installationId: number; actorNodeId: string; now?: Date }
): Promise<PublicContributorHistory> {
  const now = input.now ?? new Date();
  if (!Number.isFinite(now.getTime())) throw new Error("Contributor observation time is invalid");
  const middle = new Date(now.getTime() - 365 * DAY_MILLISECONDS);
  const start = new Date(now.getTime() - 730 * DAY_MILLISECONDS);
  const recent = await collectWindow(client, {
    installationId: input.installationId,
    actorNodeId: input.actorNodeId,
    from: middle,
    until: now,
    remainingPullRequests: MAX_PULL_REQUESTS / 2
  });
  const older = await collectWindow(client, {
    installationId: input.installationId,
    actorNodeId: input.actorNodeId,
    from: start,
    until: new Date(middle.getTime() - 1),
    remainingPullRequests: MAX_PULL_REQUESTS / 2
  });
  if (
    recent.identity.id !== older.identity.id ||
    recent.identity.login !== older.identity.login ||
    recent.identity.createdAt !== older.identity.createdAt
  ) {
    throw new ContributorHistoryUnavailableError(
      "identity_mismatch",
      "GitHub actor identity changed between contribution windows"
    );
  }
  const createdAt = new Date(recent.identity.createdAt);
  if (!Number.isFinite(createdAt.getTime()) || createdAt > now) {
    throw new ContributorHistoryUnavailableError(
      "invalid_provider_data",
      "GitHub account creation time is invalid"
    );
  }
  const activeWeeks = new Set([...older.activeWeekKeys, ...recent.activeWeekKeys]);
  const repositories = new Set([...older.repositories, ...recent.repositories]);
  try {
    return publicContributorHistorySchema.parse({
      actorNodeId: recent.identity.id,
      login: recent.identity.login,
      accountCreatedAt: createdAt.toISOString(),
      observedFrom: start.toISOString(),
      observedUntil: now.toISOString(),
      accountAgeDays: Math.floor((now.getTime() - createdAt.getTime()) / DAY_MILLISECONDS),
      commits: older.commits + recent.commits,
      issues: older.issues + recent.issues,
      pullRequests: older.pullRequests + recent.pullRequests,
      pullRequestReviews: older.pullRequestReviews + recent.pullRequestReviews,
      activeWeeks: Math.min(activeWeeks.size, 104),
      externalPullRequestsObserved: older.externalObserved + recent.externalObserved,
      externalClosedPullRequests: older.externalClosed + recent.externalClosed,
      externalMergedPullRequests: older.externalMerged + recent.externalMerged,
      distinctPublicRepositories: repositories.size,
      restrictedContributions: older.restrictedContributions + recent.restrictedContributions,
      truncated: older.truncated || recent.truncated
    });
  } catch (error) {
    throw new ContributorHistoryUnavailableError(
      "invalid_provider_data",
      error instanceof Error ? error.message : "GitHub history could not be normalized"
    );
  }
}
