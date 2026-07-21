import {
  type GitHubOutputProvider,
  type ProviderCheckRun,
  type ProviderComment,
  type PullRequestOutputTarget
} from "@mergesignal/github-output";

import { GitHubApiError, GitHubAppClient } from "./client.js";

function repositoryPath(target: PullRequestOutputTarget): string {
  return `/repos/${encodeURIComponent(target.owner)}/${encodeURIComponent(target.repository)}`;
}

function mapComment(comment: {
  id: number;
  body: string | null;
  performed_via_github_app?: { id: number } | null;
}): ProviderComment {
  return {
    id: comment.id,
    body: comment.body ?? "",
    performedViaGitHubAppId: comment.performed_via_github_app?.id ?? null
  };
}

export class GitHubRestOutputProvider implements GitHubOutputProvider {
  constructor(private readonly client: GitHubAppClient) {}

  async getPullRequestHead(target: PullRequestOutputTarget): Promise<string> {
    const pullRequest = await this.client.installationRequest<{ head: { sha: string } }>(
      target.installationId,
      target.repositoryId,
      `${repositoryPath(target)}/pulls/${target.pullRequestNumber}`
    );
    return pullRequest.head.sha.toLowerCase();
  }

  async listPullRequestComments(target: PullRequestOutputTarget): Promise<ProviderComment[]> {
    const comments: ProviderComment[] = [];
    for (let page = 1; page <= 100; page += 1) {
      const response = await this.client.installationRequest<
        Array<{
          id: number;
          body: string | null;
          performed_via_github_app?: { id: number } | null;
        }>
      >(
        target.installationId,
        target.repositoryId,
        `${repositoryPath(target)}/issues/${target.pullRequestNumber}/comments?per_page=100&page=${page}`
      );
      comments.push(...response.map(mapComment));
      if (response.length < 100) return comments;
    }
    throw new Error("GitHub comment inventory exceeded the bounded pagination limit");
  }

  async getComment(
    target: PullRequestOutputTarget,
    commentId: number
  ): Promise<ProviderComment | null> {
    try {
      return mapComment(
        await this.client.installationRequest<{
          id: number;
          body: string | null;
          performed_via_github_app?: { id: number } | null;
        }>(
          target.installationId,
          target.repositoryId,
          `${repositoryPath(target)}/issues/comments/${commentId}`
        )
      );
    } catch (error) {
      if (error instanceof GitHubApiError && error.status === 404) return null;
      throw error;
    }
  }

  async createComment(
    target: PullRequestOutputTarget,
    body: string
  ): Promise<ProviderComment> {
    return mapComment(
      await this.client.installationRequest<{
        id: number;
        body: string | null;
        performed_via_github_app?: { id: number } | null;
      }>(
        target.installationId,
        target.repositoryId,
        `${repositoryPath(target)}/issues/${target.pullRequestNumber}/comments`,
        { method: "POST", body: { body } }
      )
    );
  }

  async updateComment(
    target: PullRequestOutputTarget,
    commentId: number,
    body: string
  ): Promise<ProviderComment> {
    return mapComment(
      await this.client.installationRequest<{
        id: number;
        body: string | null;
        performed_via_github_app?: { id: number } | null;
      }>(
        target.installationId,
        target.repositoryId,
        `${repositoryPath(target)}/issues/comments/${commentId}`,
        { method: "PATCH", body: { body } }
      )
    );
  }

  async createCheckRun(
    target: PullRequestOutputTarget,
    input: { status: "in_progress"; title: string; summary: string }
  ): Promise<ProviderCheckRun> {
    const result = await this.client.installationRequest<{ id: number; head_sha: string }>(
      target.installationId,
      target.repositoryId,
      `${repositoryPath(target)}/check-runs`,
      {
        method: "POST",
        body: {
          name: "MergeSignal",
          head_sha: target.headSha,
          status: input.status,
          output: { title: input.title, summary: input.summary }
        }
      }
    );
    return { id: result.id, headSha: result.head_sha.toLowerCase() };
  }

  async completeCheckRun(
    target: PullRequestOutputTarget,
    checkRunId: number,
    input: {
      conclusion: "success" | "cancelled";
      title: string;
      summary: string;
    }
  ): Promise<ProviderCheckRun> {
    const result = await this.client.installationRequest<{ id: number; head_sha: string }>(
      target.installationId,
      target.repositoryId,
      `${repositoryPath(target)}/check-runs/${checkRunId}`,
      {
        method: "PATCH",
        body: {
          status: "completed",
          conclusion: input.conclusion,
          completed_at: new Date().toISOString(),
          output: { title: input.title, summary: input.summary }
        }
      }
    );
    return { id: result.id, headSha: result.head_sha.toLowerCase() };
  }
}
