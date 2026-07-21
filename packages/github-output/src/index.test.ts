import { describe, expect, it } from "vitest";

import { calculateReputation, type PublicContributorHistory } from "@mergesignal/reputation";

import {
  markerFor,
  reconcilePullRequestOutput,
  type GitHubOutputProvider,
  type ProviderCheckRun,
  type ProviderComment,
  type PullRequestOutputTarget
} from "./index.js";

function target(): PullRequestOutputTarget {
  const history: PublicContributorHistory = {
    actorNodeId: "U_1",
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
    truncated: false
  };
  return {
    installationId: 10,
    appId: 20,
    repositoryId: 30,
    repositoryNodeId: "R_1",
    owner: "example",
    repository: "repository",
    pullRequestNodeId: "PR_1",
    pullRequestNumber: 40,
    headSha: "a".repeat(40),
    generation: 1,
    canonicalCommentId: null,
    checkRunId: null,
    assessment: {
      status: "evaluated",
      actorNodeId: history.actorNodeId,
      login: history.login,
      history,
      result: calculateReputation(history)
    }
  };
}

class FakeProvider implements GitHubOutputProvider {
  head = "a".repeat(40);
  comments: ProviderComment[] = [];
  checks: ProviderCheckRun[] = [];
  changeHeadAfterComment = false;

  async getPullRequestHead() {
    return this.head;
  }
  async listPullRequestComments() {
    return this.comments;
  }
  async getComment(_target: PullRequestOutputTarget, id: number) {
    return this.comments.find((comment) => comment.id === id) ?? null;
  }
  async createComment(_target: PullRequestOutputTarget, body: string) {
    const comment = { id: this.comments.length + 1, body, performedViaGitHubAppId: 20 };
    this.comments.push(comment);
    if (this.changeHeadAfterComment) this.head = "b".repeat(40);
    return comment;
  }
  async updateComment(_target: PullRequestOutputTarget, id: number, body: string) {
    const comment = this.comments.find((candidate) => candidate.id === id);
    if (comment === undefined) throw new Error("missing comment");
    comment.body = body;
    if (this.changeHeadAfterComment) this.head = "b".repeat(40);
    return comment;
  }
  async createCheckRun(targetValue: PullRequestOutputTarget) {
    const check = { id: this.checks.length + 100, headSha: targetValue.headSha };
    this.checks.push(check);
    return check;
  }
  async completeCheckRun(
    _target: PullRequestOutputTarget,
    id: number,
    input: { conclusion: "success" | "cancelled" }
  ) {
    const check = this.checks.find((candidate) => candidate.id === id);
    if (check === undefined) throw new Error("missing check");
    expect(["success", "cancelled"]).toContain(input.conclusion);
    return check;
  }
}

describe("reconcilePullRequestOutput", () => {
  it("updates one app-owned comment across retries", async () => {
    const provider = new FakeProvider();
    const output = target();
    const first = await reconcilePullRequestOutput(provider, output);
    const second = await reconcilePullRequestOutput(provider, {
      ...output,
      canonicalCommentId: first.commentId,
      checkRunId: first.checkRunId
    });
    expect(second.state).toBe("published");
    expect(provider.comments).toHaveLength(1);
    expect(provider.checks).toHaveLength(1);
    expect(provider.comments[0]?.body).toMatchInlineSnapshot(`
      "## MergeSignal contributor history

      **@contributor — 96/100 · Extensive public history**

      | Signal | Public history observed |
      | --- | ---: |
      | Account age | 6 years |
      | Contributions | 340 in the last 24 months |
      | Active weeks | 60 of 104 |
      | External pull requests | 20 merged of 25 closed observed |
      | Repository breadth | 10 public repositories |

      **Evidence confidence:** High

      This score summarizes observable public GitHub history. It is not a code-quality, security, identity, or trust verdict, and it should not replace review of this PR.

      Scoring version \`mvp-v1\` · Assessed for \`aaaaaaa\`

      <!-- mergesignal:v1 installation=10 repository=R_1 pull=PR_1 -->"
    `);
  });

  it("does not fabricate a zero score for unavailable evidence", async () => {
    const provider = new FakeProvider();
    await reconcilePullRequestOutput(provider, {
      ...target(),
      assessment: {
        status: "unavailable",
        actorNodeId: "U_1",
        login: "contributor",
        reason: "provider_unavailable"
      }
    });
    expect(provider.comments[0]?.body).toContain("No zero score was substituted");
    expect(provider.comments[0]?.body).not.toMatch(/\b0\/100\b/);
  });

  it("ignores a spoofed marker that is not app-owned", async () => {
    const provider = new FakeProvider();
    provider.comments.push({ id: 1, body: markerFor(target()), performedViaGitHubAppId: null });
    await reconcilePullRequestOutput(provider, target());
    expect(provider.comments).toHaveLength(2);
  });

  it("cancels a Check when the head changes during publication", async () => {
    const provider = new FakeProvider();
    provider.changeHeadAfterComment = true;
    expect((await reconcilePullRequestOutput(provider, target())).state).toBe("stale");
  });
});
