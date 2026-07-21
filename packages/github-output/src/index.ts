import {
  totalPublicContributions,
  type ReputationAssessmentReport,
  type ReputationBand
} from "@mergesignal/reputation";

export const GITHUB_COMMENT_MARKER_VERSION = 1;

export interface PullRequestOutputTarget {
  installationId: number;
  appId: number;
  repositoryId: number;
  repositoryNodeId: string;
  owner: string;
  repository: string;
  pullRequestNodeId: string;
  pullRequestNumber: number;
  headSha: string;
  generation: number;
  canonicalCommentId: number | null;
  checkRunId: number | null;
  assessment: ReputationAssessmentReport;
}

export interface ProviderComment {
  id: number;
  body: string;
  performedViaGitHubAppId: number | null;
}

export interface ProviderCheckRun {
  id: number;
  headSha: string;
}

export interface GitHubOutputProvider {
  getPullRequestHead(target: PullRequestOutputTarget): Promise<string>;
  listPullRequestComments(target: PullRequestOutputTarget): Promise<ProviderComment[]>;
  getComment(target: PullRequestOutputTarget, commentId: number): Promise<ProviderComment | null>;
  createComment(target: PullRequestOutputTarget, body: string): Promise<ProviderComment>;
  updateComment(
    target: PullRequestOutputTarget,
    commentId: number,
    body: string
  ): Promise<ProviderComment>;
  createCheckRun(
    target: PullRequestOutputTarget,
    input: {
      status: "in_progress";
      title: string;
      summary: string;
    }
  ): Promise<ProviderCheckRun>;
  completeCheckRun(
    target: PullRequestOutputTarget,
    checkRunId: number,
    input: {
      conclusion: "success" | "cancelled";
      title: string;
      summary: string;
    }
  ): Promise<ProviderCheckRun>;
}

export interface PublicationResult {
  state: "published" | "stale";
  commentId: number;
  checkRunId: number;
  observedHeadSha: string;
}

export interface PublicationObservation {
  phase: "pre_write" | "post_comment" | "post_check";
  expectedHeadSha: string;
  observedHeadSha: string;
  commentId: number | null;
  checkRunId: number | null;
}

export function markerFor(target: PullRequestOutputTarget): string {
  return `<!-- mergesignal:v${GITHUB_COMMENT_MARKER_VERSION} installation=${target.installationId} repository=${target.repositoryNodeId} pull=${target.pullRequestNodeId} -->`;
}

export function renderLifecycleComment(target: PullRequestOutputTarget): string {
  const report = target.assessment;
  let body: string[];
  if (report.status === "evaluated") {
    const history = report.history;
    body = [
      "## MergeSignal contributor history",
      "",
      `**@${renderLogin(report.login)} — ${report.result.score}/100 · ${bandLabel(report.result.band)}**`,
      "",
      "| Signal | Public history observed |",
      "| --- | ---: |",
      `| Account age | ${formatAccountAge(history.accountAgeDays)} |`,
      `| Contributions | ${totalPublicContributions(history)} in the last 24 months |`,
      `| Active weeks | ${history.activeWeeks} of 104 |`,
      `| External pull requests | ${history.externalMergedPullRequests} merged of ${history.externalClosedPullRequests} closed observed |`,
      `| Repository breadth | ${history.distinctPublicRepositories} public repositories |`,
      "",
      `**Evidence confidence:** ${confidenceLabel(report.result.confidence)}`,
      ...(history.truncated
        ? ["", "Public-history collection reached an MVP evidence cap; confidence is limited."]
        : []),
      ...(history.restrictedContributions > 0
        ? ["", "Private contribution counts were visible only as an aggregate and did not affect this score."]
        : []),
      "",
      "This score summarizes observable public GitHub history. It is not a code-quality, security, identity, or trust verdict, and it should not replace review of this PR.",
      "",
      `Scoring version \`${report.result.scoringVersion}\` · Assessed for \`${target.headSha.slice(0, 7)}\``
    ];
  } else if (report.status === "not_evaluated") {
    body = [
      "## MergeSignal contributor history",
      "",
      report.reason === "actor_not_user"
        ? "This pull request was opened by a bot or non-human GitHub actor, so MergeSignal did not calculate a reputation score."
        : "The pull-request author is unavailable, so MergeSignal did not calculate a reputation score.",
      "",
      "No zero score was substituted. Reputation is not a code-quality or merge gate.",
      "",
      `Assessed for \`${target.headSha.slice(0, 7)}\``
    ];
  } else {
    body = [
      "## MergeSignal contributor history",
      "",
      `${report.login === null ? "This contributor" : `@${renderLogin(report.login)}`} could not be evaluated from the public GitHub evidence currently available.`,
      "",
      "No zero score was substituted. This is not a negative trust signal, and reputation is not a code-quality or merge gate.",
      "",
      `Assessed for \`${target.headSha.slice(0, 7)}\``
    ];
  }
  return [
    ...body,
    "",
    markerFor(target)
  ].join("\n");
}

function escapeMarkdown(value: string): string {
  return value.replace(/[\\`*_{}\[\]()#+.!|<>-]/g, "\\$&");
}

function renderLogin(value: string): string {
  return /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(value) ? value : escapeMarkdown(value);
}

function bandLabel(band: ReputationBand): string {
  return {
    extensive: "Extensive public history",
    substantial: "Substantial public history",
    moderate: "Moderate public history",
    emerging: "Emerging public history",
    limited: "Limited observable public history"
  }[band];
}

function confidenceLabel(confidence: "high" | "medium" | "limited"): string {
  return confidence === "high" ? "High" : confidence === "medium" ? "Medium" : "Limited";
}

function formatAccountAge(days: number): string {
  if (days >= 730) return `${Math.floor(days / 365)} years`;
  if (days >= 365) return "1 year";
  if (days >= 60) return `${Math.floor(days / 30)} months`;
  if (days >= 30) return "1 month";
  return `${days} ${days === 1 ? "day" : "days"}`;
}

function ownsComment(comment: ProviderComment, target: PullRequestOutputTarget): boolean {
  return (
    comment.performedViaGitHubAppId === target.appId && comment.body.includes(markerFor(target))
  );
}

export async function reconcilePullRequestOutput(
  provider: GitHubOutputProvider,
  target: PullRequestOutputTarget,
  observe: (observation: PublicationObservation) => Promise<void> = async () => {}
): Promise<PublicationResult> {
  const initialHead = await provider.getPullRequestHead(target);
  await observe({
    phase: "pre_write",
    expectedHeadSha: target.headSha,
    observedHeadSha: initialHead,
    commentId: target.canonicalCommentId,
    checkRunId: target.checkRunId
  });
  if (initialHead !== target.headSha) {
    throw new Error("Publication target is stale before provider mutation");
  }

  const comments = await provider.listPullRequestComments(target);
  const owned = comments.filter((comment) => ownsComment(comment, target));
  if (owned.length > 1) throw new Error("Multiple app-owned MergeSignal comments require repair");

  let canonical =
    target.canonicalCommentId === null
      ? null
      : await provider.getComment(target, target.canonicalCommentId);
  if (canonical !== null && !ownsComment(canonical, target)) {
    throw new Error("Stored canonical comment is not owned by this GitHub App installation");
  }
  canonical ??= owned[0] ?? null;

  const body = renderLifecycleComment(target);
  const writtenComment =
    canonical === null
      ? await provider.createComment(target, body)
      : await provider.updateComment(target, canonical.id, body);
  if (!ownsComment(writtenComment, target)) {
    throw new Error("GitHub did not return an owned comment after publication");
  }
  await observe({
    phase: "post_comment",
    expectedHeadSha: target.headSha,
    observedHeadSha: target.headSha,
    commentId: writtenComment.id,
    checkRunId: target.checkRunId
  });

  const check =
    target.checkRunId === null
      ? await provider.createCheckRun(target, {
          status: "in_progress",
          title: "MergeSignal is collecting contributor history",
          summary: "This Check reports lifecycle status only; it is not a code-quality gate."
        })
      : { id: target.checkRunId, headSha: target.headSha };

  const observedHeadSha = await provider.getPullRequestHead(target);
  const state = observedHeadSha === target.headSha ? "published" : "stale";
  await provider.completeCheckRun(target, check.id, {
    conclusion: state === "published" ? "success" : "cancelled",
    title: state === "published" ? "MergeSignal report published" : "Superseded by a newer head",
    summary:
      state === "published"
        ? "The app-owned PR comment is current for this head. Reputation is not a merge gate."
        : "A newer pull-request head was observed; a fresh publication has been queued."
  });
  await observe({
    phase: "post_check",
    expectedHeadSha: target.headSha,
    observedHeadSha,
    commentId: writtenComment.id,
    checkRunId: check.id
  });

  return {
    state,
    commentId: writtenComment.id,
    checkRunId: check.id,
    observedHeadSha
  };
}
