import { createHash } from "node:crypto";

import type { Selectable, Transaction } from "kysely";

import {
  MVP_SCORING_VERSION,
  calculateReputation,
  publicContributorHistorySchema,
  type PublicContributorHistory,
  type ReputationAssessmentReport,
  type ReputationScore
} from "@mergesignal/reputation";

import {
  withTenantSerializableTransaction,
  withTenantTransaction,
  type Database
} from "./client.js";
import type { MergeSignalDatabase } from "./types.js";

type TenantTransaction = Transaction<MergeSignalDatabase>;
const CACHE_MILLISECONDS = 6 * 60 * 60 * 1_000;

export interface GitHubReputationContext {
  tenantId: string;
  publicationId: string;
  pullRequestId: string;
  installationId: number;
  generation: number;
  headSha: string;
  authorNodeId: string | null;
  authorLogin: string | null;
  authorType: "User" | "Bot" | "Organization" | "Mannequin" | null;
}

export interface StoredContributorHistory {
  snapshotId: string;
  history: PublicContributorHistory;
}

function toSafeNumber(value: string | number, label: string): number {
  const number = typeof value === "number" ? value : Number(value);
  if (!Number.isSafeInteger(number) || number <= 0) throw new Error(`${label} is not a safe integer`);
  return number;
}

function toIso(value: Date): string {
  return new Date(value).toISOString();
}

function historyFromRow(
  row: Selectable<MergeSignalDatabase["app.contributor_history_snapshots"]>
): PublicContributorHistory {
  return publicContributorHistorySchema.parse({
    actorNodeId: row.actor_node_id,
    login: row.observed_login,
    accountCreatedAt: toIso(row.account_created_at),
    observedFrom: toIso(row.observed_from),
    observedUntil: toIso(row.observed_until),
    accountAgeDays: row.account_age_days,
    commits: row.commits,
    issues: row.issues,
    pullRequests: row.pull_requests,
    pullRequestReviews: row.pull_request_reviews,
    activeWeeks: row.active_weeks,
    externalPullRequestsObserved: row.external_pull_requests_observed,
    externalClosedPullRequests: row.external_closed_pull_requests,
    externalMergedPullRequests: row.external_merged_pull_requests,
    distinctPublicRepositories: row.distinct_public_repositories,
    restrictedContributions: row.restricted_contributions,
    truncated: row.truncated
  });
}

function reportForPersistence(report: ReputationAssessmentReport): ReputationAssessmentReport {
  if (report.status !== "evaluated") return report;
  return {
    ...report,
    result: {
      ...report.result,
      components: {
        accountMaturity: Number(report.result.components.accountMaturity.toFixed(4)),
        publicActivity: Number(report.result.components.publicActivity.toFixed(4)),
        regularity: Number(report.result.components.regularity.toFixed(4)),
        mergedPullRequests: Number(report.result.components.mergedPullRequests.toFixed(4)),
        repositoryBreadth: Number(report.result.components.repositoryBreadth.toFixed(4))
      }
    }
  };
}

async function selectContext(
  transaction: TenantTransaction,
  publicationId: string
): Promise<GitHubReputationContext> {
  const row = await transaction
    .selectFrom("app.github_publications as publication")
    .innerJoin("app.pr_output_cursors as cursor", "cursor.id", "publication.output_cursor_id")
    .innerJoin("app.pull_requests as pull_request", "pull_request.id", "cursor.pull_request_id")
    .select([
      "publication.id as publication_id",
      "publication.tenant_id",
      "publication.generation",
      "publication.head_sha",
      "cursor.generation as cursor_generation",
      "cursor.head_sha as cursor_head_sha",
      "cursor.installation_id",
      "pull_request.id as pull_request_id",
      "pull_request.author_node_id",
      "pull_request.author_login",
      "pull_request.author_type"
    ])
    .where("publication.id", "=", publicationId)
    .executeTakeFirstOrThrow();
  if (row.generation !== row.cursor_generation || row.head_sha !== row.cursor_head_sha) {
    throw new Error("Cannot assess a superseded GitHub publication");
  }
  return {
    tenantId: row.tenant_id,
    publicationId: row.publication_id,
    pullRequestId: row.pull_request_id,
    installationId: toSafeNumber(row.installation_id, "installation ID"),
    generation: row.generation,
    headSha: row.head_sha,
    authorNodeId: row.author_node_id,
    authorLogin: row.author_login,
    authorType: row.author_type
  };
}

export async function getGitHubReputationContext(
  database: Database,
  input: { tenantId: string; publicationId: string }
): Promise<GitHubReputationContext> {
  return withTenantTransaction(database, input.tenantId, (transaction) =>
    selectContext(transaction, input.publicationId)
  );
}

export async function findCachedContributorHistory(
  database: Database,
  input: { tenantId: string; actorNodeId: string; now?: Date }
): Promise<StoredContributorHistory | null> {
  const now = input.now ?? new Date();
  return withTenantTransaction(database, input.tenantId, async (transaction) => {
    const row = await transaction
      .selectFrom("app.contributor_history_snapshots")
      .selectAll()
      .where("actor_node_id", "=", input.actorNodeId)
      .where("cache_expires_at", ">", now)
      .orderBy("collected_at", "desc")
      .executeTakeFirst();
    return row === undefined ? null : { snapshotId: row.id, history: historyFromRow(row) };
  });
}

export async function storeContributorHistorySnapshot(
  database: Database,
  input: { tenantId: string; history: PublicContributorHistory; collectedAt?: Date }
): Promise<StoredContributorHistory> {
  const history = publicContributorHistorySchema.parse(input.history);
  const collectedAt = input.collectedAt ?? new Date();
  const cacheWindowStart = new Date(
    Math.floor(collectedAt.getTime() / CACHE_MILLISECONDS) * CACHE_MILLISECONDS
  );
  const cacheExpiresAt = new Date(collectedAt.getTime() + CACHE_MILLISECONDS);
  const digest = createHash("sha256").update(JSON.stringify(history)).digest("hex");
  return withTenantSerializableTransaction(database, input.tenantId, async (transaction) => {
    await transaction
      .insertInto("app.contributor_history_snapshots")
      .values({
        tenant_id: input.tenantId,
        actor_node_id: history.actorNodeId,
        observed_login: history.login,
        account_created_at: history.accountCreatedAt,
        observed_from: history.observedFrom,
        observed_until: history.observedUntil,
        account_age_days: history.accountAgeDays,
        commits: history.commits,
        issues: history.issues,
        pull_requests: history.pullRequests,
        pull_request_reviews: history.pullRequestReviews,
        active_weeks: history.activeWeeks,
        external_pull_requests_observed: history.externalPullRequestsObserved,
        external_closed_pull_requests: history.externalClosedPullRequests,
        external_merged_pull_requests: history.externalMergedPullRequests,
        distinct_public_repositories: history.distinctPublicRepositories,
        restricted_contributions: history.restrictedContributions,
        truncated: history.truncated,
        provider_response_digest: digest,
        cache_window_start: cacheWindowStart,
        cache_expires_at: cacheExpiresAt,
        collected_at: collectedAt
      })
      .onConflict((conflict) =>
        conflict.columns(["tenant_id", "actor_node_id", "cache_window_start"]).doNothing()
      )
      .execute();
    const row = await transaction
      .selectFrom("app.contributor_history_snapshots")
      .selectAll()
      .where("actor_node_id", "=", history.actorNodeId)
      .where("cache_window_start", "=", cacheWindowStart)
      .executeTakeFirstOrThrow();
    if (row.provider_response_digest !== digest) {
      throw new Error("Conflicting contributor history was collected in the same cache window");
    }
    return { snapshotId: row.id, history: historyFromRow(row) };
  });
}

export async function persistGitHubReputationAssessment(
  database: Database,
  input: {
    context: GitHubReputationContext;
    report: ReputationAssessmentReport;
    snapshotId?: string;
  }
): Promise<void> {
  const { context } = input;
  const suppliedReport = input.report;
  await withTenantSerializableTransaction(database, context.tenantId, async (transaction) => {
    const current = await selectContext(transaction, context.publicationId);
    if (
      current.generation !== context.generation ||
      current.headSha !== context.headSha ||
      current.authorNodeId !== context.authorNodeId ||
      current.authorType !== context.authorType
    ) {
      throw new Error("GitHub reputation assessment context changed before persistence");
    }
    const evaluated = suppliedReport.status === "evaluated";
    if (evaluated && input.snapshotId === undefined) {
      throw new Error("Evaluated reputation assessment requires a history snapshot");
    }
    if (evaluated) {
      if (
        suppliedReport.actorNodeId !== context.authorNodeId ||
        suppliedReport.history.actorNodeId !== context.authorNodeId ||
        suppliedReport.login !== suppliedReport.history.login
      ) {
        throw new Error("Evaluated reputation assessment does not match the PR author");
      }
      const snapshot = await transaction
        .selectFrom("app.contributor_history_snapshots")
        .selectAll()
        .where("id", "=", input.snapshotId!)
        .executeTakeFirstOrThrow();
      if (snapshot.actor_node_id !== suppliedReport.actorNodeId) {
        throw new Error("Reputation history snapshot belongs to a different actor");
      }
      const storedHistory = historyFromRow(snapshot);
      if (JSON.stringify(storedHistory) !== JSON.stringify(suppliedReport.history)) {
        throw new Error("Evaluated reputation history differs from its stored snapshot");
      }
      if (
        JSON.stringify(calculateReputation(storedHistory)) !==
        JSON.stringify(suppliedReport.result)
      ) {
        throw new Error("Evaluated reputation score is not reproducible from its snapshot");
      }
    } else if (
      suppliedReport.actorNodeId !== context.authorNodeId ||
      suppliedReport.login !== context.authorLogin
    ) {
      throw new Error("Unevaluated reputation assessment does not match the PR author");
    }
    const report = reportForPersistence(suppliedReport);
    const inserted = await transaction
      .insertInto("app.pr_reputation_assessments")
      .values({
        tenant_id: context.tenantId,
        pull_request_id: context.pullRequestId,
        publication_id: context.publicationId,
        history_snapshot_id: report.status === "evaluated" ? input.snapshotId! : null,
        generation: context.generation,
        head_sha: context.headSha,
        author_node_id: context.authorNodeId,
        author_login: report.login,
        author_type: context.authorType,
        status: report.status,
        reason: report.status === "evaluated" ? null : report.reason,
        account_maturity_score: report.status === "evaluated"
          ? report.result.components.accountMaturity.toString()
          : null,
        public_activity_score: report.status === "evaluated"
          ? report.result.components.publicActivity.toString()
          : null,
        regularity_score: report.status === "evaluated"
          ? report.result.components.regularity.toString()
          : null,
        merged_pull_requests_score: report.status === "evaluated"
          ? report.result.components.mergedPullRequests.toString()
          : null,
        repository_breadth_score: report.status === "evaluated"
          ? report.result.components.repositoryBreadth.toString()
          : null,
        final_score: report.status === "evaluated" ? report.result.score : null,
        band: report.status === "evaluated" ? report.result.band : null,
        confidence: report.status === "evaluated" ? report.result.confidence : null,
        scoring_version: report.status === "evaluated" ? report.result.scoringVersion : null,
        calculated_at: new Date()
      })
      .onConflict((conflict) => conflict.column("publication_id").doNothing())
      .returning("id")
      .executeTakeFirst();
    if (inserted === undefined) {
      const existing = await loadReputationReport(transaction, context.publicationId);
      if (JSON.stringify(existing) !== JSON.stringify(report)) {
        throw new Error("Conflicting reputation assessment already exists for this publication");
      }
    }
  });
}

export async function loadReputationReport(
  transaction: TenantTransaction,
  publicationId: string
): Promise<ReputationAssessmentReport> {
  const assessment = await transaction
    .selectFrom("app.pr_reputation_assessments")
    .selectAll()
    .where("publication_id", "=", publicationId)
    .executeTakeFirstOrThrow();
  if (assessment.status !== "evaluated") {
    return {
      status: assessment.status,
      actorNodeId: assessment.author_node_id,
      login: assessment.author_login,
      reason: assessment.reason as Exclude<ReputationAssessmentReport, { status: "evaluated" }>["reason"]
    } as ReputationAssessmentReport;
  }
  if (assessment.history_snapshot_id === null) throw new Error("Evaluated assessment lost its snapshot");
  const snapshot = await transaction
    .selectFrom("app.contributor_history_snapshots")
    .selectAll()
    .where("id", "=", assessment.history_snapshot_id)
    .executeTakeFirstOrThrow();
  if (
    assessment.final_score === null ||
    assessment.band === null ||
    assessment.confidence === null ||
    assessment.scoring_version !== MVP_SCORING_VERSION ||
    assessment.account_maturity_score === null ||
    assessment.public_activity_score === null ||
    assessment.regularity_score === null ||
    assessment.merged_pull_requests_score === null ||
    assessment.repository_breadth_score === null ||
    assessment.author_node_id === null ||
    assessment.author_login === null
  ) {
    throw new Error("Evaluated assessment is incomplete or uses an unsupported scoring version");
  }
  const result: ReputationScore = {
    scoringVersion: MVP_SCORING_VERSION,
    score: assessment.final_score,
    band: assessment.band,
    confidence: assessment.confidence,
    components: {
      accountMaturity: Number(assessment.account_maturity_score),
      publicActivity: Number(assessment.public_activity_score),
      regularity: Number(assessment.regularity_score),
      mergedPullRequests: Number(assessment.merged_pull_requests_score),
      repositoryBreadth: Number(assessment.repository_breadth_score)
    }
  };
  return {
    status: "evaluated",
    actorNodeId: assessment.author_node_id,
    login: assessment.author_login,
    history: historyFromRow(snapshot),
    result
  };
}
