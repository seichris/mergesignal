import { ApplicationFailure } from "@temporalio/common";

import {
  ContributorHistoryUnavailableError,
  GitHubApiError,
  GitHubGraphqlError,
  collectPublicContributorHistory,
  type GitHubAppClient,
  type GitHubRestOutputProvider
} from "@mergesignal/github";
import {
  applyGitHubDelivery,
  claimGitHubPublication,
  completeGitHubPublication,
  failGitHubPublication,
  findCachedContributorHistory,
  getGitHubReputationContext,
  persistSyntheticResultAttempt,
  persistGitHubReputationAssessment,
  reconcileInstallationRepositories,
  recordGitHubOutputObservation,
  recordWorkflowCompleted,
  storeContributorHistorySnapshot,
  type Database
} from "@mergesignal/database";
import {
  markerFor,
  reconcilePullRequestOutput,
  type PullRequestOutputTarget
} from "@mergesignal/github-output";
import { foundationMeter, withSpan } from "@mergesignal/observability";
import type { GitHubActivities, SyntheticActivities } from "@mergesignal/workflows";
import { calculateReputation, type ReputationAssessmentReport } from "@mergesignal/reputation";

const retryCounter = foundationMeter.createCounter("mergesignal.synthetic.activity.forced_retries");

interface GitHubActivityServices {
  client: GitHubAppClient;
  outputProvider: GitHubRestOutputProvider;
  appId: number;
  appOrigin: string;
}

function errorCode(error: unknown): string {
  return error instanceof Error && error.name.length > 0 ? error.name : "UnknownError";
}

function unavailableReport(
  context: Awaited<ReturnType<typeof getGitHubReputationContext>>,
  reason: "provider_unavailable" | "identity_mismatch" | "invalid_provider_data"
): ReputationAssessmentReport {
  return {
    status: "unavailable",
    actorNodeId: context.authorNodeId,
    login: context.authorLogin,
    reason
  };
}

function providerRetryDelay(
  error: GitHubApiError | GitHubGraphqlError,
  now = new Date()
): number | undefined {
  const retryAfter = error.retryAfter;
  let seconds: number | undefined;
  if (retryAfter !== null && /^\d+$/.test(retryAfter)) {
    seconds = Number(retryAfter);
  } else if (retryAfter !== null) {
    const target = Date.parse(retryAfter);
    if (Number.isFinite(target)) seconds = Math.ceil((target - now.getTime()) / 1_000);
  }
  if (seconds === undefined && error.rateLimitReset !== null && /^\d+$/.test(error.rateLimitReset)) {
    seconds = Number(error.rateLimitReset) - Math.floor(now.getTime() / 1_000);
  }
  if (seconds === undefined || !Number.isFinite(seconds)) return undefined;
  return Math.min(Math.max(Math.ceil(seconds), 1), 900) * 1_000;
}

function retryableProviderFailure(error: GitHubApiError | GitHubGraphqlError): ApplicationFailure {
  const nextRetryDelay = providerRetryDelay(error);
  return ApplicationFailure.create({
    message: error.message,
    type: "GitHubProviderRetry",
    cause: error,
    ...(nextRetryDelay === undefined ? {} : { nextRetryDelay })
  });
}

export function createActivities(
  database: Database,
  github?: GitHubActivityServices
): SyntheticActivities & GitHubActivities {
  return {
    async persistSyntheticResult(input) {
      return withSpan(
        "synthetic.persist_result",
        {
          "mergesignal.tenant.id": input.tenantId,
          "mergesignal.delivery.id": input.deliveryId
        },
        async () => {
          const result = await persistSyntheticResultAttempt(database, input);
          if (result.shouldFail) {
            retryCounter.add(1, { "mergesignal.retry.reason": "forced_test_retry" });
            throw ApplicationFailure.retryable(
              "Synthetic activity retry requested by the test delivery",
              "SyntheticForcedRetry"
            );
          }
          return {
            resultId: result.resultId,
            activityAttempts: result.activityAttempts
          };
        }
      );
    },

    async applyGitHubDelivery(input) {
      return applyGitHubDelivery(database, input);
    },

    async reconcileGitHubInstallation(input) {
      if (github === undefined) throw new Error("GitHub activity services are not configured");
      const repositories = await github.client.listInstallationRepositories(input.installationId);
      await reconcileInstallationRepositories(database, { ...input, repositories });
    },

    async assessGitHubPublication(input) {
      if (github === undefined) throw new Error("GitHub activity services are not configured");
      const context = await getGitHubReputationContext(database, input);
      if (
        context.authorNodeId === null ||
        context.authorLogin === null ||
        context.authorType === null
      ) {
        await persistGitHubReputationAssessment(database, {
          context,
          report: {
            status: "not_evaluated",
            actorNodeId: context.authorNodeId,
            login: context.authorLogin,
            reason: "author_missing"
          }
        });
        return;
      }
      if (context.authorType !== "User") {
        await persistGitHubReputationAssessment(database, {
          context,
          report: {
            status: "not_evaluated",
            actorNodeId: context.authorNodeId,
            login: context.authorLogin,
            reason: "actor_not_user"
          }
        });
        return;
      }
      try {
        let stored = await findCachedContributorHistory(database, {
          tenantId: context.tenantId,
          actorNodeId: context.authorNodeId
        });
        if (stored === null) {
          const history = await collectPublicContributorHistory(github.client, {
            installationId: context.installationId,
            actorNodeId: context.authorNodeId
          });
          stored = await storeContributorHistorySnapshot(database, {
            tenantId: context.tenantId,
            history
          });
        }
        const report: ReputationAssessmentReport = {
          status: "evaluated",
          actorNodeId: stored.history.actorNodeId,
          login: stored.history.login,
          history: stored.history,
          result: calculateReputation(stored.history)
        };
        await persistGitHubReputationAssessment(database, {
          context,
          report,
          snapshotId: stored.snapshotId
        });
      } catch (error) {
        if (error instanceof ContributorHistoryUnavailableError) {
          const reason = error.reason === "actor_not_user"
            ? "provider_unavailable"
            : error.reason;
          const report = unavailableReport(context, reason);
          await persistGitHubReputationAssessment(database, { context, report });
          return;
        }
        if (error instanceof GitHubGraphqlError && !error.retryable) {
          await persistGitHubReputationAssessment(database, {
            context,
            report: unavailableReport(context, "invalid_provider_data")
          });
          return;
        }
        if (error instanceof GitHubGraphqlError) throw retryableProviderFailure(error);
        if (error instanceof GitHubApiError && [404, 422].includes(error.status)) {
          await persistGitHubReputationAssessment(database, {
            context,
            report: unavailableReport(context, "provider_unavailable")
          });
          return;
        }
        if (error instanceof GitHubApiError) throw retryableProviderFailure(error);
        throw error;
      }
    },

    async markGitHubReputationUnavailable(input) {
      const context = await getGitHubReputationContext(database, input);
      await persistGitHubReputationAssessment(database, {
        context,
        report: unavailableReport(context, "provider_unavailable")
      });
    },

    async publishGitHubPublication(input) {
      if (github === undefined) throw new Error("GitHub activity services are not configured");
      const claim = await claimGitHubPublication(database, input);
      const target: PullRequestOutputTarget = {
        installationId: claim.installationId,
        appId: github.appId,
        repositoryId: claim.repositoryId,
        repositoryNodeId: claim.repositoryNodeId,
        owner: claim.owner,
        repository: claim.repository,
        pullRequestNodeId: claim.pullRequestNodeId,
        pullRequestNumber: claim.pullRequestNumber,
        headSha: claim.headSha,
        generation: claim.generation,
        canonicalCommentId: claim.canonicalCommentId,
        checkRunId: claim.checkRunId,
        assessment: claim.assessment
      };
      try {
        const completion = await reconcilePullRequestOutput(
          github.outputProvider,
          target,
          async (observation) => {
            await recordGitHubOutputObservation(database, {
              tenantId: claim.tenantId,
              publicationId: claim.publicationId,
              ...observation,
              appId: github.appId,
              marker: markerFor(target)
            });
          }
        );
        return await completeGitHubPublication(database, {
          tenantId: claim.tenantId,
          publicationId: claim.publicationId,
          leaseToken: claim.leaseToken,
          completion
        });
      } catch (error) {
        await failGitHubPublication(database, {
          tenantId: claim.tenantId,
          publicationId: claim.publicationId,
          leaseToken: claim.leaseToken,
          errorCode: errorCode(error)
        });
        throw error;
      }
    },

    async completeGitHubDelivery(input) {
      await recordWorkflowCompleted(database, input);
    }
  };
}
