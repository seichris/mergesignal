import { proxyActivities } from "@temporalio/workflow";

import type {
  GitHubActivities,
  GitHubDeliveryWorkflowInput,
  GitHubPublicationCommand,
  SyntheticActivities,
  SyntheticWorkflowInput,
  SyntheticWorkflowResult
} from "./types.js";

const { persistSyntheticResult } = proxyActivities<SyntheticActivities>({
  retry: {
    backoffCoefficient: 2,
    initialInterval: "100 milliseconds",
    maximumAttempts: 10,
    maximumInterval: "5 seconds"
  },
  startToCloseTimeout: "30 seconds"
});

const githubActivities = proxyActivities<GitHubActivities>({
  retry: {
    backoffCoefficient: 2,
    initialInterval: "1 second",
    maximumAttempts: 12,
    maximumInterval: "2 minutes"
  },
  startToCloseTimeout: "5 minutes"
});

export async function syntheticDeliveryWorkflow(
  input: SyntheticWorkflowInput
): Promise<SyntheticWorkflowResult> {
  return persistSyntheticResult(input);
}

export async function processGitHubDeliveryWorkflow(
  input: GitHubDeliveryWorkflowInput
): Promise<void> {
  const applied = await githubActivities.applyGitHubDelivery(input);
  if (applied.reconcileInstallation) {
    await githubActivities.reconcileGitHubInstallation({
      tenantId: input.tenantId,
      installationId: applied.installationId
    });
  }
  if (applied.publication !== null) {
    let publication: GitHubPublicationCommand | null = applied.publication;
    for (let repair = 0; repair < 5 && publication !== null; repair += 1) {
      try {
        await githubActivities.assessGitHubPublication(publication);
      } catch {
        await githubActivities.markGitHubReputationUnavailable(publication);
      }
      publication = await githubActivities.publishGitHubPublication(publication);
    }
    if (publication !== null) {
      throw new Error("GitHub publication exceeded the bounded repair chain");
    }
  }
  await githubActivities.completeGitHubDelivery(input);
}
