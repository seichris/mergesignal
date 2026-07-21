export type {
  AppliedGitHubDelivery,
  GitHubActivities,
  GitHubDeliveryWorkflowInput,
  GitHubPublicationCommand,
  SyntheticActivities,
  SyntheticWorkflowInput,
  SyntheticWorkflowResult
} from "./types.js";

const deliveryIdPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function workflowIdForSyntheticDelivery(deliveryId: string): string {
  if (!deliveryIdPattern.test(deliveryId)) throw new Error("Synthetic delivery ID must be a UUID");
  return `synthetic-delivery/${deliveryId.toLowerCase()}`;
}

export function workflowIdForGitHubDelivery(deliveryId: string): string {
  if (!deliveryIdPattern.test(deliveryId)) throw new Error("GitHub delivery ID must be a UUID");
  return `github-delivery/${deliveryId.toLowerCase()}`;
}
