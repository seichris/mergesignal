export interface SyntheticWorkflowInput {
  tenantId: string;
  deliveryId: string;
  workflowId: string;
  bodyDigest: string;
  failActivityAttempts: number;
}

export interface SyntheticWorkflowResult {
  resultId: string;
  activityAttempts: number;
}

export interface SyntheticActivities {
  persistSyntheticResult(input: SyntheticWorkflowInput): Promise<SyntheticWorkflowResult>;
}

export interface GitHubDeliveryWorkflowInput {
  tenantId: string;
  deliveryId: string;
  workflowId: string;
  expectedAppId: number;
}

export interface GitHubPublicationCommand {
  tenantId: string;
  publicationId: string;
  generation: number;
  headSha: string;
}

export interface AppliedGitHubDelivery {
  installationId: number;
  reconcileInstallation: boolean;
  publication: GitHubPublicationCommand | null;
}

export interface GitHubActivities {
  applyGitHubDelivery(input: GitHubDeliveryWorkflowInput): Promise<AppliedGitHubDelivery>;
  reconcileGitHubInstallation(input: {
    tenantId: string;
    installationId: number;
  }): Promise<void>;
  assessGitHubPublication(input: GitHubPublicationCommand): Promise<void>;
  markGitHubReputationUnavailable(input: GitHubPublicationCommand): Promise<void>;
  publishGitHubPublication(
    input: GitHubPublicationCommand
  ): Promise<GitHubPublicationCommand | null>;
  completeGitHubDelivery(input: GitHubDeliveryWorkflowInput): Promise<void>;
}
