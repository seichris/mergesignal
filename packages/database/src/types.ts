import type { ColumnType, Generated, JSONColumnType } from "kysely";

type Timestamp = ColumnType<Date, Date | string, Date | string>;
type GeneratedTimestamp = ColumnType<Date, Date | string | undefined, Date | string>;
type BigIntIdentifier = ColumnType<string, string | number, string | number>;

export interface TenantTable {
  id: string;
  slug: string;
  created_at: GeneratedTimestamp;
}

export interface WebhookDeliveryTable {
  id: Generated<string>;
  tenant_id: string;
  source: string;
  delivery_id: string;
  body_digest: string;
  payload: JSONColumnType<Record<string, unknown>>;
  received_at: GeneratedTimestamp;
}

export interface OutboxEventTable {
  id: Generated<string>;
  tenant_id: string;
  aggregate_type: string;
  aggregate_id: string;
  event_type: string;
  dedupe_key: string;
  payload: JSONColumnType<Record<string, unknown>>;
  state: Generated<"available" | "publishing" | "published">;
  attempt_count: Generated<number>;
  available_at: GeneratedTimestamp;
  lease_token: string | null;
  lease_expires_at: Timestamp | null;
  last_error_code: string | null;
  created_at: GeneratedTimestamp;
  published_at: Timestamp | null;
}

export interface WorkflowRunTable {
  id: Generated<string>;
  tenant_id: string;
  workflow_id: string;
  workflow_type: string;
  task_queue: string;
  source_delivery_id: string;
  state: Generated<"started" | "completed">;
  started_at: GeneratedTimestamp;
  completed_at: Timestamp | null;
}

export interface SyntheticActivityAttemptTable {
  tenant_id: string;
  delivery_id: string;
  attempt_count: Generated<number>;
  updated_at: GeneratedTimestamp;
}

export interface SyntheticResultTable {
  id: Generated<string>;
  tenant_id: string;
  delivery_id: string;
  workflow_id: string;
  body_digest: string;
  activity_attempts: number;
  completed_at: GeneratedTimestamp;
}

export interface AuditEventTable {
  id: Generated<string>;
  tenant_id: string;
  event_type: string;
  actor_type: string;
  actor_id: string;
  subject_type: string;
  subject_id: string;
  payload: JSONColumnType<Record<string, unknown>>;
  occurred_at: GeneratedTimestamp;
}

export interface GitHubInstallationProfileTable {
  installation_id: BigIntIdentifier;
  tenant_id: string;
  account_node_id: string;
  account_login: string;
  account_type: string;
  repository_selection: "all" | "selected" | null;
  permissions: JSONColumnType<
    Record<string, string>,
    Record<string, string>,
    Record<string, string>
  >;
  subscribed_events: string[];
  state: "active" | "suspended" | "deleted";
  last_delivery_id: string | null;
  created_at: GeneratedTimestamp;
  updated_at: GeneratedTimestamp;
}

export interface RepositoryTable {
  id: Generated<string>;
  tenant_id: string;
  installation_id: BigIntIdentifier;
  github_repository_id: BigIntIdentifier;
  repository_node_id: string;
  full_name: string;
  owner_login: string;
  name: string;
  private: boolean;
  default_branch: string | null;
  state: "active" | "removed";
  provider_updated_at: Timestamp | null;
  created_at: GeneratedTimestamp;
  updated_at: GeneratedTimestamp;
}

export interface PullRequestTable {
  id: Generated<string>;
  tenant_id: string;
  repository_id: string;
  github_pull_request_id: BigIntIdentifier;
  pull_request_node_id: string;
  number: number;
  state: "open" | "closed";
  draft: boolean;
  head_sha: string;
  base_sha: string;
  author_node_id: string | null;
  author_login: string | null;
  author_type: "User" | "Bot" | "Organization" | "Mannequin" | null;
  provider_updated_at: Timestamp;
  created_at: GeneratedTimestamp;
  updated_at: GeneratedTimestamp;
}

export interface ContributorHistorySnapshotTable {
  id: Generated<string>;
  tenant_id: string;
  actor_node_id: string;
  observed_login: string;
  account_created_at: Timestamp;
  observed_from: Timestamp;
  observed_until: Timestamp;
  account_age_days: number;
  commits: number;
  issues: number;
  pull_requests: number;
  pull_request_reviews: number;
  active_weeks: number;
  external_pull_requests_observed: number;
  external_closed_pull_requests: number;
  external_merged_pull_requests: number;
  distinct_public_repositories: number;
  restricted_contributions: number;
  truncated: boolean;
  provider_response_digest: string;
  cache_window_start: Timestamp;
  cache_expires_at: Timestamp;
  collected_at: GeneratedTimestamp;
}

export interface PullRequestReputationAssessmentTable {
  id: Generated<string>;
  tenant_id: string;
  pull_request_id: string;
  publication_id: string;
  history_snapshot_id: string | null;
  generation: number;
  head_sha: string;
  author_node_id: string | null;
  author_login: string | null;
  author_type: PullRequestTable["author_type"];
  status: "evaluated" | "not_evaluated" | "unavailable";
  reason:
    | "author_missing"
    | "actor_not_user"
    | "provider_unavailable"
    | "identity_mismatch"
    | "invalid_provider_data"
    | null;
  account_maturity_score: string | null;
  public_activity_score: string | null;
  regularity_score: string | null;
  merged_pull_requests_score: string | null;
  repository_breadth_score: string | null;
  final_score: number | null;
  band: "extensive" | "substantial" | "moderate" | "emerging" | "limited" | null;
  confidence: "high" | "medium" | "limited" | null;
  scoring_version: string | null;
  calculated_at: GeneratedTimestamp;
}

export interface PullRequestOutputCursorTable {
  id: Generated<string>;
  tenant_id: string;
  pull_request_id: string;
  installation_id: BigIntIdentifier;
  repository_node_id: string;
  pull_request_node_id: string;
  generation: number;
  head_sha: string;
  canonical_comment_id: BigIntIdentifier | null;
  current_check_run_id: BigIntIdentifier | null;
  state: "queued" | "publishing" | "published" | "stale" | "failed";
  revision: number;
  updated_at: GeneratedTimestamp;
}

export interface GitHubPublicationTable {
  id: Generated<string>;
  tenant_id: string;
  output_cursor_id: string;
  source_delivery_id: string;
  generation: number;
  head_sha: string;
  state: "queued" | "publishing" | "published" | "superseded" | "stale" | "failed";
  attempt_count: Generated<number>;
  lease_token: string | null;
  lease_expires_at: Timestamp | null;
  comment_id: BigIntIdentifier | null;
  check_run_id: BigIntIdentifier | null;
  observed_head_sha: string | null;
  last_error_code: string | null;
  created_at: GeneratedTimestamp;
  updated_at: GeneratedTimestamp;
  completed_at: Timestamp | null;
}

export interface GitHubPublicationTransitionTable {
  id: Generated<string>;
  tenant_id: string;
  publication_id: string;
  revision: number;
  prior_state: GitHubPublicationTable["state"] | null;
  state: GitHubPublicationTable["state"];
  source_delivery_id: string;
  head_sha: string;
  metadata: JSONColumnType<
    Record<string, unknown>,
    Record<string, unknown>,
    Record<string, unknown>
  >;
  occurred_at: GeneratedTimestamp;
}

export interface GitHubOutputObservationTable {
  id: Generated<string>;
  tenant_id: string;
  publication_id: string;
  phase: "pre_write" | "post_comment" | "post_check";
  expected_head_sha: string;
  observed_head_sha: string;
  comment_id: BigIntIdentifier | null;
  check_run_id: BigIntIdentifier | null;
  github_app_id: BigIntIdentifier;
  marker_digest: string;
  observed_at: GeneratedTimestamp;
}

export interface InstallationReconciliationTable {
  tenant_id: string;
  installation_id: BigIntIdentifier;
  state: "due" | "running" | "complete" | "failed";
  last_complete_at: Timestamp | null;
  next_due_at: Timestamp;
  repository_count: number | null;
  updated_at: GeneratedTimestamp;
}

export interface MergeSignalDatabase {
  "app.tenants": TenantTable;
  "app.webhook_deliveries": WebhookDeliveryTable;
  "app.outbox_events": OutboxEventTable;
  "app.workflow_runs": WorkflowRunTable;
  "app.synthetic_activity_attempts": SyntheticActivityAttemptTable;
  "app.synthetic_results": SyntheticResultTable;
  "app.github_installation_profiles": GitHubInstallationProfileTable;
  "app.repositories": RepositoryTable;
  "app.pull_requests": PullRequestTable;
  "app.contributor_history_snapshots": ContributorHistorySnapshotTable;
  "app.pr_reputation_assessments": PullRequestReputationAssessmentTable;
  "app.pr_output_cursors": PullRequestOutputCursorTable;
  "app.github_publications": GitHubPublicationTable;
  "app.github_publication_transitions": GitHubPublicationTransitionTable;
  "app.github_output_observations": GitHubOutputObservationTable;
  "app.installation_reconciliations": InstallationReconciliationTable;
  "audit.events": AuditEventTable;
}
