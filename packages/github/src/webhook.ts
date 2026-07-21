import { z } from "zod";

export const supportedGitHubEvents = [
  "check_run",
  "installation",
  "installation_repositories",
  "pull_request"
] as const;

export type SupportedGitHubEvent = (typeof supportedGitHubEvents)[number];

const installationSchema = z.object({
  id: z.number().int().positive(),
  account: z.object({
    node_id: z.string().min(1),
    login: z.string().min(1),
    type: z.string().min(1)
  }),
  permissions: z.record(z.string(), z.string()).default({}),
  events: z.array(z.string()).default([]),
  repository_selection: z.enum(["all", "selected"]).optional()
});

const repositorySchema = z.object({
  id: z.number().int().positive(),
  node_id: z.string().min(1),
  full_name: z.string().min(3),
  private: z.boolean(),
  default_branch: z.string().min(1).optional()
});

const pullRequestSchema = z.object({
  id: z.number().int().positive(),
  node_id: z.string().min(1),
  number: z.number().int().positive(),
  state: z.enum(["open", "closed"]),
  draft: z.boolean().default(false),
  updated_at: z.iso.datetime(),
  head: z.object({ sha: z.string().regex(/^[0-9a-f]{40}$/i) }),
  base: z.object({ sha: z.string().regex(/^[0-9a-f]{40}$/i) }),
  user: z
    .object({
      node_id: z.string().min(1),
      login: z.string().min(1),
      type: z.enum(["User", "Bot", "Organization", "Mannequin"])
    })
    .nullable()
});

const checkRunSchema = z.object({
  id: z.number().int().positive(),
  head_sha: z.string().regex(/^[0-9a-f]{40}$/i),
  name: z.string().min(1),
  app: z.object({ id: z.number().int().positive() }).nullable().optional()
});

const webhookPayloadSchema = z.object({
  action: z.string().min(1),
  installation: installationSchema,
  repository: repositorySchema.optional(),
  repositories: z.array(repositorySchema).optional(),
  repositories_added: z.array(repositorySchema).optional(),
  repositories_removed: z.array(repositorySchema).optional(),
  pull_request: pullRequestSchema.optional(),
  check_run: checkRunSchema.optional(),
  requested_action: z.object({ identifier: z.string().min(1) }).optional()
});

export interface GitHubWebhookEnvelope {
  event: SupportedGitHubEvent;
  action: string;
  installation: {
    id: number;
    accountNodeId: string;
    accountLogin: string;
    accountType: string;
    permissions: Record<string, string>;
    events: string[];
    repositorySelection?: "all" | "selected";
  };
  repository?: {
    id: number;
    nodeId: string;
    fullName: string;
    private: boolean;
    defaultBranch?: string;
  };
  repositories?: GitHubWebhookEnvelope["repository"][];
  repositoriesAdded?: GitHubWebhookEnvelope["repository"][];
  repositoriesRemoved?: GitHubWebhookEnvelope["repository"][];
  pullRequest?: {
    id: number;
    nodeId: string;
    number: number;
    state: "open" | "closed";
    draft: boolean;
    updatedAt: string;
    headSha: string;
    baseSha: string;
    authorNodeId: string | null;
    authorLogin: string | null;
    authorType: "User" | "Bot" | "Organization" | "Mannequin" | null;
  };
  checkRun?: {
    id: number;
    headSha: string;
    name: string;
    appId: number | null;
  };
  requestedAction?: string;
}

function mapRepository(repository: z.infer<typeof repositorySchema>) {
  return {
    id: repository.id,
    nodeId: repository.node_id,
    fullName: repository.full_name,
    private: repository.private,
    ...(repository.default_branch === undefined ? {} : { defaultBranch: repository.default_branch })
  };
}

export function parseGitHubWebhookEnvelope(
  eventHeader: string | null,
  rawBody: string
): GitHubWebhookEnvelope {
  const event = z.enum(supportedGitHubEvents).parse(eventHeader);
  const payload = webhookPayloadSchema.parse(JSON.parse(rawBody));
  const installation = {
    id: payload.installation.id,
    accountNodeId: payload.installation.account.node_id,
    accountLogin: payload.installation.account.login,
    accountType: payload.installation.account.type,
    permissions: payload.installation.permissions,
    events: payload.installation.events,
    ...(payload.installation.repository_selection === undefined
      ? {}
      : { repositorySelection: payload.installation.repository_selection })
  };
  return {
    event,
    action: payload.action,
    installation,
    ...(payload.repository === undefined ? {} : { repository: mapRepository(payload.repository) }),
    ...(payload.repositories === undefined
      ? {}
      : { repositories: payload.repositories.map(mapRepository) }),
    ...(payload.repositories_added === undefined
      ? {}
      : { repositoriesAdded: payload.repositories_added.map(mapRepository) }),
    ...(payload.repositories_removed === undefined
      ? {}
      : { repositoriesRemoved: payload.repositories_removed.map(mapRepository) }),
    ...(payload.pull_request === undefined
      ? {}
      : {
          pullRequest: {
            id: payload.pull_request.id,
            nodeId: payload.pull_request.node_id,
            number: payload.pull_request.number,
            state: payload.pull_request.state,
            draft: payload.pull_request.draft,
            updatedAt: payload.pull_request.updated_at,
            headSha: payload.pull_request.head.sha.toLowerCase(),
            baseSha: payload.pull_request.base.sha.toLowerCase(),
            authorNodeId: payload.pull_request.user?.node_id ?? null,
            authorLogin: payload.pull_request.user?.login ?? null,
            authorType: payload.pull_request.user?.type ?? null
          }
        }),
    ...(payload.check_run === undefined
      ? {}
      : {
          checkRun: {
            id: payload.check_run.id,
            headSha: payload.check_run.head_sha.toLowerCase(),
            name: payload.check_run.name,
            appId: payload.check_run.app?.id ?? null
          }
        }),
    ...(payload.requested_action === undefined
      ? {}
      : { requestedAction: payload.requested_action.identifier })
  };
}
