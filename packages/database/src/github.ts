import { createHash, randomUUID } from "node:crypto";

import { sql, type Transaction } from "kysely";

import type { GitHubWebhookEnvelope } from "@mergesignal/github";

import {
  withTenantSerializableTransaction,
  withTenantTransaction,
  type Database
} from "./client.js";
import type { MergeSignalDatabase } from "./types.js";
import { loadReputationReport } from "./reputation.js";
import type { ReputationAssessmentReport } from "@mergesignal/reputation";

type TenantTransaction = Transaction<MergeSignalDatabase>;

export interface AcceptedGitHubDelivery {
  tenantId: string;
  accepted: boolean;
  deliveryRecordId: string;
  outboxEventId: string;
}

export interface QueuedGitHubPublication {
  tenantId: string;
  publicationId: string;
  generation: number;
  headSha: string;
}

export interface AppliedGitHubDelivery {
  installationId: number;
  reconcileInstallation: boolean;
  publication: QueuedGitHubPublication | null;
}

export interface ClaimedGitHubPublication {
  publicationId: string;
  leaseToken: string;
  tenantId: string;
  installationId: number;
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

export interface GitHubPublicationCompletion {
  state: "published" | "stale";
  commentId: number;
  checkRunId: number;
  observedHeadSha: string;
}

function toSafeNumber(value: string | number, label: string): number {
  const number = typeof value === "number" ? value : Number(value);
  if (!Number.isSafeInteger(number) || number <= 0) throw new Error(`${label} is not a safe integer`);
  return number;
}

function repositoryParts(fullName: string): { owner: string; name: string } {
  const separator = fullName.indexOf("/");
  if (separator <= 0 || separator === fullName.length - 1) {
    throw new Error("GitHub repository full name is invalid");
  }
  return { owner: fullName.slice(0, separator), name: fullName.slice(separator + 1) };
}

export async function acceptGitHubDelivery(
  database: Database,
  input: { deliveryId: string; bodyDigest: string; envelope: GitHubWebhookEnvelope }
): Promise<AcceptedGitHubDelivery> {
  const { envelope } = input;
  const result = await sql<{
    tenant_id: string;
    accepted: boolean;
    delivery_record_id: string;
    outbox_event_id: string;
  }>`
    select * from app.accept_github_webhook(
      ${input.deliveryId},
      ${envelope.event},
      ${envelope.action},
      ${input.bodyDigest},
      ${envelope.installation.id}::bigint,
      ${envelope.installation.accountNodeId ?? null},
      ${envelope.installation.accountLogin ?? null},
      ${envelope.installation.accountType ?? null},
      ${envelope.installation.repositorySelection ?? null},
      ${envelope.installation.permissions === undefined
        ? null
        : JSON.stringify(envelope.installation.permissions)}::jsonb,
      ${envelope.installation.events ?? null}::text[],
      ${JSON.stringify(envelope)}::jsonb
    )
  `.execute(database);
  const row = result.rows[0];
  if (row === undefined) throw new Error("GitHub delivery was not accepted");
  return {
    tenantId: row.tenant_id,
    accepted: row.accepted,
    deliveryRecordId: row.delivery_record_id,
    outboxEventId: row.outbox_event_id
  };
}

async function updateInstallation(
  transaction: TenantTransaction,
  tenantId: string,
  deliveryId: string,
  envelope: GitHubWebhookEnvelope
): Promise<void> {
  let state: "active" | "suspended" | "deleted" | undefined;
  if (envelope.event === "installation") {
    if (["created", "unsuspended", "new_permissions_accepted"].includes(envelope.action)) {
      state = "active";
    } else if (envelope.action === "suspend") {
      state = "suspended";
    } else if (envelope.action === "deleted") {
      state = "deleted";
    }
  }

  const installationUpdates = {
    ...(envelope.installation.accountNodeId === undefined
      ? {}
      : { account_node_id: envelope.installation.accountNodeId }),
    ...(envelope.installation.accountLogin === undefined
      ? {}
      : { account_login: envelope.installation.accountLogin }),
    ...(envelope.installation.accountType === undefined
      ? {}
      : { account_type: envelope.installation.accountType }),
    ...(envelope.installation.repositorySelection === undefined
      ? {}
      : { repository_selection: envelope.installation.repositorySelection }),
    ...(envelope.installation.permissions === undefined
      ? {}
      : { permissions: envelope.installation.permissions }),
    ...(envelope.installation.events === undefined
      ? {}
      : { subscribed_events: envelope.installation.events })
  };

  await transaction
    .updateTable("app.github_installation_profiles")
    .set({
      ...installationUpdates,
      last_delivery_id: deliveryId,
      ...(state === undefined ? {} : { state }),
      updated_at: new Date()
    })
    .where("tenant_id", "=", tenantId)
    .where("installation_id", "=", envelope.installation.id.toString())
    .executeTakeFirstOrThrow();

  if (state !== "deleted") {
    await transaction
      .insertInto("app.installation_reconciliations")
      .values({
        tenant_id: tenantId,
        installation_id: envelope.installation.id,
        state: "due",
        last_complete_at: null,
        next_due_at: new Date(),
        repository_count: null
      })
      .onConflict((conflict) =>
        conflict.columns(["tenant_id", "installation_id"]).doUpdateSet({
          state: "due",
          next_due_at: new Date(),
          updated_at: new Date()
        })
      )
      .execute();
  }
}

async function upsertRepository(
  transaction: TenantTransaction,
  tenantId: string,
  installationId: number,
  repository: NonNullable<GitHubWebhookEnvelope["repository"]>,
  state: "active" | "removed" = "active"
): Promise<string> {
  const parts = repositoryParts(repository.fullName);
  const row = await transaction
    .insertInto("app.repositories")
    .values({
      tenant_id: tenantId,
      installation_id: installationId,
      github_repository_id: repository.id,
      repository_node_id: repository.nodeId,
      full_name: repository.fullName,
      owner_login: parts.owner,
      name: parts.name,
      private: repository.private,
      default_branch: repository.defaultBranch ?? null,
      state,
      provider_updated_at: new Date()
    })
    .onConflict((conflict) =>
      conflict.columns(["tenant_id", "github_repository_id"]).doUpdateSet({
        repository_node_id: repository.nodeId,
        full_name: repository.fullName,
        owner_login: parts.owner,
        name: parts.name,
        private: repository.private,
        default_branch: repository.defaultBranch ?? null,
        state,
        provider_updated_at: new Date(),
        updated_at: new Date()
      })
    )
    .returning("id")
    .executeTakeFirstOrThrow();
  return row.id;
}

async function appendTransition(
  transaction: TenantTransaction,
  input: {
    tenantId: string;
    publicationId: string;
    priorState: "queued" | "publishing" | "published" | "superseded" | "stale" | "failed" | null;
    state: "queued" | "publishing" | "published" | "superseded" | "stale" | "failed";
    sourceDeliveryId: string;
    headSha: string;
    metadata?: Record<string, unknown>;
  }
): Promise<void> {
  const head = await transaction
    .selectFrom("app.github_publication_transitions")
    .select(({ fn }) => fn.max<number>("revision").as("revision"))
    .where("publication_id", "=", input.publicationId)
    .executeTakeFirst();
  await transaction
    .insertInto("app.github_publication_transitions")
    .values({
      tenant_id: input.tenantId,
      publication_id: input.publicationId,
      revision: (head?.revision ?? 0) + 1,
      prior_state: input.priorState,
      state: input.state,
      source_delivery_id: input.sourceDeliveryId,
      head_sha: input.headSha,
      metadata: input.metadata ?? {}
    })
    .execute();
}

async function queuePublication(
  transaction: TenantTransaction,
  input: {
    tenantId: string;
    pullRequestId: string;
    installationId: number;
    repositoryNodeId: string;
    pullRequestNodeId: string;
    headSha: string;
    sourceDeliveryId: string;
    forceGeneration: boolean;
  }
): Promise<QueuedGitHubPublication> {
  await transaction
    .insertInto("app.pr_output_cursors")
    .values({
      tenant_id: input.tenantId,
      pull_request_id: input.pullRequestId,
      installation_id: input.installationId,
      repository_node_id: input.repositoryNodeId,
      pull_request_node_id: input.pullRequestNodeId,
      generation: 1,
      head_sha: input.headSha,
      canonical_comment_id: null,
      current_check_run_id: null,
      state: "queued",
      revision: 1
    })
    .onConflict((conflict) => conflict.column("pull_request_id").doNothing())
    .execute();

  let cursor = await transaction
    .selectFrom("app.pr_output_cursors")
    .selectAll()
    .where("pull_request_id", "=", input.pullRequestId)
    .forUpdate()
    .executeTakeFirstOrThrow();

  const shouldAdvance = input.forceGeneration || cursor.head_sha !== input.headSha;
  if (shouldAdvance) {
    const previous = await transaction
      .selectFrom("app.github_publications")
      .selectAll()
      .where("output_cursor_id", "=", cursor.id)
      .where("generation", "=", cursor.generation)
      .executeTakeFirst();
    if (previous !== undefined && previous.state !== "superseded") {
      await transaction
        .updateTable("app.github_publications")
        .set({ state: "superseded", lease_token: null, lease_expires_at: null, updated_at: new Date() })
        .where("id", "=", previous.id)
        .execute();
      await appendTransition(transaction, {
        tenantId: input.tenantId,
        publicationId: previous.id,
        priorState: previous.state,
        state: "superseded",
        sourceDeliveryId: input.sourceDeliveryId,
        headSha: previous.head_sha,
        metadata: { supersededByHeadSha: input.headSha }
      });
    }
    cursor = await transaction
      .updateTable("app.pr_output_cursors")
      .set({
        generation: cursor.generation + 1,
        head_sha: input.headSha,
        current_check_run_id: null,
        state: "queued",
        revision: cursor.revision + 1,
        updated_at: new Date()
      })
      .where("id", "=", cursor.id)
      .returningAll()
      .executeTakeFirstOrThrow();
  }

  let publication = await transaction
    .selectFrom("app.github_publications")
    .selectAll()
    .where("output_cursor_id", "=", cursor.id)
    .where("generation", "=", cursor.generation)
    .executeTakeFirst();
  if (publication === undefined) {
    publication = await transaction
      .insertInto("app.github_publications")
      .values({
        tenant_id: input.tenantId,
        output_cursor_id: cursor.id,
        source_delivery_id: input.sourceDeliveryId,
        generation: cursor.generation,
        head_sha: cursor.head_sha,
        state: "queued",
        lease_token: null,
        lease_expires_at: null,
        comment_id: null,
        check_run_id: null,
        observed_head_sha: null,
        last_error_code: null,
        completed_at: null
      })
      .returningAll()
      .executeTakeFirstOrThrow();
    await appendTransition(transaction, {
      tenantId: input.tenantId,
      publicationId: publication.id,
      priorState: null,
      state: "queued",
      sourceDeliveryId: input.sourceDeliveryId,
      headSha: cursor.head_sha
    });
  }
  return {
    tenantId: input.tenantId,
    publicationId: publication.id,
    generation: publication.generation,
    headSha: publication.head_sha
  };
}

export async function applyGitHubDelivery(
  database: Database,
  input: { tenantId: string; deliveryId: string; expectedAppId: number }
): Promise<AppliedGitHubDelivery> {
  return withTenantSerializableTransaction(database, input.tenantId, async (transaction) => {
    const delivery = await transaction
      .selectFrom("app.webhook_deliveries")
      .select("payload")
      .where("source", "=", "github")
      .where("delivery_id", "=", input.deliveryId)
      .executeTakeFirstOrThrow();
    const envelope = delivery.payload as unknown as GitHubWebhookEnvelope;
    const baseResult = {
      installationId: envelope.installation.id,
      reconcileInstallation:
        envelope.event === "installation" || envelope.event === "installation_repositories"
    };
    await updateInstallation(transaction, input.tenantId, input.deliveryId, envelope);

    for (const repository of [
      ...(envelope.repositories ?? []),
      ...(envelope.repositoriesAdded ?? [])
    ]) {
      if (repository !== undefined) {
        await upsertRepository(
          transaction,
          input.tenantId,
          envelope.installation.id,
          repository,
          "active"
        );
      }
    }
    for (const repository of envelope.repositoriesRemoved ?? []) {
      if (repository !== undefined) {
        await upsertRepository(
          transaction,
          input.tenantId,
          envelope.installation.id,
          repository,
          "removed"
        );
      }
    }

    if (envelope.event === "check_run") {
      if (
        !["rerequested", "requested_action"].includes(envelope.action) ||
        envelope.checkRun?.name !== "MergeSignal" ||
        envelope.checkRun.appId !== input.expectedAppId ||
        envelope.repository === undefined
      ) {
        return { ...baseResult, publication: null };
      }
      const repository = await transaction
        .selectFrom("app.repositories")
        .select("id")
        .where("tenant_id", "=", input.tenantId)
        .where("github_repository_id", "=", envelope.repository.id.toString())
        .executeTakeFirst();
      if (repository === undefined) return { ...baseResult, publication: null };
      const pullRequest = await transaction
        .selectFrom("app.pull_requests")
        .selectAll()
        .where("repository_id", "=", repository.id)
        .where("head_sha", "=", envelope.checkRun.headSha)
        .where("state", "=", "open")
        .executeTakeFirst();
      if (pullRequest === undefined) return { ...baseResult, publication: null };
      return { ...baseResult, publication: await queuePublication(transaction, {
        tenantId: input.tenantId,
        pullRequestId: pullRequest.id,
        installationId: envelope.installation.id,
        repositoryNodeId: envelope.repository.nodeId,
        pullRequestNodeId: pullRequest.pull_request_node_id,
        headSha: pullRequest.head_sha,
        sourceDeliveryId: input.deliveryId,
        forceGeneration: true
      }) };
    }

    if (
      envelope.event !== "pull_request" ||
      envelope.repository === undefined ||
      envelope.pullRequest === undefined
    ) {
      return { ...baseResult, publication: null };
    }

    const shouldPublish = ["opened", "reopened", "ready_for_review", "synchronize"].includes(
      envelope.action
    );

    const repositoryId = await upsertRepository(
      transaction,
      input.tenantId,
      envelope.installation.id,
      envelope.repository
    );
    const existing = await transaction
      .selectFrom("app.pull_requests")
      .selectAll()
      .where("repository_id", "=", repositoryId)
      .where("number", "=", envelope.pullRequest.number)
      .forUpdate()
      .executeTakeFirst();
    const providerUpdatedAt = new Date(envelope.pullRequest.updatedAt);
    if (existing !== undefined && providerUpdatedAt < new Date(existing.provider_updated_at)) {
      return { ...baseResult, publication: null };
    }

    const pullRequest = await transaction
      .insertInto("app.pull_requests")
      .values({
        tenant_id: input.tenantId,
        repository_id: repositoryId,
        github_pull_request_id: envelope.pullRequest.id,
        pull_request_node_id: envelope.pullRequest.nodeId,
        number: envelope.pullRequest.number,
        state: envelope.pullRequest.state,
        draft: envelope.pullRequest.draft,
        head_sha: envelope.pullRequest.headSha,
        base_sha: envelope.pullRequest.baseSha,
        author_node_id: envelope.pullRequest.authorNodeId,
        author_login: envelope.pullRequest.authorLogin,
        author_type: envelope.pullRequest.authorType,
        provider_updated_at: providerUpdatedAt
      })
      .onConflict((conflict) =>
        conflict.columns(["repository_id", "number"]).doUpdateSet({
          github_pull_request_id: envelope.pullRequest!.id,
          pull_request_node_id: envelope.pullRequest!.nodeId,
          state: envelope.pullRequest!.state,
          draft: envelope.pullRequest!.draft,
          head_sha: envelope.pullRequest!.headSha,
          base_sha: envelope.pullRequest!.baseSha,
          author_node_id: envelope.pullRequest!.authorNodeId,
          author_login: envelope.pullRequest!.authorLogin,
          author_type: envelope.pullRequest!.authorType,
          provider_updated_at: providerUpdatedAt,
          updated_at: new Date()
        })
      )
      .returningAll()
      .executeTakeFirstOrThrow();

    if (pullRequest.state !== "open" || !shouldPublish) {
      return { ...baseResult, publication: null };
    }
    return { ...baseResult, publication: await queuePublication(transaction, {
      tenantId: input.tenantId,
      pullRequestId: pullRequest.id,
      installationId: envelope.installation.id,
      repositoryNodeId: envelope.repository.nodeId,
      pullRequestNodeId: pullRequest.pull_request_node_id,
      headSha: pullRequest.head_sha,
      sourceDeliveryId: input.deliveryId,
      forceGeneration: false
    }) };
  });
}

export async function claimGitHubPublication(
  database: Database,
  input: { tenantId: string; publicationId: string }
): Promise<ClaimedGitHubPublication> {
  return withTenantSerializableTransaction(database, input.tenantId, async (transaction) => {
    const publication = await transaction
      .selectFrom("app.github_publications as publication")
      .innerJoin("app.pr_output_cursors as cursor", "cursor.id", "publication.output_cursor_id")
      .innerJoin("app.pull_requests as pull_request", "pull_request.id", "cursor.pull_request_id")
      .innerJoin("app.repositories as repository", "repository.id", "pull_request.repository_id")
      .select([
        "publication.id as publication_id",
        "publication.state as publication_state",
        "publication.source_delivery_id",
        "publication.generation",
        "publication.head_sha",
        "publication.lease_expires_at",
        "cursor.canonical_comment_id",
        "cursor.current_check_run_id",
        "cursor.generation as cursor_generation",
        "cursor.head_sha as cursor_head_sha",
        "cursor.repository_node_id",
        "cursor.pull_request_node_id",
        "cursor.installation_id",
        "pull_request.number as pull_request_number",
        "repository.github_repository_id",
        "repository.owner_login",
        "repository.name"
      ])
      .where("publication.id", "=", input.publicationId)
      .forUpdate("publication")
      .executeTakeFirstOrThrow();
    if (
      publication.publication_state === "superseded" ||
      publication.cursor_generation !== publication.generation ||
      publication.cursor_head_sha !== publication.head_sha
    ) {
      throw new Error("GitHub publication is no longer current");
    }
    if (
      publication.publication_state === "publishing" &&
      publication.lease_expires_at !== null &&
      new Date(publication.lease_expires_at) > new Date()
    ) {
      throw new Error("GitHub publication already has an active lease");
    }

    const leaseToken = randomUUID();
    const assessment = await loadReputationReport(transaction, input.publicationId);
    await transaction
      .updateTable("app.github_publications")
      .set({
        state: "publishing",
        lease_token: leaseToken,
        lease_expires_at: new Date(Date.now() + 60_000),
        attempt_count: sql`attempt_count + 1`,
        last_error_code: null,
        updated_at: new Date()
      })
      .where("id", "=", input.publicationId)
      .execute();
    if (publication.publication_state !== "publishing") {
      await appendTransition(transaction, {
        tenantId: input.tenantId,
        publicationId: input.publicationId,
        priorState: publication.publication_state,
        state: "publishing",
        sourceDeliveryId: publication.source_delivery_id,
        headSha: publication.head_sha
      });
    }

    return {
      publicationId: input.publicationId,
      leaseToken,
      tenantId: input.tenantId,
      installationId: toSafeNumber(publication.installation_id, "installation ID"),
      repositoryId: toSafeNumber(publication.github_repository_id, "repository ID"),
      repositoryNodeId: publication.repository_node_id,
      owner: publication.owner_login,
      repository: publication.name,
      pullRequestNodeId: publication.pull_request_node_id,
      pullRequestNumber: publication.pull_request_number,
      headSha: publication.head_sha,
      generation: publication.generation,
      canonicalCommentId:
        publication.canonical_comment_id === null
          ? null
          : toSafeNumber(publication.canonical_comment_id, "comment ID"),
      checkRunId:
        publication.current_check_run_id === null
          ? null
          : toSafeNumber(publication.current_check_run_id, "check run ID"),
      assessment
    };
  });
}

export async function recordGitHubOutputObservation(
  database: Database,
  input: {
    tenantId: string;
    publicationId: string;
    phase: "pre_write" | "post_comment" | "post_check";
    expectedHeadSha: string;
    observedHeadSha: string;
    commentId: number | null;
    checkRunId: number | null;
    appId: number;
    marker: string;
  }
): Promise<void> {
  await withTenantTransaction(database, input.tenantId, async (transaction) => {
    await transaction
      .insertInto("app.github_output_observations")
      .values({
        tenant_id: input.tenantId,
        publication_id: input.publicationId,
        phase: input.phase,
        expected_head_sha: input.expectedHeadSha,
        observed_head_sha: input.observedHeadSha,
        comment_id: input.commentId,
        check_run_id: input.checkRunId,
        github_app_id: input.appId,
        marker_digest: createHash("sha256").update(input.marker).digest("hex")
      })
      .execute();
  });
}

export async function completeGitHubPublication(
  database: Database,
  input: {
    tenantId: string;
    publicationId: string;
    leaseToken: string;
    completion: GitHubPublicationCompletion;
  }
): Promise<QueuedGitHubPublication | null> {
  return withTenantSerializableTransaction(database, input.tenantId, async (transaction) => {
    const publication = await transaction
      .selectFrom("app.github_publications")
      .selectAll()
      .where("id", "=", input.publicationId)
      .where("lease_token", "=", input.leaseToken)
      .forUpdate()
      .executeTakeFirstOrThrow();
    const cursor = await transaction
      .selectFrom("app.pr_output_cursors")
      .selectAll()
      .where("id", "=", publication.output_cursor_id)
      .forUpdate()
      .executeTakeFirstOrThrow();
    const current =
      cursor.generation === publication.generation && cursor.head_sha === publication.head_sha;
    const state = current && input.completion.state === "published" ? "published" : "stale";

    await transaction
      .updateTable("app.github_publications")
      .set({
        state,
        lease_token: null,
        lease_expires_at: null,
        comment_id: input.completion.commentId,
        check_run_id: input.completion.checkRunId,
        observed_head_sha: input.completion.observedHeadSha,
        updated_at: new Date(),
        completed_at: state === "published" ? new Date() : null
      })
      .where("id", "=", publication.id)
      .execute();
    await appendTransition(transaction, {
      tenantId: input.tenantId,
      publicationId: publication.id,
      priorState: publication.state,
      state,
      sourceDeliveryId: publication.source_delivery_id,
      headSha: publication.head_sha,
      metadata: { observedHeadSha: input.completion.observedHeadSha }
    });

    if (current) {
      await transaction
        .updateTable("app.pr_output_cursors")
        .set({
          canonical_comment_id: input.completion.commentId,
          current_check_run_id: input.completion.checkRunId,
          state,
          revision: cursor.revision + 1,
          updated_at: new Date()
        })
        .where("id", "=", cursor.id)
        .execute();
    }

    if (
      current &&
      state === "stale" &&
      input.completion.observedHeadSha !== publication.head_sha
    ) {
      await transaction
        .updateTable("app.pull_requests")
        .set({ head_sha: input.completion.observedHeadSha, updated_at: new Date() })
        .where("id", "=", cursor.pull_request_id)
        .execute();
      return queuePublication(transaction, {
        tenantId: input.tenantId,
        pullRequestId: cursor.pull_request_id,
        installationId: toSafeNumber(cursor.installation_id, "installation ID"),
        repositoryNodeId: cursor.repository_node_id,
        pullRequestNodeId: cursor.pull_request_node_id,
        headSha: input.completion.observedHeadSha,
        sourceDeliveryId: publication.source_delivery_id,
        forceGeneration: false
      });
    }
    return null;
  });
}

export async function failGitHubPublication(
  database: Database,
  input: { tenantId: string; publicationId: string; leaseToken: string; errorCode: string }
): Promise<void> {
  await withTenantTransaction(database, input.tenantId, async (transaction) => {
    const publication = await transaction
      .selectFrom("app.github_publications")
      .selectAll()
      .where("id", "=", input.publicationId)
      .where("lease_token", "=", input.leaseToken)
      .forUpdate()
      .executeTakeFirstOrThrow();
    await transaction
      .updateTable("app.github_publications")
      .set({
        state: "failed",
        lease_token: null,
        lease_expires_at: null,
        last_error_code: input.errorCode.slice(0, 80),
        updated_at: new Date()
      })
      .where("id", "=", input.publicationId)
      .execute();
    await appendTransition(transaction, {
      tenantId: input.tenantId,
      publicationId: input.publicationId,
      priorState: publication.state,
      state: "failed",
      sourceDeliveryId: publication.source_delivery_id,
      headSha: publication.head_sha,
      metadata: { errorCode: input.errorCode.slice(0, 80) }
    });
  });
}

export async function reconcileInstallationRepositories(
  database: Database,
  input: {
    tenantId: string;
    installationId: number;
    repositories: Array<NonNullable<GitHubWebhookEnvelope["repository"]>>;
  }
): Promise<void> {
  await withTenantSerializableTransaction(database, input.tenantId, async (transaction) => {
    const observedIds: string[] = [];
    for (const repository of input.repositories) {
      observedIds.push(repository.id.toString());
      await upsertRepository(
        transaction,
        input.tenantId,
        input.installationId,
        repository,
        "active"
      );
    }
    let removal = transaction
      .updateTable("app.repositories")
      .set({ state: "removed", updated_at: new Date() })
      .where("tenant_id", "=", input.tenantId)
      .where("installation_id", "=", input.installationId.toString())
      .where("state", "=", "active");
    if (observedIds.length > 0) removal = removal.where("github_repository_id", "not in", observedIds);
    await removal.execute();
    await transaction
      .insertInto("app.installation_reconciliations")
      .values({
        tenant_id: input.tenantId,
        installation_id: input.installationId,
        state: "complete",
        last_complete_at: new Date(),
        next_due_at: new Date(Date.now() + 60 * 60 * 1_000),
        repository_count: input.repositories.length
      })
      .onConflict((conflict) =>
        conflict.columns(["tenant_id", "installation_id"]).doUpdateSet({
          state: "complete",
          last_complete_at: new Date(),
          next_due_at: new Date(Date.now() + 60 * 60 * 1_000),
          repository_count: input.repositories.length,
          updated_at: new Date()
        })
      )
      .execute();
  });
}
