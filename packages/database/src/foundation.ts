import { sql } from "kysely";

import type { Database } from "./client.js";
import { withTenantTransaction } from "./client.js";

export interface SyntheticDeliveryInput {
  tenantId: string;
  deliveryId: string;
  bodyDigest: string;
  failActivityAttempts: number;
  payload: Record<string, unknown>;
}

export interface AcceptedSyntheticDelivery {
  accepted: boolean;
  deliveryRecordId: string;
  outboxEventId: string;
}

export interface ClaimedOutboxEvent {
  id: string;
  tenantId: string;
  eventType: string;
  payload: Record<string, unknown>;
  leaseToken: string;
}

export interface SyntheticActivityInput {
  tenantId: string;
  deliveryId: string;
  workflowId: string;
  bodyDigest: string;
  failActivityAttempts: number;
}

export interface SyntheticActivityResult {
  resultId: string;
  activityAttempts: number;
}

function firstRow<T>(rows: readonly T[], message: string): T {
  const row = rows[0];
  if (row === undefined) throw new Error(message);
  return row;
}

export async function acceptSyntheticDelivery(
  database: Database,
  input: SyntheticDeliveryInput
): Promise<AcceptedSyntheticDelivery> {
  return withTenantTransaction(database, input.tenantId, async (transaction) => {
    const result = await sql<{
      accepted: boolean;
      delivery_record_id: string;
      outbox_event_id: string;
    }>`
      with inserted_delivery as (
        insert into app.webhook_deliveries (
          tenant_id, source, delivery_id, body_digest, payload
        ) values (
          ${input.tenantId}::uuid,
          'synthetic',
          ${input.deliveryId},
          ${input.bodyDigest},
          ${JSON.stringify(input.payload)}::jsonb
        )
        on conflict (source, delivery_id) do nothing
        returning id
      ), selected_delivery as (
        select id from inserted_delivery
        union all
        select id from app.webhook_deliveries
        where
          source = 'synthetic'
          and delivery_id = ${input.deliveryId}
          and body_digest = ${input.bodyDigest}
        limit 1
      ), inserted_outbox as (
        insert into app.outbox_events (
          tenant_id,
          aggregate_type,
          aggregate_id,
          event_type,
          dedupe_key,
          payload
        )
        select
          ${input.tenantId}::uuid,
          'webhook_delivery',
          selected_delivery.id::text,
          'synthetic.delivery.accepted',
          'synthetic:' || ${input.deliveryId},
          jsonb_build_object(
            'tenantId', ${input.tenantId}::text,
            'deliveryId', ${input.deliveryId}::text,
            'bodyDigest', ${input.bodyDigest}::text,
            'failActivityAttempts', ${input.failActivityAttempts}::integer
          )
        from selected_delivery
        on conflict (dedupe_key) do nothing
        returning id
      ), selected_outbox as (
        select id from inserted_outbox
        union all
        select id from app.outbox_events
        where tenant_id = ${input.tenantId}::uuid and dedupe_key = 'synthetic:' || ${input.deliveryId}
        limit 1
      )
      select
        exists(select 1 from inserted_delivery) as accepted,
        selected_delivery.id::text as delivery_record_id,
        selected_outbox.id::text as outbox_event_id
      from selected_delivery
      cross join selected_outbox
    `.execute(transaction);

    const row = firstRow(
      result.rows,
      "Synthetic delivery conflicted across tenants or changed payload digest"
    );
    return {
      accepted: row.accepted,
      deliveryRecordId: row.delivery_record_id,
      outboxEventId: row.outbox_event_id
    };
  });
}

export async function claimOutboxEvents(
  database: Database,
  limit = 25
): Promise<ClaimedOutboxEvent[]> {
  const leaseToken = crypto.randomUUID();
  const result = await sql<{
    id: string;
    tenant_id: string;
    event_type: string;
    payload: Record<string, unknown>;
  }>`
    with candidates as (
      select id
      from app.outbox_events
      where (
        state = 'available'
        and available_at <= clock_timestamp()
      ) or (
        state = 'publishing'
        and lease_expires_at < clock_timestamp()
      )
      order by created_at, id
      for update skip locked
      limit ${limit}
    )
    update app.outbox_events as event
    set
      state = 'publishing',
      lease_token = ${leaseToken}::uuid,
      lease_expires_at = clock_timestamp() + interval '30 seconds',
      attempt_count = attempt_count + 1
    from candidates
    where event.id = candidates.id
    returning event.id::text, event.tenant_id::text, event.event_type, event.payload
  `.execute(database);

  return result.rows.map((row) => ({
    id: row.id,
    tenantId: row.tenant_id,
    eventType: row.event_type,
    payload: row.payload,
    leaseToken
  }));
}

export async function markOutboxPublished(
  database: Database,
  eventId: string,
  leaseToken: string
): Promise<void> {
  const result = await sql`
    update app.outbox_events
    set
      state = 'published',
      published_at = clock_timestamp(),
      lease_token = null,
      lease_expires_at = null,
      last_error_code = null
    where id = ${eventId}::uuid and lease_token = ${leaseToken}::uuid and state = 'publishing'
  `.execute(database);
  if (result.numAffectedRows !== 1n) throw new Error("Outbox publication lease was lost");
}

export async function releaseOutboxEvent(
  database: Database,
  eventId: string,
  leaseToken: string,
  errorCode: string
): Promise<void> {
  const result = await sql`
    update app.outbox_events
    set
      state = 'available',
      available_at = clock_timestamp() + least(interval '30 seconds', interval '1 second' * attempt_count),
      lease_token = null,
      lease_expires_at = null,
      last_error_code = ${errorCode.slice(0, 80)}
    where id = ${eventId}::uuid and lease_token = ${leaseToken}::uuid and state = 'publishing'
  `.execute(database);
  if (result.numAffectedRows !== 1n) throw new Error("Outbox retry lease was lost");
}

export async function recordWorkflowStarted(
  database: Database,
  input: {
    tenantId: string;
    workflowId: string;
    taskQueue: string;
    deliveryId: string;
    workflowType?: string;
  }
): Promise<void> {
  await withTenantTransaction(database, input.tenantId, async (transaction) => {
    await sql`
      insert into app.workflow_runs (
        tenant_id, workflow_id, workflow_type, task_queue, source_delivery_id
      ) values (
        ${input.tenantId}::uuid,
        ${input.workflowId},
        ${input.workflowType ?? "syntheticDeliveryWorkflow"},
        ${input.taskQueue},
        ${input.deliveryId}
      )
      on conflict (workflow_id) do nothing
    `.execute(transaction);
  });
}

export async function recordWorkflowCompleted(
  database: Database,
  input: { tenantId: string; workflowId: string }
): Promise<void> {
  await withTenantTransaction(database, input.tenantId, async (transaction) => {
    const result = await transaction
      .updateTable("app.workflow_runs")
      .set({ state: "completed", completed_at: new Date() })
      .where("tenant_id", "=", input.tenantId)
      .where("workflow_id", "=", input.workflowId)
      .where("state", "=", "started")
      .executeTakeFirst();
    if (result.numUpdatedRows !== 1n) {
      const existing = await transaction
        .selectFrom("app.workflow_runs")
        .select("state")
        .where("tenant_id", "=", input.tenantId)
        .where("workflow_id", "=", input.workflowId)
        .executeTakeFirst();
      if (existing?.state !== "completed") throw new Error("Workflow run completion was not recorded");
    }
  });
}

export async function persistSyntheticResultAttempt(
  database: Database,
  input: SyntheticActivityInput
): Promise<SyntheticActivityResult & { shouldFail: boolean }> {
  return withTenantTransaction(database, input.tenantId, async (transaction) => {
    const attemptResult = await sql<{ attempt_count: number }>`
      insert into app.synthetic_activity_attempts (tenant_id, delivery_id, attempt_count)
      values (${input.tenantId}::uuid, ${input.deliveryId}, 1)
      on conflict (tenant_id, delivery_id) do update
        set attempt_count = app.synthetic_activity_attempts.attempt_count + 1,
            updated_at = clock_timestamp()
      returning attempt_count
    `.execute(transaction);
    const attempt = firstRow(attemptResult.rows, "Synthetic activity attempt was not recorded").attempt_count;

    if (attempt <= input.failActivityAttempts) {
      return { resultId: "pending", activityAttempts: attempt, shouldFail: true };
    }

    const result = await sql<{ id: string; activity_attempts: number }>`
      insert into app.synthetic_results (
        tenant_id, delivery_id, workflow_id, body_digest, activity_attempts
      ) values (
        ${input.tenantId}::uuid,
        ${input.deliveryId},
        ${input.workflowId},
        ${input.bodyDigest},
        ${attempt}
      )
      on conflict (tenant_id, delivery_id) do update
        set delivery_id = excluded.delivery_id
      returning id::text, activity_attempts
    `.execute(transaction);
    const row = firstRow(result.rows, "Synthetic result was not persisted");

    await sql`
      update app.workflow_runs
      set state = 'completed', completed_at = clock_timestamp()
      where tenant_id = ${input.tenantId}::uuid and workflow_id = ${input.workflowId}
    `.execute(transaction);

    return {
      resultId: row.id,
      activityAttempts: row.activity_attempts,
      shouldFail: false
    };
  });
}
