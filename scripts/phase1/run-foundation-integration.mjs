import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { resolve } from "node:path";

import { Client } from "@temporalio/client";
import { NativeConnection, Worker } from "@temporalio/worker";
import pg from "pg";

import {
  acceptSyntheticDelivery,
  createDatabase,
  withTenantTransaction
} from "../../packages/database/dist/index.js";
import { migrateDatabase } from "../../packages/database/dist/migrations.js";
import { createActivities } from "../../apps/worker/dist/activities.js";
import { runOutboxRelay } from "../../apps/worker/dist/outbox-relay.js";

const { Pool } = pg;
const databaseUrl = process.env.DATABASE_URL;
const temporalAddress = process.env.TEMPORAL_ADDRESS ?? "127.0.0.1:7233";
if (databaseUrl === undefined) throw new Error("DATABASE_URL is required for Phase 1 integration");

async function connectTemporalWithRetry() {
  let lastError;
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      return await NativeConnection.connect({ address: temporalAddress });
    } catch (error) {
      lastError = error;
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 1_000));
    }
  }
  throw lastError;
}

async function waitForResult(database, tenantId, deliveryId) {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const result = await withTenantTransaction(database, tenantId, (transaction) =>
      transaction
        .selectFrom("app.synthetic_results")
        .select(["id", "activity_attempts"])
        .where("delivery_id", "=", deliveryId)
        .executeTakeFirst()
    );
    if (result !== undefined) return result;
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
  }
  throw new Error("Synthetic workflow did not persist a result before the deadline");
}

async function verifyRowLevelSecurity(firstTenantId, secondTenantId) {
  const pool = new Pool({ connectionString: databaseUrl, max: 1 });
  const client = await pool.connect();
  try {
    await client.query("begin");
    await client.query("set local role mergesignal_web");
    await client.query("select set_config('app.tenant_id', $1, true)", [firstTenantId]);
    const visible = await client.query("select id::text from app.tenants order by id");
    assert.deepEqual(visible.rows, [{ id: firstTenantId }]);
    assert.equal(visible.rows.some((row) => row.id === secondTenantId), false);
    await assert.rejects(
      client.query("update app.outbox_events set state = 'published' where tenant_id = $1", [
        firstTenantId
      ]),
      (error) => error?.code === "42501"
    );
    await client.query("rollback");
  } finally {
    client.release();
    await pool.end();
  }
}

await migrateDatabase(databaseUrl);
const database = createDatabase(databaseUrl, {
  applicationName: "mergesignal-phase1-integration",
  maximumPoolSize: 5
});
const firstTenantId = randomUUID();
const secondTenantId = randomUUID();
await database
  .insertInto("app.tenants")
  .values([
    { id: firstTenantId, slug: `integration-${firstTenantId.slice(0, 8)}` },
    { id: secondTenantId, slug: `integration-${secondTenantId.slice(0, 8)}` }
  ])
  .execute();
await verifyRowLevelSecurity(firstTenantId, secondTenantId);

const deliveryId = randomUUID();
const rawBody = JSON.stringify({ deliveryId, test: "forced-retry" });
const delivery = {
  tenantId: firstTenantId,
  deliveryId,
  bodyDigest: createHash("sha256").update(rawBody).digest("hex"),
  failActivityAttempts: 2,
  payload: { test: "forced-retry" }
};
const firstAcceptance = await acceptSyntheticDelivery(database, delivery);
const duplicateAcceptance = await acceptSyntheticDelivery(database, delivery);
assert.equal(firstAcceptance.accepted, true);
assert.equal(duplicateAcceptance.accepted, false);
assert.equal(firstAcceptance.deliveryRecordId, duplicateAcceptance.deliveryRecordId);
assert.equal(firstAcceptance.outboxEventId, duplicateAcceptance.outboxEventId);
await assert.rejects(
  acceptSyntheticDelivery(database, {
    ...delivery,
    bodyDigest: "f".repeat(64)
  }),
  /changed payload digest/
);

await withTenantTransaction(database, firstTenantId, (transaction) =>
  transaction
    .updateTable("app.outbox_events")
    .set({
      state: "publishing",
      lease_token: randomUUID(),
      lease_expires_at: new Date(0)
    })
    .where("id", "=", firstAcceptance.outboxEventId)
    .executeTakeFirstOrThrow()
);

const connection = await connectTemporalWithRetry();
const temporalClient = new Client({ connection, namespace: "default" });
const worker = await Worker.create({
  activities: createActivities(database),
  connection,
  namespace: "default",
  taskQueue: "mergesignal-foundation-integration",
  workflowsPath: resolve("packages/workflows/dist/workflows.js")
});
const relayAbort = new AbortController();
const relayEnvironment = {
  MERGESIGNAL_ENV: "test",
  DEPLOYMENT_ID: "phase1-integration",
  DATABASE_URL: databaseUrl,
  TEMPORAL_ADDRESS: temporalAddress,
  TEMPORAL_NAMESPACE: "default",
  TEMPORAL_TASK_QUEUE: "mergesignal-foundation-integration",
  TEMPORAL_TLS_ENABLED: false,
  TEMPORAL_WORKER_VERSIONING_ENABLED: false,
  TEMPORAL_DEPLOYMENT_NAME: "mergesignal-integration",
  WORKER_BUILD_ID: "phase1-integration",
  WORKER_HEALTH_PORT: 8080
};
const workerPromise = worker.run();
const relayPromise = runOutboxRelay({
  database,
  temporalClient,
  environment: relayEnvironment,
  signal: relayAbort.signal
});

try {
  const result = await waitForResult(database, firstTenantId, deliveryId);
  assert.equal(result.activity_attempts, 3);

  const state = await withTenantTransaction(database, firstTenantId, async (transaction) => {
    const [deliveries, outbox, workflows, results] = await Promise.all([
      transaction
        .selectFrom("app.webhook_deliveries")
        .select(({ fn }) => fn.countAll().as("count"))
        .where("delivery_id", "=", deliveryId)
        .executeTakeFirstOrThrow(),
      transaction
        .selectFrom("app.outbox_events")
        .select(["state", "attempt_count"])
        .where("dedupe_key", "=", `synthetic:${deliveryId}`)
        .executeTakeFirstOrThrow(),
      transaction
        .selectFrom("app.workflow_runs")
        .select(["state"])
        .where("source_delivery_id", "=", deliveryId)
        .execute(),
      transaction
        .selectFrom("app.synthetic_results")
        .select(({ fn }) => fn.countAll().as("count"))
        .where("delivery_id", "=", deliveryId)
        .executeTakeFirstOrThrow()
    ]);
    return { deliveries, outbox, workflows, results };
  });
  assert.equal(Number(state.deliveries.count), 1);
  assert.equal(state.outbox.state, "published");
  assert.equal(state.outbox.attempt_count, 1);
  assert.equal(state.workflows.length, 1);
  assert.equal(state.workflows[0]?.state, "completed");
  assert.equal(Number(state.results.count), 1);

  process.stdout.write(
    `Phase 1 foundation integration valid delivery=${deliveryId} activityAttempts=${result.activity_attempts}\n`
  );
} finally {
  relayAbort.abort();
  worker.shutdown();
  await Promise.allSettled([workerPromise, relayPromise]);
  await connection.close();
  await database.destroy();
}
