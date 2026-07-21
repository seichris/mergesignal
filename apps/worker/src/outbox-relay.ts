import {
  WorkflowExecutionAlreadyStartedError,
  type Client
} from "@temporalio/client";
import { z } from "zod";

import type { WorkerEnvironment } from "@mergesignal/config";
import {
  claimOutboxEvents,
  markOutboxPublished,
  recordWorkflowStarted,
  releaseOutboxEvent,
  type Database
} from "@mergesignal/database";
import { logEvent, withSpan } from "@mergesignal/observability";
import {
  workflowIdForGitHubDelivery,
  workflowIdForSyntheticDelivery
} from "@mergesignal/workflows";

const syntheticPayloadSchema = z.object({
  tenantId: z.uuid(),
  deliveryId: z.uuid(),
  bodyDigest: z.string().regex(/^[0-9a-f]{64}$/),
  failActivityAttempts: z.number().int().min(0).max(5)
});

const githubPayloadSchema = z.object({
  tenantId: z.uuid(),
  deliveryId: z.uuid(),
  deliveryRecordId: z.uuid()
});

function waitForPoll(signal: AbortSignal, milliseconds: number): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) {
      resolve();
      return;
    }
    const timeout = setTimeout(resolve, milliseconds);
    signal.addEventListener(
      "abort",
      () => {
        clearTimeout(timeout);
        resolve();
      },
      { once: true }
    );
  });
}

function errorCode(error: unknown): string {
  if (error instanceof Error && error.name.length > 0) return error.name;
  return "UnknownError";
}

export async function runOutboxRelay(options: {
  database: Database;
  temporalClient: Client;
  environment: WorkerEnvironment;
  signal: AbortSignal;
}): Promise<void> {
  const { database, temporalClient, environment, signal } = options;
  while (!signal.aborted) {
    const events = await claimOutboxEvents(database);
    if (events.length === 0) {
      await waitForPoll(signal, 250);
      continue;
    }

    for (const event of events) {
      if (signal.aborted) break;
      try {
        await withSpan(
          "outbox.publish",
          {
            "mergesignal.outbox.id": event.id,
            "mergesignal.outbox.event_type": event.eventType,
            "mergesignal.tenant.id": event.tenantId
          },
          async () => {
            const synthetic = event.eventType === "synthetic.delivery.accepted";
            const github = event.eventType === "github.delivery.accepted";
            if (!synthetic && !github) {
              throw new Error(`Unsupported outbox event type: ${event.eventType}`);
            }
            const payload = synthetic
              ? syntheticPayloadSchema.parse(event.payload)
              : githubPayloadSchema.parse(event.payload);
            if (payload.tenantId !== event.tenantId) {
              throw new Error("Outbox tenant does not match its payload tenant");
            }
            const workflowId = synthetic
              ? workflowIdForSyntheticDelivery(payload.deliveryId)
              : workflowIdForGitHubDelivery(payload.deliveryId);
            const workflowType = synthetic
              ? "syntheticDeliveryWorkflow"
              : "processGitHubDeliveryWorkflow";
            const args = synthetic
              ? [{ ...payload, workflowId }]
              : [
                  {
                    tenantId: payload.tenantId,
                    deliveryId: payload.deliveryId,
                    workflowId,
                    expectedAppId: Number(environment.GITHUB_APP_ID)
                  }
                ];
            try {
              await temporalClient.workflow.start(workflowType, {
                args,
                taskQueue: environment.TEMPORAL_TASK_QUEUE,
                workflowId
              });
            } catch (error) {
              if (!(error instanceof WorkflowExecutionAlreadyStartedError)) throw error;
            }
            await recordWorkflowStarted(database, {
              tenantId: payload.tenantId,
              workflowId,
              taskQueue: environment.TEMPORAL_TASK_QUEUE,
              deliveryId: payload.deliveryId,
              workflowType
            });
            await markOutboxPublished(database, event.id, event.leaseToken);
          }
        );
      } catch (error) {
        await releaseOutboxEvent(database, event.id, event.leaseToken, errorCode(error));
        logEvent("warn", "outbox.publish_failed", {
          outboxId: event.id,
          errorCode: errorCode(error)
        });
      }
    }
  }
}
