import { createHash } from "node:crypto";

import { parseWebEnvironment, type WebEnvironment } from "@mergesignal/config";
import {
  acceptGitHubDelivery,
  createDatabase,
  type AcceptedGitHubDelivery,
  type Database
} from "@mergesignal/database";
import { parseGitHubWebhookEnvelope } from "@mergesignal/github";
import { withSpan } from "@mergesignal/observability";
import { verifyGitHubWebhookSignature } from "@mergesignal/security";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const maximumBodyBytes = 1_048_576;
const deliveryPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

interface HandlerDependencies {
  environment: () => WebEnvironment;
  acceptDelivery: (input: {
    deliveryId: string;
    bodyDigest: string;
    envelope: ReturnType<typeof parseGitHubWebhookEnvelope>;
  }) => Promise<AcceptedGitHubDelivery>;
}

let environment: WebEnvironment | undefined;
let database: Database | undefined;

function getEnvironment(): WebEnvironment {
  environment ??= parseWebEnvironment();
  return environment;
}

function getDatabase(): Database {
  const current = getEnvironment();
  database ??= createDatabase(current.DATABASE_URL, {
    applicationName: `mergesignal-web:${current.DEPLOYMENT_ID}`,
    maximumPoolSize: 2
  });
  return database;
}

const defaultDependencies: HandlerDependencies = {
  environment: getEnvironment,
  acceptDelivery: (input) => acceptGitHubDelivery(getDatabase(), input)
};

export function createGitHubWebhookHandler(
  dependencies: HandlerDependencies = defaultDependencies
): (request: Request) => Promise<Response> {
  return async (request) => {
    const contentType = request.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
    if (contentType !== "application/json") {
      return Response.json({ error: "unsupported_media_type" }, { status: 415 });
    }
    const contentLength = Number(request.headers.get("content-length") ?? "0");
    if (!Number.isFinite(contentLength) || contentLength > maximumBodyBytes) {
      return Response.json({ error: "request_too_large" }, { status: 413 });
    }

    const bytes = new Uint8Array(await request.arrayBuffer());
    if (bytes.byteLength > maximumBodyBytes) {
      return Response.json({ error: "request_too_large" }, { status: 413 });
    }
    const currentEnvironment = dependencies.environment();
    if (
      !verifyGitHubWebhookSignature(
        bytes,
        request.headers.get("x-hub-signature-256"),
        currentEnvironment.GITHUB_WEBHOOK_SECRET
      )
    ) {
      return Response.json({ error: "invalid_signature" }, { status: 401 });
    }

    const deliveryId = request.headers.get("x-github-delivery") ?? "";
    if (!deliveryPattern.test(deliveryId)) {
      return Response.json({ error: "invalid_delivery_id" }, { status: 400 });
    }

    let rawBody: string;
    let envelope: ReturnType<typeof parseGitHubWebhookEnvelope>;
    try {
      rawBody = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      envelope = parseGitHubWebhookEnvelope(request.headers.get("x-github-event"), rawBody);
    } catch {
      return Response.json({ error: "unsupported_or_invalid_event" }, { status: 400 });
    }

    try {
      const result = await withSpan(
        "ingress.github_webhook",
        {
          "mergesignal.delivery.id": deliveryId,
          "mergesignal.github.event": envelope.event,
          "mergesignal.github.installation_id": envelope.installation.id
        },
        () =>
          dependencies.acceptDelivery({
            deliveryId,
            bodyDigest: createHash("sha256").update(bytes).digest("hex"),
            envelope
          })
      );
      return Response.json(result, {
        status: result.accepted ? 202 : 200,
        headers: { "cache-control": "no-store" }
      });
    } catch (error) {
      const code =
        typeof error === "object" && error !== null && "code" in error ? error.code : undefined;
      if (code === "23503") {
        return Response.json({ error: "installation_not_ready" }, { status: 503 });
      }
      if (code === "23505") {
        return Response.json({ error: "delivery_conflict" }, { status: 409 });
      }
      throw error;
    }
  };
}

export const POST = createGitHubWebhookHandler();
