import { createHash, timingSafeEqual } from "node:crypto";

import { z } from "zod";

import { parseWebEnvironment, type WebEnvironment } from "@mergesignal/config";
import {
  acceptSyntheticDelivery,
  createDatabase,
  type Database
} from "@mergesignal/database";
import { withSpan } from "@mergesignal/observability";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const requestSchema = z.object({
  tenantId: z.uuid(),
  deliveryId: z.uuid(),
  failActivityAttempts: z.number().int().min(0).max(5).default(0),
  payload: z.record(z.string(), z.unknown()).default({})
});

let environment: WebEnvironment | undefined;
let database: Database | undefined;

function getEnvironment(): WebEnvironment {
  environment ??= parseWebEnvironment();
  return environment;
}

function getDatabase(): Database {
  const currentEnvironment = getEnvironment();
  database ??= createDatabase(currentEnvironment.DATABASE_URL, {
    applicationName: `mergesignal-web:${currentEnvironment.DEPLOYMENT_ID}`,
    maximumPoolSize: 2
  });
  return database;
}

function tokenMatches(authorization: string | null, expected: string): boolean {
  const supplied = authorization?.startsWith("Bearer ") ? authorization.slice(7) : "";
  const suppliedDigest = createHash("sha256").update(supplied).digest();
  const expectedDigest = createHash("sha256").update(expected).digest();
  return timingSafeEqual(suppliedDigest, expectedDigest);
}

export async function POST(request: Request): Promise<Response> {
  const currentEnvironment = getEnvironment();
  if (!tokenMatches(request.headers.get("authorization"), currentEnvironment.INTERNAL_INGRESS_TOKEN)) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }
  const contentLength = Number(request.headers.get("content-length") ?? "0");
  if (!Number.isFinite(contentLength) || contentLength > 65_536) {
    return Response.json({ error: "request_too_large" }, { status: 413 });
  }

  const rawBody = await request.text();
  if (Buffer.byteLength(rawBody, "utf8") > 65_536) {
    return Response.json({ error: "request_too_large" }, { status: 413 });
  }

  let input: z.infer<typeof requestSchema>;
  try {
    input = requestSchema.parse(JSON.parse(rawBody));
  } catch {
    return Response.json({ error: "invalid_request" }, { status: 400 });
  }

  const result = await withSpan(
    "ingress.synthetic_delivery",
    {
      "mergesignal.tenant.id": input.tenantId,
      "mergesignal.delivery.id": input.deliveryId
    },
    () =>
      acceptSyntheticDelivery(getDatabase(), {
        ...input,
        bodyDigest: createHash("sha256").update(rawBody).digest("hex")
      })
  );

  return Response.json(result, {
    status: result.accepted ? 202 : 200,
    headers: { "cache-control": "no-store" }
  });
}
