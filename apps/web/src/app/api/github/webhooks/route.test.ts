import { createHmac } from "node:crypto";

import { describe, expect, it, vi } from "vitest";

import { createGitHubWebhookHandler } from "./route.js";

const environment = {
  MERGESIGNAL_ENV: "test" as const,
  DEPLOYMENT_ID: "test",
  DATABASE_URL: "postgresql://example:example@localhost:5432/example",
  INTERNAL_INGRESS_TOKEN: "0".repeat(32),
  GITHUB_APP_ID: "12345",
  GITHUB_APP_SLUG: "mergesignal",
  GITHUB_WEBHOOK_SECRET: "test-webhook-secret-that-is-long-enough",
  APP_ORIGIN: "http://localhost:3000"
};

const payload = JSON.stringify({
  action: "created",
  installation: {
    id: 100,
    account: { node_id: "O_1", login: "example", type: "Organization" },
    permissions: { pull_requests: "write", checks: "write" },
    events: ["pull_request"]
  },
  repositories: []
});

function signedRequest(body = payload, signatureBody = body): Request {
  const signature = createHmac("sha256", environment.GITHUB_WEBHOOK_SECRET)
    .update(signatureBody)
    .digest("hex");
  return new Request("http://localhost/api/github/webhooks", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-github-delivery": "11111111-1111-4111-8111-111111111111",
      "x-github-event": "installation",
      "x-hub-signature-256": `sha256=${signature}`
    },
    body
  });
}

describe("GitHub webhook ingress", () => {
  it("verifies the exact body and accepts a supported event", async () => {
    const acceptDelivery = vi.fn().mockResolvedValue({
      tenantId: "22222222-2222-4222-8222-222222222222",
      accepted: true,
      deliveryRecordId: "33333333-3333-4333-8333-333333333333",
      outboxEventId: "44444444-4444-4444-8444-444444444444"
    });
    const response = await createGitHubWebhookHandler({
      environment: () => environment,
      acceptDelivery
    })(signedRequest());
    expect(response.status).toBe(202);
    expect(acceptDelivery).toHaveBeenCalledOnce();
  });

  it("rejects changed, unsigned, unsupported, and oversized input before persistence", async () => {
    const acceptDelivery = vi.fn();
    const handler = createGitHubWebhookHandler({ environment: () => environment, acceptDelivery });
    expect((await handler(signedRequest(`${payload} `, payload))).status).toBe(401);
    expect(
      (
        await handler(
          new Request("http://localhost/api/github/webhooks", {
            method: "POST",
            headers: { "content-type": "text/plain" },
            body: payload
          })
        )
      ).status
    ).toBe(415);
    expect(
      (
        await handler(
          new Request("http://localhost/api/github/webhooks", {
            method: "POST",
            headers: { "content-type": "application/json", "content-length": "1048577" },
            body: "{}"
          })
        )
      ).status
    ).toBe(413);
    expect(acceptDelivery).not.toHaveBeenCalled();
  });
});
