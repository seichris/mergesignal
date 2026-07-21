import { beforeAll, describe, expect, it } from "vitest";

import { POST } from "./route.js";

beforeAll(() => {
  process.env.MERGESIGNAL_ENV = "test";
  process.env.DEPLOYMENT_ID = "web-route-test";
  process.env.DATABASE_URL = "postgresql://user:password@localhost:5432/mergesignal";
  process.env.INTERNAL_INGRESS_TOKEN = "0123456789abcdef0123456789abcdef";
  process.env.GITHUB_APP_ID = "12345";
  process.env.GITHUB_APP_SLUG = "mergesignal";
  process.env.GITHUB_WEBHOOK_SECRET = "0123456789abcdef0123456789abcdef";
  process.env.APP_ORIGIN = "http://localhost:3000";
});

describe("synthetic delivery ingress", () => {
  it("rejects unauthenticated requests before touching the database", async () => {
    const response = await POST(
      new Request("http://localhost/api/internal/synthetic-deliveries", {
        method: "POST",
        body: "{}"
      })
    );
    expect(response.status).toBe(401);
  });

  it("rejects oversized authenticated requests before parsing", async () => {
    const response = await POST(
      new Request("http://localhost/api/internal/synthetic-deliveries", {
        method: "POST",
        headers: {
          authorization: "Bearer 0123456789abcdef0123456789abcdef",
          "content-length": "65537"
        },
        body: "{}"
      })
    );
    expect(response.status).toBe(413);
  });
});
