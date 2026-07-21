import { generateKeyPairSync } from "node:crypto";

import { describe, expect, it } from "vitest";

import { GitHubAppClient, GitHubGraphqlError } from "./client.js";

function privateKey(): string {
  return generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({
    format: "pem",
    type: "pkcs8"
  }).toString();
}

describe("GitHubAppClient GraphQL", () => {
  it("uses an installation token and returns GraphQL data", async () => {
    const requests: Array<{ url: string; authorization: string | null }> = [];
    const fetchImplementation: typeof fetch = async (input, init) => {
      const url = input.toString();
      const headers = new Headers(init?.headers);
      requests.push({ url, authorization: headers.get("authorization") });
      if (url.endsWith("/access_tokens")) {
        return Response.json({
          token: "ghs_test",
          expires_at: "2026-07-22T02:00:00.000Z"
        }, { status: 201 });
      }
      return Response.json({ data: { node: { id: "U_1" } } });
    };
    const client = new GitHubAppClient({
      appId: "41",
      privateKey: privateKey(),
      fetchImplementation,
      now: () => new Date("2026-07-22T00:00:00.000Z")
    });
    await expect(client.installationGraphqlRequest(51, "query { node }", {})).resolves.toEqual({
      node: { id: "U_1" }
    });
    expect(requests[1]).toEqual({
      url: "https://api.github.com/graphql",
      authorization: "Bearer ghs_test"
    });
  });

  it("turns GraphQL rate-limit errors into typed retryable failures", async () => {
    const fetchImplementation: typeof fetch = async (input) => {
      if (input.toString().endsWith("/access_tokens")) {
        return Response.json({
          token: "ghs_test",
          expires_at: "2026-07-22T02:00:00.000Z"
        }, { status: 201 });
      }
      return Response.json(
        { errors: [{ type: "RATE_LIMITED", message: "rate limit exceeded" }] },
        { headers: { "x-ratelimit-reset": "1784689200" } }
      );
    };
    const client = new GitHubAppClient({
      appId: "41",
      privateKey: privateKey(),
      fetchImplementation,
      now: () => new Date("2026-07-22T00:00:00.000Z")
    });
    const error = await client
      .installationGraphqlRequest(51, "query { node }", {})
      .catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(GitHubGraphqlError);
    expect((error as GitHubGraphqlError).retryable).toBe(true);
    expect((error as GitHubGraphqlError).rateLimitReset).toBe("1784689200");
  });
});
