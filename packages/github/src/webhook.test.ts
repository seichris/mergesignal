import { describe, expect, it } from "vitest";

import { parseGitHubWebhookEnvelope } from "./webhook.js";

describe("parseGitHubWebhookEnvelope", () => {
  it("keeps only lifecycle fields needed after ingress", () => {
    const raw = JSON.stringify({
      action: "opened",
      installation: {
        id: 41,
        account: { node_id: "O_1", login: "example", type: "Organization" },
        permissions: { pull_requests: "write" },
        events: ["pull_request"]
      },
      repository: {
        id: 51,
        node_id: "R_1",
        full_name: "example/repository",
        private: false,
        default_branch: "main",
        description: "must not be persisted"
      },
      pull_request: {
        id: 61,
        node_id: "PR_1",
        number: 7,
        state: "open",
        draft: false,
        updated_at: "2026-07-21T00:00:00Z",
        title: "must not be persisted",
        body: "must not be persisted",
        head: { sha: "a".repeat(40) },
        base: { sha: "b".repeat(40) },
        user: { node_id: "U_1", login: "contributor", type: "User" }
      }
    });

    const envelope = parseGitHubWebhookEnvelope("pull_request", raw);
    expect(envelope.pullRequest?.headSha).toBe("a".repeat(40));
    expect(envelope.pullRequest?.authorType).toBe("User");
    expect(JSON.stringify(envelope)).not.toContain("must not be persisted");
  });

  it("rejects unsupported event headers", () => {
    expect(() => parseGitHubWebhookEnvelope("push", "{}")).toThrow();
  });
});
