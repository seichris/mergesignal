import { describe, expect, it } from "vitest";

import { verifyGitHubWebhookSignature } from "./index.js";

describe("verifyGitHubWebhookSignature", () => {
  it("matches GitHub's published SHA-256 test vector", () => {
    expect(
      verifyGitHubWebhookSignature(
        "Hello, World!",
        "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17",
        "It's a Secret to Everybody"
      )
    ).toBe(true);
  });

  it("rejects malformed and changed signatures without throwing", () => {
    expect(verifyGitHubWebhookSignature("payload", null, "secret")).toBe(false);
    expect(verifyGitHubWebhookSignature("payload", "sha256=00", "secret")).toBe(false);
    expect(verifyGitHubWebhookSignature("changed", `sha256=${"0".repeat(64)}`, "secret")).toBe(
      false
    );
  });
});
