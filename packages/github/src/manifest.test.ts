import { describe, expect, it } from "vitest";

import { buildGitHubAppManifest } from "./manifest.js";

describe("buildGitHubAppManifest", () => {
  it("requests only the Phase 2 repository permissions and webhooks", () => {
    const manifest = buildGitHubAppManifest("https://mergesignal.example.com/");
    expect(manifest.hook_attributes.url).toBe(
      "https://mergesignal.example.com/api/github/webhooks"
    );
    expect(manifest.default_permissions).toEqual({
      checks: "write",
      contents: "read",
      metadata: "read",
      pull_requests: "write"
    });
    expect(manifest.default_events).toEqual([
      "check_run",
      "installation",
      "installation_repositories",
      "pull_request"
    ]);
  });
});
