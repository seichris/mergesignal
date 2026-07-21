import { describe, expect, it, vi } from "vitest";

import { logEvent } from "./index.js";

describe("structured logging", () => {
  it("rejects fields likely to contain secrets or private payloads", () => {
    expect(() => logEvent("info", "unsafe", { authorizationToken: "secret" })).toThrow(
      /Sensitive log attribute/
    );
  });

  it("emits one JSON record for allowlisted operational metadata", () => {
    const write = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    logEvent("info", "worker.ready", { deploymentId: "test", queueDepth: 0 });
    expect(JSON.parse(String(write.mock.calls[0]?.[0]))).toMatchObject({
      severity: "info",
      event: "worker.ready",
      deploymentId: "test",
      queueDepth: 0
    });
    write.mockRestore();
  });
});
