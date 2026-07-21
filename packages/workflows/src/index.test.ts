import { describe, expect, it } from "vitest";

import { workflowIdForSyntheticDelivery } from "./index.js";

describe("workflowIdForSyntheticDelivery", () => {
  it("is deterministic and normalized", () => {
    expect(workflowIdForSyntheticDelivery("D9428888-122B-41E1-B85C-61C590CE2D9D")).toBe(
      "synthetic-delivery/d9428888-122b-41e1-b85c-61c590ce2d9d"
    );
  });

  it("rejects caller-controlled workflow path text", () => {
    expect(() => workflowIdForSyntheticDelivery("../../other-workflow")).toThrow(/UUID/);
  });
});
