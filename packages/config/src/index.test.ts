import { describe, expect, it } from "vitest";

import { parseWorkerEnvironment } from "./index.js";

const baseEnvironment = {
  MERGESIGNAL_ENV: "test",
  DEPLOYMENT_ID: "test-deployment",
  DATABASE_URL: "postgresql://user:password@localhost:5432/mergesignal",
  TEMPORAL_ADDRESS: "127.0.0.1:7233",
  TEMPORAL_NAMESPACE: "default",
  TEMPORAL_TASK_QUEUE: "mergesignal-test",
  TEMPORAL_TLS_ENABLED: "false",
  TEMPORAL_WORKER_VERSIONING_ENABLED: "false",
  TEMPORAL_DEPLOYMENT_NAME: "mergesignal-worker",
  WORKER_BUILD_ID: "test-build",
  GITHUB_APP_ID: "12345",
  GITHUB_APP_PRIVATE_KEY_BASE64: Buffer.from(
    "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"
  ).toString("base64"),
  GITHUB_VERIFY_APP_IDENTITY: "false",
  APP_ORIGIN: "http://localhost:3000"
};

describe("parseWorkerEnvironment", () => {
  it("accepts local development without Temporal credentials", () => {
    expect(parseWorkerEnvironment(baseEnvironment).TEMPORAL_WORKER_VERSIONING_ENABLED).toBe(false);
  });

  it("requires versioning in production", () => {
    expect(() =>
      parseWorkerEnvironment({
        ...baseEnvironment,
        MERGESIGNAL_ENV: "production",
        TEMPORAL_ADDRESS: "mergesignal.tmprl.cloud:7233",
        APP_ORIGIN: "https://mergesignal.example.com"
      })
    ).toThrow(/Versioning/);
  });

  it("requires TLS in production", () => {
    expect(() =>
      parseWorkerEnvironment({
        ...baseEnvironment,
        MERGESIGNAL_ENV: "production",
        TEMPORAL_ADDRESS: "mergesignal.tmprl.cloud:7233",
        TEMPORAL_WORKER_VERSIONING_ENABLED: "true",
        APP_ORIGIN: "https://mergesignal.example.com"
      })
    ).toThrow(/Temporal TLS/);
  });

  it("rejects incomplete mTLS credentials", () => {
    expect(() =>
      parseWorkerEnvironment({
        ...baseEnvironment,
        TEMPORAL_TLS_CERT: "Y2VydGlmaWNhdGU=",
        TEMPORAL_TLS_ENABLED: "true"
      })
    ).toThrow(/supplied together/);
  });
});
