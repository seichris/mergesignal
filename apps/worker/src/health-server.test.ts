import { type AddressInfo } from "node:net";

import { afterEach, describe, expect, it } from "vitest";

import {
  startWorkerHealthServer,
  stopWorkerHealthServer,
  type WorkerHealthState
} from "./health-server.js";

const servers = new Set<Awaited<ReturnType<typeof startWorkerHealthServer>>>();

afterEach(async () => {
  await Promise.all([...servers].map((server) => stopWorkerHealthServer(server)));
  servers.clear();
});

async function start(state: WorkerHealthState) {
  const server = await startWorkerHealthServer(0, state);
  servers.add(server);
  const address = server.address() as AddressInfo;
  return { server, baseUrl: `http://127.0.0.1:${address.port}` };
}

describe("worker health server", () => {
  it("reports liveness independently from readiness", async () => {
    const state = { ready: false, stopping: false };
    const { baseUrl } = await start(state);

    expect((await fetch(`${baseUrl}/livez`)).status).toBe(200);
    expect((await fetch(`${baseUrl}/readyz`)).status).toBe(503);

    state.ready = true;
    expect((await fetch(`${baseUrl}/readyz`)).status).toBe(200);

    state.stopping = true;
    expect((await fetch(`${baseUrl}/readyz`)).status).toBe(503);
  });

  it("rejects unsupported routes and methods", async () => {
    const { baseUrl } = await start({ ready: true, stopping: false });
    expect((await fetch(`${baseUrl}/missing`)).status).toBe(404);
    expect((await fetch(`${baseUrl}/livez`, { method: "POST" })).status).toBe(405);
  });
});
