import { fileURLToPath } from "node:url";

import { VersioningBehavior } from "@temporalio/common";
import { Worker } from "@temporalio/worker";

import { parseWorkerEnvironment } from "@mergesignal/config";
import { createDatabase } from "@mergesignal/database";
import { GitHubAppClient, GitHubRestOutputProvider } from "@mergesignal/github";
import {
  logEvent,
  startObservability,
  stopObservability
} from "@mergesignal/observability";

import { createActivities } from "./activities.js";
import { startWorkerHealthServer, stopWorkerHealthServer } from "./health-server.js";
import { runOutboxRelay } from "./outbox-relay.js";
import { connectTemporal } from "./temporal.js";

const environment = parseWorkerEnvironment();
await startObservability({
  serviceName: "mergesignal-worker",
  serviceVersion: environment.WORKER_BUILD_ID,
  deploymentEnvironment: environment.MERGESIGNAL_ENV,
  deploymentId: environment.DEPLOYMENT_ID,
  ...(environment.OTEL_EXPORTER_OTLP_ENDPOINT === undefined
    ? {}
    : { exporterEndpoint: environment.OTEL_EXPORTER_OTLP_ENDPOINT })
});

const database = createDatabase(environment.DATABASE_URL, {
  applicationName: `mergesignal-worker:${environment.DEPLOYMENT_ID}`,
  maximumPoolSize: 10
});
const githubClient = new GitHubAppClient({
  appId: environment.GITHUB_APP_ID,
  privateKey: Buffer.from(environment.GITHUB_APP_PRIVATE_KEY_BASE64, "base64").toString("utf8"),
  apiBaseUrl: environment.GITHUB_API_BASE_URL
});
if (environment.GITHUB_VERIFY_APP_IDENTITY) {
  const identity = await githubClient.getAppIdentity();
  if (identity.id.toString() !== environment.GITHUB_APP_ID) {
    throw new Error("Authenticated GitHub App identity does not match GITHUB_APP_ID");
  }
}
const githubOutputProvider = new GitHubRestOutputProvider(githubClient);
const { connection, client } = await connectTemporal(environment);
const workflowsPath = fileURLToPath(import.meta.resolve("@mergesignal/workflows/workflows"));
const worker = await Worker.create({
  activities: createActivities(database, {
    client: githubClient,
    outputProvider: githubOutputProvider,
    appId: Number(environment.GITHUB_APP_ID),
    appOrigin: environment.APP_ORIGIN
  }),
  connection,
  namespace: environment.TEMPORAL_NAMESPACE,
  taskQueue: environment.TEMPORAL_TASK_QUEUE,
  workerDeploymentOptions: environment.TEMPORAL_WORKER_VERSIONING_ENABLED
    ? {
        version: {
          deploymentName: environment.TEMPORAL_DEPLOYMENT_NAME,
          buildId: environment.WORKER_BUILD_ID
        },
        useWorkerVersioning: true,
        defaultVersioningBehavior: VersioningBehavior.PINNED
      }
    : {
        version: {
          deploymentName: environment.TEMPORAL_DEPLOYMENT_NAME,
          buildId: environment.WORKER_BUILD_ID
        },
        useWorkerVersioning: false
      },
  workflowsPath
});

const relayAbort = new AbortController();
const healthState = { ready: false, stopping: false };
const healthServer = await startWorkerHealthServer(environment.WORKER_HEALTH_PORT, healthState);
const stop = () => {
  if (healthState.stopping) return;
  healthState.stopping = true;
  healthState.ready = false;
  relayAbort.abort();
  worker.shutdown();
};
process.once("SIGINT", stop);
process.once("SIGTERM", stop);

logEvent("info", "worker.started", {
  deploymentId: environment.DEPLOYMENT_ID,
  healthPort: environment.WORKER_HEALTH_PORT,
  taskQueue: environment.TEMPORAL_TASK_QUEUE,
  versioningEnabled: environment.TEMPORAL_WORKER_VERSIONING_ENABLED
});
healthState.ready = true;

try {
  await Promise.all([
    worker.run(),
    runOutboxRelay({
      database,
      temporalClient: client,
      environment,
      signal: relayAbort.signal
    })
  ]);
} finally {
  healthState.stopping = true;
  healthState.ready = false;
  relayAbort.abort();
  await stopWorkerHealthServer(healthServer);
  await connection.close();
  await database.destroy();
  await stopObservability();
}
