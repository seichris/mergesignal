import { Client } from "@temporalio/client";
import { NativeConnection } from "@temporalio/worker";

import type { WorkerEnvironment } from "@mergesignal/config";

function tlsConfiguration(environment: WorkerEnvironment) {
  if (!environment.TEMPORAL_TLS_ENABLED) return false;
  if (environment.TEMPORAL_TLS_CERT !== undefined && environment.TEMPORAL_TLS_KEY !== undefined) {
    return {
      clientCertPair: {
        crt: Buffer.from(environment.TEMPORAL_TLS_CERT, "base64"),
        key: Buffer.from(environment.TEMPORAL_TLS_KEY, "base64")
      }
    };
  }
  return true;
}

export async function connectTemporal(environment: WorkerEnvironment): Promise<{
  connection: NativeConnection;
  client: Client;
}> {
  const connection = await NativeConnection.connect({
    address: environment.TEMPORAL_ADDRESS,
    ...(environment.TEMPORAL_API_KEY === undefined ? {} : { apiKey: environment.TEMPORAL_API_KEY }),
    tls: tlsConfiguration(environment)
  });
  return {
    connection,
    client: new Client({ connection, namespace: environment.TEMPORAL_NAMESPACE })
  };
}
