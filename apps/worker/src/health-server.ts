import { createServer, type Server } from "node:http";

export interface WorkerHealthState {
  ready: boolean;
  stopping: boolean;
}

function responseBody(status: "live" | "ready" | "not_ready"): string {
  return `${JSON.stringify({ status })}\n`;
}

export async function startWorkerHealthServer(
  port: number,
  state: WorkerHealthState
): Promise<Server> {
  const server = createServer((request, response) => {
    response.setHeader("cache-control", "no-store");
    response.setHeader("content-type", "application/json; charset=utf-8");

    if (request.method !== "GET") {
      response.writeHead(405, { allow: "GET" }).end();
      return;
    }
    if (request.url === "/livez") {
      response.writeHead(200).end(responseBody("live"));
      return;
    }
    if (request.url === "/readyz") {
      const ready = state.ready && !state.stopping;
      response.writeHead(ready ? 200 : 503).end(responseBody(ready ? "ready" : "not_ready"));
      return;
    }
    response.writeHead(404).end();
  });

  await new Promise<void>((resolve, reject) => {
    const handleError = (error: Error) => reject(error);
    server.once("error", handleError);
    server.listen(port, "0.0.0.0", () => {
      server.off("error", handleError);
      resolve();
    });
  });
  return server;
}

export async function stopWorkerHealthServer(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error === undefined) resolve();
      else reject(error);
    });
  });
}
